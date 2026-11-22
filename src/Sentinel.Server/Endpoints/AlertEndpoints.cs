using Microsoft.EntityFrameworkCore;
using Sentinel.Core.Abstractions;
using Sentinel.Server.Hubs;
using Sentinel.Server.Services;
using Sentinel.Shared.Api;
using Sentinel.Shared.Models;
using Sentinel.Storage;
using Sentinel.Storage.Entities;
using Sentinel.Storage.Mapping;
using Sentinel.Storage.Services;

namespace Sentinel.Server.Endpoints;

internal static class AlertEndpoints
{
    public static void MapAlertEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet(ApiRoutes.Alerts, async (
            string? status,
            string? level,
            string? type,
            string? hostId,
            string? search,
            DateTimeOffset? from,
            DateTimeOffset? to,
            int? page,
            int? pageSize,
            IDbContextFactory<SentinelDbContext> dbFactory,
            CancellationToken ct) =>
        {
            var (p, ps) = EndpointHelpers.NormalizePaging(page, pageSize);
            var parsedStatus = EndpointHelpers.TryParseEnum<AlertStatus>(status);
            var parsedLevel = EndpointHelpers.TryParseEnum<ThreatLevel>(level);
            var parsedType = EndpointHelpers.TryParseEnum<ThreatType>(type);

            await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
            var query = db.Alerts.AsNoTracking().AsQueryable();

            if (parsedStatus.HasValue) query = query.Where(a => a.Status == parsedStatus.Value);
            if (parsedLevel.HasValue) query = query.Where(a => a.Level == parsedLevel.Value);
            if (parsedType.HasValue) query = query.Where(a => a.ThreatType == parsedType.Value);
            if (!string.IsNullOrWhiteSpace(hostId)) query = query.Where(a => a.HostId == hostId.Trim());
            if (from.HasValue) query = query.Where(a => a.CreatedAtUnixMs >= from.Value.ToUnixTimeMilliseconds());
            if (to.HasValue) query = query.Where(a => a.CreatedAtUnixMs <= to.Value.ToUnixTimeMilliseconds());

            if (!string.IsNullOrWhiteSpace(search))
            {
                var term = $"%{search.Trim()}%";
                query = query.Where(a =>
                    EF.Functions.Like(a.Title, term) ||
                    EF.Functions.Like(a.Summary, term) ||
                    EF.Functions.Like(a.HostId, term) ||
                    EF.Functions.Like(a.UserId, term) ||
                    EF.Functions.Like(a.Justification, term));
            }

            var total = await query.CountAsync(ct).ConfigureAwait(false);
            var items = await query
                .OrderByDescending(a => a.UpdatedAtUnixMs)
                .Skip((p - 1) * ps)
                .Take(ps)
                .ToListAsync(ct)
                .ConfigureAwait(false);

            var alertIds = items.Select(a => a.Id).ToList();
            var pendingMap = alertIds.Count == 0
                ? new Dictionary<Guid, int>()
                : await db.ActionTickets
                    .AsNoTracking()
                    .Where(t => t.AlertId != null && alertIds.Contains(t.AlertId.Value) &&
                                (t.Status == ActionStatus.Proposed || t.Status == ActionStatus.Pending))
                    .GroupBy(t => t.AlertId!.Value)
                    .Select(g => new { AlertId = g.Key, Count = g.Count() })
                    .ToDictionaryAsync(x => x.AlertId, x => x.Count, ct)
                    .ConfigureAwait(false);

            var dtos = items.Select(a => a.ToDto(pendingMap.GetValueOrDefault(a.Id))).ToArray();
            return Results.Ok(new PagedResult<AlertDto>(dtos, total, p, ps));
        });

        app.MapGet(ApiRoutes.AlertById, async (
            Guid id,
            IDbContextFactory<SentinelDbContext> dbFactory,
            CancellationToken ct) =>
        {
            await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
            var alert = await db.Alerts
                .AsNoTracking()
                .AsSplitQuery()
                .Include(a => a.AlertEvents)
                .Include(a => a.History)
                .FirstOrDefaultAsync(a => a.Id == id, ct)
                .ConfigureAwait(false);

            if (alert is null)
                return EndpointHelpers.Error(StatusCodes.Status404NotFound, "ALERT_NOT_FOUND", "Alerte introuvable.");

            var eventIds = alert.AlertEvents.Select(ae => ae.EventId).Distinct().ToList();
            var events = eventIds.Count == 0
                ? new List<EventEntity>()
                : await db.Events
                    .AsNoTracking()
                    .Where(e => eventIds.Contains(e.Id))
                    .OrderBy(e => e.TimestampUnixMs)
                    .ToListAsync(ct)
                    .ConfigureAwait(false);

            ClusterEntity? cluster = null;
            if (alert.ClusterId is { } cid)
            {
                cluster = await db.Clusters
                    .AsNoTracking()
                    .FirstOrDefaultAsync(c => c.Id == cid, ct)
                    .ConfigureAwait(false);
            }

            var actions = await db.ActionTickets
                .AsNoTracking()
                .Where(t => t.AlertId == alert.Id)
                .OrderBy(t => t.CreatedAtUnixMs)
                .ToListAsync(ct)
                .ConfigureAwait(false);

            var pendingCount = actions.Count(t => t.Status is ActionStatus.Proposed or ActionStatus.Pending);

            var detail = new AlertDetailDto(
                alert.ToDto(pendingCount),
                alert.Justification,
                events.Select(e => e.ToDto()).ToArray(),
                cluster?.ToDto(),
                actions.Select(t => t.ToDto()).ToArray(),
                alert.History.OrderBy(h => h.Timestamp).Select(h => h.ToDto()).ToArray());

            return Results.Ok(detail);
        });

        app.MapPost(ApiRoutes.AlertApprove, async (
            Guid id,
            HttpContext ctx,
            IDbContextFactory<SentinelDbContext> dbFactory,
            IThreatPipeline pipeline,
            AgentCommandHub commandHub,
            HashChainWriter auditWriter,
            LiveBroadcaster broadcaster,
            CancellationToken ct) =>
        {
            var body = await EndpointHelpers.ReadOptionalJsonAsync<AlertDecisionRequest>(ctx.Request, ct).ConfigureAwait(false);
            var actor = EndpointHelpers.GetActor(ctx);
            var ip = EndpointHelpers.GetClientIp(ctx);
            var now = DateTimeOffset.UtcNow;

            await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
            var alert = await db.Alerts
                .AsSplitQuery()
                .Include(a => a.AlertEvents)
                .Include(a => a.History)
                .FirstOrDefaultAsync(a => a.Id == id, ct)
                .ConfigureAwait(false);

            if (alert is null)
                return EndpointHelpers.Error(StatusCodes.Status404NotFound, "ALERT_NOT_FOUND", "Alerte introuvable.");

            alert.Status = AlertStatus.Approved;
            alert.RequiresDecision = false;
            alert.UpdatedAt = now;
            alert.UpdatedAtUnixMs = now.ToUnixTimeMilliseconds();

            var proposedActions = await db.ActionTickets
                .Where(t => t.AlertId == alert.Id && t.Status == ActionStatus.Proposed)
                .ToListAsync(ct)
                .ConfigureAwait(false);

            var isActive = pipeline.Settings.Mode == OperatingMode.Active;
            var commandsToPush = new List<(string HostId, Shared.Grpc.AgentCommand Cmd)>();

            foreach (var ticket in proposedActions)
            {
                if (isActive)
                {
                    ticket.Status = ActionStatus.Pending;
                    ticket.ResultMessage = $"Approuvée par {actor}, en attente d'exécution par l'agent.";
                    commandsToPush.Add((ticket.HostId, AgentCommandHub.BuildCommand(ticket, revert: false, simulate: false)));
                }
                else
                {
                    ticket.Status = ActionStatus.Simulated;
                    ticket.ResultMessage = $"Approuvée par {actor} mais simulée (mode {pipeline.Settings.Mode}).";
                }
            }

            alert.History.Add(new AlertHistoryEntity
            {
                AlertId = alert.Id,
                Timestamp = now,
                Actor = actor,
                Action = "Approved",
                Comment = body?.Comment ?? $"Alerte approuvée ({proposedActions.Count} action(s) promue(s))."
            });

            await db.SaveChangesAsync(ct).ConfigureAwait(false);

            // Retour analyste confirmant la menace
            var eventIds = alert.AlertEvents.Select(ae => ae.EventId).ToArray();
            pipeline.ApplyFeedback(new AnalystFeedback(alert.Id, alert.ClusterId, eventIds, IsFalsePositive: false, body?.Comment));

            foreach (var (hostId, cmd) in commandsToPush)
                commandHub.TryEnqueue(hostId, cmd);

            await auditWriter.WriteAuditAsync(
                actor,
                "AlertApproved",
                $"alert:{alert.Id:D}",
                $"Alerte approuvée ({proposedActions.Count} action(s), mode={pipeline.Settings.Mode}). Commentaire: {body?.Comment}",
                ip,
                ct).ConfigureAwait(false);

            var pendingCount = await db.ActionTickets
                .CountAsync(t => t.AlertId == alert.Id && (t.Status == ActionStatus.Proposed || t.Status == ActionStatus.Pending), ct)
                .ConfigureAwait(false);

            var dto = alert.ToDto(pendingCount);
            await broadcaster.AlertUpdatedAsync(dto, ct).ConfigureAwait(false);
            foreach (var ticket in proposedActions)
                await broadcaster.ActionUpdatedAsync(ticket.ToDto(), ct).ConfigureAwait(false);
            broadcaster.NotifySummaryChanged();

            return Results.Ok(dto);
        });

        app.MapPost(ApiRoutes.AlertReject, async (
            Guid id,
            HttpContext ctx,
            IDbContextFactory<SentinelDbContext> dbFactory,
            IThreatPipeline pipeline,
            HashChainWriter auditWriter,
            LiveBroadcaster broadcaster,
            CancellationToken ct) =>
        {
            var body = await EndpointHelpers.ReadOptionalJsonAsync<AlertDecisionRequest>(ctx.Request, ct).ConfigureAwait(false);
            var actor = EndpointHelpers.GetActor(ctx);
            var ip = EndpointHelpers.GetClientIp(ctx);
            var now = DateTimeOffset.UtcNow;

            await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
            var alert = await db.Alerts
                .AsSplitQuery()
                .Include(a => a.AlertEvents)
                .Include(a => a.History)
                .FirstOrDefaultAsync(a => a.Id == id, ct)
                .ConfigureAwait(false);

            if (alert is null)
                return EndpointHelpers.Error(StatusCodes.Status404NotFound, "ALERT_NOT_FOUND", "Alerte introuvable.");

            alert.Status = AlertStatus.FalsePositive;
            alert.RequiresDecision = false;
            alert.UpdatedAt = now;
            alert.UpdatedAtUnixMs = now.ToUnixTimeMilliseconds();

            var proposedActions = await db.ActionTickets
                .Where(t => t.AlertId == alert.Id && t.Status == ActionStatus.Proposed)
                .ToListAsync(ct)
                .ConfigureAwait(false);

            foreach (var ticket in proposedActions)
            {
                ticket.Status = ActionStatus.Rejected;
                ticket.ResultMessage = $"Rejetée par {actor} (faux positif).";
            }

            alert.History.Add(new AlertHistoryEntity
            {
                AlertId = alert.Id,
                Timestamp = now,
                Actor = actor,
                Action = "Rejected",
                Comment = body?.Comment ?? "Classée comme faux positif et réinjectée dans la baseline."
            });

            await db.SaveChangesAsync(ct).ConfigureAwait(false);

            // Réinjection dans la baseline / exclusions apprises (doc §9.4)
            var eventIds = alert.AlertEvents.Select(ae => ae.EventId).ToArray();
            pipeline.ApplyFeedback(new AnalystFeedback(alert.Id, alert.ClusterId, eventIds, IsFalsePositive: true, body?.Comment));

            await auditWriter.WriteAuditAsync(
                actor,
                "AlertRejected",
                $"alert:{alert.Id:D}",
                $"Alerte classée faux positif ({proposedActions.Count} action(s) rejetée(s)). Commentaire: {body?.Comment}",
                ip,
                ct).ConfigureAwait(false);

            var dto = alert.ToDto(0);
            await broadcaster.AlertUpdatedAsync(dto, ct).ConfigureAwait(false);
            foreach (var ticket in proposedActions)
                await broadcaster.ActionUpdatedAsync(ticket.ToDto(), ct).ConfigureAwait(false);
            broadcaster.NotifySummaryChanged();

            return Results.Ok(dto);
        });

        app.MapPost(ApiRoutes.AlertAcknowledge, async (
            Guid id,
            HttpContext ctx,
            IDbContextFactory<SentinelDbContext> dbFactory,
            HashChainWriter auditWriter,
            LiveBroadcaster broadcaster,
            CancellationToken ct) =>
        {
            return await TransitionSimpleStatusAsync(
                id, AlertStatus.Acknowledged, "Acknowledged", "AlertAcknowledged",
                ctx, dbFactory, auditWriter, broadcaster, ct).ConfigureAwait(false);
        });

        app.MapPost(ApiRoutes.AlertResolve, async (
            Guid id,
            HttpContext ctx,
            IDbContextFactory<SentinelDbContext> dbFactory,
            HashChainWriter auditWriter,
            LiveBroadcaster broadcaster,
            CancellationToken ct) =>
        {
            return await TransitionSimpleStatusAsync(
                id, AlertStatus.Resolved, "Resolved", "AlertResolved",
                ctx, dbFactory, auditWriter, broadcaster, ct).ConfigureAwait(false);
        });
    }

    private static async Task<IResult> TransitionSimpleStatusAsync(
        Guid id,
        AlertStatus targetStatus,
        string historyAction,
        string auditAction,
        HttpContext ctx,
        IDbContextFactory<SentinelDbContext> dbFactory,
        HashChainWriter auditWriter,
        LiveBroadcaster broadcaster,
        CancellationToken ct)
    {
        var body = await EndpointHelpers.ReadOptionalJsonAsync<AlertDecisionRequest>(ctx.Request, ct).ConfigureAwait(false);
        var actor = EndpointHelpers.GetActor(ctx);
        var ip = EndpointHelpers.GetClientIp(ctx);
        var now = DateTimeOffset.UtcNow;

        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var alert = await db.Alerts
            .Include(a => a.History)
            .FirstOrDefaultAsync(a => a.Id == id, ct)
            .ConfigureAwait(false);

        if (alert is null)
            return EndpointHelpers.Error(StatusCodes.Status404NotFound, "ALERT_NOT_FOUND", "Alerte introuvable.");

        alert.Status = targetStatus;
        if (targetStatus == AlertStatus.Resolved)
            alert.RequiresDecision = false;
        alert.UpdatedAt = now;
        alert.UpdatedAtUnixMs = now.ToUnixTimeMilliseconds();

        alert.History.Add(new AlertHistoryEntity
        {
            AlertId = alert.Id,
            Timestamp = now,
            Actor = actor,
            Action = historyAction,
            Comment = body?.Comment
        });

        await db.SaveChangesAsync(ct).ConfigureAwait(false);

        await auditWriter.WriteAuditAsync(
            actor,
            auditAction,
            $"alert:{alert.Id:D}",
            $"Statut passé à {targetStatus}. Commentaire: {body?.Comment}",
            ip,
            ct).ConfigureAwait(false);

        var pendingCount = await db.ActionTickets
            .CountAsync(t => t.AlertId == alert.Id && (t.Status == ActionStatus.Proposed || t.Status == ActionStatus.Pending), ct)
            .ConfigureAwait(false);

        var dto = alert.ToDto(pendingCount);
        await broadcaster.AlertUpdatedAsync(dto, ct).ConfigureAwait(false);
        broadcaster.NotifySummaryChanged();

        return Results.Ok(dto);
    }
}
