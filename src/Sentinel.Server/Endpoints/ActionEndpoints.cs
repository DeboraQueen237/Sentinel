using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Sentinel.Core.Abstractions;
using Sentinel.Server.Hubs;
using Sentinel.Server.Services;
using Sentinel.Shared.Api;
using Sentinel.Shared.Json;
using Sentinel.Shared.Models;
using Sentinel.Storage;
using Sentinel.Storage.Entities;
using Sentinel.Storage.Mapping;
using Sentinel.Storage.Services;

namespace Sentinel.Server.Endpoints;

internal static class ActionEndpoints
{
    public static void MapActionEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet(ApiRoutes.Actions, async (
            string? status,
            string? type,
            string? hostId,
            bool? activeOnly,
            int? page,
            int? pageSize,
            IDbContextFactory<SentinelDbContext> dbFactory,
            CancellationToken ct) =>
        {
            var (p, ps) = EndpointHelpers.NormalizePaging(page, pageSize);
            var parsedStatus = EndpointHelpers.TryParseEnum<ActionStatus>(status);
            var parsedType = EndpointHelpers.TryParseEnum<ResponseActionType>(type);

            await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
            var query = db.ActionTickets.AsNoTracking().AsQueryable();

            if (parsedStatus.HasValue) query = query.Where(t => t.Status == parsedStatus.Value);
            if (parsedType.HasValue) query = query.Where(t => t.ActionType == (int)parsedType.Value);
            if (!string.IsNullOrWhiteSpace(hostId)) query = query.Where(t => t.HostId == hostId.Trim());
            if (activeOnly == true)
            {
                query = query.Where(t =>
                    t.Status == ActionStatus.Pending ||
                    t.Status == ActionStatus.Executed ||
                    t.Status == ActionStatus.RevertPending);
            }

            var total = await query.CountAsync(ct).ConfigureAwait(false);
            var items = await query
                .OrderByDescending(t => t.CreatedAtUnixMs)
                .Skip((p - 1) * ps)
                .Take(ps)
                .ToListAsync(ct)
                .ConfigureAwait(false);

            return Results.Ok(new PagedResult<ActionTicketDto>(items.Select(t => t.ToDto()).ToArray(), total, p, ps));
        });

        app.MapPost(ApiRoutes.Actions, async (
            [FromBody] ManualActionRequest request,
            HttpContext ctx,
            IDbContextFactory<SentinelDbContext> dbFactory,
            IThreatPipeline pipeline,
            AgentCommandHub commandHub,
            HashChainWriter auditWriter,
            LiveBroadcaster broadcaster,
            CancellationToken ct) =>
        {
            if (request is null || string.IsNullOrWhiteSpace(request.HostId) || string.IsNullOrWhiteSpace(request.Target))
            {
                return EndpointHelpers.Error(StatusCodes.Status400BadRequest, "INVALID_ACTION", "HostId et cible (Target) requis.");
            }

            if (ActionPolicyHelper.IsSkippedFromTickets(request.Type))
            {
                return EndpointHelpers.Error(StatusCodes.Status400BadRequest, "UNSUPPORTED_MANUAL_ACTION", "Ce type d'action ne peut pas être déclenché manuellement.");
            }

            var actor = EndpointHelpers.GetActor(ctx);
            var ip = EndpointHelpers.GetClientIp(ctx);
            var now = DateTimeOffset.UtcNow;
            var mode = pipeline.Settings.Mode;
            var isActive = mode == OperatingMode.Active;

            var parameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["hostId"] = request.HostId.Trim(),
                ["target"] = request.Target.Trim(),
                ["manual"] = "true",
                ["actor"] = actor,
                ["mode"] = mode.ToString()
            };

            switch (request.Type)
            {
                case ResponseActionType.BlockDomain:
                    parameters["domain"] = request.Target.Trim();
                    break;
                case ResponseActionType.BlockIp:
                    parameters["ip"] = request.Target.Trim();
                    break;
                case ResponseActionType.QuarantineFile:
                    parameters["filePath"] = request.Target.Trim();
                    break;
                case ResponseActionType.DisableDevice:
                    parameters["deviceId"] = request.Target.Trim();
                    break;
                case ResponseActionType.LockAccount or ResponseActionType.LockSession:
                    parameters["userId"] = request.Target.Trim();
                    break;
            }

            var ticket = new ActionTicketEntity
            {
                Id = Guid.NewGuid(),
                CreatedAt = now,
                CreatedAtUnixMs = now.ToUnixTimeMilliseconds(),
                HostId = request.HostId.Trim(),
                AlertId = null,
                ActionType = (int)request.Type,
                Target = request.Target.Trim(),
                ParametersJson = SentinelJson.Serialize(parameters),
                Status = isActive ? ActionStatus.Pending : ActionStatus.Simulated,
                Automatic = false,
                Reversible = ActionPolicyHelper.IsReversible(request.Type),
                Rationale = string.IsNullOrWhiteSpace(request.Comment)
                    ? $"Action manuelle ({ActionPolicyHelper.ActionTypeLabel(request.Type)}) initiée par {actor}."
                    : request.Comment.Trim(),
                ResultMessage = isActive
                    ? "En attente d'exécution par l'agent."
                    : $"Action manuelle simulée (mode {mode})."
            };

            await using (var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false))
            {
                db.ActionTickets.Add(ticket);
                await db.SaveChangesAsync(ct).ConfigureAwait(false);
            }

            if (ticket.Status == ActionStatus.Pending)
            {
                commandHub.TryEnqueue(ticket.HostId, AgentCommandHub.BuildCommand(ticket, revert: false, simulate: false));
            }

            await auditWriter.WriteAuditAsync(
                actor,
                "ManualActionCreated",
                $"action:{ticket.Id:D}",
                $"Action {request.Type} sur {ticket.Target} (poste {ticket.HostId}, statut={ticket.Status}).",
                ip,
                ct).ConfigureAwait(false);

            var dto = ticket.ToDto();
            await broadcaster.ActionUpdatedAsync(dto, ct).ConfigureAwait(false);
            broadcaster.NotifySummaryChanged();

            return Results.Created($"/api/actions/{ticket.Id:D}", dto);
        });

        app.MapPost(ApiRoutes.ActionApprove, async (
            Guid id,
            HttpContext ctx,
            IDbContextFactory<SentinelDbContext> dbFactory,
            IThreatPipeline pipeline,
            AgentCommandHub commandHub,
            HashChainWriter auditWriter,
            LiveBroadcaster broadcaster,
            CancellationToken ct) =>
        {
            var actor = EndpointHelpers.GetActor(ctx);
            var ip = EndpointHelpers.GetClientIp(ctx);
            var now = DateTimeOffset.UtcNow;

            await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
            var ticket = await db.ActionTickets.FirstOrDefaultAsync(t => t.Id == id, ct).ConfigureAwait(false);
            if (ticket is null)
                return EndpointHelpers.Error(StatusCodes.Status404NotFound, "ACTION_NOT_FOUND", "Ticket d'action introuvable.");

            if (ticket.Status != ActionStatus.Proposed)
                return EndpointHelpers.Error(StatusCodes.Status409Conflict, "INVALID_STATUS", $"Seule une action au statut Proposed peut être approuvée (statut actuel : {ticket.Status}).");

            var isActive = pipeline.Settings.Mode == OperatingMode.Active;
            ticket.Status = isActive ? ActionStatus.Pending : ActionStatus.Simulated;
            ticket.ResultMessage = isActive
                ? $"Approuvée par {actor}, en attente d'exécution."
                : $"Approuvée par {actor} mais simulée (mode {pipeline.Settings.Mode}).";

            if (ticket.AlertId is { } alertId)
            {
                db.AlertHistory.Add(new AlertHistoryEntity
                {
                    AlertId = alertId,
                    Timestamp = now,
                    Actor = actor,
                    Action = "ActionApproved",
                    Comment = $"{ActionPolicyHelper.ActionTypeLabel((ResponseActionType)ticket.ActionType)} sur {ticket.Target} approuvée."
                });
            }

            await db.SaveChangesAsync(ct).ConfigureAwait(false);

            if (ticket.Status == ActionStatus.Pending)
            {
                commandHub.TryEnqueue(ticket.HostId, AgentCommandHub.BuildCommand(ticket, revert: false, simulate: false));
            }

            await auditWriter.WriteAuditAsync(
                actor,
                "ActionApproved",
                $"action:{ticket.Id:D}",
                $"Action {(ResponseActionType)ticket.ActionType} sur {ticket.Target} approuvée (statut={ticket.Status}).",
                ip,
                ct).ConfigureAwait(false);

            var dto = ticket.ToDto();
            await broadcaster.ActionUpdatedAsync(dto, ct).ConfigureAwait(false);
            broadcaster.NotifySummaryChanged();

            return Results.Ok(dto);
        });

        app.MapPost(ApiRoutes.ActionReject, async (
            Guid id,
            HttpContext ctx,
            IDbContextFactory<SentinelDbContext> dbFactory,
            HashChainWriter auditWriter,
            LiveBroadcaster broadcaster,
            CancellationToken ct) =>
        {
            var actor = EndpointHelpers.GetActor(ctx);
            var ip = EndpointHelpers.GetClientIp(ctx);
            var now = DateTimeOffset.UtcNow;

            await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
            var ticket = await db.ActionTickets.FirstOrDefaultAsync(t => t.Id == id, ct).ConfigureAwait(false);
            if (ticket is null)
                return EndpointHelpers.Error(StatusCodes.Status404NotFound, "ACTION_NOT_FOUND", "Ticket d'action introuvable.");

            if (ticket.Status != ActionStatus.Proposed)
                return EndpointHelpers.Error(StatusCodes.Status409Conflict, "INVALID_STATUS", $"Seule une action au statut Proposed peut être rejetée (statut actuel : {ticket.Status}).");

            ticket.Status = ActionStatus.Rejected;
            ticket.ResultMessage = $"Proposition rejetée par {actor}.";

            if (ticket.AlertId is { } alertId)
            {
                db.AlertHistory.Add(new AlertHistoryEntity
                {
                    AlertId = alertId,
                    Timestamp = now,
                    Actor = actor,
                    Action = "ActionRejected",
                    Comment = $"{ActionPolicyHelper.ActionTypeLabel((ResponseActionType)ticket.ActionType)} sur {ticket.Target} rejetée."
                });
            }

            await db.SaveChangesAsync(ct).ConfigureAwait(false);

            await auditWriter.WriteAuditAsync(
                actor,
                "ActionRejected",
                $"action:{ticket.Id:D}",
                $"Action {(ResponseActionType)ticket.ActionType} sur {ticket.Target} rejetée.",
                ip,
                ct).ConfigureAwait(false);

            var dto = ticket.ToDto();
            await broadcaster.ActionUpdatedAsync(dto, ct).ConfigureAwait(false);
            broadcaster.NotifySummaryChanged();

            return Results.Ok(dto);
        });

        // Exigence F7 : annulation d'un blocage en 1 clic
        app.MapPost(ApiRoutes.ActionRevert, async (
            Guid id,
            HttpContext ctx,
            IDbContextFactory<SentinelDbContext> dbFactory,
            AgentCommandHub commandHub,
            HashChainWriter auditWriter,
            LiveBroadcaster broadcaster,
            CancellationToken ct) =>
        {
            var actor = EndpointHelpers.GetActor(ctx);
            var ip = EndpointHelpers.GetClientIp(ctx);
            var now = DateTimeOffset.UtcNow;

            await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
            var ticket = await db.ActionTickets.FirstOrDefaultAsync(t => t.Id == id, ct).ConfigureAwait(false);
            if (ticket is null)
                return EndpointHelpers.Error(StatusCodes.Status404NotFound, "ACTION_NOT_FOUND", "Ticket d'action introuvable.");

            if (!ticket.Reversible)
                return EndpointHelpers.Error(StatusCodes.Status400BadRequest, "NOT_REVERSIBLE", "Cette action n'est pas réversible.");

            if (ticket.Status is ActionStatus.Reverted or ActionStatus.Rejected)
                return EndpointHelpers.Error(StatusCodes.Status409Conflict, "ALREADY_REVERTED", $"L'action est déjà dans l'état {ticket.Status}.");

            var agentConnected = commandHub.IsConnected(ticket.HostId);

            if (ticket.Status is ActionStatus.Simulated or ActionStatus.Proposed ||
                (ticket.Status == ActionStatus.Pending && !agentConnected))
            {
                ticket.Status = ActionStatus.Reverted;
                ticket.RevertedAt = now;
                ticket.ResultMessage = $"Action annulée directement par {actor} (non exécutée sur le poste).";
            }
            else
            {
                ticket.Status = ActionStatus.RevertPending;
                ticket.ResultMessage = agentConnected
                    ? $"Demande d'annulation envoyée à l'agent par {actor}."
                    : $"Demande d'annulation en file d'attente (agent hors ligne) par {actor}.";

                if (agentConnected)
                {
                    commandHub.TryEnqueue(ticket.HostId, AgentCommandHub.BuildCommand(ticket, revert: true, simulate: false));
                }
            }

            if (ticket.AlertId is { } alertId)
            {
                db.AlertHistory.Add(new AlertHistoryEntity
                {
                    AlertId = alertId,
                    Timestamp = now,
                    Actor = actor,
                    Action = "ActionRevertRequested",
                    Comment = $"Annulation demandée pour {ActionPolicyHelper.ActionTypeLabel((ResponseActionType)ticket.ActionType)} sur {ticket.Target} ({ticket.Status})."
                });
            }

            await db.SaveChangesAsync(ct).ConfigureAwait(false);

            await auditWriter.WriteAuditAsync(
                actor,
                "ActionReverted",
                $"action:{ticket.Id:D}",
                $"Annulation F7 demandée pour {(ResponseActionType)ticket.ActionType} sur {ticket.Target} (statut={ticket.Status}).",
                ip,
                ct).ConfigureAwait(false);

            var dto = ticket.ToDto();
            await broadcaster.ActionUpdatedAsync(dto, ct).ConfigureAwait(false);
            broadcaster.NotifySummaryChanged();

            return Results.Ok(dto);
        });
    }
}
