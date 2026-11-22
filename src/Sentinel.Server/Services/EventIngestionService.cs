using Microsoft.EntityFrameworkCore;
using Sentinel.Core.Abstractions;
using Sentinel.Server.Hubs;
using Sentinel.Shared.Api;
using Sentinel.Shared.Json;
using Sentinel.Shared.Models;
using Sentinel.Storage;
using Sentinel.Storage.Entities;
using Sentinel.Storage.Mapping;
using Sentinel.Storage.Services;

namespace Sentinel.Server.Services;

/// <summary>
/// Orchestrateur central d'ingestion d'événements :
/// pipeline d'analyse → persistance chaînée SHA-256 → clusters → alertes → tickets d'actions →
/// commandes gRPC temps réel → diffusion SignalR.
/// </summary>
public sealed class EventIngestionService : IDisposable
{
    private readonly IThreatPipeline _pipeline;
    private readonly IDbContextFactory<SentinelDbContext> _dbFactory;
    private readonly HashChainWriter _hashChainWriter;
    private readonly AgentCommandHub _commandHub;
    private readonly LiveBroadcaster _broadcaster;
    private readonly ILogger<EventIngestionService> _logger;
    private readonly SemaphoreSlim _stateLock = new(1, 1);

    public EventIngestionService(
        IThreatPipeline pipeline,
        IDbContextFactory<SentinelDbContext> dbFactory,
        HashChainWriter hashChainWriter,
        AgentCommandHub commandHub,
        LiveBroadcaster broadcaster,
        ILogger<EventIngestionService> logger)
    {
        _pipeline = pipeline;
        _dbFactory = dbFactory;
        _hashChainWriter = hashChainWriter;
        _commandHub = commandHub;
        _broadcaster = broadcaster;
        _logger = logger;
    }

    public async Task<PipelineResult> IngestAsync(SecurityEvent evt, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(evt);
        var results = await IngestBatchAsync([evt], ct).ConfigureAwait(false);
        return results[0];
    }

    public async Task<IReadOnlyList<PipelineResult>> IngestBatchAsync(
        IEnumerable<SecurityEvent> events,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(events);

        var normalized = new List<SecurityEvent>();
        foreach (var raw in events)
        {
            if (raw is null) continue;
            var evt = NormalizeEvent(raw);
            normalized.Add(evt);
        }

        if (normalized.Count == 0)
            return Array.Empty<PipelineResult>();

        // 1. Exécution séquentielle dans le pipeline (préserve l'ordre causal pour la corrélation)
        var results = new List<PipelineResult>(normalized.Count);
        var eventEntities = new List<EventEntity>(normalized.Count);

        foreach (var evt in normalized)
        {
            ct.ThrowIfCancellationRequested();
            var res = await _pipeline.ProcessAsync(evt, ct).ConfigureAwait(false);
            results.Add(res);
            eventEntities.Add(res.Scored.ToEntity(res.Cluster?.Id));
        }

        // 2. Persistance chaînée cryptographiquement (une transaction atomique par lot)
        await _hashChainWriter.AppendEventsAsync(eventEntities, ct).ConfigureAwait(false);

        // 3. Mise à jour clusters, alertes, tickets d'actions et postes sous verrou séquentiel
        var broadcasts = new PendingBroadcasts();
        var commandsToPush = new List<(string HostId, Shared.Grpc.AgentCommand Command)>();

        await _stateLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await using var db = await _dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);

            for (var i = 0; i < results.Count; i++)
            {
                var res = results[i];
                var entity = eventEntities[i];

                if (entity.Score >= 30)
                {
                    broadcasts.ScoredEvents.Add(entity.ToDto());
                }

                // 3a. Upsert Cluster + liens + rattachement des événements
                if (res.Cluster is { } cluster)
                {
                    var clusterEntity = await UpsertClusterAsync(db, cluster, ct).ConfigureAwait(false);
                    broadcasts.Clusters[clusterEntity.Id] = clusterEntity.ToDto();
                }

                // 3b. Alertes + Actions
                AlertEntity? alertEntity = null;
                var alertCreated = false;
                var alertUpdated = false;

                if (res.Decision is { } decision)
                {
                    var shouldAlert = decision.AlertAdmin ||
                                      decision.Level >= ThreatLevel.High ||
                                      res.Cluster?.Escalated == true;

                    if (shouldAlert)
                    {
                        (alertEntity, alertCreated) = await UpsertAlertAsync(db, res, decision, ct).ConfigureAwait(false);
                        alertUpdated = !alertCreated;
                    }

                    // 3c. Tickets d'actions (hors LogOnly / MarkForCorrelation / AlertAdmin)
                    var createdTickets = await CreateActionTicketsAsync(db, res, decision, alertEntity, commandsToPush, ct)
                        .ConfigureAwait(false);

                    foreach (var ticket in createdTickets)
                    {
                        broadcasts.Actions.Add(ticket.ToDto());
                    }
                }

                // 3d. Mise à jour du poste (LastSeen, Users, RiskScore)
                await UpsertHostFromEventAsync(db, res, alertEntity, ct).ConfigureAwait(false);

                await db.SaveChangesAsync(ct).ConfigureAwait(false);

                // Rattachement ClusterId sur les événements antérieurs du cluster (hors chaîne SHA-256)
                if (res.Cluster is { } cl && cl.EventIds.Count > 0)
                {
                    var ids = cl.EventIds.ToList();
                    await db.Events
                        .Where(e => ids.Contains(e.Id) && e.ClusterId != cl.Id)
                        .ExecuteUpdateAsync(s => s.SetProperty(e => e.ClusterId, cl.Id), ct)
                        .ConfigureAwait(false);
                }

                if (alertEntity is not null)
                {
                    var pendingCount = await db.ActionTickets
                        .CountAsync(t => t.AlertId == alertEntity.Id &&
                                         (t.Status == ActionStatus.Proposed || t.Status == ActionStatus.Pending), ct)
                        .ConfigureAwait(false);

                    var dto = alertEntity.ToDto(pendingCount);
                    if (alertCreated)
                        broadcasts.AlertsRaised[alertEntity.Id] = dto;
                    else if (alertUpdated)
                        broadcasts.AlertsUpdated[alertEntity.Id] = dto;
                }
            }
        }
        finally
        {
            _stateLock.Release();
        }

        // 4. Pousse les commandes immédiates aux agents connectés
        foreach (var (hostId, cmd) in commandsToPush)
        {
            if (_commandHub.TryEnqueue(hostId, cmd))
            {
                _logger.LogInformation("Commande temps réel {CommandId} (action={Action}, simulate={Simulate}) envoyée à l'agent {HostId}.",
                    cmd.CommandId, (ResponseActionType)cmd.ActionType, cmd.Simulate, hostId);
            }
        }

        // 5. Diffusions SignalR temps réel
        await DispatchBroadcastsAsync(broadcasts, ct).ConfigureAwait(false);

        return results;
    }

    private static SecurityEvent NormalizeEvent(SecurityEvent evt)
    {
        var id = evt.Id == Guid.Empty ? Guid.NewGuid() : evt.Id;
        var ts = evt.Timestamp == default ? DateTimeOffset.UtcNow : evt.Timestamp;
        var hostId = string.IsNullOrWhiteSpace(evt.HostId) ? "unknown-host" : evt.HostId.Trim();
        var userId = string.IsNullOrWhiteSpace(evt.UserId) ? "unknown" : evt.UserId.Trim();
        var subject = evt.Subject ?? string.Empty;
        var eventType = string.IsNullOrWhiteSpace(evt.EventType) ? "Unknown" : evt.EventType.Trim();

        if (id == evt.Id && ts == evt.Timestamp && hostId == evt.HostId && userId == evt.UserId &&
            subject == evt.Subject && eventType == evt.EventType)
        {
            return evt;
        }

        return evt with
        {
            Id = id,
            Timestamp = ts,
            HostId = hostId,
            UserId = userId,
            EventType = eventType,
            Subject = subject
        };
    }

    private static async Task<ClusterEntity> UpsertClusterAsync(
        SentinelDbContext db,
        CorrelationCluster cluster,
        CancellationToken ct)
    {
        var existing = await db.Clusters
            .Include(c => c.Links)
            .FirstOrDefaultAsync(c => c.Id == cluster.Id, ct)
            .ConfigureAwait(false);

        if (existing is null)
        {
            var created = cluster.ToEntity();
            db.Clusters.Add(created);
            return created;
        }

        existing.FirstSeen = cluster.FirstSeen;
        existing.FirstSeenUnixMs = cluster.FirstSeen.ToUnixTimeMilliseconds();
        existing.LastSeen = cluster.LastSeen;
        existing.LastSeenUnixMs = cluster.LastSeen.ToUnixTimeMilliseconds();
        existing.Score = cluster.Score;
        existing.MaxEventScore = cluster.MaxEventScore;
        existing.Level = cluster.Level;
        existing.DominantType = cluster.DominantType;
        existing.EventCount = cluster.EventIds.Count;
        existing.Escalated = cluster.Escalated;
        existing.ChainId = cluster.Chain?.ChainId;
        existing.ChainName = cluster.Chain?.Name;
        existing.ChainStepsMatched = cluster.Chain?.StepsMatched ?? 0;
        existing.ChainTotalSteps = cluster.Chain?.TotalSteps ?? 0;
        existing.ContextKeysJson = SentinelJson.Serialize(cluster.ContextKeys);
        existing.MitreTechniquesJson = SentinelJson.Serialize(cluster.MitreTechniques);
        existing.Justification = cluster.Justification;

        if (existing.Links.Count > 0)
        {
            db.ClusterLinks.RemoveRange(existing.Links);
            existing.Links.Clear();
        }

        foreach (var l in cluster.Links)
        {
            existing.Links.Add(new ClusterLinkEntity
            {
                ClusterId = cluster.Id,
                FromEventId = l.FromEventId,
                ToEventId = l.ToEventId,
                EdgeType = (int)l.Type,
                Weight = l.Weight,
                Key = l.Key
            });
        }

        return existing;
    }

    private static async Task<(AlertEntity Alert, bool Created)> UpsertAlertAsync(
        SentinelDbContext db,
        PipelineResult result,
        ResponseDecision decision,
        CancellationToken ct)
    {
        var evt = result.Scored.Event;
        var assessment = result.Scored.Assessment;
        var cluster = result.Cluster;
        var now = DateTimeOffset.UtcNow;

        AlertEntity? existing = null;

        if (cluster is not null)
        {
            existing = await db.Alerts
                .Include(a => a.AlertEvents)
                .Include(a => a.History)
                .FirstOrDefaultAsync(a =>
                    a.ClusterId == cluster.Id &&
                    (a.Status == AlertStatus.Open || a.Status == AlertStatus.Acknowledged), ct)
                .ConfigureAwait(false);

            if (existing is null && cluster.EventIds.Count > 0)
            {
                var ids = cluster.EventIds.ToList();
                var candidateAlertId = await db.AlertEvents
                    .AsNoTracking()
                    .Where(ae => ids.Contains(ae.EventId))
                    .Select(ae => ae.AlertId)
                    .FirstOrDefaultAsync(ct)
                    .ConfigureAwait(false);

                if (candidateAlertId != Guid.Empty)
                {
                    existing = await db.Alerts
                        .Include(a => a.AlertEvents)
                        .Include(a => a.History)
                        .FirstOrDefaultAsync(a =>
                            a.Id == candidateAlertId &&
                            (a.Status == AlertStatus.Open || a.Status == AlertStatus.Acknowledged), ct)
                        .ConfigureAwait(false);
                }
            }
        }
        else
        {
            var recentCutoffMs = now.AddMinutes(-30).ToUnixTimeMilliseconds();
            existing = await db.Alerts
                .Include(a => a.AlertEvents)
                .Include(a => a.History)
                .OrderByDescending(a => a.UpdatedAtUnixMs)
                .FirstOrDefaultAsync(a =>
                    a.HostId == evt.HostId &&
                    a.ClusterId == null &&
                    a.ThreatType == decision.Type &&
                    a.UpdatedAtUnixMs >= recentCutoffMs &&
                    (a.Status == AlertStatus.Open || a.Status == AlertStatus.Acknowledged), ct)
                .ConfigureAwait(false);
        }

        var mitreSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var m in assessment.MitreTechniques) mitreSet.Add(m);
        if (cluster is not null)
        {
            foreach (var m in cluster.MitreTechniques) mitreSet.Add(m);
        }

        var eventIdsToLink = new HashSet<Guid> { evt.Id };
        if (cluster is not null)
        {
            foreach (var id in cluster.EventIds) eventIdsToLink.Add(id);
        }

        var title = BuildAlertTitle(evt, decision, cluster);
        var summary = BuildAlertSummary(evt, decision, cluster, eventIdsToLink.Count);
        var fullJustification = BuildAlertJustification(decision, cluster, assessment);
        var requiresDecision = decision.RequiresHumanApproval ||
                               (decision.Mode != OperatingMode.Active && decision.Level >= ThreatLevel.High);

        if (existing is null)
        {
            var alert = new AlertEntity
            {
                Id = Guid.NewGuid(),
                CreatedAt = now,
                CreatedAtUnixMs = now.ToUnixTimeMilliseconds(),
                UpdatedAt = now,
                UpdatedAtUnixMs = now.ToUnixTimeMilliseconds(),
                HostId = evt.HostId,
                UserId = evt.UserId,
                Title = title,
                Summary = summary,
                Justification = fullJustification,
                Score = decision.Score,
                Level = decision.Level,
                ThreatType = decision.Type,
                Status = AlertStatus.Open,
                ClusterId = cluster?.Id,
                EventCount = eventIdsToLink.Count,
                RequiresDecision = requiresDecision,
                MitreTechniquesJson = SentinelJson.Serialize(mitreSet.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList())
            };

            foreach (var eid in eventIdsToLink)
            {
                alert.AlertEvents.Add(new AlertEventEntity { AlertId = alert.Id, EventId = eid });
            }

            alert.History.Add(new AlertHistoryEntity
            {
                AlertId = alert.Id,
                Timestamp = now,
                Actor = "SENTINEL",
                Action = "Created",
                Comment = $"Alerte créée automatiquement : score {alert.Score}/100 ({ThreatLevels.Label(alert.Level)}), {alert.EventCount} événement(s)."
            });

            db.Alerts.Add(alert);
            return (alert, true);
        }

        // Mise à jour de l'alerte ouverte existante
        var previousScore = existing.Score;
        var previousCount = existing.EventCount;

        if (!string.IsNullOrWhiteSpace(existing.MitreTechniquesJson))
        {
            try
            {
                var prevMitre = SentinelJson.Deserialize<List<string>>(existing.MitreTechniquesJson);
                if (prevMitre is not null)
                {
                    foreach (var m in prevMitre) mitreSet.Add(m);
                }
            }
            catch
            {
                // Ignoré
            }
        }

        var linkedIds = existing.AlertEvents.Select(ae => ae.EventId).ToHashSet();
        foreach (var eid in eventIdsToLink)
        {
            if (linkedIds.Add(eid))
            {
                existing.AlertEvents.Add(new AlertEventEntity { AlertId = existing.Id, EventId = eid });
            }
        }

        existing.UpdatedAt = now;
        existing.UpdatedAtUnixMs = now.ToUnixTimeMilliseconds();
        existing.ClusterId = cluster?.Id ?? existing.ClusterId;
        existing.Score = Math.Max(existing.Score, decision.Score);
        existing.Level = (ThreatLevel)Math.Max((int)existing.Level, (int)decision.Level);
        if (decision.Type != ThreatType.None)
            existing.ThreatType = decision.Type;
        existing.EventCount = linkedIds.Count;
        existing.Title = BuildAlertTitle(evt, decision with { Score = existing.Score, Level = existing.Level, Type = existing.ThreatType }, cluster);
        existing.Summary = BuildAlertSummary(evt, decision with { Score = existing.Score, Level = existing.Level, Type = existing.ThreatType }, cluster, existing.EventCount);
        existing.Justification = fullJustification;
        existing.RequiresDecision = existing.Status == AlertStatus.Open && (existing.RequiresDecision || requiresDecision);
        existing.MitreTechniquesJson = SentinelJson.Serialize(mitreSet.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList());

        if (existing.Score > previousScore || existing.EventCount > previousCount)
        {
            existing.History.Add(new AlertHistoryEntity
            {
                AlertId = existing.Id,
                Timestamp = now,
                Actor = "SENTINEL",
                Action = "Updated",
                Comment = $"Alerte enrichie : score {existing.Score}/100 ({ThreatLevels.Label(existing.Level)}), {existing.EventCount} événement(s) corrélés."
            });
        }

        return (existing, false);
    }

    private static async Task<List<ActionTicketEntity>> CreateActionTicketsAsync(
        SentinelDbContext db,
        PipelineResult result,
        ResponseDecision decision,
        AlertEntity? alert,
        List<(string HostId, Shared.Grpc.AgentCommand Command)> commandsToPush,
        CancellationToken ct)
    {
        var created = new List<ActionTicketEntity>();
        var now = DateTimeOffset.UtcNow;
        var hostId = result.Scored.Event.HostId;

        // Évite de recréer un ticket identique actif/proposé pour la même alerte et cible
        List<ActionTicketEntity> existingForAlert = alert is not null
            ? await db.ActionTickets
                .AsNoTracking()
                .Where(t => t.AlertId == alert.Id &&
                            (t.Status == ActionStatus.Proposed ||
                             t.Status == ActionStatus.Pending ||
                             t.Status == ActionStatus.Executed ||
                             t.Status == ActionStatus.Simulated))
                .ToListAsync(ct)
                .ConfigureAwait(false)
            : new List<ActionTicketEntity>();

        foreach (var planned in decision.Actions)
        {
            if (ActionPolicyHelper.IsSkippedFromTickets(planned.Type))
                continue;

            var duplicate = existingForAlert.Any(t =>
                t.ActionType == (int)planned.Type &&
                string.Equals(t.Target, planned.Target, StringComparison.OrdinalIgnoreCase));

            if (duplicate)
                continue;

            ActionStatus status;
            bool shouldDispatch = false;
            bool simulateDispatch = false;
            string? resultMessage = null;

            if (decision.Mode != OperatingMode.Active)
            {
                status = ActionStatus.Simulated;
                resultMessage = decision.Mode == OperatingMode.Learning
                    ? "Mode Apprentissage : action enregistrée sans exécution."
                    : "Mode Simulation : action journalisée sans exécution.";

                if (ActionPolicyHelper.IsNotificationAction(planned.Type))
                {
                    shouldDispatch = true;
                    simulateDispatch = true;
                }
            }
            else if (planned.Automatic)
            {
                status = ActionStatus.Pending;
                shouldDispatch = true;
            }
            else if (ActionPolicyHelper.IsNotificationAction(planned.Type))
            {
                status = ActionStatus.Pending;
                shouldDispatch = true;
            }
            else
            {
                status = ActionStatus.Proposed;
            }

            var ticket = new ActionTicketEntity
            {
                Id = Guid.NewGuid(),
                CreatedAt = now,
                CreatedAtUnixMs = now.ToUnixTimeMilliseconds(),
                HostId = hostId,
                AlertId = alert?.Id,
                ActionType = (int)planned.Type,
                Target = planned.Target,
                ParametersJson = SentinelJson.Serialize(planned.Parameters),
                Status = status,
                Automatic = planned.Automatic,
                Reversible = ActionPolicyHelper.IsReversible(planned.Type),
                Rationale = planned.Rationale,
                ResultMessage = resultMessage
            };

            db.ActionTickets.Add(ticket);
            existingForAlert.Add(ticket);
            created.Add(ticket);

            if (shouldDispatch)
            {
                commandsToPush.Add((hostId, AgentCommandHub.BuildCommand(ticket, revert: false, simulate: simulateDispatch)));
            }
        }

        return created;
    }

    private static async Task UpsertHostFromEventAsync(
        SentinelDbContext db,
        PipelineResult result,
        AlertEntity? alert,
        CancellationToken ct)
    {
        var evt = result.Scored.Event;
        var now = DateTimeOffset.UtcNow;
        var eventScore = Math.Max(result.Scored.Assessment.Score, result.Cluster?.Score ?? 0);
        if (alert is not null)
        {
            eventScore = Math.Max(eventScore, alert.Score);
        }

        var host = await db.Hosts.FirstOrDefaultAsync(h => h.HostId == evt.HostId, ct).ConfigureAwait(false);
        if (host is null)
        {
            var users = string.IsNullOrWhiteSpace(evt.UserId) ? new List<string>() : new List<string> { evt.UserId };
            host = new HostEntity
            {
                HostId = evt.HostId,
                MachineName = evt.HostId,
                OsVersion = "Windows",
                AgentVersion = "1.0.0",
                BinarySha256 = string.Empty,
                FirstSeen = evt.Timestamp <= now ? evt.Timestamp : now,
                LastSeen = now,
                LastSeenUnixMs = now.ToUnixTimeMilliseconds(),
                UsersJson = SentinelJson.Serialize(users),
                RiskScore = Math.Clamp(eventScore, 0, 100)
            };
            db.Hosts.Add(host);
            return;
        }

        host.LastSeen = now;
        host.LastSeenUnixMs = now.ToUnixTimeMilliseconds();

        if (!string.IsNullOrWhiteSpace(evt.UserId))
        {
            var users = DeserializeStringList(host.UsersJson);
            if (!users.Contains(evt.UserId, StringComparer.OrdinalIgnoreCase))
            {
                users.Add(evt.UserId);
                host.UsersJson = SentinelJson.Serialize(users);
            }
        }

        if (eventScore > host.RiskScore)
        {
            host.RiskScore = Math.Clamp(eventScore, 0, 100);
        }
    }

    private async Task DispatchBroadcastsAsync(PendingBroadcasts broadcasts, CancellationToken ct)
    {
        foreach (var evt in broadcasts.ScoredEvents)
            await _broadcaster.EventScoredAsync(evt, ct).ConfigureAwait(false);

        foreach (var cluster in broadcasts.Clusters.Values)
            await _broadcaster.ClusterUpdatedAsync(cluster, ct).ConfigureAwait(false);

        foreach (var alert in broadcasts.AlertsRaised.Values)
            await _broadcaster.AlertRaisedAsync(alert, ct).ConfigureAwait(false);

        foreach (var alert in broadcasts.AlertsUpdated.Values)
        {
            if (!broadcasts.AlertsRaised.ContainsKey(alert.Id))
                await _broadcaster.AlertUpdatedAsync(alert, ct).ConfigureAwait(false);
        }

        foreach (var action in broadcasts.Actions)
            await _broadcaster.ActionUpdatedAsync(action, ct).ConfigureAwait(false);

        _broadcaster.NotifySummaryChanged();
    }

    private static string BuildAlertTitle(SecurityEvent evt, ResponseDecision decision, CorrelationCluster? cluster)
    {
        var typeLabel = ActionPolicyHelper.ThreatTypeLabel(decision.Type);
        if (cluster?.Chain is { } chain)
        {
            return $"{typeLabel} — {chain.Name} sur {evt.HostId}";
        }

        if (cluster is not null)
        {
            return $"{typeLabel} ({ThreatLevels.Label(decision.Level)}) — {cluster.EventIds.Count} événements corrélés sur {evt.HostId}";
        }

        return $"{typeLabel} ({ThreatLevels.Label(decision.Level)}) — {evt.EventType} sur {evt.HostId}";
    }

    private static string BuildAlertSummary(SecurityEvent evt, ResponseDecision decision, CorrelationCluster? cluster, int eventCount)
    {
        if (cluster?.Chain is { } chain)
        {
            return $"Chaîne d'attaque « {chain.Name} » ({chain.StepsMatched}/{chain.TotalSteps} étapes, {eventCount} événements) détectée sur {evt.HostId} (utilisateur {evt.UserId}) avec un score de {decision.Score}/100.";
        }

        if (cluster is not null)
        {
            var escalated = cluster.Escalated ? " [escalade précoce]" : string.Empty;
            return $"Corrélation de {eventCount} événements sur {evt.HostId} (score individuel max {cluster.MaxEventScore} → score cluster {decision.Score}/100{escalated}).";
        }

        return $"Événement {evt.EventType} sur « {evt.Subject} » (poste {evt.HostId}, utilisateur {evt.UserId}) évalué à {decision.Score}/100.";
    }

    private static string BuildAlertJustification(ResponseDecision decision, CorrelationCluster? cluster, ThreatAssessment assessment)
    {
        var parts = new List<string>(3) { decision.Justification };
        if (cluster is not null && !decision.Justification.Contains(cluster.Justification, StringComparison.Ordinal))
        {
            parts.Add(cluster.Justification);
        }
        if (!string.IsNullOrWhiteSpace(assessment.Justification) &&
            !decision.Justification.Contains(assessment.Justification, StringComparison.Ordinal))
        {
            parts.Add($"Dernier événement déclencheur : {assessment.Justification}");
        }
        return string.Join(" ", parts);
    }

    private static List<string> DeserializeStringList(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return new List<string>();
        try
        {
            return SentinelJson.Deserialize<List<string>>(json) ?? new List<string>();
        }
        catch
        {
            return new List<string>();
        }
    }

    public void Dispose()
    {
        _stateLock.Dispose();
    }

    private sealed class PendingBroadcasts
    {
        public List<EventDto> ScoredEvents { get; } = new();
        public Dictionary<Guid, ClusterDto> Clusters { get; } = new();
        public Dictionary<Guid, AlertDto> AlertsRaised { get; } = new();
        public Dictionary<Guid, AlertDto> AlertsUpdated { get; } = new();
        public List<ActionTicketDto> Actions { get; } = new();
    }
}
