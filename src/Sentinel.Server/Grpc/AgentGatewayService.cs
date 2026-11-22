using Grpc.Core;
using Microsoft.EntityFrameworkCore;
using Sentinel.Server.Hubs;
using Sentinel.Server.Services;
using Sentinel.Shared.Grpc;
using Sentinel.Shared.Json;
using Sentinel.Shared.Models;
using Sentinel.Storage;
using Sentinel.Storage.Entities;
using Sentinel.Storage.Mapping;
using Sentinel.Storage.Services;

namespace Sentinel.Server.Grpc;

/// <summary>
/// Implémentation serveur du contrat gRPC <c>sentinel.v1.AgentGateway</c> (doc §4, §11).
/// </summary>
public sealed class AgentGatewayService : AgentGateway.AgentGatewayBase
{
    private readonly IDbContextFactory<SentinelDbContext> _dbFactory;
    private readonly EventIngestionService _ingestion;
    private readonly AgentCommandHub _commandHub;
    private readonly LiveBroadcaster _broadcaster;
    private readonly HashChainWriter _auditWriter;
    private readonly ILogger<AgentGatewayService> _logger;

    public AgentGatewayService(
        IDbContextFactory<SentinelDbContext> dbFactory,
        EventIngestionService ingestion,
        AgentCommandHub commandHub,
        LiveBroadcaster broadcaster,
        HashChainWriter auditWriter,
        ILogger<AgentGatewayService> logger)
    {
        _dbFactory = dbFactory;
        _ingestion = ingestion;
        _commandHub = commandHub;
        _broadcaster = broadcaster;
        _auditWriter = auditWriter;
        _logger = logger;
    }

    public override async Task<AgentRegistration> Register(AgentHello request, ServerCallContext context)
    {
        var ct = context.CancellationToken;
        var hostId = string.IsNullOrWhiteSpace(request.HostId)
            ? (string.IsNullOrWhiteSpace(request.MachineName) ? "unknown-host" : request.MachineName.Trim())
            : request.HostId.Trim();

        var now = DateTimeOffset.UtcNow;

        await using var db = await _dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var host = await db.Hosts.FirstOrDefaultAsync(h => h.HostId == hostId, ct).ConfigureAwait(false);

        var users = request.Users
            .Where(u => !string.IsNullOrWhiteSpace(u))
            .Select(u => u.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (host is null)
        {
            host = new HostEntity
            {
                HostId = hostId,
                MachineName = string.IsNullOrWhiteSpace(request.MachineName) ? hostId : request.MachineName.Trim(),
                OsVersion = request.OsVersion ?? string.Empty,
                AgentVersion = request.AgentVersion ?? string.Empty,
                BinarySha256 = request.BinarySha256 ?? string.Empty,
                FirstSeen = now,
                LastSeen = now,
                LastSeenUnixMs = now.ToUnixTimeMilliseconds(),
                UsersJson = SentinelJson.Serialize(users),
                RiskScore = 0
            };
            db.Hosts.Add(host);
        }
        else
        {
            if (!string.IsNullOrWhiteSpace(host.BinarySha256) &&
                !string.IsNullOrWhiteSpace(request.BinarySha256) &&
                string.Equals(host.AgentVersion, request.AgentVersion, StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(host.BinarySha256, request.BinarySha256, StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogWarning("Changement d'empreinte binaire détecté sur l'agent {HostId} à version égale ({Version}).",
                    hostId, request.AgentVersion);

                await _auditWriter.WriteAuditAsync(
                    $"Agent:{hostId}",
                    "AgentBinaryHashChanged",
                    $"host:{hostId}",
                    $"Ancien SHA-256={host.BinarySha256}, nouveau SHA-256={request.BinarySha256}.",
                    context.Peer,
                    ct).ConfigureAwait(false);
            }

            host.MachineName = string.IsNullOrWhiteSpace(request.MachineName) ? host.MachineName : request.MachineName.Trim();
            host.OsVersion = string.IsNullOrWhiteSpace(request.OsVersion) ? host.OsVersion : request.OsVersion;
            host.AgentVersion = string.IsNullOrWhiteSpace(request.AgentVersion) ? host.AgentVersion : request.AgentVersion;
            if (!string.IsNullOrWhiteSpace(request.BinarySha256))
                host.BinarySha256 = request.BinarySha256;
            host.LastSeen = now;
            host.LastSeenUnixMs = now.ToUnixTimeMilliseconds();
            if (users.Count > 0)
                host.UsersJson = SentinelJson.Serialize(users);
        }

        var settingsEntity = await GetOrCreateSettingsAsync(db, ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);

        var openAlerts = await db.Alerts.CountAsync(
            a => a.HostId == hostId && (a.Status == AlertStatus.Open || a.Status == AlertStatus.Acknowledged), ct)
            .ConfigureAwait(false);

        await _broadcaster.HostStatusChangedAsync(host.ToDto(online: true, openAlerts), ct).ConfigureAwait(false);
        _broadcaster.NotifySummaryChanged();

        _logger.LogInformation("Agent enregistré : {HostId} ({Machine}, v{Version}).",
            host.HostId, host.MachineName, host.AgentVersion);

        return new AgentRegistration
        {
            Accepted = true,
            Message = "Enregistrement accepté.",
            SettingsJson = settingsEntity.SettingsJson,
            SettingsVersion = settingsEntity.Version
        };
    }

    public override async Task<SubmitAck> SubmitEvents(EventBatch request, ServerCallContext context)
    {
        var ct = context.CancellationToken;
        if (request.Events.Count == 0)
        {
            return new SubmitAck { Accepted = 0, Rejected = 0, Message = "Lot vide." };
        }

        var validModels = new List<SecurityEvent>(request.Events.Count);
        var rejected = 0;

        foreach (var proto in request.Events)
        {
            try
            {
                var model = proto.ToModel();
                if (string.IsNullOrWhiteSpace(model.HostId) && !string.IsNullOrWhiteSpace(request.HostId))
                {
                    model = model with { HostId = request.HostId.Trim() };
                }

                if (string.IsNullOrWhiteSpace(model.HostId) || string.IsNullOrWhiteSpace(model.EventType))
                {
                    rejected++;
                    continue;
                }

                validModels.Add(model);
            }
            catch
            {
                rejected++;
            }
        }

        if (validModels.Count > 0)
        {
            await _ingestion.IngestBatchAsync(validModels, ct).ConfigureAwait(false);
        }

        return new SubmitAck
        {
            Accepted = validModels.Count,
            Rejected = rejected,
            Message = rejected == 0 ? "OK" : $"{validModels.Count} accepté(s), {rejected} rejeté(s)."
        };
    }

    public override async Task<HeartbeatReply> Heartbeat(HeartbeatRequest request, ServerCallContext context)
    {
        var ct = context.CancellationToken;
        var hostId = request.HostId?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(hostId))
        {
            return new HeartbeatReply { Ok = false };
        }

        var now = DateTimeOffset.UtcNow;
        await using var db = await _dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);

        var host = await db.Hosts.FirstOrDefaultAsync(h => h.HostId == hostId, ct).ConfigureAwait(false);
        var collectorsPayload = request.Collectors.Select(c => new
        {
            c.Name,
            c.Running,
            c.Error,
            c.EventsProduced
        }).ToList();

        if (host is null)
        {
            host = new HostEntity
            {
                HostId = hostId,
                MachineName = hostId,
                FirstSeen = now,
                LastSeen = now,
                LastSeenUnixMs = now.ToUnixTimeMilliseconds(),
                CpuPercent = request.CpuPercent,
                WorkingSetBytes = request.WorkingSetBytes,
                QueueLength = request.QueueLength,
                CollectorsJson = SentinelJson.Serialize(collectorsPayload)
            };
            db.Hosts.Add(host);
        }
        else
        {
            host.CpuPercent = request.CpuPercent;
            host.WorkingSetBytes = request.WorkingSetBytes;
            host.QueueLength = request.QueueLength;
            host.CollectorsJson = SentinelJson.Serialize(collectorsPayload);
            host.LastSeen = now;
            host.LastSeenUnixMs = now.ToUnixTimeMilliseconds();
        }

        var settingsEntity = await GetOrCreateSettingsAsync(db, ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);

        var hasNewerSettings = settingsEntity.Version > request.SettingsVersion;
        return new HeartbeatReply
        {
            Ok = true,
            SettingsJson = hasNewerSettings ? settingsEntity.SettingsJson : string.Empty,
            SettingsVersion = settingsEntity.Version
        };
    }

    public override async Task SubscribeCommands(
        CommandSubscription request,
        IServerStreamWriter<AgentCommand> responseStream,
        ServerCallContext context)
    {
        var ct = context.CancellationToken;
        var hostId = request.HostId?.Trim();
        if (string.IsNullOrWhiteSpace(hostId))
        {
            throw new RpcException(new Status(StatusCode.InvalidArgument, "host_id requis."));
        }

        using var subscription = _commandHub.Register(hostId);
        _logger.LogInformation("Flux de commandes ouvert pour l'agent {HostId}.", hostId);

        var deliveredDuringDrain = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            // 1. Dépile d'abord les commandes persistées en attente (Pending / RevertPending)
            await using (var db = await _dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false))
            {
                var queued = await db.ActionTickets
                    .AsNoTracking()
                    .Where(t => t.HostId == hostId &&
                                (t.Status == ActionStatus.Pending || t.Status == ActionStatus.RevertPending))
                    .OrderBy(t => t.CreatedAtUnixMs)
                    .ToListAsync(ct)
                    .ConfigureAwait(false);

                foreach (var ticket in queued)
                {
                    ct.ThrowIfCancellationRequested();
                    var isRevert = ticket.Status == ActionStatus.RevertPending;
                    var cmd = AgentCommandHub.BuildCommand(ticket, revert: isRevert, simulate: false);
                    await responseStream.WriteAsync(cmd).ConfigureAwait(false);
                    deliveredDuringDrain.Add($"{cmd.CommandId}:{cmd.Revert}");
                }
            }

            // 2. Streame les commandes temps réel jusqu'à annulation/déconnexion
            await foreach (var cmd in subscription.Reader.ReadAllAsync(ct).ConfigureAwait(false))
            {
                ct.ThrowIfCancellationRequested();
                var key = $"{cmd.CommandId}:{cmd.Revert}";
                if (deliveredDuringDrain.Remove(key))
                    continue;

                await responseStream.WriteAsync(cmd).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Déconnexion normale
        }
        finally
        {
            _logger.LogInformation("Flux de commandes fermé pour l'agent {HostId}.", hostId);
        }
    }

    public override async Task<Ack> ReportActionResult(ActionResultReport request, ServerCallContext context)
    {
        var ct = context.CancellationToken;
        if (!Guid.TryParse(request.CommandId, out var ticketId))
        {
            return new Ack { Ok = false, Message = "command_id invalide." };
        }

        await using var db = await _dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var ticket = await db.ActionTickets.FirstOrDefaultAsync(t => t.Id == ticketId, ct).ConfigureAwait(false);
        if (ticket is null)
        {
            return new Ack { Ok = false, Message = "Ticket d'action introuvable." };
        }

        var now = DateTimeOffset.UtcNow;
        if (request.WasRevert)
        {
            ticket.Status = request.Success ? ActionStatus.Reverted : ActionStatus.Failed;
            if (request.Success)
                ticket.RevertedAt = now;
        }
        else
        {
            ticket.Status = request.Success ? ActionStatus.Executed : ActionStatus.Failed;
            ticket.ExecutedAt = now;
            if (!string.IsNullOrWhiteSpace(request.RevertStateJson))
                ticket.RevertStateJson = request.RevertStateJson;
        }

        ticket.ResultMessage = string.IsNullOrWhiteSpace(request.Message)
            ? (request.Success ? "Exécution confirmée par l'agent." : "Échec signalé par l'agent.")
            : request.Message;

        if (ticket.AlertId is { } alertId)
        {
            var actionName = request.WasRevert
                ? (request.Success ? "ActionReverted" : "ActionRevertFailed")
                : (request.Success ? "ActionExecuted" : "ActionFailed");

            db.AlertHistory.Add(new AlertHistoryEntity
            {
                AlertId = alertId,
                Timestamp = now,
                Actor = $"Agent:{(string.IsNullOrWhiteSpace(request.HostId) ? ticket.HostId : request.HostId)}",
                Action = actionName,
                Comment = $"{ActionPolicyHelper.ActionTypeLabel((ResponseActionType)ticket.ActionType)} ({ticket.Target}) : {ticket.ResultMessage}"
            });
        }

        await db.SaveChangesAsync(ct).ConfigureAwait(false);

        await _broadcaster.ActionUpdatedAsync(ticket.ToDto(), ct).ConfigureAwait(false);
        _broadcaster.NotifySummaryChanged();

        return new Ack { Ok = true, Message = "Compte-rendu enregistré." };
    }

    private static async Task<SettingsEntity> GetOrCreateSettingsAsync(SentinelDbContext db, CancellationToken ct)
    {
        var entity = await db.Settings.FirstOrDefaultAsync(s => s.Id == SettingsEntity.SingletonId, ct).ConfigureAwait(false);
        if (entity is not null)
            return entity;

        entity = new SettingsEntity
        {
            Id = SettingsEntity.SingletonId,
            Version = 1,
            SettingsJson = SentinelJson.Serialize(new SentinelSettings()),
            UpdatedAt = DateTimeOffset.UtcNow
        };
        db.Settings.Add(entity);
        return entity;
    }
}
