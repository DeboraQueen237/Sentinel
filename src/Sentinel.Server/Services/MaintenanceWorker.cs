using Microsoft.EntityFrameworkCore;
using Sentinel.Core.Abstractions;
using Sentinel.Server.Hubs;
using Sentinel.Shared.Models;
using Sentinel.Storage;
using Sentinel.Storage.Entities;
using Sentinel.Storage.Mapping;
using Sentinel.Storage.Services;

namespace Sentinel.Server.Services;

/// <summary>
/// Tâche de fond périodique de maintenance :
/// - Sauvegarde de l'instantané de baseline toutes les 5 minutes (et à l'arrêt propre) ;
/// - Purge de rétention (<see cref="RetentionCleaner"/>) toutes les 6 heures ;
/// - Suivi des transitions en ligne / hors ligne des postes (seuil 60 s) avec diffusion SignalR.
/// </summary>
public sealed class MaintenanceWorker : BackgroundService
{
    private static readonly TimeSpan TickInterval = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan BaselineSaveInterval = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan RetentionInterval = TimeSpan.FromHours(6);
    private static readonly TimeSpan HostOnlineWindow = TimeSpan.FromSeconds(60);

    private readonly IDbContextFactory<SentinelDbContext> _dbFactory;
    private readonly IThreatPipeline _pipeline;
    private readonly RetentionCleaner _retentionCleaner;
    private readonly AgentCommandHub _commandHub;
    private readonly LiveBroadcaster _broadcaster;
    private readonly ILogger<MaintenanceWorker> _logger;

    private readonly Dictionary<string, bool> _lastKnownOnline = new(StringComparer.OrdinalIgnoreCase);

    public MaintenanceWorker(
        IDbContextFactory<SentinelDbContext> dbFactory,
        IThreatPipeline pipeline,
        RetentionCleaner retentionCleaner,
        AgentCommandHub commandHub,
        LiveBroadcaster broadcaster,
        ILogger<MaintenanceWorker> logger)
    {
        _dbFactory = dbFactory;
        _pipeline = pipeline;
        _retentionCleaner = retentionCleaner;
        _commandHub = commandHub;
        _broadcaster = broadcaster;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var lastBaselineSave = DateTimeOffset.UtcNow;
        var lastRetentionRun = DateTimeOffset.UtcNow;

        using var timer = new PeriodicTimer(TickInterval);
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
            {
                var now = DateTimeOffset.UtcNow;

                try
                {
                    await CheckHostStatusesAsync(now, stoppingToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Erreur lors de la vérification du statut des postes.");
                }

                if (now - lastBaselineSave >= BaselineSaveInterval)
                {
                    lastBaselineSave = now;
                    try
                    {
                        await SaveBaselineSnapshotAsync(stoppingToken).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                    {
                        break;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Échec de sauvegarde périodique de la baseline.");
                    }
                }

                if (now - lastRetentionRun >= RetentionInterval)
                {
                    lastRetentionRun = now;
                    try
                    {
                        await _retentionCleaner.CleanAsync(_pipeline.Settings, stoppingToken).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                    {
                        break;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Échec de la purge périodique de rétention.");
                    }
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Arrêt normal
        }
        finally
        {
            // Sauvegarde finale de la baseline avant arrêt
            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                await SaveBaselineSnapshotAsync(cts.Token).ConfigureAwait(false);
            }
            catch
            {
                // Ignoré à l'arrêt
            }
        }
    }

    internal async Task SaveBaselineSnapshotAsync(CancellationToken ct)
    {
        var json = _pipeline.ExportBaseline();
        if (string.IsNullOrWhiteSpace(json))
            return;

        await using var db = await _dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var existing = await db.BaselineSnapshots
            .FirstOrDefaultAsync(b => b.Id == BaselineSnapshotEntity.SingletonId, ct)
            .ConfigureAwait(false);

        var now = DateTimeOffset.UtcNow;
        if (existing is null)
        {
            db.BaselineSnapshots.Add(new BaselineSnapshotEntity
            {
                Id = BaselineSnapshotEntity.SingletonId,
                SnapshotJson = json,
                UpdatedAt = now
            });
        }
        else
        {
            existing.SnapshotJson = json;
            existing.UpdatedAt = now;
        }

        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    private async Task CheckHostStatusesAsync(DateTimeOffset now, CancellationToken ct)
    {
        var cutoffMs = now.Subtract(HostOnlineWindow).ToUnixTimeMilliseconds();
        await using var db = await _dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);

        var hosts = await db.Hosts.AsNoTracking().ToListAsync(ct).ConfigureAwait(false);
        if (hosts.Count == 0)
            return;

        var changed = new List<(HostEntity Host, bool Online)>();
        foreach (var h in hosts)
        {
            var isOnline = h.LastSeenUnixMs >= cutoffMs || _commandHub.IsConnected(h.HostId);
            if (!_lastKnownOnline.TryGetValue(h.HostId, out var prev))
            {
                _lastKnownOnline[h.HostId] = isOnline;
            }
            else if (prev != isOnline)
            {
                _lastKnownOnline[h.HostId] = isOnline;
                changed.Add((h, isOnline));
            }
        }

        if (changed.Count == 0)
            return;

        var openAlertCounts = await db.Alerts
            .AsNoTracking()
            .Where(a => a.Status == AlertStatus.Open || a.Status == AlertStatus.Acknowledged)
            .GroupBy(a => a.HostId)
            .Select(g => new { HostId = g.Key, Count = g.Count() })
            .ToDictionaryAsync(x => x.HostId, x => x.Count, StringComparer.OrdinalIgnoreCase, ct)
            .ConfigureAwait(false);

        foreach (var (host, online) in changed)
        {
            await _broadcaster.HostStatusChangedAsync(
                host.ToDto(online, openAlertCounts.GetValueOrDefault(host.HostId)), ct).ConfigureAwait(false);
        }

        _broadcaster.NotifySummaryChanged();
    }
}
