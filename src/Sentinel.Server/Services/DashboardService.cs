using Microsoft.EntityFrameworkCore;
using Sentinel.Core.Abstractions;
using Sentinel.Shared.Api;
using Sentinel.Shared.Models;
using Sentinel.Storage;
using Sentinel.Storage.Mapping;

namespace Sentinel.Server.Services;

/// <summary>
/// Calcule les indicateurs agrégés et séries temporelles du tableau de bord (doc §10.1-1).
/// </summary>
public sealed class DashboardService
{
    private static readonly TimeSpan HostOnlineWindow = TimeSpan.FromSeconds(60);

    private readonly IDbContextFactory<SentinelDbContext> _dbFactory;
    private readonly IThreatPipeline _pipeline;
    private readonly AgentCommandHub _commandHub;

    public DashboardService(
        IDbContextFactory<SentinelDbContext> dbFactory,
        IThreatPipeline pipeline,
        AgentCommandHub commandHub)
    {
        _dbFactory = dbFactory;
        _pipeline = pipeline;
        _commandHub = commandHub;
    }

    public async Task<DashboardSummaryDto> GetSummaryAsync(CancellationToken ct = default)
    {
        var now = DateTimeOffset.UtcNow;
        var since24hMs = now.AddHours(-24).ToUnixTimeMilliseconds();
        var onlineCutoffMs = now.Subtract(HostOnlineWindow).ToUnixTimeMilliseconds();

        await using var db = await _dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);

        // Alertes actives (Open ou Acknowledged)
        var activeAlertsList = await db.Alerts
            .AsNoTracking()
            .Where(a => a.Status == AlertStatus.Open || a.Status == AlertStatus.Acknowledged)
            .Select(a => new { a.Level, a.RequiresDecision })
            .ToListAsync(ct)
            .ConfigureAwait(false);

        var activeAlerts = activeAlertsList.Count;
        var criticalAlerts = activeAlertsList.Count(a => a.Level == ThreatLevel.Critical);
        var highAlerts = activeAlertsList.Count(a => a.Level == ThreatLevel.High);
        var moderateAlerts = activeAlertsList.Count(a => a.Level == ThreatLevel.Moderate);
        var lowAlerts = activeAlertsList.Count(a => a.Level == ThreatLevel.Low);
        var alertsAwaitingDecision = activeAlertsList.Count(a => a.RequiresDecision);

        // Blocages actifs
        var activeTickets = await db.ActionTickets
            .AsNoTracking()
            .Where(t => t.Status == ActionStatus.Executed || t.Status == ActionStatus.Pending)
            .Select(t => t.ActionType)
            .ToListAsync(ct)
            .ConfigureAwait(false);
        var activeBlocks = activeTickets.Count(t => ActionPolicyHelper.IsBlockingAction((ResponseActionType)t));

        // Clusters sur 24h
        var clusters24hScores = await db.Clusters
            .AsNoTracking()
            .Where(c => c.LastSeenUnixMs >= since24hMs)
            .Select(c => c.Score)
            .ToListAsync(ct)
            .ConfigureAwait(false);

        var clustersLast24h = clusters24hScores.Count;

        // Score de sécurité global (0..100, 100 = sain)
        var globalScore = ComputeGlobalSecurityScore(criticalAlerts, highAlerts, moderateAlerts, lowAlerts, clusters24hScores);

        // Distributions 24h sur les événements
        var recentEventStats = await db.Events
            .AsNoTracking()
            .Where(e => e.TimestampUnixMs >= since24hMs)
            .Select(e => new { e.Level, e.ThreatType, e.Category })
            .ToListAsync(ct)
            .ConfigureAwait(false);

        long eventsLast24h = recentEventStats.Count;

        var levelDist = Enum.GetValues<ThreatLevel>().ToDictionary(l => l, _ => 0);
        var typeDist = new Dictionary<ThreatType, int>();
        var catDist = new Dictionary<EventCategory, long>();

        foreach (var ev in recentEventStats)
        {
            var lvl = (ThreatLevel)ev.Level;
            levelDist[lvl] = levelDist.GetValueOrDefault(lvl) + 1;

            var tt = (ThreatType)ev.ThreatType;
            if (tt != ThreatType.None)
                typeDist[tt] = typeDist.GetValueOrDefault(tt) + 1;

            var cat = (EventCategory)ev.Category;
            catDist[cat] = catDist.GetValueOrDefault(cat) + 1L;
        }

        // Postes en ligne / total
        var hosts = await db.Hosts
            .AsNoTracking()
            .Select(h => new { h.HostId, h.LastSeenUnixMs })
            .ToListAsync(ct)
            .ConfigureAwait(false);

        var hostsTotal = hosts.Count;
        var hostsOnline = hosts.Count(h => h.LastSeenUnixMs >= onlineCutoffMs || _commandHub.IsConnected(h.HostId));

        // 10 alertes les plus récentes
        var recentAlertEntities = await db.Alerts
            .AsNoTracking()
            .OrderByDescending(a => a.UpdatedAtUnixMs)
            .Take(10)
            .ToListAsync(ct)
            .ConfigureAwait(false);

        var alertIds = recentAlertEntities.Select(a => a.Id).ToList();
        var pendingByAlert = alertIds.Count == 0
            ? new Dictionary<Guid, int>()
            : await db.ActionTickets
                .AsNoTracking()
                .Where(t => t.AlertId != null && alertIds.Contains(t.AlertId.Value) &&
                            (t.Status == ActionStatus.Proposed || t.Status == ActionStatus.Pending))
                .GroupBy(t => t.AlertId!.Value)
                .Select(g => new { AlertId = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.AlertId, x => x.Count, ct)
                .ConfigureAwait(false);

        var recentAlerts = recentAlertEntities
            .Select(a => a.ToDto(pendingByAlert.GetValueOrDefault(a.Id)))
            .ToArray();

        var settings = _pipeline.Settings;
        var stats = _pipeline.Stats;

        return new DashboardSummaryDto(
            GlobalSecurityScore: globalScore,
            ActiveAlerts: activeAlerts,
            CriticalAlerts: criticalAlerts,
            AlertsAwaitingDecision: alertsAwaitingDecision,
            ActiveBlocks: activeBlocks,
            EventsLast24h: eventsLast24h,
            ClustersLast24h: clustersLast24h,
            HostsOnline: hostsOnline,
            HostsTotal: hostsTotal,
            Mode: settings.Mode,
            LlmAvailable: stats.LlmAvailable,
            LlmModel: settings.Llm.Model,
            LevelDistribution24h: levelDist,
            ThreatTypes24h: typeDist,
            Categories24h: catDist,
            RecentAlerts: recentAlerts,
            GeneratedAt: now);
    }

    public async Task<IReadOnlyList<TimeSeriesPointDto>> GetTimelineAsync(string? range, CancellationToken ct = default)
    {
        var now = DateTimeOffset.UtcNow;
        var (bucketCount, bucketSpan) = (range?.Trim().ToLowerInvariant()) switch
        {
            "7d" => (28, TimeSpan.FromHours(6)),
            "30d" => (30, TimeSpan.FromDays(1)),
            _ => (24, TimeSpan.FromHours(1))
        };

        var currentBucketStart = AlignFloor(now, bucketSpan);
        var start = currentBucketStart.AddTicks(-bucketSpan.Ticks * (bucketCount - 1));
        var startMs = start.ToUnixTimeMilliseconds();
        var bucketMs = (long)bucketSpan.TotalMilliseconds;

        await using var db = await _dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);

        var events = await db.Events
            .AsNoTracking()
            .Where(e => e.TimestampUnixMs >= startMs)
            .Select(e => new { e.TimestampUnixMs, e.Score })
            .ToListAsync(ct)
            .ConfigureAwait(false);

        var alerts = await db.Alerts
            .AsNoTracking()
            .Where(a => a.CreatedAtUnixMs >= startMs)
            .Select(a => a.CreatedAtUnixMs)
            .ToListAsync(ct)
            .ConfigureAwait(false);

        var actions = await db.ActionTickets
            .AsNoTracking()
            .Where(t => t.CreatedAtUnixMs >= startMs &&
                        (t.Status == ActionStatus.Executed || t.Status == ActionStatus.Pending || t.Status == ActionStatus.Simulated))
            .Select(t => new { t.CreatedAtUnixMs, t.ActionType })
            .ToListAsync(ct)
            .ConfigureAwait(false);

        var eventCounts = new long[bucketCount];
        var scoreSums = new long[bucketCount];
        var maxScores = new int[bucketCount];
        var alertCounts = new int[bucketCount];
        var blockCounts = new int[bucketCount];

        foreach (var e in events)
        {
            var idx = (int)((e.TimestampUnixMs - startMs) / bucketMs);
            if (idx < 0 || idx >= bucketCount) continue;
            eventCounts[idx]++;
            scoreSums[idx] += e.Score;
            if (e.Score > maxScores[idx]) maxScores[idx] = e.Score;
        }

        foreach (var ts in alerts)
        {
            var idx = (int)((ts - startMs) / bucketMs);
            if (idx < 0 || idx >= bucketCount) continue;
            alertCounts[idx]++;
        }

        foreach (var a in actions)
        {
            if (!ActionPolicyHelper.IsBlockingAction((ResponseActionType)a.ActionType)) continue;
            var idx = (int)((a.CreatedAtUnixMs - startMs) / bucketMs);
            if (idx < 0 || idx >= bucketCount) continue;
            blockCounts[idx]++;
        }

        var points = new TimeSeriesPointDto[bucketCount];
        for (var i = 0; i < bucketCount; i++)
        {
            var avg = eventCounts[i] > 0 ? Math.Round((double)scoreSums[i] / eventCounts[i], 1) : 0.0;
            points[i] = new TimeSeriesPointDto(
                start.AddTicks(bucketSpan.Ticks * i),
                eventCounts[i],
                alertCounts[i],
                maxScores[i],
                avg,
                blockCounts[i]);
        }

        return points;
    }

    public static int ComputeGlobalSecurityScore(
        int criticalAlerts,
        int highAlerts,
        int moderateAlerts,
        int lowAlerts,
        IReadOnlyList<int> recentClusterScores)
    {
        var alertPenalty = Math.Min(75,
            criticalAlerts * 22 +
            highAlerts * 12 +
            moderateAlerts * 5 +
            lowAlerts * 2);

        var clusterPenalty = 0;
        foreach (var s in recentClusterScores)
        {
            if (s >= 90) clusterPenalty += 8;
            else if (s >= 75) clusterPenalty += 5;
            else if (s >= 55) clusterPenalty += 2;
        }
        clusterPenalty = Math.Min(25, clusterPenalty);

        return Math.Clamp(100 - alertPenalty - clusterPenalty, 0, 100);
    }

    private static DateTimeOffset AlignFloor(DateTimeOffset value, TimeSpan bucket)
    {
        var ticks = value.UtcTicks - (value.UtcTicks % bucket.Ticks);
        return new DateTimeOffset(ticks, TimeSpan.Zero);
    }
}
