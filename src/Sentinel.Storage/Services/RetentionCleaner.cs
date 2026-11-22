using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Sentinel.Shared.Models;

namespace Sentinel.Storage.Services;

/// <summary>Bilan d'une exécution de purge de rétention.</summary>
public sealed record RetentionCleanupResult(
    int EventsDeleted,
    int ClustersDeleted,
    int AlertsDeleted,
    int SessionsDeleted,
    DateTimeOffset ExecutedAt);

/// <summary>
/// Applique la politique de rétention configurée (doc §2.3) :
/// 90 jours par défaut pour les événements bruts, 365 jours pour les alertes, et nettoyage des sessions expirées.
/// Les entrées du journal d'audit (<c>AuditEntries</c>) ne sont jamais purgées automatiquement.
/// </summary>
public sealed class RetentionCleaner
{
    private readonly IDbContextFactory<SentinelDbContext> _dbFactory;
    private readonly ILogger<RetentionCleaner>? _logger;

    public RetentionCleaner(
        IDbContextFactory<SentinelDbContext> dbFactory,
        ILogger<RetentionCleaner>? logger = null)
    {
        _dbFactory = dbFactory;
        _logger = logger;
    }

    /// <summary>Exécute la purge selon les durées de rétention de <paramref name="settings"/>.</summary>
    public Task<RetentionCleanupResult> CleanAsync(
        SentinelSettings settings,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(settings);
        return CleanAsync(settings.EventRetentionDays, settings.AlertRetentionDays, null, ct);
    }

    /// <summary>Exécute la purge selon les durées fournies (en jours).</summary>
    public async Task<RetentionCleanupResult> CleanAsync(
        int eventRetentionDays = 90,
        int alertRetentionDays = 365,
        DateTimeOffset? utcNow = null,
        CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        return await CleanAsync(db, eventRetentionDays, alertRetentionDays, utcNow, ct).ConfigureAwait(false);
    }

    /// <summary>Exécute la purge sur un contexte fourni (pratique pour les tests).</summary>
    public async Task<RetentionCleanupResult> CleanAsync(
        SentinelDbContext db,
        int eventRetentionDays = 90,
        int alertRetentionDays = 365,
        DateTimeOffset? utcNow = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(db);

        var safeEventDays = Math.Max(1, eventRetentionDays);
        var safeAlertDays = Math.Max(1, alertRetentionDays);
        var now = utcNow ?? DateTimeOffset.UtcNow;

        var eventCutoffMs = now.AddDays(-safeEventDays).ToUnixTimeMilliseconds();
        var alertCutoffMs = now.AddDays(-safeAlertDays).ToUnixTimeMilliseconds();

        // 1. Purge des événements bruts dépassant EventRetentionDays
        var eventsDeleted = await db.Events
            .Where(e => e.TimestampUnixMs < eventCutoffMs)
            .ExecuteDeleteAsync(ct)
            .ConfigureAwait(false);

        // 2. Purge des alertes dépassant AlertRetentionDays (cascade vers AlertEvents et AlertHistory)
        var alertsDeleted = await db.Alerts
            .Where(a => a.UpdatedAtUnixMs < alertCutoffMs)
            .ExecuteDeleteAsync(ct)
            .ConfigureAwait(false);

        // 3. Purge des clusters anciens qui ne sont plus référencés par une alerte active/conservée (cascade ClusterLinks)
        var clustersDeleted = await db.Clusters
            .Where(c => c.LastSeenUnixMs < eventCutoffMs && !db.Alerts.Any(a => a.ClusterId == c.Id))
            .ExecuteDeleteAsync(ct)
            .ConfigureAwait(false);

        // 4. Purge des sessions administrateur expirées ou révoquées (filtrage mémoire sûr pour DateTimeOffset/SQLite)
        var allSessions = await db.AdminSessions.ToListAsync(ct).ConfigureAwait(false);
        var expiredSessions = allSessions.Where(s => s.Revoked || s.ExpiresAt <= now).ToList();
        var sessionsDeleted = expiredSessions.Count;
        if (sessionsDeleted > 0)
        {
            db.AdminSessions.RemoveRange(expiredSessions);
            await db.SaveChangesAsync(ct).ConfigureAwait(false);
        }

        if (eventsDeleted > 0 || alertsDeleted > 0 || clustersDeleted > 0 || sessionsDeleted > 0)
        {
            _logger?.LogInformation(
                "Purge de rétention effectuée : {Events} événements, {Clusters} clusters, {Alerts} alertes, {Sessions} sessions supprimés.",
                eventsDeleted, clustersDeleted, alertsDeleted, sessionsDeleted);
        }

        return new RetentionCleanupResult(eventsDeleted, clustersDeleted, alertsDeleted, sessionsDeleted, now);
    }
}
