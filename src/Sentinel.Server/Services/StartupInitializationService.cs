using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Sentinel.Core.Abstractions;
using Sentinel.Shared.Infrastructure;
using Sentinel.Shared.Json;
using Sentinel.Shared.Models;
using Sentinel.Shared.Security;
using Sentinel.Storage;
using Sentinel.Storage.Entities;
using Sentinel.Storage.Mapping;

namespace Sentinel.Server.Services;

/// <summary>
/// Service d'initialisation synchrone au démarrage du serveur :
/// 1. Initialise le schéma SQLite (WAL) via <see cref="SentinelDbInitializer"/>.
/// 2. Charge/crée <see cref="SettingsEntity"/> et configure <see cref="IThreatPipeline"/>.
/// 3. Restaure la baseline (<see cref="BaselineSnapshotEntity"/>) et réhydrate le moteur avec les événements des 24 dernières heures.
/// </summary>
public sealed class StartupInitializationService : IHostedService
{
    private const int MaxWarmUpEvents = 20_000;

    private readonly SentinelDbInitializer _dbInitializer;
    private readonly IDbContextFactory<SentinelDbContext> _dbFactory;
    private readonly IThreatPipeline _pipeline;
    private readonly IAlertNotificationDispatcher _notifications;
    private readonly IHostEnvironment _environment;
    private readonly ILogger<StartupInitializationService> _logger;

    public StartupInitializationService(
        SentinelDbInitializer dbInitializer,
        IDbContextFactory<SentinelDbContext> dbFactory,
        IThreatPipeline pipeline,
        IAlertNotificationDispatcher notifications,
        IHostEnvironment environment,
        ILogger<StartupInitializationService> logger)
    {
        _dbInitializer = dbInitializer;
        _dbFactory = dbFactory;
        _pipeline = pipeline;
        _notifications = notifications;
        _environment = environment;
        _logger = logger;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        // 0. Durcissement NTFS des répertoires de données (hors environnement Testing)
        if (!_environment.IsEnvironment("Testing"))
        {
            var acl = DirectorySecurityHardener.HardenDirectory(SentinelPaths.Root);
            if (acl.Applied)
                _logger.LogInformation("Durcissement NTFS appliqué sur {Path} : {Message}", acl.Path, acl.Message);
            else
                _logger.LogDebug("Durcissement NTFS non appliqué sur {Path} : {Message}", acl.Path, acl.Message);
        }

        // 1. Base de données
        await _dbInitializer.InitializeAsync(cancellationToken).ConfigureAwait(false);

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);

        // 2. Paramètres globaux
        var settingsEntity = await db.Settings
            .FirstOrDefaultAsync(s => s.Id == SettingsEntity.SingletonId, cancellationToken)
            .ConfigureAwait(false);

        SentinelSettings settings;
        if (settingsEntity is null)
        {
            settings = new SentinelSettings();
            settingsEntity = new SettingsEntity
            {
                Id = SettingsEntity.SingletonId,
                Version = 1,
                SettingsJson = SentinelJson.Serialize(settings),
                UpdatedAt = DateTimeOffset.UtcNow
            };
            db.Settings.Add(settingsEntity);
            await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
        else
        {
            settings = SentinelJson.Deserialize<SentinelSettings>(settingsEntity.SettingsJson) ?? new SentinelSettings();
        }

        _pipeline.UpdateSettings(settings);
        _notifications.UpdateSettings(settings.Notifications ?? new NotificationSettings());

        // 3. Restauration de la baseline comportementale
        var snapshot = await db.BaselineSnapshots
            .AsNoTracking()
            .FirstOrDefaultAsync(b => b.Id == BaselineSnapshotEntity.SingletonId, cancellationToken)
            .ConfigureAwait(false);

        if (snapshot is not null && !string.IsNullOrWhiteSpace(snapshot.SnapshotJson) && snapshot.SnapshotJson != "{}")
        {
            try
            {
                _pipeline.ImportBaseline(snapshot.SnapshotJson);
                _logger.LogInformation("Instantané de baseline restauré (date={UpdatedAt}).", snapshot.UpdatedAt);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Impossible de restaurer l'instantané de baseline ; reconstruction à partir des événements récents.");
            }
        }

        // 4. Réhydratation du moteur de corrélation sur les dernières 24h
        var cutoffMs = DateTimeOffset.UtcNow.AddHours(-24).ToUnixTimeMilliseconds();
        var recentEvents = await db.Events
            .AsNoTracking()
            .Where(e => e.TimestampUnixMs >= cutoffMs)
            .OrderBy(e => e.TimestampUnixMs)
            .Take(MaxWarmUpEvents)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        if (recentEvents.Count > 0)
        {
            await _pipeline.WarmUpAsync(recentEvents.Select(e => e.ToScoredEvent()), cancellationToken).ConfigureAwait(false);
            _logger.LogInformation("Pipeline réhydraté avec {Count} événement(s) des dernières 24 heures.", recentEvents.Count);
        }
        else
        {
            _logger.LogInformation("Démarrage SENTINEL prêt (mode={Mode}, aucun événement récent à réhydrater).", settings.Mode);
        }

        // 5. Pré-chargement des résultats d'évaluation A/B/C si la table est vide et que docs/evaluation-results.json existe
        if (!await db.EvaluationMetrics.AnyAsync(cancellationToken).ConfigureAwait(false))
        {
            var candidates = new[]
            {
                Path.Combine(AppContext.BaseDirectory, "evaluation-results.json"),
                Path.GetFullPath(Path.Combine(Directory.GetCurrentDirectory(), "docs", "evaluation-results.json")),
                Path.GetFullPath(Path.Combine(Directory.GetCurrentDirectory(), "..", "..", "docs", "evaluation-results.json"))
            };
            var evalFile = candidates.FirstOrDefault(File.Exists);
            if (evalFile is not null)
            {
                try
                {
                    var json = await File.ReadAllTextAsync(evalFile, cancellationToken).ConfigureAwait(false);
                    var items = SentinelJson.Deserialize<List<Sentinel.Shared.Api.ScenarioMetricDto>>(json);
                    if (items is { Count: > 0 })
                    {
                        var now = DateTimeOffset.UtcNow;
                        foreach (var m in items)
                        {
                            db.EvaluationMetrics.Add(new EvaluationMetricEntity
                            {
                                RunAt = now,
                                Scenario = m.Scenario,
                                Configuration = m.Configuration,
                                Detected = m.Detected,
                                EventsBeforeAlert = m.EventsBeforeAlert,
                                SecondsToDetect = m.SecondsToDetect,
                                PeakScore = m.PeakScore,
                                FalsePositives = m.FalsePositives
                            });
                        }
                        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
                        _logger.LogInformation("{Count} métriques d'évaluation scientifique A/B/C pré-chargées depuis {File}.", items.Count, evalFile);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Impossible de pré-charger les résultats d'évaluation depuis {File}.", evalFile);
                }
            }
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
