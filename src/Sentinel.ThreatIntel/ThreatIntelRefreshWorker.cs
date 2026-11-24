using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Shared.Models;

namespace Sentinel.ThreatIntel;

/// <summary>
/// Service d'arrière-plan assurant le rafraîchissement périodique des flux de renseignement sur les menaces
/// selon <see cref="ThreatIntelSettings.RefreshIntervalHours"/>, sans jamais interrompre l'hôte hors ligne.
/// </summary>
public sealed class ThreatIntelRefreshWorker : BackgroundService
{
    private readonly IReputationService _reputationService;
    private readonly ThreatIntelOptions _options;
    private readonly TimeProvider _clock;
    private readonly ILogger<ThreatIntelRefreshWorker> _logger;

    public ThreatIntelRefreshWorker(
        IReputationService reputationService,
        ThreatIntelOptions? options = null,
        TimeProvider? clock = null,
        ILogger<ThreatIntelRefreshWorker>? logger = null)
    {
        _reputationService = reputationService ?? throw new ArgumentNullException(nameof(reputationService));
        _options = options ?? new ThreatIntelOptions();
        _clock = clock ?? TimeProvider.System;
        _logger = logger ?? NullLogger<ThreatIntelRefreshWorker>.Instance;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (_options.InitialRefreshDelay > TimeSpan.Zero)
        {
            try
            {
                await Task.Delay(_options.InitialRefreshDelay, _clock, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            var settings = GetEffectiveSettings();
            if (settings.Enabled)
            {
                try
                {
                    var status = await _reputationService.RefreshNowAsync(stoppingToken).ConfigureAwait(false);
                    _logger.LogInformation(
                        "Cycle Threat Intelligence terminé : {Total} indicateurs actifs (modeHorsLigne={Offline}).",
                        status.TotalIndicators,
                        status.OfflineMode);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception ex)
                {
                    // Tolérance totale au hors-ligne : ne jamais faire planter le BackgroundService
                    _logger.LogWarning(ex, "Échec du cycle de rafraîchissement Threat Intelligence (poursuite hors ligne).");
                }
            }

            var interval = ResolveRefreshInterval(settings);
            try
            {
                await Task.Delay(interval, _clock, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
        }
    }

    private ThreatIntelSettings GetEffectiveSettings() =>
        _reputationService is ReputationService concrete
            ? concrete.CurrentSettings
            : _options.Settings;

    private TimeSpan ResolveRefreshInterval(ThreatIntelSettings settings)
    {
        if (_options.RefreshIntervalOverride is { } custom && custom > TimeSpan.Zero)
        {
            return custom;
        }

        var hours = Math.Clamp(settings.RefreshIntervalHours, 1, 168);
        return TimeSpan.FromHours(hours);
    }
}
