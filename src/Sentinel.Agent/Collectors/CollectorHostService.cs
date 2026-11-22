using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Sentinel.Agent.Configuration;
using Sentinel.Shared.Grpc;
using Sentinel.Shared.Models;

namespace Sentinel.Agent.Collectors;

/// <summary>
/// Supervise le cycle de vie de tous les <see cref="IEventCollector"/> avec isolation par try/catch
/// afin qu'un collecteur en échec (ex. droits insuffisants) n'interrompe jamais l'agent.
/// </summary>
public sealed class CollectorHostService : BackgroundService
{
    private readonly IReadOnlyList<IEventCollector> _collectors;
    private readonly AgentStateStore _stateStore;
    private readonly ILogger<CollectorHostService> _logger;

    public CollectorHostService(
        IEnumerable<IEventCollector> collectors,
        AgentStateStore stateStore,
        ILogger<CollectorHostService> logger)
    {
        _collectors = collectors.ToArray();
        _stateStore = stateStore;
        _logger = logger;
        _stateStore.SettingsChanged += OnSettingsChanged;
    }

    public IReadOnlyList<CollectorStatus> GetStatuses() =>
        _collectors.Select(c => new CollectorStatus
        {
            Name = c.Name,
            Running = c.IsRunning,
            Error = c.LastError ?? string.Empty,
            EventsProduced = c.EventsProduced
        }).ToArray();

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var currentSettings = _stateStore.CurrentSettings;

        foreach (var collector in _collectors)
        {
            try
            {
                collector.UpdateSettings(currentSettings);
                await collector.StartAsync(stoppingToken);
                _logger.LogInformation("Collecteur « {Name} » démarré (actif={Running}, info={Error}).",
                    collector.Name, collector.IsRunning, string.IsNullOrEmpty(collector.LastError) ? "nominal" : collector.LastError);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Échec au démarrage du collecteur « {Name} » ; l'agent continue en mode dégradé.", collector.Name);
            }
        }

        try
        {
            await Task.Delay(Timeout.Infinite, stoppingToken);
        }
        catch (OperationCanceledException)
        {
            // Arrêt normal du service.
        }
        finally
        {
            foreach (var collector in _collectors)
            {
                try
                {
                    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                    await collector.StopAsync(cts.Token);
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Erreur à l'arrêt du collecteur « {Name} ».", collector.Name);
                }
            }
        }
    }

    private void OnSettingsChanged(SentinelSettings settings)
    {
        foreach (var collector in _collectors)
        {
            try
            {
                collector.UpdateSettings(settings);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Échec lors de la mise à jour des paramètres du collecteur « {Name} ».", collector.Name);
            }
        }
    }

    public override void Dispose()
    {
        _stateStore.SettingsChanged -= OnSettingsChanged;
        base.Dispose();
    }
}
