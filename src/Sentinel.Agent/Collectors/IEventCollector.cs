using Sentinel.Shared.Models;

namespace Sentinel.Agent.Collectors;

/// <summary>Contrat commun à tous les collecteurs de l'agent SENTINEL.</summary>
public interface IEventCollector
{
    string Name { get; }
    bool IsRunning { get; }
    string? LastError { get; }
    long EventsProduced { get; }

    Task StartAsync(CancellationToken cancellationToken);
    Task StopAsync(CancellationToken cancellationToken);
    void UpdateSettings(SentinelSettings settings);
}
