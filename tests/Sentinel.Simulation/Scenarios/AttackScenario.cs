using Sentinel.Shared.Models;

namespace Sentinel.Simulation.Scenarios;

/// <summary>
/// Définition d'un scénario d'attaque simulé mappé à MITRE ATT&amp;CK (doc §8.3, §14.1, §14.4).
/// </summary>
public sealed record AttackScenario(
    string Id,
    string Name,
    string Description,
    IReadOnlyList<string> MitreTechniques,
    ThreatType ExpectedThreatType,
    string? ExpectedChainId,
    bool IsMultiStageChain,
    IReadOnlyList<SecurityEvent> Events);

/// <summary>
/// Profil d'un poste simulé pour le rejeu en direct via gRPC (<c>--push-grpc</c>).
/// </summary>
public sealed record SimulatedHostPlan(
    string HostId,
    string MachineName,
    string OsVersion,
    string UserId,
    IReadOnlyList<SecurityEvent> Events);
