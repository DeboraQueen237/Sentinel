using Sentinel.Shared.Infrastructure;

namespace Sentinel.Agent.Configuration;

/// <summary>Configuration de l'agent chargée depuis appsettings.json (section « Agent »).</summary>
public sealed class AgentOptions
{
    public const string SectionName = "Agent";

    public string ServerGrpcUrl { get; set; } = SentinelEndpoints.ServerGrpcUrl;
    public bool UseMtls { get; set; } = true;
    public int HeartbeatIntervalSeconds { get; set; } = 15;
    public int BatchSize { get; set; } = 100;
    public int BatchFlushIntervalMs { get; set; } = 2000;
    public int MaxOutboxEvents { get; set; } = 50_000;
    public int ChannelCapacity { get; set; } = 4096;
    public string IntegrityManifestPath { get; set; } = string.Empty;
}
