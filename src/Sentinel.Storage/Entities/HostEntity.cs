namespace Sentinel.Storage.Entities;

/// <summary>Poste supervisé enregistré via gRPC (métadonnées système, santé et score de risque).</summary>
public sealed class HostEntity
{
    public string HostId { get; set; } = string.Empty;

    public string MachineName { get; set; } = string.Empty;

    public string OsVersion { get; set; } = string.Empty;

    public string AgentVersion { get; set; } = string.Empty;

    public string BinarySha256 { get; set; } = string.Empty;

    public DateTimeOffset FirstSeen { get; set; }

    public DateTimeOffset LastSeen { get; set; }

    public long LastSeenUnixMs { get; set; }

    public string UsersJson { get; set; } = "[]";

    public double CpuPercent { get; set; }

    public long WorkingSetBytes { get; set; }

    public int QueueLength { get; set; }

    public string CollectorsJson { get; set; } = "[]";

    public int RiskScore { get; set; }
}
