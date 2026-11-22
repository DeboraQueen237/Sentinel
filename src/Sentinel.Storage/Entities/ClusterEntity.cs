using Sentinel.Shared.Models;

namespace Sentinel.Storage.Entities;

/// <summary>Cluster de corrélation persisté (composante connexe du graphe, doc §8.2).</summary>
public sealed class ClusterEntity
{
    public Guid Id { get; set; }

    public string HostId { get; set; } = string.Empty;

    public DateTimeOffset FirstSeen { get; set; }

    public long FirstSeenUnixMs { get; set; }

    public DateTimeOffset LastSeen { get; set; }

    public long LastSeenUnixMs { get; set; }

    public int Score { get; set; }

    public int MaxEventScore { get; set; }

    public ThreatLevel Level { get; set; }

    public ThreatType DominantType { get; set; }

    public int EventCount { get; set; }

    public bool Escalated { get; set; }

    public string? ChainId { get; set; }

    public string? ChainName { get; set; }

    public int ChainStepsMatched { get; set; }

    public int ChainTotalSteps { get; set; }

    public string ContextKeysJson { get; set; } = "[]";

    public string MitreTechniquesJson { get; set; } = "[]";

    public string Justification { get; set; } = string.Empty;

    public List<ClusterLinkEntity> Links { get; set; } = new();
}
