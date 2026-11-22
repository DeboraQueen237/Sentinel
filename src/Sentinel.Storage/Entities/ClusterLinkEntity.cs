namespace Sentinel.Storage.Entities;

/// <summary>Arête de corrélation entre deux événements au sein d'un cluster.</summary>
public sealed class ClusterLinkEntity
{
    public long Id { get; set; }

    public Guid ClusterId { get; set; }

    public Guid FromEventId { get; set; }

    public Guid ToEventId { get; set; }

    /// <summary>Valeur entière de <see cref="Sentinel.Shared.Models.GraphEdgeType"/>.</summary>
    public int EdgeType { get; set; }

    public double Weight { get; set; }

    public string Key { get; set; } = string.Empty;

    public ClusterEntity? Cluster { get; set; }
}
