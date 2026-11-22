using Sentinel.Shared.Models;

namespace Sentinel.Storage.Entities;

/// <summary>Alerte de sécurité destinée à l'administrateur (niveaux 2 à 4, doc §9–§10).</summary>
public sealed class AlertEntity
{
    public Guid Id { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public long CreatedAtUnixMs { get; set; }

    public DateTimeOffset UpdatedAt { get; set; }

    public long UpdatedAtUnixMs { get; set; }

    public string HostId { get; set; } = string.Empty;

    public string UserId { get; set; } = string.Empty;

    public string Title { get; set; } = string.Empty;

    public string Summary { get; set; } = string.Empty;

    public string Justification { get; set; } = string.Empty;

    public int Score { get; set; }

    public ThreatLevel Level { get; set; }

    public ThreatType ThreatType { get; set; }

    public AlertStatus Status { get; set; } = AlertStatus.Open;

    public Guid? ClusterId { get; set; }

    public int EventCount { get; set; }

    public bool RequiresDecision { get; set; }

    public string MitreTechniquesJson { get; set; } = "[]";

    public List<AlertEventEntity> AlertEvents { get; set; } = new();

    public List<AlertHistoryEntity> History { get; set; } = new();
}
