namespace Sentinel.Storage.Entities;

/// <summary>Entrée d'historique d'une alerte (changement de statut, décision analyste, commentaire).</summary>
public sealed class AlertHistoryEntity
{
    public long Id { get; set; }

    public Guid AlertId { get; set; }

    public DateTimeOffset Timestamp { get; set; }

    public string Actor { get; set; } = string.Empty;

    public string Action { get; set; } = string.Empty;

    public string? Comment { get; set; }

    public AlertEntity? Alert { get; set; }
}
