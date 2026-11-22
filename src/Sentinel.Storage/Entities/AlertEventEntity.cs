namespace Sentinel.Storage.Entities;

/// <summary>Table de liaison (clé primaire composite) entre une alerte et ses événements associés.</summary>
public sealed class AlertEventEntity
{
    public Guid AlertId { get; set; }

    public Guid EventId { get; set; }

    public AlertEntity? Alert { get; set; }
}
