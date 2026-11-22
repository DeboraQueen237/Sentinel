namespace Sentinel.Storage.Entities;

/// <summary>Singleton persistant (Id = 1) de l'instantané sérialisé de la baseline comportementale.</summary>
public sealed class BaselineSnapshotEntity
{
    public const int SingletonId = 1;

    public int Id { get; set; } = SingletonId;

    public string SnapshotJson { get; set; } = "{}";

    public DateTimeOffset UpdatedAt { get; set; }
}
