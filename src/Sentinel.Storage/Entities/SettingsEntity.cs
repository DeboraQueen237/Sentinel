namespace Sentinel.Storage.Entities;

/// <summary>Singleton persistant (Id = 1) des paramètres globaux <c>SentinelSettings</c>.</summary>
public sealed class SettingsEntity
{
    public const int SingletonId = 1;

    public int Id { get; set; } = SingletonId;

    public long Version { get; set; } = 1;

    public string SettingsJson { get; set; } = "{}";

    public DateTimeOffset UpdatedAt { get; set; }
}
