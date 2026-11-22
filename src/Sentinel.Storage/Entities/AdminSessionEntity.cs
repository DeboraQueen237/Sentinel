namespace Sentinel.Storage.Entities;

/// <summary>Session courte d'authentification administrateur (jeton stocké uniquement sous forme de hash SHA-256).</summary>
public sealed class AdminSessionEntity
{
    /// <summary>Empreinte SHA-256 hexadécimale du jeton Bearer.</summary>
    public string TokenHash { get; set; } = string.Empty;

    public string Username { get; set; } = string.Empty;

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset ExpiresAt { get; set; }

    public string? IpAddress { get; set; }

    public bool Revoked { get; set; }
}
