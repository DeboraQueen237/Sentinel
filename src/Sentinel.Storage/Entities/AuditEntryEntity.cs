namespace Sentinel.Storage.Entities;

/// <summary>
/// Entrée du journal d'audit des accès et actions administrateur, chaînée en SHA-256 (doc §2.3, §10.1, §11).
/// </summary>
public sealed class AuditEntryEntity
{
    public long Id { get; set; }

    public DateTimeOffset Timestamp { get; set; }

    public long TimestampUnixMs { get; set; }

    public string Actor { get; set; } = string.Empty;

    public string Action { get; set; } = string.Empty;

    public string Target { get; set; } = string.Empty;

    public string? Details { get; set; }

    public string? IpAddress { get; set; }

    /// <summary>Empreinte SHA-256 chaînée : <c>SHA256(PreviousHash | payload)</c>.</summary>
    public string Hash { get; set; } = string.Empty;

    /// <summary>Empreinte SHA-256 de l'entrée précédente (ou <c>HashChain.Genesis</c> pour la première entrée).</summary>
    public string PreviousHash { get; set; } = string.Empty;
}
