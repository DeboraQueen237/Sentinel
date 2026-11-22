namespace Sentinel.Storage.Entities;

/// <summary>
/// Événement de sécurité normalisé, évalué et chaîné cryptographiquement (doc §3.2, §5.1, §11).
/// </summary>
public sealed class EventEntity
{
    public Guid Id { get; set; }

    public DateTimeOffset Timestamp { get; set; }

    /// <summary>
    /// Horodatage Unix en millisecondes (UTC), indexé pour les tris et filtres temporels SQLite
    /// (SQLite ne compare pas nativement <see cref="DateTimeOffset"/> en LINQ).
    /// </summary>
    public long TimestampUnixMs { get; set; }

    public string HostId { get; set; } = string.Empty;

    public string UserId { get; set; } = string.Empty;

    /// <summary>Valeur entière de <see cref="Sentinel.Shared.Models.EventCategory"/>.</summary>
    public int Category { get; set; }

    public string EventType { get; set; } = string.Empty;

    public string Subject { get; set; } = string.Empty;

    public string AttributesJson { get; set; } = "{}";

    public string? CorrelationHints { get; set; }

    public int Score { get; set; }

    /// <summary>Valeur entière de <see cref="Sentinel.Shared.Models.ThreatLevel"/>.</summary>
    public int Level { get; set; }

    /// <summary>Valeur entière de <see cref="Sentinel.Shared.Models.ThreatType"/>.</summary>
    public int ThreatType { get; set; }

    public string Justification { get; set; } = string.Empty;

    /// <summary>Valeur entière de <see cref="Sentinel.Shared.Models.AssessmentSource"/>.</summary>
    public int Source { get; set; }

    public double Confidence { get; set; }

    public string MatchedRulesJson { get; set; } = "[]";

    public string MitreTechniquesJson { get; set; } = "[]";

    public Guid? ClusterId { get; set; }

    /// <summary>Numéro séquentiel strictement croissant et unique dans la chaîne d'intégrité.</summary>
    public long ChainSeq { get; set; }

    /// <summary>Empreinte SHA-256 chaînée : <c>SHA256(PreviousHash | payload)</c>.</summary>
    public string Hash { get; set; } = string.Empty;

    /// <summary>Empreinte SHA-256 de l'événement précédent (ou <c>HashChain.Genesis</c> pour <c>ChainSeq == 1</c>).</summary>
    public string PreviousHash { get; set; } = string.Empty;
}
