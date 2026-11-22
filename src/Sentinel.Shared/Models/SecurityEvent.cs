using System.Text.Json.Serialization;

namespace Sentinel.Shared.Models;

/// <summary>
/// Événement normalisé, schéma commun à tous les collecteurs (doc §5.1, exigence F2).
/// Les clés d'<see cref="Attributes"/> doivent provenir de <see cref="AttributeKeys"/>.
/// </summary>
public sealed record SecurityEvent(
    Guid Id,
    DateTimeOffset Timestamp,
    string HostId,
    string UserId,
    EventCategory Category,
    string EventType,
    string Subject,
    IReadOnlyDictionary<string, string> Attributes,
    string? CorrelationHints)
{
    /// <summary>Lecture sûre d'un attribut.</summary>
    public string? Attr(string key) => Attributes.TryGetValue(key, out var v) ? v : null;

    public bool AttrIsTrue(string key) =>
        Attributes.TryGetValue(key, out var v) && (v == "1" || v.Equals("true", StringComparison.OrdinalIgnoreCase));

    public double? AttrDouble(string key) =>
        Attributes.TryGetValue(key, out var v) &&
        double.TryParse(v, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var d)
            ? d : null;

    public long? AttrLong(string key) =>
        Attributes.TryGetValue(key, out var v) &&
        long.TryParse(v, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var l)
            ? l : null;

    /// <summary>Fabrique pratique pour les collecteurs.</summary>
    public static SecurityEvent Create(
        string hostId, string userId, EventCategory category, string eventType, string subject,
        IReadOnlyDictionary<string, string>? attributes = null, string? correlationHints = null,
        DateTimeOffset? timestamp = null) =>
        new(Guid.NewGuid(), timestamp ?? DateTimeOffset.UtcNow, hostId, userId, category, eventType, subject,
            attributes ?? new Dictionary<string, string>(), correlationHints);
}

/// <summary>Résultat de scoring d'un événement (doc §5.2, exigence F3).</summary>
public sealed record ThreatAssessment(
    Guid EventId,
    int Score,
    ThreatType Type,
    string Justification,
    AssessmentSource Source,
    double Confidence)
{
    /// <summary>Règles déclenchées (identifiants), pour l'explicabilité.</summary>
    public IReadOnlyList<string> MatchedRules { get; init; } = Array.Empty<string>();

    /// <summary>Techniques MITRE ATT&amp;CK associées (ex. "T1566").</summary>
    public IReadOnlyList<string> MitreTechniques { get; init; } = Array.Empty<string>();

    [JsonIgnore]
    public ThreatLevel Level => ThreatLevels.FromScore(Score);
}

/// <summary>Événement + évaluation.</summary>
public sealed record ScoredEvent(SecurityEvent Event, ThreatAssessment Assessment);

/// <summary>Seuils des niveaux (configurables, défauts doc §9.1).</summary>
public sealed class ThreatThresholds
{
    public int Low { get; set; } = 30;
    public int Moderate { get; set; } = 55;
    public int High { get; set; } = 75;
    public int Critical { get; set; } = 90;

    public ThreatLevel LevelOf(int score) =>
        score >= Critical ? ThreatLevel.Critical :
        score >= High ? ThreatLevel.High :
        score >= Moderate ? ThreatLevel.Moderate :
        score >= Low ? ThreatLevel.Low : ThreatLevel.Info;
}

public static class ThreatLevels
{
    public static ThreatThresholds Default { get; } = new();

    public static ThreatLevel FromScore(int score) => Default.LevelOf(score);

    public static string Label(ThreatLevel level) => level switch
    {
        ThreatLevel.Info => "Info",
        ThreatLevel.Low => "Faible",
        ThreatLevel.Moderate => "Modéré",
        ThreatLevel.High => "Élevé",
        ThreatLevel.Critical => "Critique",
        _ => level.ToString()
    };

    /// <summary>Niveau supérieur (escalade précoce, doc §8.2-5).</summary>
    public static ThreatLevel Raise(ThreatLevel level) =>
        level >= ThreatLevel.Critical ? ThreatLevel.Critical : level + 1;
}
