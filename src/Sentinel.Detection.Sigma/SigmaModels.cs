using System.Text.RegularExpressions;
using Sentinel.Shared.Models;

namespace Sentinel.Detection.Sigma;

/// <summary>Source de journaux ciblee par une regle Sigma (<c>logsource</c>).</summary>
public sealed record SigmaLogSource(
    string? Category,
    string? Product,
    string? Service);

/// <summary>Resultat d'une correspondance de regle Sigma sur un <see cref="SecurityEvent"/>.</summary>
public sealed record SigmaMatch(
    string RuleId,
    string Title,
    string Level,
    int Score,
    string SourceFile,
    IReadOnlyList<string> MitreTechniques,
    IReadOnlyList<string> MitreTactics,
    IReadOnlyList<string> MatchedSelections,
    string Description);

/// <summary>Erreur non fatale rencontree lors du chargement ou de l'analyse d'une regle Sigma.</summary>
public sealed record SigmaLoadError(
    string FilePath,
    string Message,
    Exception? Exception = null);

/// <summary>Bilan d'un chargement ou rechargement de regles Sigma.</summary>
public sealed record SigmaRuleLoadResult(
    int LoadedCount,
    IReadOnlyList<SigmaLoadError> Errors);

/// <summary>Exception interne levee lors de l'analyse syntaxique d'une regle Sigma invalide.</summary>
public sealed class SigmaParseException : Exception
{
    public SigmaParseException(string message) : base(message) { }
    public SigmaParseException(string message, Exception innerException) : base(message, innerException) { }
}

/// <summary>Niveaux de severite Sigma standard et correspondance vers le score SENTINEL (0–100).</summary>
public static class SigmaLevels
{
    public const string Informational = "informational";
    public const string Low = "low";
    public const string Medium = "medium";
    public const string High = "high";
    public const string Critical = "critical";

    /// <summary>Normalise le niveau Sigma en minuscules (defaut : <c>medium</c>).</summary>
    public static string Normalize(string? rawLevel)
    {
        if (string.IsNullOrWhiteSpace(rawLevel))
            return Medium;

        return rawLevel.Trim().ToLowerInvariant() switch
        {
            "informational" or "info" => Informational,
            "low" => Low,
            "medium" or "moderate" => Medium,
            "high" => High,
            "critical" => Critical,
            _ => Medium
        };
    }

    /// <summary>Score SENTINEL associe au niveau Sigma : informational=15, low=35, medium=60, high=80, critical=95.</summary>
    public static int ToScore(string? level) => Normalize(level) switch
    {
        Informational => 15,
        Low => 35,
        Medium => 60,
        High => 80,
        Critical => 95,
        _ => 60
    };

    /// <summary>Confiance de base associee au niveau Sigma.</summary>
    public static double ToConfidence(string? level) => Normalize(level) switch
    {
        Informational => 0.50,
        Low => 0.65,
        Medium => 0.78,
        High => 0.88,
        Critical => 0.95,
        _ => 0.75
    };

    /// <summary>Deduit un <see cref="ThreatType"/> SENTINEL a partir des tactiques/techniques MITRE et du niveau Sigma.</summary>
    public static ThreatType InferThreatType(
        IReadOnlyList<string> mitreTechniques,
        IReadOnlyList<string> mitreTactics,
        string level)
    {
        foreach (var tech in mitreTechniques)
        {
            if (tech.StartsWith("T1486", StringComparison.OrdinalIgnoreCase) ||
                tech.StartsWith("T1490", StringComparison.OrdinalIgnoreCase))
                return ThreatType.Ransomware;

            if (tech.StartsWith("T1562", StringComparison.OrdinalIgnoreCase))
                return ThreatType.Tampering;

            if (tech.StartsWith("T1003", StringComparison.OrdinalIgnoreCase) ||
                tech.StartsWith("T1110", StringComparison.OrdinalIgnoreCase))
                return ThreatType.Intrusion;

            if (tech.StartsWith("T1547", StringComparison.OrdinalIgnoreCase) ||
                tech.StartsWith("T1053", StringComparison.OrdinalIgnoreCase))
                return ThreatType.Persistence;

            if (tech.StartsWith("T1041", StringComparison.OrdinalIgnoreCase) ||
                tech.StartsWith("T1052", StringComparison.OrdinalIgnoreCase))
                return ThreatType.Exfiltration;

            if (tech.StartsWith("T1566", StringComparison.OrdinalIgnoreCase))
                return ThreatType.Phishing;
        }

        foreach (var tactic in mitreTactics)
        {
            switch (tactic.ToLowerInvariant())
            {
                case "impact": return ThreatType.Ransomware;
                case "persistence": return ThreatType.Persistence;
                case "credential_access" or "credential-access" or "lateral_movement" or "lateral-movement":
                    return ThreatType.Intrusion;
                case "exfiltration": return ThreatType.Exfiltration;
                case "initial_access" or "initial-access": return ThreatType.Phishing;
            }
        }

        return Normalize(level) is Informational or Low ? ThreatType.Anomaly : ThreatType.Malware;
    }
}

/// <summary>
/// Representation compilee d'une regle Sigma prete pour une evaluation haute performance.
/// </summary>
public sealed class SigmaRule
{
    private static readonly Regex MitreTechniqueTagRegex = new(
        @"^attack\.(t\d{4}(?:\.\d{3})?)$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase,
        TimeSpan.FromMilliseconds(100));

    private static readonly HashSet<string> KnownMitreTactics = new(StringComparer.OrdinalIgnoreCase)
    {
        "reconnaissance", "resource_development", "initial_access", "execution",
        "persistence", "privilege_escalation", "defense_evasion", "credential_access",
        "discovery", "lateral_movement", "collection", "command_and_control",
        "exfiltration", "impact",
        "resource-development", "initial-access", "privilege-escalation",
        "defense-evasion", "credential-access", "lateral-movement", "command-and-control"
    };

    private volatile bool _enabled = true;

    public required string Id { get; init; }
    public required string Title { get; init; }
    public string Status { get; init; } = "experimental";
    public string Description { get; init; } = string.Empty;
    public string Author { get; init; } = string.Empty;
    public string License { get; init; } = string.Empty;
    public string Level { get; init; } = SigmaLevels.Medium;
    public required SigmaLogSource LogSource { get; init; }
    public IReadOnlyList<string> Tags { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> MitreTechniques { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> MitreTactics { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> References { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> FalsePositives { get; init; } = Array.Empty<string>();
    public required IReadOnlyDictionary<string, SigmaSelection> Selections { get; init; }
    public required string Condition { get; init; }
    public required SigmaConditionNode ConditionAst { get; init; }
    public string SourceFile { get; init; } = string.Empty;

    /// <summary>Indique si la regle est active lors de l'evaluation.</summary>
    public bool Enabled
    {
        get => _enabled;
        set => _enabled = value;
    }

    /// <summary>Tableau interne des selections indexees pour evaluation sans lookup dictionnaire.</summary>
    internal SigmaSelection[] IndexedSelections { get; init; } = Array.Empty<SigmaSelection>();

    /// <summary>Score SENTINEL derive du niveau Sigma.</summary>
    public int Score => SigmaLevels.ToScore(Level);

    /// <summary>Extrait et normalise les techniques (<c>T1059.001</c>) et tactiques MITRE ATT&amp;CK depuis les tags Sigma.</summary>
    public static (IReadOnlyList<string> Techniques, IReadOnlyList<string> Tactics) ExtractMitreFromTags(
        IEnumerable<string>? tags)
    {
        if (tags is null)
            return (Array.Empty<string>(), Array.Empty<string>());

        var techniques = new List<string>();
        var tactics = new List<string>();
        var seenTech = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var seenTactic = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var rawTag in tags)
        {
            if (string.IsNullOrWhiteSpace(rawTag))
                continue;

            var tag = rawTag.Trim();
            var match = MitreTechniqueTagRegex.Match(tag);
            if (match.Success)
            {
                var normalized = match.Groups[1].Value.ToUpperInvariant();
                if (seenTech.Add(normalized))
                    techniques.Add(normalized);
                continue;
            }

            if (tag.StartsWith("attack.", StringComparison.OrdinalIgnoreCase))
            {
                var rest = tag["attack.".Length..].Trim().ToLowerInvariant();
                if (rest.Length > 0 && KnownMitreTactics.Contains(rest))
                {
                    var canonical = rest.Replace('-', '_');
                    if (seenTactic.Add(canonical))
                        tactics.Add(canonical);
                }
            }
        }

        return (
            techniques.Count == 0 ? Array.Empty<string>() : techniques.ToArray(),
            tactics.Count == 0 ? Array.Empty<string>() : tactics.ToArray());
    }
}
