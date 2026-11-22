using Sentinel.Shared.Api;
using Sentinel.Shared.Models;

namespace Sentinel.Detection.Static;

/// <summary>Noms explicites des moteurs YARA signales dans les resultats et les journaux.</summary>
public static class YaraEngineNames
{
    public const string Native = "dnYara (libyara)";
    public const string ManagedFallback = "ManagedFallback (libyara indisponible)";
}

/// <summary>Normalisation des niveaux de severite YARA et correspondance vers les scores SENTINEL.</summary>
public static class YaraSeverityLevels
{
    public const string Informational = "informational";
    public const string Low = "low";
    public const string Medium = "medium";
    public const string High = "high";
    public const string Critical = "critical";

    public static string Normalize(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return High;

        return raw.Trim().ToLowerInvariant() switch
        {
            "info" or "informational" => Informational,
            "low" => Low,
            "medium" or "moderate" => Medium,
            "high" => High,
            "critical" or "crit" => Critical,
            _ => High
        };
    }

    public static int ToScore(string? level) => Normalize(level) switch
    {
        Informational => 20,
        Low => 40,
        Medium => 65,
        High => 85,
        Critical => 95,
        _ => 80
    };
}

/// <summary>Correspondance d'une regle YARA lors d'un scan.</summary>
public sealed record YaraMatchResult(
    string RuleId,
    string Namespace,
    string SourceFile,
    string Level,
    int Score,
    string? Description,
    IReadOnlyList<string> Tags,
    IReadOnlyList<string> MitreTechniques,
    IReadOnlyList<string> MatchedStrings,
    IReadOnlyDictionary<string, string> Metadata,
    string EngineName);

/// <summary>Rapport complet d'un scan YARA sur un fichier ou un tampon memoire.</summary>
public sealed record YaraScanReport(
    IReadOnlyList<YaraMatchResult> Matches,
    string EngineName,
    bool UsedFallback,
    double ElapsedMs,
    string? Error = null);

/// <summary>Erreur non fatale rencontree lors du chargement ou de la compilation d'une regle YARA.</summary>
public sealed record YaraLoadError(
    string FilePath,
    string Message,
    Exception? Exception = null);

/// <summary>Bilan d'un chargement ou rechargement de regles YARA.</summary>
public sealed record YaraRuleLoadResult(
    int LoadedCount,
    string EngineName,
    bool UsedFallback,
    IReadOnlyList<YaraLoadError> Errors);

/// <summary>Metadonnees d'une section PE extraites par <see cref="PeStaticAnalyzer"/>.</summary>
public sealed record PeSectionInfo(
    string Name,
    uint VirtualSize,
    uint RawSize,
    uint RawOffset,
    double Entropy,
    bool IsExecutable,
    bool IsWritable);

/// <summary>Resultat detaille de l'analyse statique PE d'un fichier.</summary>
public sealed record PeAnalysisResult(
    string FilePath,
    string Sha256,
    long SizeBytes,
    bool IsPe,
    bool Is64Bit,
    bool IsDll,
    bool IsDotNet,
    bool IsSigned,
    bool HasValidSignature,
    bool HasValidCertChain,
    string? Publisher,
    DateTimeOffset? CompileTime,
    uint RawTimeDateStamp,
    bool TimestampAnomaly,
    string? TimestampAnomalyReason,
    IReadOnlyList<PeSectionInfo> Sections,
    double MaxEntropy,
    double FileEntropy,
    string? ProbablePacker,
    int TotalImportCount,
    IReadOnlyList<string> SuspiciousImports,
    int RiskScore,
    IReadOnlyList<string> Signals,
    IReadOnlyList<string> MitreTechniques,
    string? Error = null);

/// <summary>Resultat enrichi d'un scan statique complet (PE + YARA + contributions de score).</summary>
public sealed record StaticScanOutcome(
    StaticScanResultDto Result,
    PeAnalysisResult? PeAnalysis,
    YaraScanReport? YaraReport,
    IReadOnlyList<ScoreContribution> Contributions,
    bool Skipped = false,
    string? SkipReason = null,
    bool TimedOut = false);

/// <summary>Synthese d'un scan planifie ou a la demande sur les dossiers surveilles.</summary>
public sealed record ScheduledScanSummary(
    int FoldersRequested,
    int FoldersScanned,
    IReadOnlyList<string> RejectedFolders,
    int FilesEvaluated,
    int FilesScanned,
    int FilesSkipped,
    int FindingsCount,
    IReadOnlyList<StaticScanOutcome> Findings,
    double ElapsedMs,
    DateTimeOffset CompletedAt);
