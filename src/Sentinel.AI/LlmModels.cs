using Sentinel.Shared.Models;

namespace Sentinel.AI;

/// <summary>Résumé compact d'un événement récent passé en contexte au LLM (doc §7.3).</summary>
public sealed record RecentEventSummary(
    DateTimeOffset Timestamp,
    EventCategory Category,
    string EventType,
    string Subject,
    int Score,
    ThreatType ThreatType);

/// <summary>Contexte fourni au LLM local pour évaluer un événement ambigu.</summary>
public sealed record LlmScoringContext(
    SecurityEvent Event,
    int RuleScore,
    ThreatType RuleType,
    string RuleJustification,
    IReadOnlyList<string> MatchedRules,
    IReadOnlyList<RecentEventSummary> RecentEvents,
    string BaselineSummary);

/// <summary>Résultat validé produit par le LLM local (doc §7.3).</summary>
public sealed record LlmAssessmentResult(
    int Score,
    ThreatType Type,
    string Justification,
    double Confidence,
    double LatencyMs = 0);

/// <summary>Métriques thread-safe de l'évaluateur LLM local.</summary>
public sealed record LlmMetrics(
    long Calls,
    long Successes,
    long Failures,
    double AvgLatencyMs,
    bool IsAvailable,
    DateTimeOffset? LastCheckedAt,
    DateTimeOffset? NextRetryAt);
