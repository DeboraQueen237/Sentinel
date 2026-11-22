using Sentinel.Shared.Api;
using Sentinel.Shared.Models;

namespace Sentinel.Simulation.Benchmark;

/// <summary>
/// Configuration expérimentale du protocole §14.3 (A : règles seules, B : règles + IA, C : règles + IA + corrélation).
/// </summary>
public sealed record EvaluationConfigSpec(
    string Key,
    string DisplayName,
    bool EnableLlm,
    bool EnableCorrelation,
    bool EarlyEscalation);

/// <summary>
/// Résultat détaillé d'un scénario d'attaque pour une configuration donnée.
/// </summary>
public sealed record ScenarioRunDetail(
    string ScenarioId,
    string ScenarioName,
    IReadOnlyList<string> MitreTechniques,
    string ConfigKey,
    string ConfigurationName,
    int TotalAttackEvents,
    bool IsMultiStageChain,
    bool Detected,
    int EventsBeforeAlert,
    double SecondsToDetect,
    int PeakScore,
    int FirstAlertScore,
    ThreatLevel FirstAlertLevel,
    ThreatType FirstAlertType,
    string? FirstAlertTriggerEvent,
    string? DetectedChainName,
    bool EarlyEscalated,
    int FalsePositives,
    long LlmCalls,
    double AvgLatencyMs);

/// <summary>
/// Synthèse agrégée des métriques scientifiques pour une configuration (A, B ou C).
/// </summary>
public sealed record ConfigurationSummary(
    string ConfigKey,
    string ConfigurationName,
    int DetectedCount,
    int TotalScenarios,
    double Recall,
    double Precision,
    int BenignEventsCount,
    int FalsePositives,
    double FalsePositiveRate,
    double AvgEventsBeforeAlertAllDetected,
    double AvgEventsBeforeAlertMultiStage,
    double AvgSecondsToDetectAllDetected,
    double AvgLatencyMs,
    double WorkingSetMb,
    long TotalLlmCalls,
    double LlmUsageRatio);

/// <summary>
/// Rapport scientifique complet de l'évaluation A vs B vs C (doc §1.2, §8.4, §14).
/// </summary>
public sealed record EvaluationReport(
    DateTimeOffset GeneratedAt,
    string HostId,
    string LlmModeLabel,
    bool UsingRealOllama,
    int BenignEventCount,
    IReadOnlyList<ConfigurationSummary> Summaries,
    IReadOnlyList<ScenarioRunDetail> Details,
    double PairedAvgTtdA,
    double PairedAvgTtdCvsA,
    double GainTtdCvsAPercent,
    double PairedAvgTtdB,
    double PairedAvgTtdCvsB,
    double GainTtdCvsBPercent,
    double GainEventsCvsA,
    double GainEventsCvsB,
    bool SecondEventHypothesisVerified)
{
    /// <summary>Convertit les résultats au format DTO attendu par <c>Sentinel.Server</c> et <c>Sentinel.Admin</c>.</summary>
    public IReadOnlyList<ScenarioMetricDto> ToScenarioMetricDtos() =>
        Details.Select(d => new ScenarioMetricDto(
            d.ScenarioName,
            d.ConfigurationName,
            d.Detected,
            d.Detected ? d.EventsBeforeAlert : 0,
            d.Detected ? Math.Round(d.SecondsToDetect, 2) : 0.0,
            d.PeakScore,
            d.FalsePositives)).ToArray();
}
