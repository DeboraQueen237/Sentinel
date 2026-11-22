using Sentinel.Shared.Api;
using Sentinel.Shared.Models;

namespace Sentinel.Core.Abstractions;

/// <summary>
/// Point d'entrée du cœur d'analyse : scoring hybride (règles + baseline + LLM) → corrélation → décision.
/// Implémentation thread-safe, en mémoire ; la persistance est assurée par l'appelant (Sentinel.Server).
/// CONTRAT FIGÉ : consommé par Sentinel.Server et Sentinel.Simulation.
/// </summary>
public interface IThreatPipeline
{
    /// <summary>Traite un événement normalisé et retourne score, cluster éventuel et décision.</summary>
    ValueTask<PipelineResult> ProcessAsync(SecurityEvent evt, CancellationToken ct = default);

    /// <summary>Paramètres courants (copie).</summary>
    SentinelSettings Settings { get; }

    /// <summary>Applique de nouveaux paramètres à chaud (seuils, mode, exclusions, LLM, corrélation).</summary>
    void UpdateSettings(SentinelSettings settings);

    /// <summary>Retour analyste (faux positif ⇒ baseline + liste d'exclusion apprise, doc §9.4).</summary>
    void ApplyFeedback(AnalystFeedback feedback);

    /// <summary>Historique des retours analyste (v2 M8, réversibles).</summary>
    IReadOnlyList<FeedbackHistoryEntryDto> GetFeedbackHistory() => Array.Empty<FeedbackHistoryEntryDto>();

    /// <summary>Annule un retour analyste précédemment appliqué sur le modèle de corrélation (v2 M8).</summary>
    bool RevertFeedback(Guid feedbackId) => false;

    /// <summary>Clusters actifs (fenêtre longue) éventuellement filtrés par poste.</summary>
    IReadOnlyList<CorrelationCluster> GetActiveClusters(string? hostId = null);

    CorrelationCluster? GetCluster(Guid clusterId);

    /// <summary>Résumé de baseline d'un couple poste/utilisateur (null si inconnu).</summary>
    BaselineSummaryDto? GetBaseline(string hostId, string? userId = null);

    /// <summary>Réhydrate l'index de corrélation et la baseline au démarrage à partir d'événements récents persistés.</summary>
    Task WarmUpAsync(IEnumerable<ScoredEvent> recentEvents, CancellationToken ct = default);

    /// <summary>Instantané sérialisable (JSON) de la baseline, pour persistance périodique.</summary>
    string ExportBaseline();

    void ImportBaseline(string json);

    PipelineStats Stats { get; }
}

public sealed record PipelineStats(
    long EventsProcessed,
    long LlmCalls,
    long LlmFailures,
    double AvgPipelineLatencyMs,
    double AvgLlmLatencyMs,
    bool LlmAvailable,
    int ActiveClusters);
