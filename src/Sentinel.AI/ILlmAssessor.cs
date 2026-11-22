using Sentinel.Shared.Models;

namespace Sentinel.AI;

/// <summary>
/// Contrat d'évaluation contextuelle par IA locale (Ollama, doc §7).
/// Ne déclenche jamais d'action ; retourne <c>null</c> si indisponible ou sortie invalide (repli règles).
/// </summary>
public interface ILlmAssessor
{
    /// <summary>Évalue un événement ambigu dans son contexte récent et sa baseline.</summary>
    Task<LlmAssessmentResult?> AssessAsync(LlmScoringContext context, CancellationToken ct = default);

    /// <summary>Vérifie la disponibilité d'Ollama et la présence du modèle configuré.</summary>
    Task<bool> CheckHealthAsync(CancellationToken ct = default);

    /// <summary>Calcule un vecteur d'embedding local via <c>/api/embeddings</c> (<c>null</c> si indisponible).</summary>
    Task<float[]?> GetEmbeddingAsync(string text, CancellationToken ct = default);

    /// <summary>Disponibilité mise en cache du service LLM.</summary>
    bool IsAvailable { get; }

    /// <summary>Statistiques d'appels, d'échecs et de latence moyenne.</summary>
    LlmMetrics Metrics { get; }

    /// <summary>Met à jour à chaud les paramètres LLM (modèle, endpoint, timeout, concurrence).</summary>
    void UpdateSettings(LlmSettings settings) { }
}
