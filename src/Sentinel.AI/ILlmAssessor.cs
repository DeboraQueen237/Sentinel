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

    /// <summary>Liste les modèles actuellement installés dans Ollama local (<c>/api/tags</c>).</summary>
    Task<IReadOnlyList<string>> ListInstalledModelsAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<string>>(Array.Empty<string>());

    /// <summary>Modèle effectivement actif (auto-sélectionné parmi les Qwen locaux ou configuré).</summary>
    string ActiveModel => string.Empty;

    /// <summary>Dernière décision de sélection automatique du modèle Ollama local.</summary>
    OllamaModelSelection? LastSelection => null;

    /// <summary>Force une ré-inspection immédiate de <c>/api/tags</c> et ré-sélectionne le meilleur modèle Qwen local.</summary>
    Task<OllamaModelSelection> RefreshModelSelectionAsync(CancellationToken ct = default) =>
        Task.FromResult(new OllamaModelSelection(
            ActiveModel,
            AutoSelected: false,
            IsQwen: false,
            HostRamGb: OllamaModelSelector.GetHostRamGb(),
            Reason: "Non pris en charge par cet évaluateur.",
            Candidates: Array.Empty<OllamaInstalledModel>()));

    /// <summary>Précharge le modèle actif en RAM/VRAM via Ollama (<c>keep_alive</c>) sans bloquer le pipeline.</summary>
    Task<bool> WarmUpAsync(CancellationToken ct = default) => Task.FromResult(false);
}
