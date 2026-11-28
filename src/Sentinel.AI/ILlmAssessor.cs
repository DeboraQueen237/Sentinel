using Sentinel.Shared.Api;
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

    /// <summary>
    /// Produit un diagnostic d'incident SOC complet et un plan d'action priorisé (via Qwen local si disponible,
    /// sinon playbook déterministe structuré). Purement consultatif : ne déclenche jamais d'action automatique.
    /// </summary>
    Task<AiIncidentAnalysisDto> AnalyzeIncidentAsync(
        string targetId,
        string title,
        int score,
        ThreatLevel level,
        ThreatType threatType,
        string contextSummary,
        IReadOnlyList<string> mitreTechniques,
        CancellationToken ct = default) =>
        Task.FromResult(BuildDeterministicPlaybook(targetId, title, score, level, threatType, contextSummary, mitreTechniques));

    /// <summary>Construit un plan d'action SOC déterministe de repli lorsque le LLM local n'est pas sollicité ou hors ligne.</summary>
    static AiIncidentAnalysisDto BuildDeterministicPlaybook(
        string targetId,
        string title,
        int score,
        ThreatLevel level,
        ThreatType threatType,
        string contextSummary,
        IReadOnlyList<string> mitreTechniques)
    {
        var (rootCause, immediate, hardening) = threatType switch
        {
            ThreatType.Ransomware => (
                "Activité compatible avec un chiffrement rapide ou une altération de fichier canari sur le poste.",
                new[]
                {
                    "Isoler immédiatement le poste du réseau local via le ticket d'action réversible.",
                    "Suspendre ou terminer le processus suspect identifié dans le graphe causal.",
                    "Vérifier l'intégrité des sauvegardes hors ligne avant toute restauration."
                },
                new[]
                {
                    "Maintenir les fichiers canaris actifs dans Documents, Bureau et Téléchargements.",
                    "Activer la protection des dossiers contrôlés Microsoft Defender.",
                    "Restreindre l'exécution de binaires non signés depuis %TEMP% et Téléchargements."
                }),
            ThreatType.Phishing or ThreatType.SocialEngineering => (
                "Chaîne d'hameçonnage probable : ouverture d'un lien/domaine suspect suivie d'une exécution locale.",
                new[]
                {
                    "Bloquer le domaine et l'IP distants via le pare-feu / fichier hosts SENTINEL (réversible).",
                    "Inspecter les processus enfants lancés après la visite navigateur ou copie presse-papiers.",
                    "Révoquer et renouveler les sessions actives de l'utilisateur concerné si des identifiants ont été saisis."
                },
                new[]
                {
                    "Maintenir l'extension navigateur SENTINEL et les flux URLhaus / ThreatFox actifs.",
                    "Sensibiliser l'utilisateur aux domaines récemment enregistrés et doubles extensions."
                }),
            ThreatType.BadUsb => (
                "Injection de frappes surhumaines (HID) ou périphérique USB composite inhabituel détecté.",
                new[]
                {
                    "Déconnecter physiquement le périphérique USB suspect et désactiver l'instance PnP.",
                    "Vérifier les interpréteurs (PowerShell, cmd) ou tâches planifiées créés dans les 3 minutes suivant l'insertion."
                },
                new[]
                {
                    "Restreindre l'installation de nouveaux périphériques HID non approuvés sur les postes sensibles.",
                    "Conserver l'analyse de cadence de frappe (horodatages uniquement) active."
                }),
            ThreatType.Tampering => (
                "Tentative d'arrêt de service de protection, d'ajout d'exclusion Defender ou d'altération de binaire.",
                new[]
                {
                    "Vérifier l'état des services SentinelAgent, SentinelWatchdog et WinDefend dans l'écran Santé.",
                    "Contrôler le journal d'audit chaîné SHA-256 et lancer un Audit de Sécurité Système complet.",
                    "Inspecter le compte ayant initié la modification de service ou d'exclusion."
                },
                new[]
                {
                    "Vérifier le durcissement ACL NTFS sur %ProgramData%\\Sentinel et C:\\Program Files\\Sentinel.",
                    "Activer la protection contre les falsifications (Tamper Protection) de Windows Defender."
                }),
            ThreatType.Exfiltration or ThreatType.Intrusion => (
                "Communication sortante anormale ou séquence d'authentification suspecte vers un hôte externe.",
                new[]
                {
                    "Bloquer l'adresse IP / le port distant suspect et capturer les métadonnées du processus émetteur.",
                    "Vérifier les comptes ayant ouvert une session récemment et forcer une rotation de mot de passe + 2FA."
                },
                new[]
                {
                    "Limiter les flux sortants des interpréteurs système (PowerShell, curl, bitsadmin) par pare-feu.",
                    "Auditer les clés Run et tâches planifiées via le Scan Système Général."
                }),
            _ => (
                "Comportement anormal détecté par corrélation multi-moteurs (Règles, Sigma, YARA/PE ou Baseline).",
                new[]
                {
                    "Examiner la branche causale complète dans le Graphe de corrélation (processus parent → action → cible).",
                    "Lancer un Scan Système Général pour vérifier l'absence de persistance associée.",
                    "Approuver l'action proposée ou marquer en Faux Positif si l'outil est légitime."
                },
                new[]
                {
                    "Ajouter le chemin ou hash vérifié aux exclusions uniquement s'il s'agit d'un outil métier signé.",
                    "Maintenir le mode Actif après la période d'apprentissage initiale."
                })
        };

        var mitreText = mitreTechniques.Count > 0 ? $" Techniques MITRE : {string.Join(", ", mitreTechniques)}." : string.Empty;
        var summary = $"[{level} — {score}/100] {title}.{mitreText} {PromptBuilder.SanitizeUntrusted(contextSummary, 240)}".Trim();

        return new AiIncidentAnalysisDto(
            TargetId: targetId,
            GeneratedAt: DateTimeOffset.UtcNow,
            AiUsed: false,
            ModelUsed: "Playbook SOC déterministe",
            ExecutiveSummary: summary,
            RootCauseHypothesis: rootCause,
            ImmediateActions: immediate,
            HardeningSteps: hardening,
            Confidence: 0.85,
            LatencyMs: 0.5);
    }
}
