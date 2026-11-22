namespace Sentinel.Shared.Models;

/// <summary>
/// Paramètres globaux de SENTINEL, modifiables depuis l'écran « Paramètres » (doc §10.1-7).
/// Stockés par le serveur, appliqués au moteur et diffusés aux agents.
/// </summary>
public sealed class SentinelSettings
{
    public ThreatThresholds Thresholds { get; set; } = new();
    public OperatingMode Mode { get; set; } = OperatingMode.Learning;
    /// <summary>Début de la période d'apprentissage ; passage automatique en mode Active après <see cref="LearningPeriodDays"/>.</summary>
    public DateTimeOffset LearningStartedAt { get; set; } = DateTimeOffset.UtcNow;
    public int LearningPeriodDays { get; set; } = 7;
    public bool AutoLeaveLearning { get; set; } = true;

    public List<string> WatchedFolders { get; set; } = new() { "%USERPROFILE%\\Downloads", "%USERPROFILE%\\Desktop", "%USERPROFILE%\\Documents", "%TEMP%" };
    public List<string> ExcludedProcesses { get; set; } = new() { "MsMpEng.exe", "svchost.exe", "SearchIndexer.exe", "Sentinel.Agent.exe", "Sentinel.Server.exe" };
    public List<string> ExcludedDomains { get; set; } = new() { "microsoft.com", "windowsupdate.com", "office.com", "github.com" };
    public List<string> ExcludedHashes { get; set; } = new();
    public List<string> ExcludedPaths { get; set; } = new();

    public int EventRetentionDays { get; set; } = 90;
    public int AlertRetentionDays { get; set; } = 365;

    public LlmSettings Llm { get; set; } = new();
    public CorrelationSettings Correlation { get; set; } = new();

    public bool EnableClipboardMonitoring { get; set; } = true;
    public bool EnableTypingRhythm { get; set; } = true;
    public bool EnableBrowserMonitoring { get; set; } = true;
    public bool EnableNetworkMonitoring { get; set; } = true;
}

public sealed class LlmSettings
{
    public bool Enabled { get; set; } = true;
    public string Endpoint { get; set; } = "http://localhost:11434";
    public string Model { get; set; } = "qwen2.5:7b";
    public string EmbeddingModel { get; set; } = "nomic-embed-text";
    public int TimeoutSeconds { get; set; } = 10;
    /// <summary>Le LLM n'est appelé que si le score des règles est dans cette bande « ambiguë » (doc §7.1).</summary>
    public int AmbiguityLow { get; set; } = 25;
    public int AmbiguityHigh { get; set; } = 80;
    /// <summary>Confiance minimale pour retenir l'avis du LLM.</summary>
    public double MinConfidence { get; set; } = 0.5;
    /// <summary>Nombre max d'appels LLM simultanés.</summary>
    public int MaxConcurrency { get; set; } = 1;
}

public sealed class CorrelationSettings
{
    public int ShortWindowMinutes { get; set; } = 5;
    public int MediumWindowMinutes { get; set; } = 30;
    public int LongWindowHours { get; set; } = 24;
    /// <summary>Score individuel minimal pour qu'un événement participe à la corrélation (niveau 1 = marquage).</summary>
    public int MinEventScore { get; set; } = 30;
    /// <summary>Demi-vie de la décroissance temporelle (facteur_temps), en minutes.</summary>
    public double DecayHalfLifeMinutes { get; set; } = 15;
    public double SameEntityWeight { get; set; } = 0.8;
    public double SameTypeWeight { get; set; } = 0.3;
    public bool EarlyEscalation { get; set; } = true;
    /// <summary>Permet de désactiver la corrélation (configuration B de l'évaluation §14.3).</summary>
    public bool Enabled { get; set; } = true;
}
