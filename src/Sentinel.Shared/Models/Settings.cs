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
    public bool EnableDefenderCollector { get; set; } = true;
    public bool EnableSysmonCollector { get; set; } = true;

    public CanarySettings Canaries { get; set; } = new();
    public ScriptVisibilitySettings ScriptVisibility { get; set; } = new();
    public ThreatIntelSettings ThreatIntel { get; set; } = new();
    public StaticScanSettings StaticScan { get; set; } = new();
    public RulesSettings Rules { get; set; } = new();
    public MlSettings MachineLearning { get; set; } = new();
    public NotificationSettings Notifications { get; set; } = new();
    /// <summary>Langue préférée de la console ("fr" ou "en").</summary>
    public string Language { get; set; } = "fr";
}

public sealed class LlmSettings
{
    public bool Enabled { get; set; } = true;
    public string Endpoint { get; set; } = "http://localhost:11434";
    public string Model { get; set; } = "qwen2.5-coder:3b";
    /// <summary>Sélectionne automatiquement le meilleur modèle Qwen déjà installé localement dans Ollama selon la RAM du poste.</summary>
    public bool AutoSelectBestQwen { get; set; } = true;
    public string EmbeddingModel { get; set; } = "nomic-embed-text";
    public int TimeoutSeconds { get; set; } = 45;
    /// <summary>Le LLM n'est appelé que si le score des règles est dans cette bande « ambiguë » (doc §7.1).</summary>
    public int AmbiguityLow { get; set; } = 25;
    public int AmbiguityHigh { get; set; } = 80;
    /// <summary>Confiance minimale pour retenir l'avis du LLM.</summary>
    public double MinConfidence { get; set; } = 0.5;
    /// <summary>Nombre max d'appels LLM simultanés.</summary>
    public int MaxConcurrency { get; set; } = 1;
    /// <summary>Durée de maintien du modèle en RAM/VRAM par Ollama (ex. "10m", "30m").</summary>
    public string KeepAlive { get; set; } = "10m";
    /// <summary>Taille de fenêtre de contexte Ollama (num_ctx) optimisée pour faible latence locale.</summary>
    public int ContextWindow { get; set; } = 2048;
    /// <summary>Nombre maximal de tokens générés (num_predict) pour une sortie JSON concise et rapide.</summary>
    public int MaxOutputTokens { get; set; } = 160;
    /// <summary>Active le cache sémantique TTL en mémoire pour éviter les appels redondants sur rafales similaires.</summary>
    public bool EnableResponseCache { get; set; } = true;
    /// <summary>Durée de vie du cache sémantique LLM en minutes.</summary>
    public int CacheTtlMinutes { get; set; } = 5;
    /// <summary>Précharge le modèle sélectionné au démarrage du serveur pour éliminer la latence à froid.</summary>
    public bool WarmUpOnStartup { get; set; } = true;
}

/// <summary>
/// Paramètres de notifications externes administrateur par niveau de criticité (opt-in strict, métadonnées uniquement).
/// Les secrets (mot de passe SMTP, jetons WhatsApp/Telegram, clé HMAC) ne sont JAMAIS stockés ici :
/// ils sont chiffrés au repos via DPAPI dans <c>SentinelPaths.NotificationSecretsFile</c>.
/// </summary>
public sealed class NotificationSettings
{
    public bool Enabled { get; set; } = false;
    /// <summary>Délai anti-spam (minutes) entre deux notifications identiques sur un même canal ; contourné immédiatement en cas d'escalade de criticité.</summary>
    public int CooldownMinutes { get; set; } = 5;
    /// <summary>Envoie également une notification lorsqu'un cluster corrélé atteint ou dépasse le niveau minimal configuré.</summary>
    public bool NotifyOnCorrelatedCluster { get; set; } = true;
    public bool IncludeDashboardUrl { get; set; } = true;
    public string DashboardBaseUrl { get; set; } = "http://127.0.0.1:5200";

    public EmailNotificationSettings Email { get; set; } = new();
    public WhatsAppNotificationSettings WhatsApp { get; set; } = new();
    public WebhookNotificationSettings Webhook { get; set; } = new();
}

public sealed class EmailNotificationSettings
{
    public bool Enabled { get; set; } = false;
    public ThreatLevel MinLevel { get; set; } = ThreatLevel.High;
    public string SmtpHost { get; set; } = string.Empty;
    public int SmtpPort { get; set; } = 587;
    public bool UseStartTls { get; set; } = true;
    public string Username { get; set; } = string.Empty;
    public string FromAddress { get; set; } = string.Empty;
    public string FromName { get; set; } = "SENTINEL SOC";
    public List<string> Recipients { get; set; } = new();
}

public sealed class WhatsAppNotificationSettings
{
    public bool Enabled { get; set; } = false;
    public ThreatLevel MinLevel { get; set; } = ThreatLevel.Critical;
    /// <summary>Fournisseur API officiel : "MetaCloud" (Graph API) ou "Twilio".</summary>
    public string Provider { get; set; } = "MetaCloud";
    /// <summary>Identifiant du numéro expéditeur Meta WhatsApp Business Cloud API.</summary>
    public string PhoneNumberId { get; set; } = string.Empty;
    /// <summary>Account SID Twilio (utilisé si Provider = "Twilio").</summary>
    public string AccountSid { get; set; } = string.Empty;
    /// <summary>Numéro expéditeur Twilio au format whatsapp:+14155238886.</summary>
    public string FromNumber { get; set; } = string.Empty;
    public string ApiVersion { get; set; } = "v21.0";
    /// <summary>Numéros destinataires administrateurs au format international E.164 (ex. +2376XXXXXXXX).</summary>
    public List<string> Recipients { get; set; } = new();
}

public sealed class WebhookNotificationSettings
{
    public bool Enabled { get; set; } = false;
    public ThreatLevel MinLevel { get; set; } = ThreatLevel.High;
    /// <summary>Format de charge utile : "GenericJson", "Slack", "Teams", "Discord" ou "Telegram".</summary>
    public string Format { get; set; } = "GenericJson";
    /// <summary>URL HTTPS cible (inutile pour Telegram si le jeton bot est renseigné dans les secrets).</summary>
    public string Url { get; set; } = string.Empty;
    /// <summary>Identifiant de chat/groupe Telegram (utilisé lorsque Format = "Telegram").</summary>
    public string TelegramChatId { get; set; } = string.Empty;
}

public sealed class CanarySettings
{
    public bool Enabled { get; set; } = true;
    public int FilesPerFolder { get; set; } = 2;
    public List<string> Folders { get; set; } = new() { "%USERPROFILE%\\Documents", "%USERPROFILE%\\Desktop", "%USERPROFILE%\\Downloads" };
    public bool AutoIsolateOnTrigger { get; set; } = true;
}

public sealed class ScriptVisibilitySettings
{
    public bool Enabled { get; set; } = true;
    public bool EnablePowerShell4104 { get; set; } = true;
    public bool EnableEtwAmsi { get; set; } = true;
    /// <summary>Stocke un extrait nettoyé et tronqué (max 300 car.) uniquement si explicitement activé.</summary>
    public bool StoreSanitizedExcerpt { get; set; } = false;
    public int MaxExcerptLength { get; set; } = 300;
}

public sealed class ThreatIntelSettings
{
    public bool Enabled { get; set; } = true;
    public bool EnableAbuseChFeeds { get; set; } = true;
    /// <summary>Flux communautaires optionnels (désactivés par défaut pour respect strict des licences).</summary>
    public bool EnableOpenPhishCommunity { get; set; } = false;
    public bool EnablePhishTank { get; set; } = false;
    /// <summary>Interrogation VirusTotal uniquement à la demande avec clé fournie par l'utilisateur.</summary>
    public bool EnableVirusTotalOnDemand { get; set; } = false;
    public int RefreshIntervalHours { get; set; } = 6;
    public int IndicatorTtlDays { get; set; } = 30;
}

public sealed class StaticScanSettings
{
    public bool Enabled { get; set; } = true;
    public bool ScanOnFileEvent { get; set; } = true;
    public bool ScanOnProcessStart { get; set; } = true;
    public long MaxFileSizeBytes { get; set; } = 25 * 1024 * 1024;
    public int TimeoutMs { get; set; } = 4000;
    public int MaxConcurrency { get; set; } = 2;
    public int ScheduledScanIntervalHours { get; set; } = 24;
}

public sealed class RulesSettings
{
    public bool EnableSigma { get; set; } = true;
    public bool EnableYara { get; set; } = true;
    public bool HotReload { get; set; } = true;
    public List<string> DisabledRuleIds { get; set; } = new();
    public List<string> ExcludedRuleTargets { get; set; } = new();
}

public sealed class MlSettings
{
    public bool Enabled { get; set; } = true;
    /// <summary>Contribution maximale du classifieur ML au score (jamais seul décisif).</summary>
    public int MaxScoreContribution { get; set; } = 35;
    public double SuspiciousProbabilityThreshold { get; set; } = 0.65;
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
