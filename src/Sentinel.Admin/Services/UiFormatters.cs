using System.Globalization;
using Sentinel.Shared.Api;
using Sentinel.Shared.Models;

namespace Sentinel.Admin.Services;

/// <summary>Libellés français, palettes sémantiques et formatage cohérent pour toute la console SOC.</summary>
public static class UiFormatters
{
    private static readonly CultureInfo FrCulture = CultureInfo.GetCultureInfo("fr-FR");

    public static string ThreatLevelLabel(ThreatLevel level) => level switch
    {
        ThreatLevel.Info => "Info",
        ThreatLevel.Low => "Faible",
        ThreatLevel.Moderate => "Modéré",
        ThreatLevel.High => "Élevé",
        ThreatLevel.Critical => "Critique",
        _ => level.ToString()
    };

    public static string ThreatLevelCss(ThreatLevel level) => level switch
    {
        ThreatLevel.Info => "sev-info",
        ThreatLevel.Low => "sev-low",
        ThreatLevel.Moderate => "sev-moderate",
        ThreatLevel.High => "sev-high",
        ThreatLevel.Critical => "sev-critical",
        _ => "sev-info"
    };

    public static string ThreatLevelHex(ThreatLevel level) => level switch
    {
        ThreatLevel.Info => "#38bdf8",
        ThreatLevel.Low => "#06b6d4",
        ThreatLevel.Moderate => "#f59e0b",
        ThreatLevel.High => "#f97316",
        ThreatLevel.Critical => "#ef4444",
        _ => "#64748b"
    };

    public static string ThreatTypeLabel(ThreatType type) => type switch
    {
        ThreatType.None => "Aucune menace",
        ThreatType.Phishing => "Phishing",
        ThreatType.Malware => "Malware",
        ThreatType.Ransomware => "Ransomware",
        ThreatType.BadUsb => "BadUSB",
        ThreatType.Exfiltration => "Exfiltration",
        ThreatType.Intrusion => "Intrusion",
        ThreatType.SocialEngineering => "Ingénierie sociale",
        ThreatType.Persistence => "Persistance",
        ThreatType.Anomaly => "Anomalie",
        ThreatType.Tampering => "Auto-protection",
        _ => type.ToString()
    };

    public static string ThreatTypeHex(ThreatType type) => type switch
    {
        ThreatType.Phishing => "#06b6d4",
        ThreatType.Malware => "#ef4444",
        ThreatType.Ransomware => "#dc2626",
        ThreatType.BadUsb => "#f97316",
        ThreatType.Exfiltration => "#8b5cf6",
        ThreatType.Intrusion => "#ec4899",
        ThreatType.SocialEngineering => "#f59e0b",
        ThreatType.Persistence => "#6366f1",
        ThreatType.Anomaly => "#14b8a6",
        ThreatType.Tampering => "#e11d48",
        _ => "#64748b"
    };

    public static string EventCategoryLabel(EventCategory category) => category switch
    {
        EventCategory.Process => "Processus",
        EventCategory.Network => "Réseau",
        EventCategory.Clipboard => "Presse-papiers",
        EventCategory.File => "Fichiers",
        EventCategory.Session => "Sessions",
        EventCategory.Device => "Périphériques",
        EventCategory.Browser => "Navigation",
        EventCategory.Typing => "Rythme de saisie",
        EventCategory.Installation => "Installations",
        EventCategory.System => "Système",
        _ => category.ToString()
    };

    public static string OperatingModeLabel(OperatingMode mode) => mode switch
    {
        OperatingMode.Learning => "Apprentissage",
        OperatingMode.Simulation => "Simulation",
        OperatingMode.Active => "Actif",
        _ => mode.ToString()
    };

    public static string OperatingModeCss(OperatingMode mode) => mode switch
    {
        OperatingMode.Learning => "mode-learning",
        OperatingMode.Simulation => "mode-simulation",
        OperatingMode.Active => "mode-active",
        _ => "mode-learning"
    };

    public static string OperatingModeDescription(OperatingMode mode) => mode switch
    {
        OperatingMode.Learning => "Construction de la baseline comportementale sans blocage automatique.",
        OperatingMode.Simulation => "Les actions sont évaluées et journalisées mais non exécutées sur les postes.",
        OperatingMode.Active => "Protection active : les blocages critiques réversibles sont exécutés selon la matrice.",
        _ => string.Empty
    };

    public static string AlertStatusLabel(AlertStatus status) => status switch
    {
        AlertStatus.Open => "Ouverte",
        AlertStatus.Acknowledged => "Acquittée",
        AlertStatus.Approved => "Approuvée",
        AlertStatus.FalsePositive => "Faux positif",
        AlertStatus.Resolved => "Résolue",
        _ => status.ToString()
    };

    public static string AlertStatusCss(AlertStatus status) => status switch
    {
        AlertStatus.Open => "status-open",
        AlertStatus.Acknowledged => "status-ack",
        AlertStatus.Approved => "status-approved",
        AlertStatus.FalsePositive => "status-fp",
        AlertStatus.Resolved => "status-resolved",
        _ => "status-open"
    };

    public static string ActionStatusLabel(ActionStatus status) => status switch
    {
        ActionStatus.Proposed => "Proposition (Niv. 3)",
        ActionStatus.Pending => "En attente agent",
        ActionStatus.Executed => "Exécutée",
        ActionStatus.Simulated => "Simulée",
        ActionStatus.Failed => "Échec",
        ActionStatus.Reverted => "Annulée",
        ActionStatus.Rejected => "Rejetée",
        ActionStatus.RevertPending => "Annulation en cours",
        _ => status.ToString()
    };

    public static string ActionStatusCss(ActionStatus status) => status switch
    {
        ActionStatus.Proposed => "act-proposed",
        ActionStatus.Pending => "act-pending",
        ActionStatus.Executed => "act-executed",
        ActionStatus.Simulated => "act-simulated",
        ActionStatus.Failed => "act-failed",
        ActionStatus.Reverted => "act-reverted",
        ActionStatus.Rejected => "act-rejected",
        ActionStatus.RevertPending => "act-pending",
        _ => "act-pending"
    };

    public static string ResponseActionLabel(ResponseActionType action) => action switch
    {
        ResponseActionType.LogOnly => "Journalisation seule",
        ResponseActionType.MarkForCorrelation => "Marquage corrélation",
        ResponseActionType.NotifyUser => "Notification utilisateur",
        ResponseActionType.EnhancedMonitoring => "Surveillance renforcée",
        ResponseActionType.AlertAdmin => "Alerte administrateur",
        ResponseActionType.UserAwareness => "Sensibilisation utilisateur",
        ResponseActionType.WatchHash => "Mise sous surveillance hash",
        ResponseActionType.BlockDomain => "Blocage de domaine",
        ResponseActionType.CloseBrowserTab => "Fermeture onglet navigateur",
        ResponseActionType.SuspendProcess => "Suspension de processus",
        ResponseActionType.KillProcess => "Arrêt de processus",
        ResponseActionType.QuarantineFile => "Quarantaine de fichier",
        ResponseActionType.IsolateNetwork => "Isolement réseau",
        ResponseActionType.ProtectFolders => "Protection des dossiers",
        ResponseActionType.DisableDevice => "Désactivation périphérique",
        ResponseActionType.BlockProcessConnections => "Coupure réseau du processus",
        ResponseActionType.ThrottleTraffic => "Limitation de trafic",
        ResponseActionType.BlockIp => "Blocage d'adresse IP",
        ResponseActionType.LockSession => "Verrouillage de session",
        ResponseActionType.LockAccount => "Verrouillage de compte",
        _ => action.ToString()
    };

    public static string AssessmentSourceLabel(AssessmentSource source) => source switch
    {
        AssessmentSource.Rules => "Règles déterministes",
        AssessmentSource.Llm => "IA locale (Ollama)",
        AssessmentSource.Hybrid => "Hybride (Règles + IA)",
        _ => source.ToString()
    };

    public static string EntityKindLabel(EntityKind kind) => kind switch
    {
        EntityKind.Host => "Poste",
        EntityKind.User => "Utilisateur",
        EntityKind.Domain => "Domaine",
        EntityKind.Process => "Processus",
        EntityKind.File => "Fichier",
        EntityKind.Device => "Périphérique",
        EntityKind.Ip => "Adresse IP",
        _ => kind.ToString()
    };

    public static string GraphNodeTypeLabel(GraphNodeType type) => type switch
    {
        GraphNodeType.Event => "Événement",
        GraphNodeType.Process => "Processus",
        GraphNodeType.File => "Fichier",
        GraphNodeType.Domain => "Domaine",
        GraphNodeType.Ip => "Adresse IP",
        GraphNodeType.User => "Utilisateur",
        GraphNodeType.Device => "Périphérique",
        GraphNodeType.Threat => "Menace",
        GraphNodeType.Host => "Poste",
        _ => type.ToString()
    };

    public static string GraphEdgeTypeLabel(GraphEdgeType type) => type switch
    {
        GraphEdgeType.Spawned => "SPAWNED",
        GraphEdgeType.ConnectedTo => "CONNECTED_TO",
        GraphEdgeType.Wrote => "WROTE",
        GraphEdgeType.CopiedFromClipboard => "COPIED_CLIPBOARD",
        GraphEdgeType.OpenedUrl => "OPENED_URL",
        GraphEdgeType.SameDomain => "SAME_DOMAIN",
        GraphEdgeType.SameWindow => "SAME_WINDOW",
        GraphEdgeType.SameAnomalyType => "SAME_ANOMALY",
        GraphEdgeType.SameHash => "SAME_HASH",
        GraphEdgeType.SameEntity => "SAME_ENTITY",
        GraphEdgeType.InvolvedIn => "INVOLVED_IN",
        GraphEdgeType.Sequence => "SEQUENCE",
        _ => type.ToString()
    };

    public static (string Label, string CssClass, string ColorHex) GlobalSecurityStatus(int score) => score switch
    {
        >= 85 => ("Poste sécurisé", "health-safe", "#10b981"),
        >= 65 => ("Vigilance", "health-watch", "#06b6d4"),
        >= 40 => ("Risque élevé", "health-elevated", "#f59e0b"),
        _ => ("Alerte critique", "health-critical", "#ef4444")
    };

    public static string ScoreColorHex(int score) => score switch
    {
        >= 90 => "#ef4444",
        >= 75 => "#f97316",
        >= 55 => "#f59e0b",
        >= 30 => "#06b6d4",
        _ => "#10b981"
    };

    public static string FormatDateTime(DateTimeOffset dt) =>
        dt.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss", FrCulture);

    public static string FormatShortDateTime(DateTimeOffset dt) =>
        dt.ToLocalTime().ToString("dd/MM HH:mm", FrCulture);

    public static string RelativeTime(DateTimeOffset dt)
    {
        var diff = DateTimeOffset.UtcNow - dt;
        if (diff.TotalSeconds < 45) return "à l'instant";
        if (diff.TotalMinutes < 60) return $"il y a {(int)diff.TotalMinutes} min";
        if (diff.TotalHours < 24) return $"il y a {(int)diff.TotalHours} h";
        if (diff.TotalDays < 30) return $"il y a {(int)diff.TotalDays} j";
        return dt.ToLocalTime().ToString("dd/MM/yyyy", FrCulture);
    }

    public static string TruncateHash(string? hash, int keep = 14)
    {
        if (string.IsNullOrWhiteSpace(hash)) return "—";
        return hash.Length <= keep ? hash : $"{hash[..keep]}…";
    }

    public static string EntityDetailHref(EntityKind kind, string key) =>
        $"/entities/{kind}/{Uri.EscapeDataString(key)}";
}
