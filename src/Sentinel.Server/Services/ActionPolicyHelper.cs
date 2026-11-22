using Sentinel.Shared.Models;

namespace Sentinel.Server.Services;

/// <summary>
/// Règles métier partagées pour la catégorisation des actions, leur réversibilité (doc §9.3, F7)
/// et les libellés français affichés dans les alertes et rapports.
/// </summary>
public static class ActionPolicyHelper
{
    public static bool IsSkippedFromTickets(ResponseActionType type) =>
        type is ResponseActionType.LogOnly
            or ResponseActionType.MarkForCorrelation
            or ResponseActionType.AlertAdmin;

    public static bool IsNotificationAction(ResponseActionType type) =>
        type is ResponseActionType.NotifyUser
            or ResponseActionType.UserAwareness;

    public static bool IsBlockingAction(ResponseActionType type) =>
        type is ResponseActionType.BlockDomain
            or ResponseActionType.CloseBrowserTab
            or ResponseActionType.SuspendProcess
            or ResponseActionType.KillProcess
            or ResponseActionType.QuarantineFile
            or ResponseActionType.IsolateNetwork
            or ResponseActionType.ProtectFolders
            or ResponseActionType.DisableDevice
            or ResponseActionType.BlockProcessConnections
            or ResponseActionType.ThrottleTraffic
            or ResponseActionType.BlockIp
            or ResponseActionType.LockSession
            or ResponseActionType.LockAccount;

    /// <summary>Indique si une action dispose d'un mécanisme d'annulation (exigence F7).</summary>
    public static bool IsReversible(ResponseActionType type) =>
        type is ResponseActionType.BlockDomain
            or ResponseActionType.SuspendProcess
            or ResponseActionType.QuarantineFile
            or ResponseActionType.IsolateNetwork
            or ResponseActionType.ProtectFolders
            or ResponseActionType.DisableDevice
            or ResponseActionType.BlockProcessConnections
            or ResponseActionType.ThrottleTraffic
            or ResponseActionType.BlockIp
            or ResponseActionType.LockSession
            or ResponseActionType.LockAccount
            or ResponseActionType.WatchHash
            or ResponseActionType.EnhancedMonitoring;

    public static string ThreatTypeLabel(ThreatType type) => type switch
    {
        ThreatType.Phishing => "Hameçonnage (Phishing)",
        ThreatType.Malware => "Logiciel malveillant",
        ThreatType.Ransomware => "Rançongiciel (Ransomware)",
        ThreatType.BadUsb => "Périphérique suspect (BadUSB)",
        ThreatType.Exfiltration => "Exfiltration de données",
        ThreatType.Intrusion => "Intrusion / Force brute",
        ThreatType.SocialEngineering => "Ingénierie sociale",
        ThreatType.Persistence => "Persistance malveillante",
        ThreatType.Anomaly => "Anomalie comportementale",
        ThreatType.Tampering => "Atteinte à l'auto-protection",
        _ => "Activité suspecte"
    };

    public static string ActionTypeLabel(ResponseActionType type) => type switch
    {
        ResponseActionType.LogOnly => "Journalisation seule",
        ResponseActionType.MarkForCorrelation => "Marquage pour corrélation",
        ResponseActionType.NotifyUser => "Notification utilisateur",
        ResponseActionType.EnhancedMonitoring => "Surveillance renforcée",
        ResponseActionType.AlertAdmin => "Alerte administrateur",
        ResponseActionType.UserAwareness => "Sensibilisation utilisateur",
        ResponseActionType.WatchHash => "Surveillance d'empreinte SHA-256",
        ResponseActionType.BlockDomain => "Blocage de domaine",
        ResponseActionType.CloseBrowserTab => "Fermeture d'onglet navigateur",
        ResponseActionType.SuspendProcess => "Suspension de processus",
        ResponseActionType.KillProcess => "Arrêt de processus",
        ResponseActionType.QuarantineFile => "Mise en quarantaine (chiffrée)",
        ResponseActionType.IsolateNetwork => "Isolement réseau du poste",
        ResponseActionType.ProtectFolders => "Protection des dossiers sensibles",
        ResponseActionType.DisableDevice => "Désactivation de périphérique (PnP)",
        ResponseActionType.BlockProcessConnections => "Coupure réseau du processus",
        ResponseActionType.ThrottleTraffic => "Limitation du trafic sortant",
        ResponseActionType.BlockIp => "Blocage d'adresse IP",
        ResponseActionType.LockSession => "Verrouillage de session",
        ResponseActionType.LockAccount => "Verrouillage de compte",
        _ => type.ToString()
    };

    public static string ActionStatusLabel(ActionStatus status) => status switch
    {
        ActionStatus.Proposed => "Proposée (attente validation)",
        ActionStatus.Pending => "En attente d'exécution",
        ActionStatus.Executed => "Exécutée",
        ActionStatus.Simulated => "Simulée",
        ActionStatus.Failed => "Échec",
        ActionStatus.Reverted => "Annulée (restaurée)",
        ActionStatus.Rejected => "Rejetée",
        ActionStatus.RevertPending => "Annulation en cours",
        _ => status.ToString()
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

    public static string? TryExtractDomain(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return null;

        var trimmed = raw.Trim();
        if (trimmed.Contains("://", StringComparison.Ordinal) &&
            Uri.TryCreate(trimmed, UriKind.Absolute, out var uri) &&
            !string.IsNullOrWhiteSpace(uri.Host))
        {
            return uri.Host.TrimEnd('.').ToLowerInvariant();
        }

        // Domaine nu (ex. "evil.xyz" ou "sub.evil.xyz:443")
        if (!trimmed.Contains('\\') && !trimmed.Contains(' ') && trimmed.Contains('.'))
        {
            var slash = trimmed.IndexOf('/');
            var hostPart = slash > 0 ? trimmed[..slash] : trimmed;
            var colon = hostPart.IndexOf(':');
            if (colon > 0) hostPart = hostPart[..colon];
            if (hostPart.Length >= 3 && hostPart.Length <= 253 &&
                hostPart.All(c => char.IsLetterOrDigit(c) || c is '.' or '-'))
            {
                return hostPart.TrimEnd('.').ToLowerInvariant();
            }
        }

        return null;
    }
}
