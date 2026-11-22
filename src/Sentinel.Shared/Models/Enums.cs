namespace Sentinel.Shared.Models;

/// <summary>Canal de collecte d'un événement (liste fermée, cf. doc §2.1).</summary>
public enum EventCategory
{
    Process = 0,
    Network = 1,
    Clipboard = 2,
    File = 3,
    Session = 4,
    Device = 5,
    Browser = 6,
    Typing = 7,
    Installation = 8,
    /// <summary>Événements internes à SENTINEL (auto-protection, watchdog, intégrité).</summary>
    System = 9,
    /// <summary>Détections et état de santé Microsoft Defender (v2 M1).</summary>
    Defender = 10,
    /// <summary>Visibilité scripts PowerShell 4104 / ETW AMSI (v2 M7).</summary>
    Script = 11,
    /// <summary>Alertes fichiers canari anti-ransomware (v2 M6).</summary>
    Canary = 12,
    /// <summary>Résultats d'analyse statique PE / YARA (v2 M3).</summary>
    StaticAnalysis = 13,
    /// <summary>Correspondances flux de renseignement sur les menaces (v2 M4).</summary>
    ThreatIntel = 14
}

/// <summary>Type de menace attribué par le scoring (doc §5.2 / §9.2).</summary>
public enum ThreatType
{
    None = 0,
    Phishing = 1,
    Malware = 2,
    Ransomware = 3,
    BadUsb = 4,
    Exfiltration = 5,
    Intrusion = 6,
    SocialEngineering = 7,
    Persistence = 8,
    Anomaly = 9,
    Tampering = 10
}

/// <summary>Niveau de menace gradué (doc §9.1).</summary>
public enum ThreatLevel
{
    Info = 0,      // 0–29
    Low = 1,       // 30–54
    Moderate = 2,  // 55–74
    High = 3,      // 75–89
    Critical = 4   // 90–100
}

/// <summary>Origine du score.</summary>
public enum AssessmentSource
{
    Rules = 0,
    Llm = 1,
    Hybrid = 2,
    Sigma = 3,
    Yara = 4,
    ThreatIntel = 5,
    MachineLearning = 6,
    MultiEngine = 7
}

/// <summary>Mode de fonctionnement global du moteur de décision (doc §9.4).</summary>
public enum OperatingMode
{
    /// <summary>Construction de la baseline : aucune action automatique.</summary>
    Learning = 0,
    /// <summary>Les actions sont journalisées mais pas exécutées.</summary>
    Simulation = 1,
    /// <summary>Les actions sont réellement exécutées selon la matrice.</summary>
    Active = 2
}

/// <summary>Actions de réponse possibles (doc §9.2).</summary>
public enum ResponseActionType
{
    LogOnly = 0,
    MarkForCorrelation = 1,
    NotifyUser = 2,
    EnhancedMonitoring = 3,
    AlertAdmin = 4,
    UserAwareness = 5,
    WatchHash = 6,
    BlockDomain = 10,
    CloseBrowserTab = 11,
    SuspendProcess = 12,
    KillProcess = 13,
    QuarantineFile = 14,
    IsolateNetwork = 15,
    ProtectFolders = 16,
    DisableDevice = 17,
    BlockProcessConnections = 18,
    ThrottleTraffic = 19,
    BlockIp = 20,
    LockSession = 21,
    LockAccount = 22
}

/// <summary>Cycle de vie d'un ticket d'action (doc §9.3).</summary>
public enum ActionStatus
{
    /// <summary>Proposée à l'administrateur (niveau 3) – attend une décision humaine.</summary>
    Proposed = 0,
    /// <summary>Approuvée / automatique, en attente d'exécution par l'agent.</summary>
    Pending = 1,
    Executed = 2,
    /// <summary>Mode simulation ou apprentissage : journalisée mais non exécutée.</summary>
    Simulated = 3,
    Failed = 4,
    /// <summary>Annulée (« Annuler » depuis le dashboard), état initial restauré.</summary>
    Reverted = 5,
    /// <summary>Proposition rejetée par l'administrateur.</summary>
    Rejected = 6,
    /// <summary>Demande d'annulation envoyée à l'agent, en attente de confirmation.</summary>
    RevertPending = 7
}

/// <summary>Statut d'une alerte.</summary>
public enum AlertStatus
{
    Open = 0,
    Acknowledged = 1,
    /// <summary>L'administrateur a validé la menace (et les actions proposées).</summary>
    Approved = 2,
    /// <summary>Faux positif : réinjecté dans la baseline (doc §9.4).</summary>
    FalsePositive = 3,
    Resolved = 4
}

/// <summary>Types de nœuds du graphe de corrélation (doc §5.3).</summary>
public enum GraphNodeType
{
    Event = 0,
    Process = 1,
    File = 2,
    Domain = 3,
    Ip = 4,
    User = 5,
    Device = 6,
    Threat = 7,
    Host = 8
}

/// <summary>Types d'arêtes du graphe de corrélation (doc §5.3).</summary>
public enum GraphEdgeType
{
    Spawned = 0,
    ConnectedTo = 1,
    Wrote = 2,
    CopiedFromClipboard = 3,
    OpenedUrl = 4,
    SameDomain = 5,
    SameWindow = 6,
    SameAnomalyType = 7,
    SameHash = 8,
    SameEntity = 9,
    InvolvedIn = 10,
    Sequence = 11
}
