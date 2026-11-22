namespace Sentinel.Shared.Models;

/// <summary>
/// Identifiants normalisés des types d'événements (champ <see cref="SecurityEvent.EventType"/>).
/// Contrat partagé entre collecteurs (Agent/Tray/Extension) et moteur d'analyse (Core).
/// </summary>
public static class EventTypes
{
    // Processus (§6.1)
    public const string ProcessStart = "ProcessStart";
    public const string ProcessStop = "ProcessStop";

    // Réseau (§6.2)
    public const string NetworkConnection = "NetworkConnection";
    public const string DnsQuery = "DnsQuery";
    public const string NetworkVolume = "NetworkVolume";

    // Presse-papiers (§6.3)
    public const string ClipboardUrl = "ClipboardUrl";
    public const string ClipboardCommand = "ClipboardCommand";

    // Fichiers (§6.4)
    public const string FileCreated = "FileCreated";
    public const string FileModified = "FileModified";
    public const string FileRenamed = "FileRenamed";
    public const string FileDeleted = "FileDeleted";
    /// <summary>Agrégat produit par le collecteur : rafale de modifications (suspicion ransomware).</summary>
    public const string FileBurst = "FileBurst";

    // Sessions (§6.5)
    public const string LogonSuccess = "LogonSuccess";     // 4624
    public const string LogonFailure = "LogonFailure";     // 4625
    public const string Logoff = "Logoff";                 // 4634 / 4647
    public const string SessionLocked = "SessionLocked";   // 4800
    public const string SessionUnlocked = "SessionUnlocked"; // 4801

    // Dynamique de saisie (§6.6)
    public const string TypingStats = "TypingStats";

    // Périphériques (§6.7)
    public const string UsbInserted = "UsbInserted";
    public const string UsbRemoved = "UsbRemoved";
    public const string DeviceAdded = "DeviceAdded";

    // Navigation (§6.8)
    public const string UrlVisited = "UrlVisited";
    public const string LinkClicked = "LinkClicked";
    public const string Redirect = "Redirect";
    public const string DownloadStarted = "DownloadStarted";

    // Installations / persistance (§6.9, §8.3)
    public const string AppInstalled = "AppInstalled";
    public const string StartupEntryAdded = "StartupEntryAdded";
    public const string ScheduledTaskCreated = "ScheduledTaskCreated";

    // Système / auto-protection (§11)
    public const string AgentStarted = "AgentStarted";
    public const string AgentStopped = "AgentStopped";
    public const string AgentTampering = "AgentTampering";
    public const string IntegrityViolation = "IntegrityViolation";
    public const string Heartbeat = "Heartbeat";

    // Microsoft Defender (v2 M1)
    public const string DefenderThreatDetected = "DefenderThreatDetected";
    public const string DefenderActionTaken = "DefenderActionTaken";
    public const string DefenderRealtimeDisabled = "DefenderRealtimeDisabled";
    public const string DefenderExclusionAdded = "DefenderExclusionAdded";
    public const string DefenderServiceStopped = "DefenderServiceStopped";
    public const string DefenderTampering = "DefenderTampering";

    // Sysmon optionnel (v2 M1)
    public const string SysmonProcessCreate = "SysmonProcessCreate";
    public const string SysmonNetworkConnect = "SysmonNetworkConnect";
    public const string SysmonFileCreate = "SysmonFileCreate";
    public const string SysmonRegistryEvent = "SysmonRegistryEvent";
    public const string SysmonTaskEvent = "SysmonTaskEvent";

    // Analyse statique / YARA / ML (v2 M3, M5)
    public const string YaraMatch = "YaraMatch";
    public const string PeStaticAnomaly = "PeStaticAnomaly";
    public const string StaticScanCompleted = "StaticScanCompleted";
    public const string MlPeClassification = "MlPeClassification";

    // Threat Intelligence (v2 M4)
    public const string ThreatIntelMatch = "ThreatIntelMatch";

    // Fichiers canari anti-ransomware (v2 M6)
    public const string CanaryModified = "CanaryModified";
    public const string CanaryRenamed = "CanaryRenamed";
    public const string CanaryDeleted = "CanaryDeleted";
    public const string CanaryEncrypted = "CanaryEncrypted";

    // Visibilité scripts (v2 M7 — PowerShell 4104 + ETW AMSI)
    public const string PowerShellScriptBlock = "PowerShellScriptBlock";
    public const string AmsiScriptScan = "AmsiScriptScan";
    public const string ScriptLoggingBypass = "ScriptLoggingBypass";
}

/// <summary>
/// Clés normalisées d'attributs (<see cref="SecurityEvent.Attributes"/>). Les valeurs sont des chaînes ;
/// nombres au format invariant, booléens "true"/"false".
/// </summary>
public static class AttributeKeys
{
    // Communs
    public const string ProcessId = "pid";
    public const string ProcessName = "process.name";
    public const string ProcessPath = "process.path";
    public const string Sha256 = "sha256";
    public const string SessionId = "session.id";

    // Processus
    public const string ParentProcessId = "parent.pid";
    public const string ParentProcessName = "parent.name";
    public const string ParentProcessPath = "parent.path";
    public const string CommandLine = "cmdline";
    public const string Signed = "signed";            // true/false (Authenticode valide)
    public const string Publisher = "publisher";      // éditeur du certificat
    public const string Elevated = "elevated";        // true/false
    public const string ExitCode = "exit.code";

    // Réseau
    public const string LocalIp = "net.local.ip";
    public const string LocalPort = "net.local.port";
    public const string RemoteIp = "net.remote.ip";
    public const string RemotePort = "net.remote.port";
    public const string Protocol = "net.protocol";   // tcp/udp
    public const string Direction = "net.direction"; // outbound/inbound
    public const string BytesSent = "net.bytes.sent";
    public const string BytesReceived = "net.bytes.received";
    public const string Domain = "domain";            // domaine résolu / visité
    public const string IsPrivateIp = "net.remote.private"; // true/false

    // URL / navigation / presse-papiers
    public const string Url = "url";                  // URL (sans query string sensible)
    public const string UrlScheme = "url.scheme";
    public const string IsShortener = "url.shortener"; // true/false
    public const string DomainAgeDays = "domain.age.days";
    public const string Referrer = "referrer";
    public const string RedirectCount = "redirect.count";
    public const string TabId = "browser.tab.id";
    public const string Browser = "browser";
    public const string ContentHash = "content.hash";  // hash SHA-256 du contenu copié (jamais le contenu)
    public const string ContentType = "content.type";  // url, command, text
    public const string CommandKind = "command.kind";  // powershell, cmd, bash, encoded…
    public const string FileName = "file.name";        // téléchargement

    // Fichiers
    public const string FilePath = "file.path";
    public const string OldFilePath = "file.old.path";
    public const string Extension = "file.ext";
    public const string OldExtension = "file.old.ext";
    public const string FileSize = "file.size";
    public const string Entropy = "file.entropy";      // 0..8 bits/octet
    public const string DoubleExtension = "file.double.ext"; // true/false
    public const string IsExecutable = "file.executable";    // true/false
    public const string IsArchive = "file.archive";          // true/false
    public const string WatchedFolder = "file.folder";       // Downloads, Desktop, Documents, Temp…
    public const string BurstCount = "burst.count";          // nb de modifs dans la fenêtre (FileBurst)
    public const string BurstWindowSeconds = "burst.window.s";
    public const string BurstDistinctExtensions = "burst.ext.distinct";
    public const string BurstAvgEntropy = "burst.entropy.avg";

    // Sessions
    public const string WindowsEventId = "win.event.id";
    public const string LogonType = "logon.type";
    public const string SourceIp = "source.ip";
    public const string TargetUser = "target.user";
    public const string FailureReason = "failure.reason";
    public const string FailureCount = "failure.count";

    // Saisie (statistiques uniquement, JAMAIS les touches)
    public const string KeysPerSecond = "typing.kps";
    public const string MeanIntervalMs = "typing.interval.mean.ms";
    public const string IntervalStdDevMs = "typing.interval.std.ms";
    public const string SampleSize = "typing.samples";
    public const string Injected = "typing.injected"; // true si LLKHF_INJECTED détecté

    // Périphériques
    public const string DeviceId = "device.id";
    public const string VendorId = "device.vid";
    public const string ProductId = "device.pid";
    public const string DeviceClass = "device.class";  // HID, USBSTOR, Keyboard, ...
    public const string DeviceName = "device.name";
    public const string IsKeyboard = "device.keyboard"; // true/false
    public const string IsStorage = "device.storage";   // true/false

    // Installations / persistance
    public const string AppName = "app.name";
    public const string AppVersion = "app.version";
    public const string AppPublisher = "app.publisher";
    public const string RegistryKey = "reg.key";
    public const string RegistryValue = "reg.value";
    public const string TaskName = "task.name";

    // Système
    public const string AgentVersion = "agent.version";
    public const string Reason = "reason";
    public const string Component = "component";

    // Dédoublonnage multi-sources (v2 M1)
    public const string CollectorSource = "collector.source";
    public const string EventSources = "event.sources";
    public const string DeduplicatedCount = "event.dedup.count";

    // Microsoft Defender (v2 M1)
    public const string DefenderThreatId = "defender.threat.id";
    public const string DefenderThreatName = "defender.threat.name";
    public const string DefenderSeverity = "defender.severity";
    public const string DefenderCategory = "defender.category";
    public const string DefenderAction = "defender.action";
    public const string DefenderExclusion = "defender.exclusion";
    public const string DefenderStatus = "defender.status";

    // Sysmon (v2 M1)
    public const string SysmonEventId = "sysmon.event.id";
    public const string SysmonRuleName = "sysmon.rule";
    public const string SysmonHashes = "sysmon.hashes";
    public const string TargetObject = "reg.target.object";

    // Sigma / YARA / Analyse statique PE (v2 M2, M3)
    public const string SigmaRuleId = "sigma.rule.id";
    public const string SigmaRuleTitle = "sigma.rule.title";
    public const string SigmaLevel = "sigma.level";
    public const string YaraRule = "yara.rule";
    public const string YaraNamespace = "yara.namespace";
    public const string YaraEngine = "yara.engine";
    public const string PePacker = "pe.packer";
    public const string PeCompileTime = "pe.compile.time";
    public const string PeSuspiciousImports = "pe.imports.suspicious";
    public const string PeSigned = "pe.signed";
    public const string PeSectionCount = "pe.sections";
    public const string PeMaxEntropy = "pe.entropy.max";

    // Threat Intelligence (v2 M4)
    public const string ThreatIntelSource = "ti.source";
    public const string ThreatIntelIndicator = "ti.indicator";
    public const string ThreatIntelIndicatorType = "ti.indicator.type";
    public const string ThreatIntelThreat = "ti.threat";
    public const string ThreatIntelFirstSeen = "ti.first.seen";
    public const string ThreatIntelConfidence = "ti.confidence";

    // Machine Learning PE (v2 M5)
    public const string MlScore = "ml.score";
    public const string MlModelVersion = "ml.model.version";
    public const string MlTopFeatures = "ml.features.top";

    // Fichiers canari (v2 M6)
    public const string CanaryId = "canary.id";
    public const string CanaryFolder = "canary.folder";
    public const string CanaryExpectedHash = "canary.hash.expected";
    public const string CanaryObservedHash = "canary.hash.observed";

    // Visibilité scripts (v2 M7)
    public const string ScriptBlockId = "script.block.id";
    public const string ScriptPath = "script.path";
    public const string ScriptHash = "script.hash";
    public const string ScriptLength = "script.length";
    public const string ScriptIndicators = "script.indicators";
    public const string ScriptExcerpt = "script.excerpt";
    public const string ScriptObfuscationScore = "script.obfuscation";
}

/// <summary>Noms des dossiers surveillés (valeur de <see cref="AttributeKeys.WatchedFolder"/>).</summary>
public static class WatchedFolders
{
    public const string Downloads = "Downloads";
    public const string Desktop = "Desktop";
    public const string Documents = "Documents";
    public const string Temp = "Temp";
    public const string Custom = "Custom";
}
