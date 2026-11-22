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
