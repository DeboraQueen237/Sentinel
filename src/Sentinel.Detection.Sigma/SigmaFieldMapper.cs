using Sentinel.Shared.Models;

namespace Sentinel.Detection.Sigma;

/// <summary>Description documentee d'un mapping entre un champ Sigma standard et <see cref="SecurityEvent"/>.</summary>
public sealed record SigmaFieldMapping(
    string SigmaField,
    IReadOnlyList<string> SentinelTargets,
    string Description,
    bool IsVirtualOnly = false);

/// <summary>
/// Mapping documente entre les champs Sigma standard (Sysmon / Windows Security / PowerShell / Defender)
/// et le schema normalise <see cref="SecurityEvent"/> de SENTINEL v2.
/// </summary>
public static class SigmaFieldMapper
{
    /// <summary>Table publique documentee des mappings de champs Sigma vers SENTINEL.</summary>
    public static IReadOnlyDictionary<string, SigmaFieldMapping> FieldMappings { get; } =
        new Dictionary<string, SigmaFieldMapping>(StringComparer.OrdinalIgnoreCase)
        {
            ["Image"] = new(
                "Image",
                [AttributeKeys.ProcessPath, AttributeKeys.ProcessName, nameof(SecurityEvent.Subject)],
                "Chemin complet de l'executable du processus (repli sur process.name puis Subject pour la categorie Process)."),

            ["OriginalFileName"] = new(
                "OriginalFileName",
                ["process.original.filename", AttributeKeys.ProcessName, AttributeKeys.FileName, AttributeKeys.ProcessPath],
                "Nom de fichier original du binaire PE ou nom de fichier extrait de process.path."),

            ["CommandLine"] = new(
                "CommandLine",
                [AttributeKeys.CommandLine, nameof(SecurityEvent.Subject)],
                "Ligne de commande complete du processus (ou commande presse-papiers pour ClipboardCommand)."),

            ["ParentImage"] = new(
                "ParentImage",
                [AttributeKeys.ParentProcessPath, AttributeKeys.ParentProcessName],
                "Chemin complet ou nom du processus parent."),

            ["ParentCommandLine"] = new(
                "ParentCommandLine",
                ["parent.cmdline", "ParentCommandLine"],
                "Ligne de commande du processus parent si disponible."),

            ["TargetFilename"] = new(
                "TargetFilename",
                [AttributeKeys.FilePath, AttributeKeys.FileName, nameof(SecurityEvent.Subject)],
                "Chemin complet du fichier cible (File, Canary, StaticAnalysis)."),

            ["DestinationIp"] = new(
                "DestinationIp",
                [AttributeKeys.RemoteIp, nameof(SecurityEvent.Subject)],
                "Adresse IP distante d'une connexion reseau sortante ou entrante."),

            ["DestinationPort"] = new(
                "DestinationPort",
                [AttributeKeys.RemotePort],
                "Port TCP/UDP distant de la connexion reseau."),

            ["DestinationHostname"] = new(
                "DestinationHostname",
                [AttributeKeys.Domain, AttributeKeys.Url, nameof(SecurityEvent.Subject)],
                "Nom d'hote, domaine ou URL de destination."),

            ["QueryName"] = new(
                "QueryName",
                [AttributeKeys.Domain, nameof(SecurityEvent.Subject)],
                "Nom de domaine interroge lors d'une requete DNS (DnsQuery)."),

            ["SourceIp"] = new(
                "SourceIp",
                [AttributeKeys.SourceIp, AttributeKeys.LocalIp],
                "Adresse IP source d'une authentification (Session) ou IP locale d'une connexion reseau."),

            ["User"] = new(
                "User",
                [nameof(SecurityEvent.UserId), AttributeKeys.TargetUser],
                "Identifiant utilisateur associe a l'evenement (target.user prioritaire pour les evenements Session)."),

            ["TargetObject"] = new(
                "TargetObject",
                [AttributeKeys.TargetObject, AttributeKeys.RegistryKey, nameof(SecurityEvent.Subject)],
                "Chemin complet de cle ou valeur de registre cible (StartupEntryAdded, SysmonRegistryEvent)."),

            ["Details"] = new(
                "Details",
                [AttributeKeys.RegistryValue, AttributeKeys.DefenderExclusion, AttributeKeys.TaskName, AttributeKeys.Reason],
                "Donnees de valeur de registre, exclusion Defender, nom de tache ou motif systeme."),

            ["EventID"] = new(
                "EventID",
                [AttributeKeys.WindowsEventId, AttributeKeys.SysmonEventId, nameof(SecurityEvent.EventType)],
                "Identifiant d'evenement Windows ou Sysmon (deduit de EventType si non renseigne explicitement).",
                IsVirtualOnly: true),

            ["ScriptBlockText"] = new(
                "ScriptBlockText",
                ["ScriptBlockText", "script.text", AttributeKeys.ScriptExcerpt, AttributeKeys.CommandLine, nameof(SecurityEvent.Subject)],
                "Contenu ou extrait d'un bloc de script PowerShell (Event ID 4104) ou scan AMSI."),

            ["Hashes"] = new(
                "Hashes",
                [AttributeKeys.SysmonHashes, AttributeKeys.Sha256, AttributeKeys.ScriptHash],
                "Empreintes cryptographiques (format Sysmon ou SHA-256 brut)."),

            ["Product"] = new(
                "Product",
                ["sigma.product"],
                "Produit source Sigma normalise (par defaut 'windows' pour l'agent SENTINEL).",
                IsVirtualOnly: true),

            ["Category"] = new(
                "Category",
                ["sigma.category", nameof(SecurityEvent.Category), nameof(SecurityEvent.EventType)],
                "Categorie logsource Sigma derivee de SecurityEvent.Category et EventType (ex. process_creation, ps_script).",
                IsVirtualOnly: true),

            ["Service"] = new(
                "Service",
                ["sigma.service", nameof(SecurityEvent.EventType)],
                "Service logsource Sigma derive du canal Windows (powershell, windefend, security, sysmon).",
                IsVirtualOnly: true)
        };

    /// <summary>
    /// Indique si un champ Sigma peut etre synthetise virtuellement sans apparaitre dans
    /// <see cref="SecurityEvent.Attributes"/> (exclu du pre-filtrage Aho-Corasick pour garantir 0 faux negatif).
    /// </summary>
    public static bool IsVirtualOnlyField(string sigmaField) =>
        FieldMappings.TryGetValue(sigmaField, out var mapping) && mapping.IsVirtualOnly;

    /// <summary>Resout la valeur d'un champ Sigma a partir d'un <see cref="SecurityEvent"/>.</summary>
    public static string? GetFieldValue(SecurityEvent evt, string sigmaField)
    {
        // Fast-path case-insensitive sur les 20 champs Sigma standard
        if (sigmaField.Equals("Image", StringComparison.OrdinalIgnoreCase))
            return ResolveImage(evt);

        if (sigmaField.Equals("OriginalFileName", StringComparison.OrdinalIgnoreCase))
            return ResolveOriginalFileName(evt);

        if (sigmaField.Equals("CommandLine", StringComparison.OrdinalIgnoreCase))
            return evt.Attr(AttributeKeys.CommandLine)
                ?? evt.Attr("CommandLine")
                ?? (evt.EventType == EventTypes.ClipboardCommand ? evt.Subject : null);

        if (sigmaField.Equals("ParentImage", StringComparison.OrdinalIgnoreCase))
            return evt.Attr(AttributeKeys.ParentProcessPath)
                ?? evt.Attr(AttributeKeys.ParentProcessName)
                ?? evt.Attr("ParentImage");

        if (sigmaField.Equals("ParentCommandLine", StringComparison.OrdinalIgnoreCase))
            return evt.Attr("parent.cmdline") ?? evt.Attr("ParentCommandLine");

        if (sigmaField.Equals("TargetFilename", StringComparison.OrdinalIgnoreCase))
            return evt.Attr(AttributeKeys.FilePath)
                ?? evt.Attr(AttributeKeys.FileName)
                ?? evt.Attr("TargetFilename")
                ?? (evt.Category is EventCategory.File or EventCategory.Canary or EventCategory.StaticAnalysis ? evt.Subject : null);

        if (sigmaField.Equals("DestinationIp", StringComparison.OrdinalIgnoreCase))
            return evt.Attr(AttributeKeys.RemoteIp)
                ?? evt.Attr("DestinationIp")
                ?? (evt.Category == EventCategory.Network && evt.EventType == EventTypes.NetworkConnection ? evt.Subject : null);

        if (sigmaField.Equals("DestinationPort", StringComparison.OrdinalIgnoreCase))
            return evt.Attr(AttributeKeys.RemotePort) ?? evt.Attr("DestinationPort");

        if (sigmaField.Equals("DestinationHostname", StringComparison.OrdinalIgnoreCase))
            return evt.Attr(AttributeKeys.Domain)
                ?? evt.Attr(AttributeKeys.Url)
                ?? evt.Attr("DestinationHostname")
                ?? (evt.Category is EventCategory.Network or EventCategory.Browser ? evt.Subject : null);

        if (sigmaField.Equals("QueryName", StringComparison.OrdinalIgnoreCase))
            return evt.Attr(AttributeKeys.Domain)
                ?? evt.Attr("QueryName")
                ?? (evt.EventType == EventTypes.DnsQuery ? evt.Subject : null);

        if (sigmaField.Equals("SourceIp", StringComparison.OrdinalIgnoreCase))
            return evt.Attr(AttributeKeys.SourceIp)
                ?? evt.Attr(AttributeKeys.LocalIp)
                ?? evt.Attr("SourceIp");

        if (sigmaField.Equals("User", StringComparison.OrdinalIgnoreCase))
        {
            if (evt.Category == EventCategory.Session)
                return evt.Attr(AttributeKeys.TargetUser) ?? NullIfEmpty(evt.UserId);
            return NullIfEmpty(evt.UserId) ?? evt.Attr(AttributeKeys.TargetUser);
        }

        if (sigmaField.Equals("TargetObject", StringComparison.OrdinalIgnoreCase))
            return evt.Attr(AttributeKeys.TargetObject)
                ?? evt.Attr(AttributeKeys.RegistryKey)
                ?? evt.Attr("TargetObject")
                ?? (evt.EventType is EventTypes.StartupEntryAdded or EventTypes.SysmonRegistryEvent ? evt.Subject : null);

        if (sigmaField.Equals("Details", StringComparison.OrdinalIgnoreCase))
            return evt.Attr(AttributeKeys.RegistryValue)
                ?? evt.Attr(AttributeKeys.DefenderExclusion)
                ?? evt.Attr("Details")
                ?? evt.Attr(AttributeKeys.TaskName)
                ?? evt.Attr(AttributeKeys.Reason);

        if (sigmaField.Equals("EventID", StringComparison.OrdinalIgnoreCase))
            return ResolveEventId(evt);

        if (sigmaField.Equals("ScriptBlockText", StringComparison.OrdinalIgnoreCase))
            return evt.Attr("ScriptBlockText")
                ?? evt.Attr("script.text")
                ?? evt.Attr(AttributeKeys.ScriptExcerpt)
                ?? (evt.Category == EventCategory.Script ? evt.Attr(AttributeKeys.CommandLine) ?? NullIfEmpty(evt.Subject) : null);

        if (sigmaField.Equals("Hashes", StringComparison.OrdinalIgnoreCase))
            return evt.Attr(AttributeKeys.SysmonHashes)
                ?? evt.Attr(AttributeKeys.Sha256)
                ?? evt.Attr(AttributeKeys.ScriptHash)
                ?? evt.Attr("Hashes");

        if (sigmaField.Equals("Product", StringComparison.OrdinalIgnoreCase))
            return evt.Attr("sigma.product") ?? "windows";

        if (sigmaField.Equals("Category", StringComparison.OrdinalIgnoreCase))
            return evt.Attr("sigma.category") ?? ResolveSigmaCategory(evt);

        if (sigmaField.Equals("Service", StringComparison.OrdinalIgnoreCase))
            return evt.Attr("sigma.service") ?? ResolveSigmaService(evt);

        // Champs SENTINEL supplementaires et acces direct aux attributs
        if (sigmaField.Equals("EventType", StringComparison.OrdinalIgnoreCase))
            return evt.EventType;
        if (sigmaField.Equals("Subject", StringComparison.OrdinalIgnoreCase))
            return evt.Subject;
        if (sigmaField.Equals("HostId", StringComparison.OrdinalIgnoreCase))
            return evt.HostId;

        if (evt.Attributes.TryGetValue(sigmaField, out var direct))
            return direct;

        foreach (var kv in evt.Attributes)
        {
            if (kv.Key.Equals(sigmaField, StringComparison.OrdinalIgnoreCase))
                return kv.Value;
        }

        return null;
    }

    /// <summary>
    /// Determine les <see cref="EventCategory"/> SENTINEL pouvant declencher une regle selon son <c>logsource</c>.
    /// </summary>
    public static EventCategory[] MapLogSourceToCategories(SigmaLogSource logSource)
    {
        // Ignorer les regles explicitement destinees a des OS non Windows (ex. linux, macos, aws)
        if (!string.IsNullOrWhiteSpace(logSource.Product) &&
            !logSource.Product.Equals("windows", StringComparison.OrdinalIgnoreCase) &&
            !logSource.Product.Equals("sentinel", StringComparison.OrdinalIgnoreCase) &&
            !logSource.Product.Equals("generic", StringComparison.OrdinalIgnoreCase))
        {
            return Array.Empty<EventCategory>();
        }

        var category = logSource.Category?.Trim().ToLowerInvariant();
        if (!string.IsNullOrEmpty(category))
        {
            return category switch
            {
                "process_creation" or "process_access" or "process_termination" or "image_load" or "create_remote_thread"
                    => [EventCategory.Process],

                "network_connection" or "firewall"
                    => [EventCategory.Network],

                "dns_query" or "dns"
                    => [EventCategory.Network],

                "proxy" or "webserver"
                    => [EventCategory.Network, EventCategory.Browser],

                "file_event" or "file_access" or "file_change" or "file_delete" or "file_rename" or "file_executable_detected"
                    => [EventCategory.File, EventCategory.Canary, EventCategory.StaticAnalysis],

                "registry_event" or "registry_set" or "registry_add" or "registry_delete" or "registry_rename"
                    => [EventCategory.Installation, EventCategory.System, EventCategory.Defender],

                "ps_script" or "ps_module" or "ps_classic_start" or "ps_classic_provider_start"
                    => [EventCategory.Script],

                "antivirus"
                    => [EventCategory.Defender],

                "task_creation" or "scheduled_task"
                    => [EventCategory.Installation, EventCategory.Process],

                "clipboard"
                    => [EventCategory.Clipboard],

                "usb" or "device"
                    => [EventCategory.Device],

                _ => AllCategories
            };
        }

        var service = logSource.Service?.Trim().ToLowerInvariant();
        if (!string.IsNullOrEmpty(service))
        {
            return service switch
            {
                "powershell" or "powershell-classic"
                    => [EventCategory.Script, EventCategory.Process],

                "windefend" or "defender"
                    => [EventCategory.Defender, EventCategory.Process],

                "security"
                    => [EventCategory.Session, EventCategory.Installation, EventCategory.Process, EventCategory.System],

                "taskscheduler"
                    => [EventCategory.Installation, EventCategory.Process],

                "sysmon"
                    => [EventCategory.Process, EventCategory.Network, EventCategory.File, EventCategory.Installation],

                "system"
                    => [EventCategory.System, EventCategory.Installation, EventCategory.Defender],

                "dns-client"
                    => [EventCategory.Network],

                _ => AllCategories
            };
        }

        return AllCategories;
    }

    private static readonly EventCategory[] AllCategories = Enum.GetValues<EventCategory>();

    private static string? ResolveImage(SecurityEvent evt)
    {
        var path = evt.Attr(AttributeKeys.ProcessPath);
        if (!string.IsNullOrEmpty(path))
            return path;

        var direct = evt.Attr("Image");
        if (!string.IsNullOrEmpty(direct))
            return direct;

        if (evt.Category == EventCategory.Process && !string.IsNullOrEmpty(evt.Subject) &&
            (evt.Subject.Contains('\\') || evt.Subject.Contains('/')))
        {
            return evt.Subject;
        }

        var procName = evt.Attr(AttributeKeys.ProcessName);
        if (!string.IsNullOrEmpty(procName))
            return procName;

        return evt.Category == EventCategory.Process ? NullIfEmpty(evt.Subject) : null;
    }

    private static string? ResolveOriginalFileName(SecurityEvent evt)
    {
        var orig = evt.Attr("process.original.filename") ?? evt.Attr("OriginalFileName");
        if (!string.IsNullOrEmpty(orig))
            return orig;

        var procName = evt.Attr(AttributeKeys.ProcessName);
        if (!string.IsNullOrEmpty(procName))
            return procName;

        var fileName = evt.Attr(AttributeKeys.FileName);
        if (!string.IsNullOrEmpty(fileName))
            return fileName;

        var path = evt.Attr(AttributeKeys.ProcessPath)
                ?? evt.Attr(AttributeKeys.FilePath)
                ?? (evt.Category is EventCategory.Process or EventCategory.File ? evt.Subject : null);

        if (string.IsNullOrEmpty(path))
            return null;

        var lastSep = path.LastIndexOfAny(['\\', '/']);
        return lastSep >= 0 && lastSep < path.Length - 1 ? path[(lastSep + 1)..] : path;
    }

    private static string? ResolveEventId(SecurityEvent evt)
    {
        var id = evt.Attr(AttributeKeys.WindowsEventId)
              ?? evt.Attr(AttributeKeys.SysmonEventId)
              ?? evt.Attr("EventID");
        if (!string.IsNullOrEmpty(id))
            return id;

        return evt.EventType switch
        {
            EventTypes.SysmonProcessCreate or EventTypes.ProcessStart => "1",
            EventTypes.SysmonNetworkConnect or EventTypes.NetworkConnection => "3",
            EventTypes.SysmonFileCreate or EventTypes.FileCreated => "11",
            EventTypes.SysmonRegistryEvent or EventTypes.StartupEntryAdded => "13",
            EventTypes.DnsQuery => "22",
            EventTypes.PowerShellScriptBlock => "4104",
            EventTypes.LogonSuccess => "4624",
            EventTypes.LogonFailure => "4625",
            EventTypes.Logoff => "4634",
            EventTypes.ScheduledTaskCreated => "4698",
            EventTypes.SessionLocked => "4800",
            EventTypes.SessionUnlocked => "4801",
            EventTypes.DefenderThreatDetected => "1116",
            EventTypes.DefenderActionTaken => "1117",
            EventTypes.DefenderRealtimeDisabled => "5001",
            EventTypes.DefenderExclusionAdded => "5007",
            _ => null
        };
    }

    private static string ResolveSigmaCategory(SecurityEvent evt) => evt.EventType switch
    {
        EventTypes.ProcessStart or EventTypes.SysmonProcessCreate => "process_creation",
        EventTypes.ProcessStop => "process_termination",
        EventTypes.NetworkConnection or EventTypes.SysmonNetworkConnect => "network_connection",
        EventTypes.DnsQuery => "dns_query",
        EventTypes.FileCreated or EventTypes.SysmonFileCreate => "file_event",
        EventTypes.FileDeleted or EventTypes.CanaryDeleted => "file_delete",
        EventTypes.FileRenamed or EventTypes.CanaryRenamed => "file_rename",
        EventTypes.FileModified or EventTypes.FileBurst or EventTypes.CanaryModified or EventTypes.CanaryEncrypted => "file_change",
        EventTypes.StartupEntryAdded or EventTypes.SysmonRegistryEvent => "registry_set",
        EventTypes.PowerShellScriptBlock or EventTypes.AmsiScriptScan => "ps_script",
        EventTypes.ScheduledTaskCreated or EventTypes.SysmonTaskEvent => "task_creation",
        EventTypes.DefenderThreatDetected or EventTypes.DefenderActionTaken
            or EventTypes.DefenderRealtimeDisabled or EventTypes.DefenderExclusionAdded
            or EventTypes.DefenderServiceStopped or EventTypes.DefenderTampering => "antivirus",
        _ => evt.Category.ToString().ToLowerInvariant()
    };

    private static string ResolveSigmaService(SecurityEvent evt) => evt.EventType switch
    {
        EventTypes.PowerShellScriptBlock or EventTypes.ScriptLoggingBypass or EventTypes.AmsiScriptScan => "powershell",
        EventTypes.DefenderThreatDetected or EventTypes.DefenderActionTaken
            or EventTypes.DefenderRealtimeDisabled or EventTypes.DefenderExclusionAdded
            or EventTypes.DefenderServiceStopped or EventTypes.DefenderTampering => "windefend",
        EventTypes.LogonSuccess or EventTypes.LogonFailure or EventTypes.Logoff
            or EventTypes.SessionLocked or EventTypes.SessionUnlocked or EventTypes.ScheduledTaskCreated => "security",
        EventTypes.SysmonProcessCreate or EventTypes.SysmonNetworkConnect
            or EventTypes.SysmonFileCreate or EventTypes.SysmonRegistryEvent or EventTypes.SysmonTaskEvent => "sysmon",
        _ => evt.Category switch
        {
            EventCategory.Script => "powershell",
            EventCategory.Defender => "windefend",
            EventCategory.Session => "security",
            EventCategory.System => "system",
            _ => "sysmon"
        }
    };

    private static string? NullIfEmpty(string? value) =>
        string.IsNullOrEmpty(value) ? null : value;
}
