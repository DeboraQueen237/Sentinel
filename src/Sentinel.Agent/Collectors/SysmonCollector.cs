using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.ServiceProcess;
using System.Xml.Linq;
using Microsoft.Extensions.Logging;
using Sentinel.Agent.Configuration;
using Sentinel.Agent.Pipeline;
using Sentinel.Shared.Models;

namespace Sentinel.Agent.Collectors;

/// <summary>
/// Collecteur Sysmon optionnel (v2 Mission 1) :
/// Détecte la présence de Microsoft Sysmon sans jamais l'embarquer (licence Sysinternals) et,
/// s'il est installé, lit le journal <c>Microsoft-Windows-Sysmon/Operational</c> pour enrichir
/// processus (ID 1), connexions réseau (ID 3), créations de fichiers (ID 11), registre/tâches (ID 12/13/14)
/// et requêtes DNS (ID 22).
/// </summary>
public sealed class SysmonCollector : IEventCollector, IDisposable
{
    public const string SysmonLogName = "Microsoft-Windows-Sysmon/Operational";
    private const string SysmonXPathQuery =
        "*[System[(EventID=1 or EventID=3 or EventID=11 or EventID=12 or EventID=13 or EventID=14 or EventID=22)]]";

    private readonly IEventSink _sink;
    private readonly AgentStateStore _stateStore;
    private readonly ILogger<SysmonCollector> _logger;

    private EventLogWatcher? _watcher;
    private volatile bool _enabled = true;
    private volatile bool _isRunning;
    private volatile bool _installed;
    private volatile string? _lastError;
    private long _eventsProduced;

    public string Name => "Sysmon";
    public bool IsRunning => _isRunning;
    public bool IsSysmonInstalled => _installed;
    public string? LastError => _lastError;
    public long EventsProduced => Interlocked.Read(ref _eventsProduced);

    public SysmonCollector(
        IEventSink sink,
        AgentStateStore stateStore,
        ILogger<SysmonCollector> logger)
    {
        _sink = sink;
        _stateStore = stateStore;
        _logger = logger;
    }

    /// <summary>Vérifie si Sysmon (service ou journal Operational) est installé sur ce poste.</summary>
    public static bool ProbeInstalled()
    {
        try
        {
            foreach (var serviceName in new[] { "Sysmon64", "Sysmon" })
            {
                try
                {
                    using var sc = new ServiceController(serviceName);
                    _ = sc.Status;
                    return true;
                }
                catch
                {
                    // Service absent
                }
            }

            using var session = new EventLogSession();
            return session.GetLogNames().Any(n => string.Equals(n, SysmonLogName, StringComparison.OrdinalIgnoreCase));
        }
        catch
        {
            return false;
        }
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (!_enabled)
        {
            _isRunning = false;
            _lastError = "Désactivé par configuration.";
            return Task.CompletedTask;
        }

        _installed = ProbeInstalled();
        if (!_installed)
        {
            _isRunning = false;
            _lastError = "Sysmon non installé (optionnel — non embarqué par SENTINEL).";
            _logger.LogInformation("Collecteur Sysmon inactif : Sysmon n'est pas installé sur ce poste.");
            return Task.CompletedTask;
        }

        try
        {
            var query = new EventLogQuery(SysmonLogName, PathType.LogName, SysmonXPathQuery);
            _watcher = new EventLogWatcher(query);
            _watcher.EventRecordWritten += OnSysmonEventRecord;
            _watcher.Enabled = true;

            _isRunning = true;
            _lastError = null;
            _logger.LogInformation("Collecteur Sysmon actif sur le journal {LogName}.", SysmonLogName);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or EventLogException)
        {
            DisposeWatcher();
            _isRunning = false;
            _lastError = $"Sysmon détecté mais journal inaccessible ({ex.Message}).";
            _logger.LogWarning("Collecteur Sysmon en échec d'ouverture : {Reason}", _lastError);
        }

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _isRunning = false;
        DisposeWatcher();
        return Task.CompletedTask;
    }

    public void UpdateSettings(SentinelSettings settings)
    {
        _enabled = settings.EnableSysmonCollector;
    }

    private void OnSysmonEventRecord(object? sender, EventRecordWrittenEventArgs args)
    {
        if (!_isRunning || !_enabled || args.EventRecord is null) return;
        try
        {
            using var record = args.EventRecord;
            var evt = ParseSysmonEventXml(record.ToXml(), _stateStore.HostId, Environment.UserName);
            if (evt is not null && _sink.Publish(evt))
            {
                Interlocked.Increment(ref _eventsProduced);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Erreur lors de l'analyse d'un événement Sysmon.");
        }
    }

    /// <summary>
    /// Parse un événement XML du journal <c>Microsoft-Windows-Sysmon/Operational</c> en <see cref="SecurityEvent"/>.
    /// Supporte les Event ID 1 (ProcessCreate), 3 (NetworkConnect), 11 (FileCreate), 12/13/14 (Registry), 22 (DnsQuery).
    /// </summary>
    public static SecurityEvent? ParseSysmonEventXml(string xml, string hostId, string defaultUser = "SYSTEM")
    {
        if (string.IsNullOrWhiteSpace(xml)) return null;

        XDocument doc;
        try
        {
            doc = XDocument.Parse(xml);
        }
        catch
        {
            return null;
        }

        var system = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "System");
        var eventIdStr = system?.Elements().FirstOrDefault(e => e.Name.LocalName == "EventID")?.Value;
        if (!int.TryParse(eventIdStr, NumberStyles.Integer, CultureInfo.InvariantCulture, out var eventId))
        {
            return null;
        }

        var timeCreatedRaw = system?.Elements().FirstOrDefault(e => e.Name.LocalName == "TimeCreated")?.Attribute("SystemTime")?.Value;
        var timestamp = DateTimeOffset.TryParse(timeCreatedRaw, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var parsedTs)
            ? parsedTs.ToUniversalTime()
            : DateTimeOffset.UtcNow;

        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var el in doc.Descendants().Where(e => e.Name.LocalName == "Data"))
        {
            var name = el.Attribute("Name")?.Value;
            if (!string.IsNullOrWhiteSpace(name))
            {
                data[name] = el.Value.Trim();
            }
        }

        var user = FirstNonEmpty(data, "User") ?? defaultUser;
        var attrs = new Dictionary<string, string>
        {
            [AttributeKeys.WindowsEventId] = eventId.ToString(CultureInfo.InvariantCulture),
            [AttributeKeys.SysmonEventId] = eventId.ToString(CultureInfo.InvariantCulture),
            [AttributeKeys.CollectorSource] = "Sysmon",
            [AttributeKeys.EventSources] = "Sysmon"
        };

        var ruleName = FirstNonEmpty(data, "RuleName");
        if (!string.IsNullOrWhiteSpace(ruleName) && ruleName != "-")
        {
            attrs[AttributeKeys.SysmonRuleName] = ruleName;
        }

        switch (eventId)
        {
            case 1: // Process Create
            {
                var image = FirstNonEmpty(data, "Image") ?? string.Empty;
                var procName = Path.GetFileName(image);
                var pid = FirstNonEmpty(data, "ProcessId");
                var ppid = FirstNonEmpty(data, "ParentProcessId");
                var parentImage = FirstNonEmpty(data, "ParentImage");
                var cmd = FirstNonEmpty(data, "CommandLine");
                var hashes = FirstNonEmpty(data, "Hashes");
                var sha256 = ExtractSha256FromSysmonHashes(hashes);

                if (!string.IsNullOrWhiteSpace(pid)) attrs[AttributeKeys.ProcessId] = pid;
                if (!string.IsNullOrWhiteSpace(image)) attrs[AttributeKeys.ProcessPath] = image;
                if (!string.IsNullOrWhiteSpace(procName)) attrs[AttributeKeys.ProcessName] = procName;
                if (!string.IsNullOrWhiteSpace(ppid)) attrs[AttributeKeys.ParentProcessId] = ppid;
                if (!string.IsNullOrWhiteSpace(parentImage))
                {
                    attrs[AttributeKeys.ParentProcessPath] = parentImage;
                    attrs[AttributeKeys.ParentProcessName] = Path.GetFileName(parentImage);
                }
                if (!string.IsNullOrWhiteSpace(cmd)) attrs[AttributeKeys.CommandLine] = cmd;
                if (!string.IsNullOrWhiteSpace(hashes)) attrs[AttributeKeys.SysmonHashes] = hashes;
                if (!string.IsNullOrWhiteSpace(sha256)) attrs[AttributeKeys.Sha256] = sha256;

                var hints = $"pid:{pid};ppid:{ppid}" + (string.IsNullOrEmpty(sha256) ? string.Empty : $";sha256:{sha256}");
                return SecurityEvent.Create(
                    hostId, user, EventCategory.Process, EventTypes.ProcessStart,
                    string.IsNullOrWhiteSpace(image) ? procName : image, attrs, hints, timestamp);
            }

            case 3: // Network Connect
            {
                var image = FirstNonEmpty(data, "Image");
                var pid = FirstNonEmpty(data, "ProcessId");
                var dstIp = FirstNonEmpty(data, "DestinationIp");
                var dstPort = FirstNonEmpty(data, "DestinationPort");
                var dstHost = FirstNonEmpty(data, "DestinationHostname");
                var srcIp = FirstNonEmpty(data, "SourceIp");
                var proto = FirstNonEmpty(data, "Protocol") ?? "tcp";

                if (!string.IsNullOrWhiteSpace(pid)) attrs[AttributeKeys.ProcessId] = pid;
                if (!string.IsNullOrWhiteSpace(image))
                {
                    attrs[AttributeKeys.ProcessPath] = image;
                    attrs[AttributeKeys.ProcessName] = Path.GetFileName(image);
                }
                if (!string.IsNullOrWhiteSpace(srcIp)) attrs[AttributeKeys.LocalIp] = srcIp;
                if (!string.IsNullOrWhiteSpace(dstIp)) attrs[AttributeKeys.RemoteIp] = dstIp;
                if (!string.IsNullOrWhiteSpace(dstPort)) attrs[AttributeKeys.RemotePort] = dstPort;
                if (!string.IsNullOrWhiteSpace(dstHost) && dstHost != "-") attrs[AttributeKeys.Domain] = dstHost;
                attrs[AttributeKeys.Protocol] = proto.ToLowerInvariant();
                attrs[AttributeKeys.Direction] = "outbound";

                var subject = !string.IsNullOrWhiteSpace(dstHost) && dstHost != "-" ? dstHost : (dstIp ?? "unknown");
                return SecurityEvent.Create(
                    hostId, user, EventCategory.Network, EventTypes.NetworkConnection,
                    subject, attrs, $"pid:{pid};ip:{dstIp};domain:{dstHost}", timestamp);
            }

            case 11: // FileCreate
            {
                var targetFile = FirstNonEmpty(data, "TargetFilename") ?? string.Empty;
                var image = FirstNonEmpty(data, "Image");
                var pid = FirstNonEmpty(data, "ProcessId");

                if (!string.IsNullOrWhiteSpace(pid)) attrs[AttributeKeys.ProcessId] = pid;
                if (!string.IsNullOrWhiteSpace(image))
                {
                    attrs[AttributeKeys.ProcessPath] = image;
                    attrs[AttributeKeys.ProcessName] = Path.GetFileName(image);
                }
                if (!string.IsNullOrWhiteSpace(targetFile))
                {
                    attrs[AttributeKeys.FilePath] = targetFile;
                    attrs[AttributeKeys.FileName] = Path.GetFileName(targetFile);
                    var ext = Path.GetExtension(targetFile);
                    if (!string.IsNullOrWhiteSpace(ext)) attrs[AttributeKeys.Extension] = ext.ToLowerInvariant();
                }

                // Création d'une tâche planifiée dans System32\Tasks
                if (targetFile.Contains(@"\System32\Tasks\", StringComparison.OrdinalIgnoreCase))
                {
                    attrs[AttributeKeys.TaskName] = Path.GetFileName(targetFile);
                    return SecurityEvent.Create(
                        hostId, user, EventCategory.Installation, EventTypes.ScheduledTaskCreated,
                        targetFile, attrs, $"pid:{pid};task:{Path.GetFileName(targetFile)}", timestamp);
                }

                return SecurityEvent.Create(
                    hostId, user, EventCategory.File, EventTypes.FileCreated,
                    targetFile, attrs, $"pid:{pid};file:{targetFile}", timestamp);
            }

            case 12:
            case 13:
            case 14: // Registry Object Create/Delete/SetValue
            {
                var targetObject = FirstNonEmpty(data, "TargetObject") ?? string.Empty;
                var details = FirstNonEmpty(data, "Details") ?? string.Empty;
                var image = FirstNonEmpty(data, "Image");
                var pid = FirstNonEmpty(data, "ProcessId");

                if (!string.IsNullOrWhiteSpace(pid)) attrs[AttributeKeys.ProcessId] = pid;
                if (!string.IsNullOrWhiteSpace(image))
                {
                    attrs[AttributeKeys.ProcessPath] = image;
                    attrs[AttributeKeys.ProcessName] = Path.GetFileName(image);
                }
                attrs[AttributeKeys.RegistryKey] = targetObject;
                attrs[AttributeKeys.TargetObject] = targetObject;
                if (!string.IsNullOrWhiteSpace(details)) attrs[AttributeKeys.RegistryValue] = details;

                var isStartup = targetObject.Contains(@"\CurrentVersion\Run", StringComparison.OrdinalIgnoreCase) ||
                                targetObject.Contains(@"\Winlogon\", StringComparison.OrdinalIgnoreCase) ||
                                targetObject.Contains(@"\Image File Execution Options\", StringComparison.OrdinalIgnoreCase);

                var isDefenderReg = targetObject.Contains(@"Windows Defender", StringComparison.OrdinalIgnoreCase) &&
                                    (targetObject.Contains("Exclusions", StringComparison.OrdinalIgnoreCase) ||
                                     targetObject.Contains("DisableRealtimeMonitoring", StringComparison.OrdinalIgnoreCase));

                if (isDefenderReg)
                {
                    attrs[AttributeKeys.DefenderExclusion] = details;
                    var evtType = targetObject.Contains("Exclusions", StringComparison.OrdinalIgnoreCase)
                        ? EventTypes.DefenderExclusionAdded
                        : EventTypes.DefenderRealtimeDisabled;
                    return SecurityEvent.Create(hostId, user, EventCategory.Defender, evtType, targetObject, attrs, $"defender:reg:{targetObject}", timestamp);
                }

                return SecurityEvent.Create(
                    hostId,
                    user,
                    EventCategory.Installation,
                    isStartup ? EventTypes.StartupEntryAdded : EventTypes.SysmonRegistryEvent,
                    targetObject,
                    attrs,
                    $"pid:{pid};reg:{targetObject}",
                    timestamp);
            }

            case 22: // DNS Query
            {
                var queryName = FirstNonEmpty(data, "QueryName") ?? string.Empty;
                var image = FirstNonEmpty(data, "Image");
                var pid = FirstNonEmpty(data, "ProcessId");

                if (!string.IsNullOrWhiteSpace(pid)) attrs[AttributeKeys.ProcessId] = pid;
                if (!string.IsNullOrWhiteSpace(image))
                {
                    attrs[AttributeKeys.ProcessPath] = image;
                    attrs[AttributeKeys.ProcessName] = Path.GetFileName(image);
                }
                if (!string.IsNullOrWhiteSpace(queryName)) attrs[AttributeKeys.Domain] = queryName.TrimEnd('.').ToLowerInvariant();

                return SecurityEvent.Create(
                    hostId, user, EventCategory.Network, EventTypes.DnsQuery,
                    queryName, attrs, $"pid:{pid};domain:{queryName}", timestamp);
            }

            default:
                return null;
        }
    }

    public static string? ExtractSha256FromSysmonHashes(string? hashes)
    {
        if (string.IsNullOrWhiteSpace(hashes)) return null;
        foreach (var part in hashes.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (part.StartsWith("SHA256=", StringComparison.OrdinalIgnoreCase))
            {
                return part["SHA256=".Length..].Trim().ToLowerInvariant();
            }
        }
        return null;
    }

    private static string? FirstNonEmpty(Dictionary<string, string> map, params string[] keys)
    {
        foreach (var k in keys)
        {
            if (map.TryGetValue(k, out var v) && !string.IsNullOrWhiteSpace(v))
                return v.Trim();
        }
        return null;
    }

    private void DisposeWatcher()
    {
        if (_watcher is null) return;
        try { _watcher.Enabled = false; } catch { /* ignoré */ }
        try { _watcher.Dispose(); } catch { /* ignoré */ }
        _watcher = null;
    }

    public void Dispose() => DisposeWatcher();
}
