using System.Collections.Concurrent;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Management;
using System.ServiceProcess;
using System.Text.Json;
using System.Xml.Linq;
using Microsoft.Extensions.Logging;
using Sentinel.Agent.Configuration;
using Sentinel.Agent.Pipeline;
using Sentinel.Shared.Models;

namespace Sentinel.Agent.Collectors;

/// <summary>Snapshot de l'état de santé de Microsoft Defender sur le poste.</summary>
public sealed record DefenderHealthSnapshot(
    bool Available,
    bool RealtimeProtectionEnabled,
    bool ServiceRunning,
    string? SignatureVersion,
    string? Error);

/// <summary>
/// Collecteur Microsoft Defender (v2 Mission 1) :
/// 1) Écoute le journal <c>Microsoft-Windows-Windows Defender/Operational</c> (détections 1116/1117/1118/1119,
///    affaiblissement 5001/5007/5010/5012/5101) ;
/// 2) Interroge périodiquement WMI <c>root\Microsoft\Windows\Defender</c> (<c>MSFT_MpThreatDetection</c>,
///    <c>MSFT_MpThreat</c>, <c>MSFT_MpComputerStatus</c>, <c>MSFT_MpPreference</c>) pour capturer
///    les détections actives, la désactivation temps réel, l'arrêt du service WinDefend et l'ajout d'exclusions.
/// </summary>
public sealed class DefenderCollector : IEventCollector, IDisposable
{
    public const string OperationalLogName = "Microsoft-Windows-Windows Defender/Operational";
    private const string DefenderWmiNamespace = @"root\Microsoft\Windows\Defender";
    private const string OperationalXPathQuery =
        "*[System[(EventID=1116 or EventID=1117 or EventID=1118 or EventID=1119 or EventID=5001 or EventID=5007 or EventID=5010 or EventID=5012 or EventID=5101)]]";

    private readonly IEventSink _sink;
    private readonly AgentStateStore _stateStore;
    private readonly ILogger<DefenderCollector> _logger;
    private readonly ConcurrentDictionary<string, byte> _seenWmiDetections = new(StringComparer.OrdinalIgnoreCase);

    private HashSet<string> _knownExclusions = new(StringComparer.OrdinalIgnoreCase);
    private bool _exclusionsBaselineInitialized;
    private bool? _lastRealtimeEnabled;
    private bool? _lastServiceRunning;

    private EventLogWatcher? _watcher;
    private CancellationTokenSource? _cts;
    private Task? _wmiPollingTask;
    private volatile bool _enabled = true;
    private volatile bool _isRunning;
    private volatile string? _lastError;
    private long _eventsProduced;

    public string Name => "Defender";
    public bool IsRunning => _isRunning;
    public string? LastError => _lastError;
    public long EventsProduced => Interlocked.Read(ref _eventsProduced);

    public DefenderCollector(
        IEventSink sink,
        AgentStateStore stateStore,
        ILogger<DefenderCollector> logger)
    {
        _sink = sink;
        _stateStore = stateStore;
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (!_enabled)
        {
            _isRunning = false;
            _lastError = "Désactivé par configuration.";
            return Task.CompletedTask;
        }

        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var logStarted = false;
        string? logError = null;

        try
        {
            var query = new EventLogQuery(OperationalLogName, PathType.LogName, OperationalXPathQuery);
            _watcher = new EventLogWatcher(query);
            _watcher.EventRecordWritten += OnDefenderEventRecord;
            _watcher.Enabled = true;
            logStarted = true;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or EventLogException)
        {
            DisposeWatcher();
            logError = $"Journal Defender inaccessible ({ex.Message})";
            _logger.LogWarning("Collecteur Defender : {Reason}. Poursuite via WMI.", logError);
        }

        var health = ProbeStatus();
        _lastRealtimeEnabled = health.Available ? health.RealtimeProtectionEnabled : null;
        _lastServiceRunning = health.ServiceRunning;
        _isRunning = logStarted || health.Available || health.ServiceRunning;
        _lastError = health.Available
            ? (health.RealtimeProtectionEnabled ? logError : "Defender actif mais protection temps réel désactivée")
            : (logError ?? health.Error ?? "Microsoft Defender non détecté");

        _wmiPollingTask = Task.Run(() => WmiPollLoopAsync(_cts.Token), _cts.Token);
        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        _isRunning = false;
        _cts?.Cancel();
        DisposeWatcher();

        if (_wmiPollingTask is not null)
        {
            try { await _wmiPollingTask.WaitAsync(TimeSpan.FromSeconds(3), cancellationToken); } catch { /* ignoré */ }
            _wmiPollingTask = null;
        }
    }

    public void UpdateSettings(SentinelSettings settings)
    {
        _enabled = settings.EnableDefenderCollector;
    }

    /// <summary>Sonde l'état courant de Microsoft Defender via WMI et le gestionnaire de services.</summary>
    public static DefenderHealthSnapshot ProbeStatus()
    {
        bool serviceRunning = false;
        try
        {
            using var sc = new ServiceController("WinDefend");
            serviceRunning = sc.Status == ServiceControllerStatus.Running;
        }
        catch
        {
            serviceRunning = false;
        }

        try
        {
            var scope = new ManagementScope(DefenderWmiNamespace);
            scope.Connect();
            using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery(
                "SELECT RealTimeProtectionEnabled, AntivirusEnabled, AntivirusSignatureVersion FROM MSFT_MpComputerStatus"));
            using var results = searcher.Get();
            foreach (ManagementObject obj in results)
            {
                var rt = obj["RealTimeProtectionEnabled"] is bool b && b;
                var av = obj["AntivirusEnabled"] is bool a && a;
                var sig = obj["AntivirusSignatureVersion"]?.ToString();
                return new DefenderHealthSnapshot(av || serviceRunning, rt, serviceRunning, sig, null);
            }
        }
        catch (Exception ex)
        {
            return new DefenderHealthSnapshot(serviceRunning, serviceRunning, serviceRunning, null, ex.Message);
        }

        return new DefenderHealthSnapshot(serviceRunning, false, serviceRunning, null, "Aucune instance MSFT_MpComputerStatus.");
    }

    private void OnDefenderEventRecord(object? sender, EventRecordWrittenEventArgs args)
    {
        if (!_isRunning || !_enabled || args.EventRecord is null) return;
        try
        {
            using var record = args.EventRecord;
            var xml = record.ToXml();
            var evt = ParseOperationalEventXml(xml, _stateStore.HostId, Environment.UserName);
            if (evt is not null && _sink.Publish(evt))
            {
                Interlocked.Increment(ref _eventsProduced);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Erreur lors de l'analyse d'un événement Defender Operational.");
        }
    }

    private async Task WmiPollLoopAsync(CancellationToken ct)
    {
        // Premier passage pour établir la baseline d'exclusions et détecter un affaiblissement existant
        PollWmiOnce();

        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(20), ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            if (!_enabled) continue;
            PollWmiOnce();
        }
    }

    private void PollWmiOnce()
    {
        try
        {
            var health = ProbeStatus();
            var now = DateTimeOffset.UtcNow;

            if (_lastServiceRunning == true && !health.ServiceRunning)
            {
                PublishWeakeningEvent(
                    EventTypes.DefenderServiceStopped,
                    "WinDefend",
                    "Service Microsoft Defender (WinDefend) arrêté",
                    "DefenderWMI",
                    now);
            }
            _lastServiceRunning = health.ServiceRunning;

            if (health.Available)
            {
                if ((_lastRealtimeEnabled == true && !health.RealtimeProtectionEnabled) ||
                    (_lastRealtimeEnabled is null && !health.RealtimeProtectionEnabled))
                {
                    PublishWeakeningEvent(
                        EventTypes.DefenderRealtimeDisabled,
                        "RealTimeProtection",
                        "Protection temps réel Microsoft Defender désactivée",
                        "DefenderWMI",
                        now);
                }
                _lastRealtimeEnabled = health.RealtimeProtectionEnabled;
            }

            PollWmiExclusions(now);
            PollWmiThreatDetections();
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Échec de sonde WMI Microsoft Defender.");
        }
    }

    private void PollWmiExclusions(DateTimeOffset now)
    {
        try
        {
            var scope = new ManagementScope(DefenderWmiNamespace);
            scope.Connect();
            using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery(
                "SELECT ExclusionPath, ExclusionProcess, ExclusionExtension FROM MSFT_MpPreference"));
            using var results = searcher.Get();

            var current = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (ManagementObject obj in results)
            {
                AddArrayEntries(current, "path", obj["ExclusionPath"]);
                AddArrayEntries(current, "process", obj["ExclusionProcess"]);
                AddArrayEntries(current, "ext", obj["ExclusionExtension"]);
            }

            if (!_exclusionsBaselineInitialized)
            {
                _knownExclusions = current;
                _exclusionsBaselineInitialized = true;
                return;
            }

            foreach (var added in current.Where(e => !_knownExclusions.Contains(e)))
            {
                var attrs = new Dictionary<string, string>
                {
                    [AttributeKeys.DefenderExclusion] = added,
                    [AttributeKeys.DefenderStatus] = "ExclusionAdded",
                    [AttributeKeys.CollectorSource] = "DefenderWMI",
                    [AttributeKeys.EventSources] = "DefenderWMI"
                };

                var evt = SecurityEvent.Create(
                    _stateStore.HostId,
                    Environment.UserName,
                    EventCategory.Defender,
                    EventTypes.DefenderExclusionAdded,
                    added,
                    attrs,
                    $"defender:exclusion:{added}",
                    now);

                if (_sink.Publish(evt))
                {
                    Interlocked.Increment(ref _eventsProduced);
                }
            }

            _knownExclusions = current;
        }
        catch
        {
            // Accès WMI MSFT_MpPreference restreint sans privilèges administrateur : ignoré proprement.
        }
    }

    private void PollWmiThreatDetections()
    {
        try
        {
            var scope = new ManagementScope(DefenderWmiNamespace);
            scope.Connect();

            // Charge le dictionnaire ThreatID -> (ThreatName, SeverityID, CategoryID) depuis MSFT_MpThreat
            var catalog = new Dictionary<string, (string Name, string Severity, string Category)>(StringComparer.OrdinalIgnoreCase);
            using (var threatSearcher = new ManagementObjectSearcher(scope, new ObjectQuery(
                "SELECT ThreatID, ThreatName, SeverityID, CategoryID FROM MSFT_MpThreat")))
            using (var threatResults = threatSearcher.Get())
            {
                foreach (ManagementObject t in threatResults)
                {
                    var tid = t["ThreatID"]?.ToString();
                    if (string.IsNullOrWhiteSpace(tid)) continue;
                    catalog[tid] = (
                        t["ThreatName"]?.ToString() ?? $"Threat-{tid}",
                        MapSeverityId(t["SeverityID"]?.ToString()),
                        t["CategoryID"]?.ToString() ?? "Unknown");
                }
            }

            using var detSearcher = new ManagementObjectSearcher(scope, new ObjectQuery(
                "SELECT DetectionID, ThreatID, ProcessName, Resources, InitialDetectionTime, ActionSuccess, CleaningActionID, DomainUser FROM MSFT_MpThreatDetection"));
            using var detResults = detSearcher.Get();
            foreach (ManagementObject d in detResults)
            {
                var detectionId = d["DetectionID"]?.ToString() ?? Guid.NewGuid().ToString("N");
                if (!_seenWmiDetections.TryAdd(detectionId, 0))
                {
                    continue;
                }

                var threatId = d["ThreatID"]?.ToString() ?? string.Empty;
                (string Name, string Severity, string Category) info = catalog.TryGetValue(threatId, out var c)
                    ? c
                    : ($"Threat-{threatId}", "High", "Malware");

                var resources = d["Resources"] is string[] arr ? arr : [];
                var firstResource = resources.FirstOrDefault() ?? string.Empty;
                var filePath = ExtractResourcePath(firstResource);

                var dto = new DefenderWmiDetectionModel(
                    DetectionId: detectionId,
                    ThreatId: threatId,
                    ThreatName: info.Name,
                    Severity: info.Severity,
                    Category: info.Category,
                    ProcessName: d["ProcessName"]?.ToString(),
                    FilePath: filePath,
                    DomainUser: d["DomainUser"]?.ToString(),
                    Action: MapCleaningAction(d["CleaningActionID"]?.ToString()),
                    ActionSuccess: d["ActionSuccess"] is bool ok && ok,
                    DetectedAt: TryParseWmiDateTime(d["InitialDetectionTime"]?.ToString()) ?? DateTimeOffset.UtcNow);

                var evt = ConvertWmiDetection(dto, _stateStore.HostId, Environment.UserName);
                if (_sink.Publish(evt))
                {
                    Interlocked.Increment(ref _eventsProduced);
                }
            }
        }
        catch
        {
            // Namespace WMI non accessible ou vide : mode dégradé silencieux.
        }
    }

    private void PublishWeakeningEvent(string eventType, string subject, string reason, string source, DateTimeOffset ts)
    {
        var attrs = new Dictionary<string, string>
        {
            [AttributeKeys.Reason] = reason,
            [AttributeKeys.DefenderStatus] = eventType,
            [AttributeKeys.CollectorSource] = source,
            [AttributeKeys.EventSources] = source
        };

        var evt = SecurityEvent.Create(
            _stateStore.HostId,
            Environment.UserName,
            EventCategory.Defender,
            eventType,
            subject,
            attrs,
            $"defender:{eventType}",
            ts);

        if (_sink.Publish(evt))
        {
            Interlocked.Increment(ref _eventsProduced);
        }
    }

    /// <summary>
    /// Parse un événement XML du journal <c>Microsoft-Windows-Windows Defender/Operational</c> en <see cref="SecurityEvent"/>.
    /// Méthode pure dédiée aussi aux tests unitaires avec fixtures XML.
    /// </summary>
    public static SecurityEvent? ParseOperationalEventXml(string xml, string hostId, string defaultUser = "SYSTEM")
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

        var user = FirstNonEmpty(data, "Detection User", "User", "DomainUser") ?? defaultUser;
        var attrs = new Dictionary<string, string>
        {
            [AttributeKeys.WindowsEventId] = eventId.ToString(CultureInfo.InvariantCulture),
            [AttributeKeys.CollectorSource] = "DefenderEventLog",
            [AttributeKeys.EventSources] = "DefenderEventLog"
        };

        switch (eventId)
        {
            case 1116:
            case 1117:
            case 1118:
            case 1119:
            {
                var threatName = FirstNonEmpty(data, "Threat Name", "Name") ?? "UnknownThreat";
                var threatId = FirstNonEmpty(data, "Threat ID", "ID") ?? string.Empty;
                var severity = FirstNonEmpty(data, "Severity Name", "Severity") ?? (eventId is 1118 or 1119 ? "Severe" : "High");
                var category = FirstNonEmpty(data, "Category Name", "Category") ?? "Malware";
                var rawPath = FirstNonEmpty(data, "Path", "Resources") ?? threatName;
                var filePath = ExtractResourcePath(rawPath);
                var procName = FirstNonEmpty(data, "Process Name", "ProcessName");
                var action = FirstNonEmpty(data, "Action Name", "Action");

                attrs[AttributeKeys.DefenderThreatName] = threatName;
                if (!string.IsNullOrWhiteSpace(threatId)) attrs[AttributeKeys.DefenderThreatId] = threatId;
                attrs[AttributeKeys.DefenderSeverity] = severity;
                attrs[AttributeKeys.DefenderCategory] = category;
                if (!string.IsNullOrWhiteSpace(filePath)) attrs[AttributeKeys.FilePath] = filePath;
                if (!string.IsNullOrWhiteSpace(procName)) attrs[AttributeKeys.ProcessName] = procName;
                if (!string.IsNullOrWhiteSpace(action)) attrs[AttributeKeys.DefenderAction] = action;

                var eventType = eventId == 1117 ? EventTypes.DefenderActionTaken : EventTypes.DefenderThreatDetected;
                if (eventId is 1118 or 1119)
                {
                    attrs[AttributeKeys.DefenderStatus] = "ActionFailed";
                }

                var hints = $"defender:{threatId};file:{filePath}";
                return SecurityEvent.Create(
                    hostId,
                    user,
                    EventCategory.Defender,
                    eventType,
                    string.IsNullOrWhiteSpace(filePath) ? threatName : filePath,
                    attrs,
                    hints,
                    timestamp);
            }

            case 5001:
                attrs[AttributeKeys.DefenderStatus] = "RealtimeDisabled";
                attrs[AttributeKeys.Reason] = "Protection temps réel Microsoft Defender désactivée (Event ID 5001)";
                return SecurityEvent.Create(hostId, user, EventCategory.Defender, EventTypes.DefenderRealtimeDisabled,
                    "RealTimeProtection", attrs, "defender:realtime-disabled", timestamp);

            case 5007:
            {
                var newValue = FirstNonEmpty(data, "New Value", "NewValue") ?? string.Empty;
                var oldValue = FirstNonEmpty(data, "Old Value", "OldValue") ?? string.Empty;
                var combined = $"{newValue} {oldValue}";
                if (combined.Contains("Exclusions", StringComparison.OrdinalIgnoreCase))
                {
                    attrs[AttributeKeys.DefenderExclusion] = newValue;
                    attrs[AttributeKeys.DefenderStatus] = "ExclusionAdded";
                    attrs[AttributeKeys.Reason] = $"Exclusion Microsoft Defender ajoutée : {newValue}";
                    return SecurityEvent.Create(hostId, user, EventCategory.Defender, EventTypes.DefenderExclusionAdded,
                        string.IsNullOrWhiteSpace(newValue) ? "DefenderExclusion" : newValue, attrs, $"defender:exclusion:{newValue}", timestamp);
                }

                if (combined.Contains("DisableRealtimeMonitoring", StringComparison.OrdinalIgnoreCase) &&
                    newValue.Contains("0x1", StringComparison.OrdinalIgnoreCase))
                {
                    attrs[AttributeKeys.DefenderStatus] = "RealtimeDisabled";
                    attrs[AttributeKeys.Reason] = "DisableRealtimeMonitoring activé dans la configuration Defender (Event ID 5007)";
                    return SecurityEvent.Create(hostId, user, EventCategory.Defender, EventTypes.DefenderRealtimeDisabled,
                        "DisableRealtimeMonitoring", attrs, "defender:realtime-disabled", timestamp);
                }

                if (combined.Contains("DisableAntiSpyware", StringComparison.OrdinalIgnoreCase) ||
                    combined.Contains("DisableBehaviorMonitoring", StringComparison.OrdinalIgnoreCase) ||
                    combined.Contains("DisableIOAVProtection", StringComparison.OrdinalIgnoreCase))
                {
                    attrs[AttributeKeys.DefenderStatus] = "Tampering";
                    attrs[AttributeKeys.Reason] = $"Affaiblissement de la configuration Defender : {newValue}";
                    return SecurityEvent.Create(hostId, user, EventCategory.Defender, EventTypes.DefenderTampering,
                        newValue, attrs, "defender:tampering", timestamp);
                }

                return null;
            }

            case 5010:
            case 5012:
                attrs[AttributeKeys.DefenderStatus] = "ScanningDisabled";
                attrs[AttributeKeys.Reason] = $"Analyse antivirus/antispyware Defender désactivée (Event ID {eventId})";
                return SecurityEvent.Create(hostId, user, EventCategory.Defender, EventTypes.DefenderTampering,
                    $"DefenderScanningDisabled-{eventId}", attrs, "defender:tampering", timestamp);

            case 5101:
                attrs[AttributeKeys.DefenderStatus] = "ServiceStopped";
                attrs[AttributeKeys.Reason] = "Arrêt ou altération du service Microsoft Defender (Event ID 5101)";
                return SecurityEvent.Create(hostId, user, EventCategory.Defender, EventTypes.DefenderServiceStopped,
                    "WinDefend", attrs, "defender:service-stopped", timestamp);

            default:
                return null;
        }
    }

    /// <summary>
    /// Parse un document JSON représentant une détection WMI (<c>MSFT_MpThreatDetection</c> + <c>MSFT_MpThreat</c>).
    /// Utile pour l'ingestion et les tests unitaires reproductibles.
    /// </summary>
    public static SecurityEvent? ParseWmiThreatDetectionJson(string json, string hostId, string defaultUser = "SYSTEM")
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try
        {
            var model = JsonSerializer.Deserialize<DefenderWmiDetectionModel>(json, new JsonSerializerOptions(JsonSerializerDefaults.Web));
            return model is null ? null : ConvertWmiDetection(model, hostId, defaultUser);
        }
        catch
        {
            return null;
        }
    }

    public static SecurityEvent ConvertWmiDetection(DefenderWmiDetectionModel dto, string hostId, string defaultUser)
    {
        var attrs = new Dictionary<string, string>
        {
            [AttributeKeys.DefenderThreatId] = dto.ThreatId ?? string.Empty,
            [AttributeKeys.DefenderThreatName] = dto.ThreatName ?? "UnknownThreat",
            [AttributeKeys.DefenderSeverity] = string.IsNullOrWhiteSpace(dto.Severity) ? "High" : dto.Severity,
            [AttributeKeys.DefenderCategory] = string.IsNullOrWhiteSpace(dto.Category) ? "Malware" : dto.Category,
            [AttributeKeys.CollectorSource] = "DefenderWMI",
            [AttributeKeys.EventSources] = "DefenderWMI"
        };

        if (!string.IsNullOrWhiteSpace(dto.FilePath)) attrs[AttributeKeys.FilePath] = dto.FilePath;
        if (!string.IsNullOrWhiteSpace(dto.ProcessName)) attrs[AttributeKeys.ProcessName] = dto.ProcessName;
        if (!string.IsNullOrWhiteSpace(dto.Action)) attrs[AttributeKeys.DefenderAction] = dto.Action;
        if (!dto.ActionSuccess) attrs[AttributeKeys.DefenderStatus] = "ActionPendingOrFailed";

        var user = string.IsNullOrWhiteSpace(dto.DomainUser) ? defaultUser : dto.DomainUser;
        var subject = !string.IsNullOrWhiteSpace(dto.FilePath) ? dto.FilePath : (dto.ThreatName ?? "DefenderThreat");
        var hints = $"defender:{dto.ThreatId};file:{dto.FilePath}";

        return SecurityEvent.Create(
            hostId,
            user,
            EventCategory.Defender,
            EventTypes.DefenderThreatDetected,
            subject,
            attrs,
            hints,
            dto.DetectedAt == default ? DateTimeOffset.UtcNow : dto.DetectedAt);
    }

    private static string ExtractResourcePath(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return string.Empty;
        var cleaned = raw.Trim();
        // Format Defender courant : "file:_C:\Users\...\eicar.com" ou "containerfile:_C:\..."
        var idx = cleaned.IndexOf(":_", StringComparison.Ordinal);
        if (idx >= 0 && idx + 2 < cleaned.Length)
        {
            cleaned = cleaned[(idx + 2)..];
        }
        var arrowIdx = cleaned.IndexOf("->", StringComparison.Ordinal);
        if (arrowIdx > 0)
        {
            cleaned = cleaned[..arrowIdx].Trim();
        }
        return cleaned;
    }

    private static void AddArrayEntries(HashSet<string> target, string kind, object? value)
    {
        if (value is string[] items)
        {
            foreach (var item in items)
            {
                if (!string.IsNullOrWhiteSpace(item))
                    target.Add($"{kind}:{item.Trim()}");
            }
        }
    }

    private static string MapSeverityId(string? id) => id switch
    {
        "1" => "Low",
        "2" => "Moderate",
        "4" => "High",
        "5" => "Severe",
        _ => "High"
    };

    private static string MapCleaningAction(string? id) => id switch
    {
        "1" => "Clean",
        "2" => "Quarantine",
        "3" => "Remove",
        "6" => "Allow",
        "8" => "UserDefined",
        "9" => "NoAction",
        "10" => "Block",
        _ => "Unknown"
    };

    private static DateTimeOffset? TryParseWmiDateTime(string? wmiDate)
    {
        if (string.IsNullOrWhiteSpace(wmiDate)) return null;
        try
        {
            var dt = ManagementDateTimeConverter.ToDateTime(wmiDate);
            return new DateTimeOffset(dt.ToUniversalTime(), TimeSpan.Zero);
        }
        catch
        {
            return DateTimeOffset.TryParse(wmiDate, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var parsed)
                ? parsed.ToUniversalTime()
                : null;
        }
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

    public void Dispose()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        DisposeWatcher();
    }
}

/// <summary>Modèle JSON/WMI d'une détection Microsoft Defender (<c>MSFT_MpThreatDetection</c>).</summary>
public sealed record DefenderWmiDetectionModel(
    string? DetectionId,
    string? ThreatId,
    string? ThreatName,
    string? Severity,
    string? Category,
    string? ProcessName,
    string? FilePath,
    string? DomainUser,
    string? Action,
    bool ActionSuccess,
    DateTimeOffset DetectedAt);
