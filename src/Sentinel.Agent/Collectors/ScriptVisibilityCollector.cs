using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Extensions.Logging;
using Sentinel.Agent.Configuration;
using Sentinel.Agent.Pipeline;
using Sentinel.Shared.Models;

namespace Sentinel.Agent.Collectors;

/// <summary>Résultat de l'analyse en mémoire d'un bloc de script (aucun contenu brut conservé par défaut).</summary>
public sealed record ScriptInspectionResult(
    string ScriptHash,
    int Length,
    double ObfuscationScore,
    IReadOnlyList<string> Indicators,
    bool IsLoggingBypass,
    bool IsSuspicious,
    string? SanitizedExcerpt);

/// <summary>
/// Collecteur de visibilité des scripts SANS fournisseur AMSI managé (v2 Mission 7) :
/// 1) Lit le journal PowerShell Script Block Logging (<c>Microsoft-Windows-PowerShell/Operational</c>, Event ID 4104) ;
/// 2) S'abonne en option au fournisseur ETW <c>Microsoft-Antimalware-Scan-Interface</c> lorsque les privilèges le permettent.
/// Confidentialité : ne stocke par défaut que les métadonnées (hash SHA-256, taille, indicateurs, score d'obfuscation) ;
/// un extrait nettoyé et tronqué n'est conservé que si <see cref="ScriptVisibilitySettings.StoreSanitizedExcerpt"/> est activé.
/// </summary>
public sealed partial class ScriptVisibilityCollector : IEventCollector, IDisposable
{
    public const string PowerShellOperationalLog = "Microsoft-Windows-PowerShell/Operational";
    public static readonly Guid AmsiEtwProviderGuid = new("2A576B87-09A7-520E-C21A-4942F0271D67");
    private const string PowerShell4104Query = "*[System[(EventID=4104)]]";

    private readonly IEventSink _sink;
    private readonly AgentStateStore _stateStore;
    private readonly ILogger<ScriptVisibilityCollector> _logger;

    private ScriptVisibilitySettings _settings = new();
    private EventLogWatcher? _psWatcher;
    private TraceEventSession? _etwSession;
    private Task? _etwTask;
    private CancellationTokenSource? _cts;
    private volatile bool _isRunning;
    private volatile string? _lastError;
    private long _eventsProduced;

    public string Name => "ScriptVisibility";
    public bool IsRunning => _isRunning;
    public string? LastError => _lastError;
    public long EventsProduced => Interlocked.Read(ref _eventsProduced);

    public ScriptVisibilityCollector(
        IEventSink sink,
        AgentStateStore stateStore,
        ILogger<ScriptVisibilityCollector> logger)
    {
        _sink = sink;
        _stateStore = stateStore;
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _settings = _stateStore.CurrentSettings.ScriptVisibility ?? new ScriptVisibilitySettings();
        if (!_settings.Enabled)
        {
            _isRunning = false;
            _lastError = "Visibilité scripts désactivée par configuration.";
            return Task.CompletedTask;
        }

        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var psActive = false;
        var etwActive = false;
        var notes = new List<string>();

        if (_settings.EnablePowerShell4104)
        {
            try
            {
                var query = new EventLogQuery(PowerShellOperationalLog, PathType.LogName, PowerShell4104Query);
                _psWatcher = new EventLogWatcher(query);
                _psWatcher.EventRecordWritten += OnPowerShell4104;
                _psWatcher.Enabled = true;
                psActive = true;
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or EventLogException)
            {
                DisposePsWatcher();
                notes.Add($"Journal PowerShell 4104 indisponible ({ex.Message})");
            }
        }

        if (_settings.EnableEtwAmsi)
        {
            try
            {
                if (TraceEventSession.IsElevated() == true)
                {
                    var sessionName = $"SentinelAmsiEtw-{Environment.ProcessId}";
                    _etwSession = new TraceEventSession(sessionName);
                    _etwSession.EnableProvider(AmsiEtwProviderGuid, TraceEventLevel.Informational);
                    _etwSession.Source.Dynamic.All += OnAmsiEtwEvent;
                    _etwTask = Task.Run(() =>
                    {
                        try { _etwSession.Source.Process(); } catch { /* arrêt normal */ }
                    }, _cts.Token);
                    etwActive = true;
                }
                else
                {
                    notes.Add("ETW AMSI désactivé sans privilèges administrateur (4104 utilisé)");
                }
            }
            catch (Exception ex)
            {
                DisposeEtwSession();
                notes.Add($"ETW AMSI indisponible ({ex.Message})");
            }
        }

        _isRunning = psActive || etwActive;
        _lastError = notes.Count > 0 ? string.Join(" ; ", notes) : null;
        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        _isRunning = false;
        _cts?.Cancel();
        DisposePsWatcher();
        DisposeEtwSession();

        if (_etwTask is not null)
        {
            try { await _etwTask.WaitAsync(TimeSpan.FromSeconds(2), cancellationToken); } catch { /* ignoré */ }
            _etwTask = null;
        }
    }

    public void UpdateSettings(SentinelSettings settings)
    {
        _settings = settings.ScriptVisibility ?? new ScriptVisibilitySettings();
    }

    private void OnPowerShell4104(object? sender, EventRecordWrittenEventArgs args)
    {
        if (!_isRunning || !_settings.Enabled || args.EventRecord is null) return;
        try
        {
            using var record = args.EventRecord;
            var evt = AnalyzeScriptBlockXml(
                record.ToXml(),
                _stateStore.HostId,
                _settings.StoreSanitizedExcerpt,
                _settings.MaxExcerptLength,
                Environment.UserName);

            if (evt is not null && _sink.Publish(evt))
            {
                Interlocked.Increment(ref _eventsProduced);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Erreur lors de l'analyse d'un événement PowerShell 4104.");
        }
    }

    private void OnAmsiEtwEvent(TraceEvent data)
    {
        if (!_isRunning || !_settings.Enabled) return;
        try
        {
            var appName = data.PayloadByName("appname")?.ToString() ?? data.ProcessName ?? "unknown";
            var contentName = data.PayloadByName("contentname")?.ToString() ?? string.Empty;
            var content = data.PayloadByName("content")?.ToString();
            if (string.IsNullOrWhiteSpace(content)) return;

            var inspection = InspectScriptText(content, _settings.StoreSanitizedExcerpt, _settings.MaxExcerptLength);
            if (!inspection.IsSuspicious) return;

            var attrs = BuildAttributes(inspection, "EtwAmsi", null, contentName, data.ProcessID);
            attrs[AttributeKeys.ProcessName] = appName;

            var evt = SecurityEvent.Create(
                _stateStore.HostId,
                Environment.UserName,
                EventCategory.Script,
                inspection.IsLoggingBypass ? EventTypes.ScriptLoggingBypass : EventTypes.AmsiScriptScan,
                string.IsNullOrWhiteSpace(contentName) ? $"amsi:{appName}" : contentName,
                attrs,
                $"pid:{data.ProcessID};script:{inspection.ScriptHash[..12]}",
                DateTimeOffset.UtcNow);

            if (_sink.Publish(evt))
            {
                Interlocked.Increment(ref _eventsProduced);
            }
        }
        catch
        {
            // Ignoré pour ne jamais perturber le flux ETW.
        }
    }

    /// <summary>
    /// Analyse un événement XML PowerShell Event ID 4104 en <see cref="SecurityEvent"/>.
    /// Retourne <c>null</c> pour les scripts bénins sans aucun indicateur suspect afin de préserver
    /// performances et confidentialité.
    /// </summary>
    public static SecurityEvent? AnalyzeScriptBlockXml(
        string xml,
        string hostId,
        bool storeSanitizedExcerpt = false,
        int maxExcerptLength = 300,
        string defaultUser = "unknown")
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
        if (!int.TryParse(eventIdStr, NumberStyles.Integer, CultureInfo.InvariantCulture, out var eventId) || eventId != 4104)
        {
            return null;
        }

        var timeCreatedRaw = system?.Elements().FirstOrDefault(e => e.Name.LocalName == "TimeCreated")?.Attribute("SystemTime")?.Value;
        var timestamp = DateTimeOffset.TryParse(timeCreatedRaw, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var parsedTs)
            ? parsedTs.ToUniversalTime()
            : DateTimeOffset.UtcNow;

        var pidRaw = system?.Elements().FirstOrDefault(e => e.Name.LocalName == "Execution")?.Attribute("ProcessID")?.Value;
        int.TryParse(pidRaw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var pid);

        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var el in doc.Descendants().Where(e => e.Name.LocalName == "Data"))
        {
            var name = el.Attribute("Name")?.Value;
            if (!string.IsNullOrWhiteSpace(name))
            {
                data[name] = el.Value;
            }
        }

        if (!data.TryGetValue("ScriptBlockText", out var scriptText) || string.IsNullOrWhiteSpace(scriptText))
        {
            return null;
        }

        var inspection = InspectScriptText(scriptText, storeSanitizedExcerpt, maxExcerptLength);
        if (!inspection.IsSuspicious)
        {
            return null;
        }

        data.TryGetValue("ScriptBlockId", out var blockId);
        data.TryGetValue("Path", out var scriptPath);

        var attrs = BuildAttributes(inspection, "PowerShell4104", blockId, scriptPath, pid);
        attrs[AttributeKeys.WindowsEventId] = "4104";
        attrs[AttributeKeys.ProcessName] = "powershell.exe";

        var subject = !string.IsNullOrWhiteSpace(scriptPath)
            ? scriptPath.Trim()
            : $"ScriptBlock:{(string.IsNullOrWhiteSpace(blockId) ? inspection.ScriptHash[..12] : blockId.Trim())}";

        return SecurityEvent.Create(
            hostId,
            defaultUser,
            EventCategory.Script,
            inspection.IsLoggingBypass ? EventTypes.ScriptLoggingBypass : EventTypes.PowerShellScriptBlock,
            subject,
            attrs,
            $"pid:{pid};script:{inspection.ScriptHash[..12]}",
            timestamp);
    }

    /// <summary>Inspecte un texte de script en mémoire et en extrait uniquement métadonnées, hash et indicateurs.</summary>
    public static ScriptInspectionResult InspectScriptText(
        string scriptText,
        bool storeSanitizedExcerpt = false,
        int maxExcerptLength = 300)
    {
        var normalized = scriptText ?? string.Empty;
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(normalized))).ToLowerInvariant();
        var indicators = new List<string>();
        var isBypass = false;

        if (EncodedCommandRegex().IsMatch(normalized))
        {
            indicators.Add("EncodedCommand");
        }

        var hasDownload = DownloadRegex().IsMatch(normalized);
        var hasExec = InvokeExecRegex().IsMatch(normalized);
        if (hasDownload && hasExec)
        {
            indicators.Add("DownloadAndExecute");
        }
        else if (hasDownload)
        {
            indicators.Add("RemoteDownload");
        }

        if (LoggingOrDefenderBypassRegex().IsMatch(normalized))
        {
            indicators.Add("LoggingOrDefenseBypass");
            isBypass = true;
        }

        if (RecoveryOrCredAbuseRegex().IsMatch(normalized))
        {
            indicators.Add("RecoveryOrCredentialAbuse");
        }

        var obfScore = ComputeObfuscationScore(normalized);
        if (obfScore >= 0.55)
        {
            indicators.Add("HighObfuscation");
        }

        var isSuspicious = indicators.Count > 0;
        string? excerpt = null;
        if (isSuspicious && storeSanitizedExcerpt)
        {
            excerpt = SanitizeAndTruncateExcerpt(normalized, Math.Clamp(maxExcerptLength, 64, 512));
        }

        return new ScriptInspectionResult(
            hash,
            normalized.Length,
            Math.Round(obfScore, 3),
            indicators,
            isBypass,
            isSuspicious,
            excerpt);
    }

    public static double ComputeObfuscationScore(string text)
    {
        if (string.IsNullOrWhiteSpace(text) || text.Length < 16) return 0;

        var score = 0.0;
        var backticks = text.Count(c => c == '`');
        if (backticks >= 4) score += Math.Min(0.45, backticks * 0.05);

        if (CharArrayObfuscationRegex().IsMatch(text)) score += 0.35;
        if (text.Contains("-join", StringComparison.OrdinalIgnoreCase) && text.Contains('[') && text.Contains(']')) score += 0.25;

        var longBase64Matches = LongBase64Regex().Matches(text);
        if (longBase64Matches.Count > 0) score += 0.35;

        var specialChars = text.Count(c => c is '^' or '$' or '+' or '{' or '}' or '(' or ')');
        var specialRatio = (double)specialChars / text.Length;
        if (specialRatio > 0.28) score += 0.25;

        return Math.Clamp(score, 0.0, 1.0);
    }

    /// <summary>Nettoie les secrets potentiels (tokens, mots de passe, chaînes de connexion) et tronque l'extrait.</summary>
    public static string SanitizeAndTruncateExcerpt(string text, int maxLen)
    {
        var singleLine = WhitespaceRegex().Replace(text, " ").Trim();
        singleLine = SecretValueRegex().Replace(singleLine, "$1=[REDACTED]");
        return singleLine.Length <= maxLen ? singleLine : singleLine[..maxLen] + "...";
    }

    private static Dictionary<string, string> BuildAttributes(
        ScriptInspectionResult inspection,
        string source,
        string? blockId,
        string? scriptPath,
        int pid)
    {
        var attrs = new Dictionary<string, string>
        {
            [AttributeKeys.ScriptHash] = inspection.ScriptHash,
            [AttributeKeys.ScriptLength] = inspection.Length.ToString(CultureInfo.InvariantCulture),
            [AttributeKeys.ScriptObfuscationScore] = inspection.ObfuscationScore.ToString("F2", CultureInfo.InvariantCulture),
            [AttributeKeys.ScriptIndicators] = string.Join(",", inspection.Indicators),
            [AttributeKeys.CollectorSource] = source,
            [AttributeKeys.EventSources] = source
        };

        if (pid > 0) attrs[AttributeKeys.ProcessId] = pid.ToString(CultureInfo.InvariantCulture);
        if (!string.IsNullOrWhiteSpace(blockId)) attrs[AttributeKeys.ScriptBlockId] = blockId.Trim();
        if (!string.IsNullOrWhiteSpace(scriptPath)) attrs[AttributeKeys.ScriptPath] = scriptPath.Trim();
        if (!string.IsNullOrWhiteSpace(inspection.SanitizedExcerpt)) attrs[AttributeKeys.ScriptExcerpt] = inspection.SanitizedExcerpt;

        return attrs;
    }

    [GeneratedRegex(@"(?i)(?:-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedcommand)\s+[A-Za-z0-9+/=]{16,}|FromBase64String\s*\()", RegexOptions.Compiled)]
    private static partial Regex EncodedCommandRegex();

    [GeneratedRegex(@"(?i)(?:DownloadString|DownloadFile|DownloadData|Invoke-WebRequest|\biwr\b|\birm\b|Invoke-RestMethod|Start-BitsTransfer|Net\.WebClient|Msxml2\.XMLHTTP)", RegexOptions.Compiled)]
    private static partial Regex DownloadRegex();

    [GeneratedRegex(@"(?i)(?:\bIEX\b|Invoke-Expression|Invoke-Command|\bICM\b|ScriptBlock\]::Create|Start-Process)", RegexOptions.Compiled)]
    private static partial Regex InvokeExecRegex();

    [GeneratedRegex(@"(?i)(?:AmsiUtils|amsiInitFailed|AmsiScanBuffer|EnableScriptBlockLogging|Set-MpPreference\s+.*-Disable|Add-MpPreference\s+.*-Exclusion|EtwEventWrite)", RegexOptions.Compiled)]
    private static partial Regex LoggingOrDefenderBypassRegex();

    [GeneratedRegex(@"(?i)(?:vssadmin\s+delete\s+shadows|wbadmin\s+delete\s+catalog|bcdedit\s+/set.*recoveryenabled\s+no|MiniDumpWriteDump|lsass\.dmp)", RegexOptions.Compiled)]
    private static partial Regex RecoveryOrCredAbuseRegex();

    [GeneratedRegex(@"(?i)(?:\[char\]\s*\d+|\[convert\]::ToChar|\-bxor\s+\d+)", RegexOptions.Compiled)]
    private static partial Regex CharArrayObfuscationRegex();

    [GeneratedRegex(@"[A-Za-z0-9+/]{64,}={0,2}", RegexOptions.Compiled)]
    private static partial Regex LongBase64Regex();

    [GeneratedRegex(@"\s+", RegexOptions.Compiled)]
    private static partial Regex WhitespaceRegex();

    [GeneratedRegex(@"(?i)(password|passwd|pwd|secret|apikey|api_key|token|bearer)\s*[:=]\s*['""]?[^\s'"";]+['""]?", RegexOptions.Compiled)]
    private static partial Regex SecretValueRegex();

    private void DisposePsWatcher()
    {
        if (_psWatcher is null) return;
        try { _psWatcher.Enabled = false; } catch { /* ignoré */ }
        try { _psWatcher.Dispose(); } catch { /* ignoré */ }
        _psWatcher = null;
    }

    private void DisposeEtwSession()
    {
        if (_etwSession is null) return;
        try { _etwSession.Stop(); } catch { /* ignoré */ }
        try { _etwSession.Dispose(); } catch { /* ignoré */ }
        _etwSession = null;
    }

    public void Dispose()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        DisposePsWatcher();
        DisposeEtwSession();
    }
}
