using System.Diagnostics;
using System.Globalization;
using System.Management;
using System.Security.Principal;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Extensions.Logging;
using Sentinel.Agent.Configuration;
using Sentinel.Agent.Pipeline;
using Sentinel.Shared.Models;

namespace Sentinel.Agent.Collectors;

/// <summary>
/// Collecteur de processus (doc §6.1) avec dégradation gracieuse en 3 niveaux :
/// 1) ETW <c>Microsoft-Windows-Kernel-Process</c> si élevé ;
/// 2) WMI <c>Win32_ProcessStartTrace</c> / <c>Win32_ProcessStopTrace</c> ;
/// 3) Polling léger (<c>Process.GetProcesses()</c>, 3 s) sans privilèges Administrateur.
/// </summary>
public sealed class ProcessCollector : IEventCollector, IDisposable
{
    private const string EtwSessionName = "Sentinel-Process-ETW";
    private static readonly Guid KernelProcessProviderGuid = new("22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716");

    private readonly IEventSink _sink;
    private readonly AgentStateStore _stateStore;
    private readonly ProcessEnricher _enricher;
    private readonly ILogger<ProcessCollector> _logger;

    private volatile SentinelSettings _settings;
    private volatile bool _isRunning;
    private volatile string? _lastError;
    private long _eventsProduced;

    private TraceEventSession? _etwSession;
    private Thread? _etwThread;
    private ManagementEventWatcher? _wmiStartWatcher;
    private ManagementEventWatcher? _wmiStopWatcher;
    private CancellationTokenSource? _cts;
    private Task? _pollingTask;

    public string Name => "Process";
    public bool IsRunning => _isRunning;
    public string? LastError => _lastError;
    public long EventsProduced => Interlocked.Read(ref _eventsProduced);

    public ProcessCollector(
        IEventSink sink,
        AgentStateStore stateStore,
        ProcessEnricher enricher,
        ILogger<ProcessCollector> logger)
    {
        _sink = sink;
        _stateStore = stateStore;
        _enricher = enricher;
        _logger = logger;
        _settings = stateStore.CurrentSettings;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        SeedKnownProcesses();

        if (IsAdministrator() && TryStartEtw())
        {
            _isRunning = true;
            _lastError = null;
            return Task.CompletedTask;
        }

        if (TryStartWmi())
        {
            _isRunning = true;
            _lastError = IsAdministrator()
                ? "ETW indisponible ; collecte WMI Win32_ProcessStartTrace active."
                : "Exécution sans privilèges Administrateur ; collecte WMI active.";
            return Task.CompletedTask;
        }

        // Fallback universel non privilégié.
        _isRunning = true;
        _lastError = "Mode dégradé (polling léger 3 s) : privilèges Administrateur requis pour ETW/WMI ProcessTrace.";
        _pollingTask = Task.Run(() => PollingLoopAsync(_cts.Token), _cts.Token);
        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        _isRunning = false;
        _cts?.Cancel();

        try { _etwSession?.Dispose(); } catch { /* ignoré */ }
        _etwSession = null;

        StopWatcher(ref _wmiStartWatcher);
        StopWatcher(ref _wmiStopWatcher);

        if (_pollingTask is not null)
        {
            try { await _pollingTask.WaitAsync(TimeSpan.FromSeconds(3), cancellationToken); } catch { /* ignoré */ }
            _pollingTask = null;
        }
    }

    public void UpdateSettings(SentinelSettings settings) => _settings = settings;

    private bool TryStartEtw()
    {
        try
        {
            _etwSession = new TraceEventSession(EtwSessionName);
            _etwSession.StopOnDispose = true;
            // 0x10 = WINEVENT_KEYWORD_PROCESS
            _etwSession.EnableProvider(KernelProcessProviderGuid, TraceEventLevel.Informational, 0x10);

            _etwSession.Source.Dynamic.All += OnEtwProcessEvent;

            _etwThread = new Thread(() =>
            {
                try
                {
                    _etwSession?.Source.Process();
                }
                catch (Exception ex) when (_isRunning)
                {
                    _logger.LogDebug(ex, "Fin de session ETW Processus.");
                }
            })
            {
                IsBackground = true,
                Name = "Sentinel-ETW-Process"
            };
            _etwThread.Start();
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Impossible de démarrer ETW Microsoft-Windows-Kernel-Process.");
            try { _etwSession?.Dispose(); } catch { /* ignoré */ }
            _etwSession = null;
            return false;
        }
    }

    private void OnEtwProcessEvent(TraceEvent data)
    {
        if (!_isRunning)
        {
            return;
        }

        var id = (int)data.ID;
        if (id == 1) // ProcessStart
        {
            var pid = GetPayloadInt(data, "ProcessID", data.ProcessID);
            var parentPid = GetPayloadInt(data, "ParentProcessID", 0);
            var imageName = data.PayloadByName("ImageName")?.ToString();
            var sessionId = GetPayloadInt(data, "SessionID", -1);
            ThreadPool.QueueUserWorkItem(_ => EmitProcessStart(pid, parentPid, imageName, cmdLine: null, sessionId, data.TimeStamp));
        }
        else if (id == 2) // ProcessStop
        {
            var pid = GetPayloadInt(data, "ProcessID", data.ProcessID);
            var exitCode = GetPayloadInt(data, "ExitCode", 0);
            var imageName = data.PayloadByName("ImageName")?.ToString();
            EmitProcessStop(pid, imageName, exitCode, data.TimeStamp);
        }
    }

    private bool TryStartWmi()
    {
        try
        {
            _wmiStartWatcher = new ManagementEventWatcher(new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace"));
            _wmiStartWatcher.EventArrived += (_, e) =>
            {
                var pid = Convert.ToInt32(e.NewEvent["ProcessID"]);
                var parentPid = Convert.ToInt32(e.NewEvent["ParentProcessID"]);
                var name = e.NewEvent["ProcessName"]?.ToString();
                var sessionId = e.NewEvent["SessionID"] is not null ? Convert.ToInt32(e.NewEvent["SessionID"]) : -1;
                ThreadPool.QueueUserWorkItem(_ => EmitProcessStart(pid, parentPid, name, cmdLine: null, sessionId, DateTimeOffset.UtcNow));
            };
            _wmiStartWatcher.Start();

            _wmiStopWatcher = new ManagementEventWatcher(new WqlEventQuery("SELECT * FROM Win32_ProcessStopTrace"));
            _wmiStopWatcher.EventArrived += (_, e) =>
            {
                var pid = Convert.ToInt32(e.NewEvent["ProcessID"]);
                var name = e.NewEvent["ProcessName"]?.ToString();
                var exitCode = e.NewEvent["ExitStatus"] is not null ? Convert.ToInt32(e.NewEvent["ExitStatus"]) : 0;
                EmitProcessStop(pid, name, exitCode, DateTimeOffset.UtcNow);
            };
            _wmiStopWatcher.Start();
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "WMI Win32_ProcessStartTrace inaccessible.");
            StopWatcher(ref _wmiStartWatcher);
            StopWatcher(ref _wmiStopWatcher);
            return false;
        }
    }

    private async Task PollingLoopAsync(CancellationToken ct)
    {
        var seen = new Dictionary<int, string>();
        foreach (var proc in Process.GetProcesses())
        {
            try { seen[proc.Id] = proc.ProcessName + ".exe"; } catch { /* ignoré */ }
            finally { proc.Dispose(); }
        }

        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(3), ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            var current = new Dictionary<int, (string Name, int SessionId)>();
            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    current[proc.Id] = (proc.ProcessName + ".exe", proc.SessionId);
                }
                catch
                {
                    // Processus éphémère.
                }
                finally
                {
                    proc.Dispose();
                }
            }

            foreach (var (pid, info) in current)
            {
                if (!seen.ContainsKey(pid))
                {
                    EmitProcessStart(pid, parentPid: 0, info.Name, cmdLine: null, info.SessionId, DateTimeOffset.UtcNow);
                }
            }

            foreach (var (pid, oldName) in seen)
            {
                if (!current.ContainsKey(pid))
                {
                    EmitProcessStop(pid, oldName, exitCode: 0, DateTimeOffset.UtcNow);
                }
            }

            seen = current.ToDictionary(kv => kv.Key, kv => kv.Value.Name);
        }
    }

    private void EmitProcessStart(int pid, int parentPid, string? rawName, string? cmdLine, int sessionId, DateTimeOffset timestamp)
    {
        try
        {
            var path = ProcessEnricher.TryGetProcessPath(pid);
            var processName = !string.IsNullOrWhiteSpace(path)
                ? Path.GetFileName(path)
                : (!string.IsNullOrWhiteSpace(rawName) ? Path.GetFileName(rawName) : $"pid-{pid}");

            if (IsExcludedProcess(processName))
            {
                _enricher.RememberProcess(pid, processName, path);
                return;
            }

            if (string.IsNullOrWhiteSpace(cmdLine) || parentPid <= 0)
            {
                var (wmiCmd, wmiParent) = ProcessEnricher.TryQueryWmiProcessDetails(pid);
                cmdLine ??= wmiCmd;
                if (parentPid <= 0 && wmiParent > 0)
                {
                    parentPid = wmiParent;
                }
            }

            _enricher.RememberProcess(pid, processName, path);
            var (parentName, parentPath) = _enricher.ResolveParent(parentPid);
            var binInfo = _enricher.InspectBinary(path);
            var elevated = ProcessEnricher.TryIsProcessElevated(pid);

            if (!string.IsNullOrEmpty(binInfo.Sha256) &&
                _settings.ExcludedHashes.Any(h => h.Equals(binInfo.Sha256, StringComparison.OrdinalIgnoreCase)))
            {
                return;
            }

            var attrs = new Dictionary<string, string>
            {
                [AttributeKeys.ProcessId] = pid.ToString(CultureInfo.InvariantCulture),
                [AttributeKeys.ProcessName] = processName,
                [AttributeKeys.Signed] = binInfo.IsSigned ? "true" : "false"
            };

            if (!string.IsNullOrWhiteSpace(path)) attrs[AttributeKeys.ProcessPath] = path;
            if (parentPid > 0) attrs[AttributeKeys.ParentProcessId] = parentPid.ToString(CultureInfo.InvariantCulture);
            if (!string.IsNullOrWhiteSpace(parentName)) attrs[AttributeKeys.ParentProcessName] = parentName;
            if (!string.IsNullOrWhiteSpace(parentPath)) attrs[AttributeKeys.ParentProcessPath] = parentPath;
            if (!string.IsNullOrWhiteSpace(cmdLine)) attrs[AttributeKeys.CommandLine] = cmdLine;
            if (!string.IsNullOrWhiteSpace(binInfo.Sha256)) attrs[AttributeKeys.Sha256] = binInfo.Sha256;
            if (!string.IsNullOrWhiteSpace(binInfo.Publisher)) attrs[AttributeKeys.Publisher] = binInfo.Publisher;
            if (elevated.HasValue) attrs[AttributeKeys.Elevated] = elevated.Value ? "true" : "false";
            if (sessionId >= 0) attrs[AttributeKeys.SessionId] = sessionId.ToString(CultureInfo.InvariantCulture);

            var hints = $"pid:{pid};parent:{parentPid};proc:{processName}" +
                        (string.IsNullOrEmpty(binInfo.Sha256) ? string.Empty : $";hash:{binInfo.Sha256}");

            var evt = SecurityEvent.Create(
                _stateStore.HostId,
                Environment.UserName,
                EventCategory.Process,
                EventTypes.ProcessStart,
                path ?? processName,
                attrs,
                hints,
                timestamp);

            if (_sink.Publish(evt))
            {
                Interlocked.Increment(ref _eventsProduced);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Erreur lors de l'enrichissement ProcessStart pour PID {Pid}.", pid);
        }
    }

    private void EmitProcessStop(int pid, string? rawName, int exitCode, DateTimeOffset timestamp)
    {
        var name = !string.IsNullOrWhiteSpace(rawName) ? Path.GetFileName(rawName) : $"pid-{pid}";
        _enricher.ForgetProcess(pid);

        if (IsExcludedProcess(name))
        {
            return;
        }

        var evt = SecurityEvent.Create(
            _stateStore.HostId,
            Environment.UserName,
            EventCategory.Process,
            EventTypes.ProcessStop,
            name,
            new Dictionary<string, string>
            {
                [AttributeKeys.ProcessId] = pid.ToString(CultureInfo.InvariantCulture),
                [AttributeKeys.ProcessName] = name,
                [AttributeKeys.ExitCode] = exitCode.ToString(CultureInfo.InvariantCulture)
            },
            $"pid:{pid};proc:{name}",
            timestamp);

        if (_sink.Publish(evt))
        {
            Interlocked.Increment(ref _eventsProduced);
        }
    }

    private bool IsExcludedProcess(string processName)
    {
        foreach (var ex in _settings.ExcludedProcesses)
        {
            if (processName.Equals(ex, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    private void SeedKnownProcesses()
    {
        foreach (var proc in Process.GetProcesses())
        {
            try
            {
                var path = ProcessEnricher.TryGetProcessPath(proc.Id);
                _enricher.RememberProcess(proc.Id, proc.ProcessName + ".exe", path);
            }
            catch
            {
                // Ignoré.
            }
            finally
            {
                proc.Dispose();
            }
        }
    }

    private static int GetPayloadInt(TraceEvent data, string name, int fallback)
    {
        var val = data.PayloadByName(name);
        return val is null ? fallback : Convert.ToInt32(val);
    }

    private static bool IsAdministrator()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    private static void StopWatcher(ref ManagementEventWatcher? watcher)
    {
        if (watcher is null) return;
        try { watcher.Stop(); } catch { /* ignoré */ }
        try { watcher.Dispose(); } catch { /* ignoré */ }
        watcher = null;
    }

    public void Dispose()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        try { _etwSession?.Dispose(); } catch { /* ignoré */ }
        StopWatcher(ref _wmiStartWatcher);
        StopWatcher(ref _wmiStopWatcher);
    }
}
