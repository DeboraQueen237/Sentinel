using System.Collections.Concurrent;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Xml.Linq;
using Microsoft.Extensions.Logging;
using Sentinel.Agent.Configuration;
using Sentinel.Agent.Pipeline;
using Sentinel.Shared.Models;

namespace Sentinel.Agent.Collectors;

/// <summary>
/// Collecteur de sessions Windows (doc §6.5) : surveille le journal <c>Security</c> pour les événements
/// 4624, 4625, 4634, 4647, 4800 et 4801 via <see cref="EventLogWatcher"/>.
/// En cas d'accès refusé (exécution non Administrateur), signale l'état dans <see cref="LastError"/>
/// sans planter et bascule sur la surveillance des sessions actives via WTS API (<c>wtsapi32.dll</c>).
/// </summary>
public sealed class SessionCollector : IEventCollector, IDisposable
{
    private const string SecurityXPathQuery =
        "*[System[(EventID=4624 or EventID=4625 or EventID=4634 or EventID=4647 or EventID=4800 or EventID=4801)]]";

    private readonly IEventSink _sink;
    private readonly AgentStateStore _stateStore;
    private readonly ILogger<SessionCollector> _logger;
    private readonly ConcurrentDictionary<string, Queue<DateTimeOffset>> _recentFailures = new(StringComparer.OrdinalIgnoreCase);

    private EventLogWatcher? _watcher;
    private CancellationTokenSource? _cts;
    private Task? _wtsFallbackTask;
    private volatile bool _isRunning;
    private volatile string? _lastError;
    private long _eventsProduced;

    public string Name => "Session";
    public bool IsRunning => _isRunning;
    public string? LastError => _lastError;
    public long EventsProduced => Interlocked.Read(ref _eventsProduced);

    public SessionCollector(
        IEventSink sink,
        AgentStateStore stateStore,
        ILogger<SessionCollector> logger)
    {
        _sink = sink;
        _stateStore = stateStore;
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        try
        {
            var query = new EventLogQuery("Security", PathType.LogName, SecurityXPathQuery);
            _watcher = new EventLogWatcher(query);
            _watcher.EventRecordWritten += OnSecurityEventRecord;
            _watcher.Enabled = true;

            _isRunning = true;
            _lastError = null;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or EventLogException)
        {
            DisposeWatcher();
            _lastError = $"Journal Security inaccessible ({ex.Message}) ; bascule sur surveillance WTS des sessions actives.";
            _logger.LogWarning("Collecteur Session en mode dégradé WTS : {Reason}", _lastError);

            _isRunning = true;
            _wtsFallbackTask = Task.Run(() => WtsSessionMonitorLoopAsync(_cts.Token), _cts.Token);
        }

        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        _isRunning = false;
        _cts?.Cancel();
        DisposeWatcher();

        if (_wtsFallbackTask is not null)
        {
            try { await _wtsFallbackTask.WaitAsync(TimeSpan.FromSeconds(3), cancellationToken); } catch { /* ignoré */ }
            _wtsFallbackTask = null;
        }
    }

    public void UpdateSettings(SentinelSettings settings)
    {
        // Aucun filtre spécifique aux sessions pour le moment.
    }

    private void OnSecurityEventRecord(object? sender, EventRecordWrittenEventArgs args)
    {
        if (!_isRunning || args.EventRecord is null)
        {
            return;
        }

        try
        {
            using var record = args.EventRecord;
            var eventId = record.Id;
            var eventType = eventId switch
            {
                4624 => EventTypes.LogonSuccess,
                4625 => EventTypes.LogonFailure,
                4634 or 4647 => EventTypes.Logoff,
                4800 => EventTypes.SessionLocked,
                4801 => EventTypes.SessionUnlocked,
                _ => null
            };

            if (eventType is null)
            {
                return;
            }

            var dataMap = ParseEventData(record.ToXml());
            var targetUser = FirstNonEmpty(dataMap, "TargetUserName", "SubjectUserName") ?? Environment.UserName;
            // Ignore les comptes machine bruités ($).
            if (targetUser.EndsWith('$') && eventId is 4624 or 4634)
            {
                return;
            }

            var logonType = FirstNonEmpty(dataMap, "LogonType");
            var sourceIp = FirstNonEmpty(dataMap, "IpAddress");
            if (sourceIp is "-" or "::1" or "127.0.0.1")
            {
                sourceIp = sourceIp == "-" ? null : sourceIp;
            }

            var attrs = new Dictionary<string, string>
            {
                [AttributeKeys.WindowsEventId] = eventId.ToString(CultureInfo.InvariantCulture),
                [AttributeKeys.TargetUser] = targetUser
            };

            if (!string.IsNullOrWhiteSpace(logonType)) attrs[AttributeKeys.LogonType] = logonType;
            if (!string.IsNullOrWhiteSpace(sourceIp)) attrs[AttributeKeys.SourceIp] = sourceIp;

            var timestamp = record.TimeCreated.HasValue
                ? new DateTimeOffset(record.TimeCreated.Value.ToUniversalTime(), TimeSpan.Zero)
                : DateTimeOffset.UtcNow;

            if (eventId == 4625)
            {
                var status = FirstNonEmpty(dataMap, "SubStatus", "Status", "FailureReason");
                if (!string.IsNullOrWhiteSpace(status))
                {
                    attrs[AttributeKeys.FailureReason] = status;
                }

                var count = TrackFailure($"{targetUser}|{sourceIp ?? "local"}", timestamp);
                attrs[AttributeKeys.FailureCount] = count.ToString(CultureInfo.InvariantCulture);
            }

            var hints = $"user:{targetUser}" + (string.IsNullOrEmpty(sourceIp) ? string.Empty : $";ip:{sourceIp}");
            var evt = SecurityEvent.Create(
                _stateStore.HostId,
                targetUser,
                EventCategory.Session,
                eventType,
                targetUser,
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
            _logger.LogDebug(ex, "Erreur lors de l'analyse d'un événement du journal Security.");
        }
    }

    private int TrackFailure(string key, DateTimeOffset now)
    {
        var queue = _recentFailures.GetOrAdd(key, _ => new Queue<DateTimeOffset>());
        lock (queue)
        {
            var cutoff = now.AddMinutes(-10);
            while (queue.Count > 0 && queue.Peek() < cutoff)
            {
                queue.Dequeue();
            }
            queue.Enqueue(now);
            return queue.Count;
        }
    }

    private async Task WtsSessionMonitorLoopAsync(CancellationToken ct)
    {
        var previous = EnumerateWtsSessions();

        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(5), ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            var current = EnumerateWtsSessions();
            var now = DateTimeOffset.UtcNow;

            foreach (var (sessionId, info) in current)
            {
                if (string.IsNullOrWhiteSpace(info.UserName))
                {
                    continue;
                }

                if (!previous.TryGetValue(sessionId, out var old))
                {
                    EmitWtsSessionEvent(EventTypes.LogonSuccess, sessionId, info.UserName, now);
                }
                else if (old.State != info.State)
                {
                    if (info.State == WtsConnectState.Disconnected)
                    {
                        EmitWtsSessionEvent(EventTypes.SessionLocked, sessionId, info.UserName, now);
                    }
                    else if (info.State == WtsConnectState.Active && old.State == WtsConnectState.Disconnected)
                    {
                        EmitWtsSessionEvent(EventTypes.SessionUnlocked, sessionId, info.UserName, now);
                    }
                }
            }

            foreach (var (sessionId, old) in previous)
            {
                if (!string.IsNullOrWhiteSpace(old.UserName) && !current.ContainsKey(sessionId))
                {
                    EmitWtsSessionEvent(EventTypes.Logoff, sessionId, old.UserName, now);
                }
            }

            previous = current;
        }
    }

    private void EmitWtsSessionEvent(string eventType, int sessionId, string userName, DateTimeOffset timestamp)
    {
        var evt = SecurityEvent.Create(
            _stateStore.HostId,
            userName,
            EventCategory.Session,
            eventType,
            userName,
            new Dictionary<string, string>
            {
                [AttributeKeys.SessionId] = sessionId.ToString(CultureInfo.InvariantCulture),
                [AttributeKeys.TargetUser] = userName
            },
            $"user:{userName};session:{sessionId}",
            timestamp);

        if (_sink.Publish(evt))
        {
            Interlocked.Increment(ref _eventsProduced);
        }
    }

    private static Dictionary<string, string> ParseEventData(string xml)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var doc = XDocument.Parse(xml);
            foreach (var data in doc.Descendants().Where(e => e.Name.LocalName == "Data"))
            {
                var name = data.Attribute("Name")?.Value;
                if (!string.IsNullOrWhiteSpace(name))
                {
                    map[name] = data.Value;
                }
            }
        }
        catch
        {
            // Ignoré.
        }
        return map;
    }

    private static string? FirstNonEmpty(Dictionary<string, string> map, params string[] keys)
    {
        foreach (var k in keys)
        {
            if (map.TryGetValue(k, out var val) && !string.IsNullOrWhiteSpace(val))
            {
                return val.Trim();
            }
        }
        return null;
    }

    private static Dictionary<int, WtsSessionSnapshot> EnumerateWtsSessions()
    {
        var result = new Dictionary<int, WtsSessionSnapshot>();
        IntPtr ppSessionInfo = IntPtr.Zero;
        int count = 0;

        try
        {
            if (!WTSEnumerateSessions(IntPtr.Zero, 0, 1, out ppSessionInfo, out count))
            {
                return result;
            }

            int dataSize = Marshal.SizeOf<WtsSessionInfo>();
            for (int i = 0; i < count; i++)
            {
                var info = Marshal.PtrToStructure<WtsSessionInfo>(IntPtr.Add(ppSessionInfo, i * dataSize));
                var user = QueryWtsString(info.SessionId, WtsInfoClassUserName);
                result[info.SessionId] = new WtsSessionSnapshot(user, info.State);
            }
        }
        catch
        {
            // Ignoré.
        }
        finally
        {
            if (ppSessionInfo != IntPtr.Zero)
            {
                WTSFreeMemory(ppSessionInfo);
            }
        }

        return result;
    }

    private static string QueryWtsString(int sessionId, int infoClass)
    {
        if (!WTSQuerySessionInformation(IntPtr.Zero, sessionId, infoClass, out var buffer, out var bytes) || buffer == IntPtr.Zero)
        {
            return string.Empty;
        }

        try
        {
            return bytes > 0 ? Marshal.PtrToStringUni(buffer) ?? string.Empty : string.Empty;
        }
        finally
        {
            WTSFreeMemory(buffer);
        }
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

    private const int WtsInfoClassUserName = 5;

    private enum WtsConnectState
    {
        Active = 0,
        Connected = 1,
        ConnectQuery = 2,
        Shadow = 3,
        Disconnected = 4,
        Idle = 5,
        Listen = 6,
        Reset = 7,
        Down = 8,
        Init = 9
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WtsSessionInfo
    {
        public int SessionId;
        [MarshalAs(UnmanagedType.LPTStr)]
        public string WinStationName;
        public WtsConnectState State;
    }

    private readonly record struct WtsSessionSnapshot(string UserName, WtsConnectState State);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSEnumerateSessions(
        IntPtr hServer,
        int reserved,
        int version,
        out IntPtr ppSessionInfo,
        out int pCount);

    [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool WTSQuerySessionInformation(
        IntPtr hServer,
        int sessionId,
        int wtsInfoClass,
        out IntPtr ppBuffer,
        out int pBytesReturned);

    [DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr pMemory);
}
