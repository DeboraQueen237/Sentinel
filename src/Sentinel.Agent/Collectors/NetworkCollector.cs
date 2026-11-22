using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Extensions.Logging;
using Sentinel.Agent.Configuration;
using Sentinel.Agent.Pipeline;
using Sentinel.Shared.Models;

namespace Sentinel.Agent.Collectors;

/// <summary>
/// Collecteur réseau (doc §6.2) : ETW <c>Microsoft-Windows-TCPIP</c> + <c>Microsoft-Windows-DNS-Client</c>
/// si exécuté en Administrateur, complété par un polling périodique <c>GetExtendedTcpTable</c> (P/Invoke)
/// associant PID ↔ connexion sortante, cache DNS IP→domaine, détection d'IP privée et suivi des volumes.
/// </summary>
public sealed class NetworkCollector : IEventCollector, IDisposable
{
    private const string EtwSessionName = "Sentinel-Network-ETW";
    private static readonly Guid TcpIpProviderGuid = new("2F07E2EE-15DB-40F1-90EF-9D7BA282188A");
    private static readonly Guid DnsClientProviderGuid = new("1C95126E-7EEA-49A9-A3FE-A378B03DDB4D");
    private const long VolumeAlertThresholdBytes = 10L * 1024 * 1024; // 10 Mo sortants

    private readonly IEventSink _sink;
    private readonly AgentStateStore _stateStore;
    private readonly ILogger<NetworkCollector> _logger;

    private readonly ConcurrentDictionary<string, (string Domain, DateTimeOffset ExpiresAt)> _dnsCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DateTimeOffset> _seenConnections = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<(int Pid, string RemoteIp), VolumeCounter> _volumeByPeer = new();

    private volatile SentinelSettings _settings;
    private volatile bool _isRunning;
    private volatile string? _lastError;
    private long _eventsProduced;

    private TraceEventSession? _etwSession;
    private Thread? _etwThread;
    private CancellationTokenSource? _cts;
    private Task? _pollingTask;

    public string Name => "Network";
    public bool IsRunning => _isRunning;
    public string? LastError => _lastError;
    public long EventsProduced => Interlocked.Read(ref _eventsProduced);

    public NetworkCollector(
        IEventSink sink,
        AgentStateStore stateStore,
        ILogger<NetworkCollector> logger)
    {
        _sink = sink;
        _stateStore = stateStore;
        _logger = logger;
        _settings = stateStore.CurrentSettings;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var etwStarted = IsAdministrator() && TryStartEtw();
        _lastError = etwStarted
            ? null
            : "Mode dégradé (GetExtendedTcpTable 5 s) : privilèges Administrateur requis pour ETW TCPIP/DNS-Client.";

        _isRunning = true;
        _pollingTask = Task.Run(() => PollingLoopAsync(_cts.Token), _cts.Token);
        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        _isRunning = false;
        _cts?.Cancel();
        try { _etwSession?.Dispose(); } catch { /* ignoré */ }
        _etwSession = null;

        if (_pollingTask is not null)
        {
            try { await _pollingTask.WaitAsync(TimeSpan.FromSeconds(3), cancellationToken); } catch { /* ignoré */ }
            _pollingTask = null;
        }
    }

    public void UpdateSettings(SentinelSettings settings) => _settings = settings;

    public static bool IsPrivateIp(IPAddress ip)
    {
        if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any))
        {
            return true;
        }

        if (ip.IsIPv4MappedToIPv6)
        {
            ip = ip.MapToIPv4();
        }

        var bytes = ip.GetAddressBytes();
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            return bytes[0] == 10
                   || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
                   || (bytes[0] == 192 && bytes[1] == 168)
                   || (bytes[0] == 169 && bytes[1] == 254)
                   || bytes[0] == 127
                   || (bytes[0] == 100 && bytes[1] >= 64 && bytes[1] <= 127); // CGNAT
        }

        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || (bytes[0] & 0xFE) == 0xFC; // ULA fc00::/7
        }

        return false;
    }

    private bool TryStartEtw()
    {
        try
        {
            _etwSession = new TraceEventSession(EtwSessionName);
            _etwSession.StopOnDispose = true;
            _etwSession.EnableProvider(DnsClientProviderGuid, TraceEventLevel.Informational);
            _etwSession.EnableProvider(TcpIpProviderGuid, TraceEventLevel.Informational);

            _etwSession.Source.Dynamic.All += OnEtwNetworkEvent;

            _etwThread = new Thread(() =>
            {
                try { _etwSession?.Source.Process(); }
                catch (Exception ex) when (_isRunning)
                {
                    _logger.LogDebug(ex, "Fin de session ETW Réseau.");
                }
            })
            {
                IsBackground = true,
                Name = "Sentinel-ETW-Network"
            };
            _etwThread.Start();
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Impossible de démarrer ETW TCPIP / DNS-Client.");
            try { _etwSession?.Dispose(); } catch { /* ignoré */ }
            _etwSession = null;
            return false;
        }
    }

    private void OnEtwNetworkEvent(TraceEvent data)
    {
        if (!_isRunning || !_settings.EnableNetworkMonitoring)
        {
            return;
        }

        try
        {
            if (data.ProviderGuid == DnsClientProviderGuid)
            {
                HandleDnsEvent(data);
            }
            else if (data.ProviderGuid == TcpIpProviderGuid)
            {
                HandleTcpEtwEvent(data);
            }
        }
        catch
        {
            // Tolérance aux payloads ETW incomplets.
        }
    }

    private void HandleDnsEvent(TraceEvent data)
    {
        // Event ID 3008 (QueryCompleted) ou 3006 (QueryInitiated)
        var eventId = (int)data.ID;
        if (eventId != 3008 && eventId != 3006)
        {
            return;
        }

        var queryName = data.PayloadByName("QueryName")?.ToString()?.Trim().TrimEnd('.');
        if (string.IsNullOrWhiteSpace(queryName) || queryName.EndsWith(".local", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var queryResults = data.PayloadByName("QueryResults")?.ToString();
        var resolvedIps = new List<string>();
        if (!string.IsNullOrWhiteSpace(queryResults))
        {
            var expiry = DateTimeOffset.UtcNow.AddMinutes(30);
            foreach (var token in queryResults.Split([';', ' ', ','], StringSplitOptions.RemoveEmptyEntries))
            {
                var candidate = token.StartsWith("type:", StringComparison.OrdinalIgnoreCase) ? string.Empty : token.Trim();
                if (IPAddress.TryParse(candidate, out var ip))
                {
                    var normIp = ip.ToString();
                    _dnsCache[normIp] = (queryName, expiry);
                    resolvedIps.Add(normIp);
                }
            }

            if (_dnsCache.Count > 4096)
            {
                PruneDnsCache();
            }
        }

        if (eventId == 3008 && !IsExcludedDomain(queryName))
        {
            var pid = data.ProcessID;
            var procName = ResolveProcessName(pid);
            if (IsExcludedProcess(procName))
            {
                return;
            }

            var attrs = new Dictionary<string, string>
            {
                [AttributeKeys.Domain] = queryName,
                [AttributeKeys.ProcessId] = pid.ToString(CultureInfo.InvariantCulture),
                [AttributeKeys.ProcessName] = procName
            };
            if (resolvedIps.Count > 0)
            {
                attrs[AttributeKeys.RemoteIp] = resolvedIps[0];
            }

            var evt = SecurityEvent.Create(
                _stateStore.HostId,
                Environment.UserName,
                EventCategory.Network,
                EventTypes.DnsQuery,
                queryName,
                attrs,
                $"domain:{queryName};pid:{pid}",
                data.TimeStamp);

            if (_sink.Publish(evt))
            {
                Interlocked.Increment(ref _eventsProduced);
            }
        }
    }

    private void HandleTcpEtwEvent(TraceEvent data)
    {
        // Suivi des volumes émis/reçus via événements Send/Receive TCPIP (ex. IDs 1018/1033/1159/1160)
        var sizeObj = data.PayloadByName("NumBytes") ?? data.PayloadByName("Size") ?? data.PayloadByName("Length");
        if (sizeObj is null)
        {
            return;
        }

        var bytes = Convert.ToInt64(sizeObj);
        if (bytes <= 0)
        {
            return;
        }

        var remoteIp = ExtractIpPayload(data, "daddr") ?? ExtractIpPayload(data, "RemoteAddress");
        if (string.IsNullOrEmpty(remoteIp))
        {
            return;
        }

        var counter = _volumeByPeer.GetOrAdd((data.ProcessID, remoteIp), _ => new VolumeCounter());
        if (data.EventName.Contains("Send", StringComparison.OrdinalIgnoreCase))
        {
            counter.AddSent(bytes);
        }
        else if (data.EventName.Contains("Recv", StringComparison.OrdinalIgnoreCase) ||
                 data.EventName.Contains("Receive", StringComparison.OrdinalIgnoreCase))
        {
            counter.AddReceived(bytes);
        }
    }

    private async Task PollingLoopAsync(CancellationToken ct)
    {
        long lastIfaceSent = ReadTotalOutboundInterfaceBytes();

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

            if (!_settings.EnableNetworkMonitoring)
            {
                continue;
            }

            try
            {
                PollTcpConnections();
                FlushVolumeAlerts(ref lastIfaceSent);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Erreur pendant le scan TCP périodique.");
            }
        }
    }

    private void PollTcpConnections()
    {
        var now = DateTimeOffset.UtcNow;
        var connections = EnumerateTcpV4Connections();
        foreach (var conn in connections)
        {
            if (conn.State != TcpStateEstablished || conn.RemotePort == 0)
            {
                continue;
            }

            if (IPAddress.IsLoopback(conn.RemoteAddress) || conn.RemoteAddress.Equals(IPAddress.Any))
            {
                continue;
            }

            var remoteIp = conn.RemoteAddress.ToString();
            var dedupKey = $"{conn.Pid}|{remoteIp}:{conn.RemotePort}";
            if (_seenConnections.TryGetValue(dedupKey, out var lastSeen) && (now - lastSeen).TotalSeconds < 60)
            {
                continue;
            }
            _seenConnections[dedupKey] = now;

            var procName = ResolveProcessName(conn.Pid);
            if (IsExcludedProcess(procName))
            {
                continue;
            }

            string? domain = null;
            if (_dnsCache.TryGetValue(remoteIp, out var cached) && cached.ExpiresAt > now)
            {
                domain = cached.Domain;
                if (IsExcludedDomain(domain))
                {
                    continue;
                }
            }

            var isPrivate = IsPrivateIp(conn.RemoteAddress);
            long sent = 0, received = 0;
            if (_volumeByPeer.TryGetValue((conn.Pid, remoteIp), out var vol))
            {
                sent = vol.BytesSent;
                received = vol.BytesReceived;
            }

            var attrs = new Dictionary<string, string>
            {
                [AttributeKeys.ProcessId] = conn.Pid.ToString(CultureInfo.InvariantCulture),
                [AttributeKeys.ProcessName] = procName,
                [AttributeKeys.LocalIp] = conn.LocalAddress.ToString(),
                [AttributeKeys.LocalPort] = conn.LocalPort.ToString(CultureInfo.InvariantCulture),
                [AttributeKeys.RemoteIp] = remoteIp,
                [AttributeKeys.RemotePort] = conn.RemotePort.ToString(CultureInfo.InvariantCulture),
                [AttributeKeys.Protocol] = "tcp",
                [AttributeKeys.Direction] = "outbound",
                [AttributeKeys.IsPrivateIp] = isPrivate ? "true" : "false",
                [AttributeKeys.BytesSent] = sent.ToString(CultureInfo.InvariantCulture),
                [AttributeKeys.BytesReceived] = received.ToString(CultureInfo.InvariantCulture)
            };

            if (!string.IsNullOrEmpty(domain))
            {
                attrs[AttributeKeys.Domain] = domain;
            }

            var subject = !string.IsNullOrEmpty(domain) ? domain : $"{remoteIp}:{conn.RemotePort}";
            var hints = $"ip:{remoteIp};pid:{conn.Pid};proc:{procName}" +
                        (string.IsNullOrEmpty(domain) ? string.Empty : $";domain:{domain}");

            var evt = SecurityEvent.Create(
                _stateStore.HostId,
                Environment.UserName,
                EventCategory.Network,
                EventTypes.NetworkConnection,
                subject,
                attrs,
                hints,
                now);

            if (_sink.Publish(evt))
            {
                Interlocked.Increment(ref _eventsProduced);
            }
        }

        if (_seenConnections.Count > 4096)
        {
            foreach (var kv in _seenConnections)
            {
                if ((now - kv.Value).TotalSeconds > 120)
                {
                    _seenConnections.TryRemove(kv.Key, out _);
                }
            }
        }
    }

    private void FlushVolumeAlerts(ref long lastIfaceSent)
    {
        var now = DateTimeOffset.UtcNow;

        foreach (var (key, counter) in _volumeByPeer.ToArray())
        {
            var sent = counter.DrainSentIfAbove(VolumeAlertThresholdBytes);
            if (sent <= 0)
            {
                continue;
            }

            var procName = ResolveProcessName(key.Pid);
            if (IsExcludedProcess(procName))
            {
                continue;
            }

            _dnsCache.TryGetValue(key.RemoteIp, out var dns);
            var attrs = new Dictionary<string, string>
            {
                [AttributeKeys.ProcessId] = key.Pid.ToString(CultureInfo.InvariantCulture),
                [AttributeKeys.ProcessName] = procName,
                [AttributeKeys.RemoteIp] = key.RemoteIp,
                [AttributeKeys.BytesSent] = sent.ToString(CultureInfo.InvariantCulture),
                [AttributeKeys.BytesReceived] = counter.BytesReceived.ToString(CultureInfo.InvariantCulture),
                [AttributeKeys.Direction] = "outbound"
            };
            if (!string.IsNullOrEmpty(dns.Domain))
            {
                attrs[AttributeKeys.Domain] = dns.Domain;
            }

            var evt = SecurityEvent.Create(
                _stateStore.HostId,
                Environment.UserName,
                EventCategory.Network,
                EventTypes.NetworkVolume,
                !string.IsNullOrEmpty(dns.Domain) ? dns.Domain : key.RemoteIp,
                attrs,
                $"ip:{key.RemoteIp};pid:{key.Pid}" + (string.IsNullOrEmpty(dns.Domain) ? string.Empty : $";domain:{dns.Domain}"),
                now);

            if (_sink.Publish(evt))
            {
                Interlocked.Increment(ref _eventsProduced);
            }
        }

        // Suivi global des interfaces réseau en secours si ETW est indisponible.
        var totalSent = ReadTotalOutboundInterfaceBytes();
        var delta = totalSent - lastIfaceSent;
        lastIfaceSent = totalSent;

        if (_etwSession is null && delta >= VolumeAlertThresholdBytes * 5)
        {
            var evt = SecurityEvent.Create(
                _stateStore.HostId,
                Environment.UserName,
                EventCategory.Network,
                EventTypes.NetworkVolume,
                Environment.MachineName,
                new Dictionary<string, string>
                {
                    [AttributeKeys.BytesSent] = delta.ToString(CultureInfo.InvariantCulture),
                    [AttributeKeys.Direction] = "outbound"
                },
                $"host:{_stateStore.HostId}",
                now);

            if (_sink.Publish(evt))
            {
                Interlocked.Increment(ref _eventsProduced);
            }
        }
    }

    private static long ReadTotalOutboundInterfaceBytes()
    {
        long total = 0;
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up ||
                    ni.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                {
                    continue;
                }
                total += ni.GetIPv4Statistics().BytesSent;
            }
        }
        catch
        {
            // Ignoré.
        }
        return total;
    }

    private static List<TcpConnectionRow> EnumerateTcpV4Connections()
    {
        var list = new List<TcpConnectionRow>();
        int bufferSize = 0;
        _ = GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, sort: false, AfInet, TcpTableOwnerPidAll, 0);
        if (bufferSize <= 0)
        {
            return list;
        }

        IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            if (GetExtendedTcpTable(buffer, ref bufferSize, sort: false, AfInet, TcpTableOwnerPidAll, 0) != 0)
            {
                return list;
            }

            int rowCount = Marshal.ReadInt32(buffer);
            IntPtr rowPtr = IntPtr.Add(buffer, sizeof(int));
            int rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();

            for (int i = 0; i < rowCount; i++)
            {
                var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(rowPtr);
                var localPort = (int)(((row.LocalPort & 0xFF) << 8) | ((row.LocalPort >> 8) & 0xFF));
                var remotePort = (int)(((row.RemotePort & 0xFF) << 8) | ((row.RemotePort >> 8) & 0xFF));

                list.Add(new TcpConnectionRow(
                    (int)row.OwningPid,
                    new IPAddress(row.LocalAddr),
                    localPort,
                    new IPAddress(row.RemoteAddr),
                    remotePort,
                    (int)row.State));

                rowPtr = IntPtr.Add(rowPtr, rowSize);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return list;
    }

    private static string ResolveProcessName(int pid)
    {
        if (pid <= 0) return "System";
        try
        {
            using var p = Process.GetProcessById(pid);
            return p.ProcessName + ".exe";
        }
        catch
        {
            return $"pid-{pid}";
        }
    }

    private static string? ExtractIpPayload(TraceEvent data, string name)
    {
        var val = data.PayloadByName(name);
        if (val is null) return null;
        if (val is IPAddress ip) return ip.ToString();
        if (val is uint u32) return new IPAddress(u32).ToString();
        var s = val.ToString();
        return IPAddress.TryParse(s, out var parsed) ? parsed.ToString() : null;
    }

    private bool IsExcludedProcess(string procName) =>
        _settings.ExcludedProcesses.Any(e => procName.Equals(e, StringComparison.OrdinalIgnoreCase));

    private bool IsExcludedDomain(string domain) =>
        _settings.ExcludedDomains.Any(e =>
            domain.Equals(e, StringComparison.OrdinalIgnoreCase) ||
            domain.EndsWith("." + e, StringComparison.OrdinalIgnoreCase));

    private void PruneDnsCache()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var kv in _dnsCache)
        {
            if (kv.Value.ExpiresAt <= now)
            {
                _dnsCache.TryRemove(kv.Key, out _);
            }
        }
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

    public void Dispose()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        try { _etwSession?.Dispose(); } catch { /* ignoré */ }
    }

    private const int AfInet = 2;
    private const int TcpTableOwnerPidAll = 5;
    private const int TcpStateEstablished = 5;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref int pdwSize,
        bool sort,
        int ipVersion,
        int tableClass,
        uint reserved);

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
        public uint OwningPid;
    }

    private readonly record struct TcpConnectionRow(
        int Pid,
        IPAddress LocalAddress,
        int LocalPort,
        IPAddress RemoteAddress,
        int RemotePort,
        int State);

    private sealed class VolumeCounter
    {
        private long _sent;
        private long _received;
        private long _reportedSent;

        public long BytesSent => Interlocked.Read(ref _sent);
        public long BytesReceived => Interlocked.Read(ref _received);

        public void AddSent(long delta) => Interlocked.Add(ref _sent, delta);
        public void AddReceived(long delta) => Interlocked.Add(ref _received, delta);

        public long DrainSentIfAbove(long threshold)
        {
            var current = Interlocked.Read(ref _sent);
            var previous = Interlocked.Read(ref _reportedSent);
            var diff = current - previous;
            if (diff < threshold)
            {
                return 0;
            }
            Interlocked.Exchange(ref _reportedSent, current);
            return diff;
        }
    }
}
