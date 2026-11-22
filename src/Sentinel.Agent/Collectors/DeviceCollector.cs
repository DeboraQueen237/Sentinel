using System.Management;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Sentinel.Agent.Configuration;
using Sentinel.Agent.Pipeline;
using Sentinel.Shared.Models;

namespace Sentinel.Agent.Collectors;

/// <summary>
/// Collecteur de périphériques USB / HID (doc §6.7) : écoute <c>Win32_DeviceChangeEvent</c> via WMI
/// et interroge <c>Win32_PnPEntity</c> pour extraire VID, PID, classe, nom et détecter les claviers HID
/// suspects (BadUSB) ainsi que les supports de stockage amovibles.
/// </summary>
public sealed partial class DeviceCollector : IEventCollector, IDisposable
{
    private readonly IEventSink _sink;
    private readonly AgentStateStore _stateStore;
    private readonly ILogger<DeviceCollector> _logger;
    private readonly object _diffGate = new();

    private Dictionary<string, PnpDeviceInfo> _knownDevices = new(StringComparer.OrdinalIgnoreCase);
    private ManagementEventWatcher? _deviceWatcher;
    private CancellationTokenSource? _cts;
    private Task? _pollingTask;
    private DateTimeOffset _lastScanUtc = DateTimeOffset.MinValue;

    private volatile bool _isRunning;
    private volatile string? _lastError;
    private long _eventsProduced;

    public string Name => "Device";
    public bool IsRunning => _isRunning;
    public string? LastError => _lastError;
    public long EventsProduced => Interlocked.Read(ref _eventsProduced);

    public DeviceCollector(
        IEventSink sink,
        AgentStateStore stateStore,
        ILogger<DeviceCollector> logger)
    {
        _sink = sink;
        _stateStore = stateStore;
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        _knownDevices = QueryUsbAndHidDevices();

        try
        {
            _deviceWatcher = new ManagementEventWatcher(
                new WqlEventQuery("SELECT * FROM Win32_DeviceChangeEvent WHERE EventType = 2 OR EventType = 3"));
            _deviceWatcher.EventArrived += (_, _) => ScheduleReconcile();
            _deviceWatcher.Start();

            _isRunning = true;
            _lastError = null;
        }
        catch (Exception ex)
        {
            DisposeWatcher();
            _lastError = $"WMI Win32_DeviceChangeEvent indisponible ({ex.Message}) ; bascule en polling PnP 10 s.";
            _logger.LogWarning("Collecteur Device en mode polling : {Error}", _lastError);

            _isRunning = true;
            _pollingTask = Task.Run(() => PollingLoopAsync(_cts.Token), _cts.Token);
        }

        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        _isRunning = false;
        _cts?.Cancel();
        DisposeWatcher();

        if (_pollingTask is not null)
        {
            try { await _pollingTask.WaitAsync(TimeSpan.FromSeconds(3), cancellationToken); } catch { /* ignoré */ }
            _pollingTask = null;
        }
    }

    public void UpdateSettings(SentinelSettings settings)
    {
        // Aucun paramètre dynamique spécifique pour les périphériques.
    }

    private void ScheduleReconcile()
    {
        if (!_isRunning) return;
        var now = DateTimeOffset.UtcNow;
        if ((now - _lastScanUtc).TotalMilliseconds < 600)
        {
            return;
        }
        _lastScanUtc = now;

        ThreadPool.QueueUserWorkItem(_ =>
        {
            Thread.Sleep(400); // Laisse le temps à Windows d'enregistrer l'instance PnP.
            ReconcileDevices();
        });
    }

    private async Task PollingLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(10), ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            ReconcileDevices();
        }
    }

    private void ReconcileDevices()
    {
        if (!_isRunning) return;
        try
        {
            var snapshot = QueryUsbAndHidDevices();
            List<PnpDeviceInfo> added;
            List<PnpDeviceInfo> removed;

            lock (_diffGate)
            {
                added = snapshot.Values.Where(d => !_knownDevices.ContainsKey(d.DeviceId)).ToList();
                removed = _knownDevices.Values.Where(d => !snapshot.ContainsKey(d.DeviceId)).ToList();
                _knownDevices = snapshot;
            }

            foreach (var dev in added)
            {
                var eventType = dev.DeviceId.StartsWith("USB", StringComparison.OrdinalIgnoreCase)
                    ? EventTypes.UsbInserted
                    : EventTypes.DeviceAdded;
                EmitDeviceEvent(eventType, dev);
            }

            foreach (var dev in removed)
            {
                EmitDeviceEvent(EventTypes.UsbRemoved, dev);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Erreur lors de l'inventaire des périphériques PnP.");
        }
    }

    private void EmitDeviceEvent(string eventType, PnpDeviceInfo dev)
    {
        var attrs = new Dictionary<string, string>
        {
            [AttributeKeys.DeviceId] = dev.DeviceId,
            [AttributeKeys.DeviceClass] = dev.DeviceClass,
            [AttributeKeys.DeviceName] = dev.Name,
            [AttributeKeys.IsKeyboard] = dev.IsKeyboard ? "true" : "false",
            [AttributeKeys.IsStorage] = dev.IsStorage ? "true" : "false"
        };

        if (!string.IsNullOrEmpty(dev.VendorId)) attrs[AttributeKeys.VendorId] = dev.VendorId;
        if (!string.IsNullOrEmpty(dev.ProductId)) attrs[AttributeKeys.ProductId] = dev.ProductId;

        var hints = $"device:{dev.DeviceId}" +
                    (string.IsNullOrEmpty(dev.VendorId) ? string.Empty : $";vid:{dev.VendorId};pid:{dev.ProductId}");

        var evt = SecurityEvent.Create(
            _stateStore.HostId,
            Environment.UserName,
            EventCategory.Device,
            eventType,
            dev.Name,
            attrs,
            hints);

        if (_sink.Publish(evt))
        {
            Interlocked.Increment(ref _eventsProduced);
        }
    }

    private Dictionary<string, PnpDeviceInfo> QueryUsbAndHidDevices()
    {
        var devices = new Dictionary<string, PnpDeviceInfo>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT PNPDeviceID, Name, PNPClass, Service, Description FROM Win32_PnPEntity " +
                "WHERE PNPDeviceID LIKE 'USB%' OR PNPDeviceID LIKE 'HID%' OR PNPDeviceID LIKE 'USBSTOR%'");
            using var results = searcher.Get();
            foreach (ManagementObject obj in results)
            {
                var id = obj["PNPDeviceID"]?.ToString();
                if (string.IsNullOrWhiteSpace(id))
                {
                    continue;
                }

                var name = obj["Name"]?.ToString() ?? obj["Description"]?.ToString() ?? id;
                var pnpClass = obj["PNPClass"]?.ToString() ?? "Unknown";
                var service = obj["Service"]?.ToString() ?? string.Empty;

                var (vid, pid) = ExtractVidPid(id);
                var isKeyboard =
                    pnpClass.Equals("Keyboard", StringComparison.OrdinalIgnoreCase) ||
                    service.Equals("kbdhid", StringComparison.OrdinalIgnoreCase) ||
                    name.Contains("Keyboard", StringComparison.OrdinalIgnoreCase) ||
                    name.Contains("Clavier", StringComparison.OrdinalIgnoreCase);

                var isStorage =
                    id.StartsWith("USBSTOR", StringComparison.OrdinalIgnoreCase) ||
                    pnpClass.Equals("DiskDrive", StringComparison.OrdinalIgnoreCase) ||
                    pnpClass.Equals("WPD", StringComparison.OrdinalIgnoreCase) ||
                    service.Equals("USBSTOR", StringComparison.OrdinalIgnoreCase) ||
                    name.Contains("Mass Storage", StringComparison.OrdinalIgnoreCase);

                devices[id] = new PnpDeviceInfo(id, vid, pid, pnpClass, name, isKeyboard, isStorage);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Échec de requête Win32_PnPEntity.");
        }

        return devices;
    }

    public static (string? VendorId, string? ProductId) ExtractVidPid(string deviceId)
    {
        var match = VidPidRegex().Match(deviceId);
        return match.Success
            ? (match.Groups[1].Value.ToUpperInvariant(), match.Groups[2].Value.ToUpperInvariant())
            : (null, null);
    }

    [GeneratedRegex(@"VID_([0-9A-Fa-f]{4}).*?PID_([0-9A-Fa-f]{4})", RegexOptions.IgnoreCase)]
    private static partial Regex VidPidRegex();

    private void DisposeWatcher()
    {
        if (_deviceWatcher is null) return;
        try { _deviceWatcher.Stop(); } catch { /* ignoré */ }
        try { _deviceWatcher.Dispose(); } catch { /* ignoré */ }
        _deviceWatcher = null;
    }

    public void Dispose()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        DisposeWatcher();
    }

    private sealed record PnpDeviceInfo(
        string DeviceId,
        string? VendorId,
        string? ProductId,
        string DeviceClass,
        string Name,
        bool IsKeyboard,
        bool IsStorage);
}
