using System.Xml.Linq;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using Sentinel.Agent.Configuration;
using Sentinel.Agent.Pipeline;
using Sentinel.Shared.Models;

namespace Sentinel.Agent.Collectors;

/// <summary>
/// Collecteur d'installations et de persistance (doc §6.9, §8.3) :
/// surveille les clés Registre <c>Uninstall</c> (<see cref="EventTypes.AppInstalled"/>),
/// les clés <c>Run</c>/<c>RunOnce</c> (<see cref="EventTypes.StartupEntryAdded"/>) et
/// les nouvelles tâches planifiées (<see cref="EventTypes.ScheduledTaskCreated"/>).
/// </summary>
public sealed class InstallationCollector : IEventCollector, IDisposable
{
    private static readonly (RegistryHive Hive, RegistryView View, string SubKey, string DisplayPrefix)[] UninstallRoots =
    [
        (RegistryHive.LocalMachine, RegistryView.Registry64, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (RegistryHive.LocalMachine, RegistryView.Registry32, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", @"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (RegistryHive.CurrentUser, RegistryView.Default, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
    ];

    private static readonly (RegistryHive Hive, RegistryView View, string SubKey, string DisplayPrefix)[] RunRoots =
    [
        (RegistryHive.LocalMachine, RegistryView.Registry64, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (RegistryHive.LocalMachine, RegistryView.Registry64, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (RegistryHive.LocalMachine, RegistryView.Registry32, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", @"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
        (RegistryHive.CurrentUser, RegistryView.Default, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (RegistryHive.CurrentUser, RegistryView.Default, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")
    ];

    private readonly IEventSink _sink;
    private readonly AgentStateStore _stateStore;
    private readonly ILogger<InstallationCollector> _logger;

    private Dictionary<string, InstalledAppInfo> _knownApps = new(StringComparer.OrdinalIgnoreCase);
    private Dictionary<string, string> _knownRunEntries = new(StringComparer.OrdinalIgnoreCase);
    private HashSet<string> _knownTasks = new(StringComparer.OrdinalIgnoreCase);

    private CancellationTokenSource? _cts;
    private Task? _loopTask;
    private volatile bool _isRunning;
    private volatile string? _lastError;
    private long _eventsProduced;

    public string Name => "Installation";
    public bool IsRunning => _isRunning;
    public string? LastError => _lastError;
    public long EventsProduced => Interlocked.Read(ref _eventsProduced);

    public InstallationCollector(
        IEventSink sink,
        AgentStateStore stateStore,
        ILogger<InstallationCollector> logger)
    {
        _sink = sink;
        _stateStore = stateStore;
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        // Capture l'état initial afin de ne signaler que les ajouts postérieurs au démarrage.
        _knownApps = SnapshotInstalledApps();
        _knownRunEntries = SnapshotRunEntries();
        _knownTasks = SnapshotScheduledTasks();

        _isRunning = true;
        _lastError = null;
        _loopTask = Task.Run(() => MonitorLoopAsync(_cts.Token), _cts.Token);
        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        _isRunning = false;
        _cts?.Cancel();
        if (_loopTask is not null)
        {
            try { await _loopTask.WaitAsync(TimeSpan.FromSeconds(3), cancellationToken); } catch { /* ignoré */ }
            _loopTask = null;
        }
    }

    public void UpdateSettings(SentinelSettings settings)
    {
        // Aucun paramètre dynamique spécifique pour les installations.
    }

    private async Task MonitorLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(30), ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            try
            {
                DiffInstalledApps();
                DiffRunEntries();
                DiffScheduledTasks();
            }
            catch (Exception ex)
            {
                _lastError = ex.Message;
                _logger.LogDebug(ex, "Erreur lors du scan Installations/Persistance.");
            }
        }
    }

    private void DiffInstalledApps()
    {
        var current = SnapshotInstalledApps();
        foreach (var (key, app) in current)
        {
            if (_knownApps.ContainsKey(key))
            {
                continue;
            }

            var attrs = new Dictionary<string, string>
            {
                [AttributeKeys.AppName] = app.Name,
                [AttributeKeys.RegistryKey] = app.RegistryKey
            };
            if (!string.IsNullOrWhiteSpace(app.Version)) attrs[AttributeKeys.AppVersion] = app.Version;
            if (!string.IsNullOrWhiteSpace(app.Publisher)) attrs[AttributeKeys.AppPublisher] = app.Publisher;

            var evt = SecurityEvent.Create(
                _stateStore.HostId,
                Environment.UserName,
                EventCategory.Installation,
                EventTypes.AppInstalled,
                app.Name,
                attrs,
                $"app:{app.Name}");

            if (_sink.Publish(evt))
            {
                Interlocked.Increment(ref _eventsProduced);
            }
        }

        _knownApps = current;
    }

    private void DiffRunEntries()
    {
        var current = SnapshotRunEntries();
        foreach (var (fullKey, value) in current)
        {
            if (_knownRunEntries.TryGetValue(fullKey, out var oldVal) &&
                string.Equals(oldVal, value, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var sepIndex = fullKey.LastIndexOf('|');
            var regKey = sepIndex > 0 ? fullKey[..sepIndex] : fullKey;
            var valueName = sepIndex > 0 ? fullKey[(sepIndex + 1)..] : fullKey;
            var exePath = ExtractExecutableFromCommand(value);

            var attrs = new Dictionary<string, string>
            {
                [AttributeKeys.RegistryKey] = regKey,
                [AttributeKeys.RegistryValue] = value,
                [AttributeKeys.AppName] = valueName
            };
            if (!string.IsNullOrWhiteSpace(exePath))
            {
                attrs[AttributeKeys.ProcessPath] = exePath;
            }

            var evt = SecurityEvent.Create(
                _stateStore.HostId,
                Environment.UserName,
                EventCategory.Installation,
                EventTypes.StartupEntryAdded,
                $"{regKey}\\{valueName}",
                attrs,
                $"startup:{valueName}" + (string.IsNullOrEmpty(exePath) ? string.Empty : $";file:{Path.GetFileName(exePath)}"));

            if (_sink.Publish(evt))
            {
                Interlocked.Increment(ref _eventsProduced);
            }
        }

        _knownRunEntries = current;
    }

    private void DiffScheduledTasks()
    {
        var current = SnapshotScheduledTasks();
        foreach (var taskFile in current)
        {
            if (_knownTasks.Contains(taskFile))
            {
                continue;
            }

            var taskName = ExtractTaskRelativeName(taskFile);
            var command = TryReadTaskCommand(taskFile);

            var attrs = new Dictionary<string, string>
            {
                [AttributeKeys.TaskName] = taskName
            };
            if (!string.IsNullOrWhiteSpace(command))
            {
                attrs[AttributeKeys.ProcessPath] = command;
            }

            var evt = SecurityEvent.Create(
                _stateStore.HostId,
                Environment.UserName,
                EventCategory.Installation,
                EventTypes.ScheduledTaskCreated,
                taskName,
                attrs,
                $"task:{taskName}");

            if (_sink.Publish(evt))
            {
                Interlocked.Increment(ref _eventsProduced);
            }
        }

        _knownTasks = current;
    }

    private static Dictionary<string, InstalledAppInfo> SnapshotInstalledApps()
    {
        var map = new Dictionary<string, InstalledAppInfo>(StringComparer.OrdinalIgnoreCase);
        foreach (var (hive, view, subKey, prefix) in UninstallRoots)
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                using var root = baseKey.OpenSubKey(subKey, writable: false);
                if (root is null) continue;

                foreach (var name in root.GetSubKeyNames())
                {
                    try
                    {
                        using var appKey = root.OpenSubKey(name, writable: false);
                        var displayName = appKey?.GetValue("DisplayName")?.ToString()?.Trim();
                        if (string.IsNullOrWhiteSpace(displayName))
                        {
                            continue;
                        }

                        var fullKey = $"{prefix}\\{name}";
                        map[fullKey] = new InstalledAppInfo(
                            displayName,
                            appKey?.GetValue("DisplayVersion")?.ToString()?.Trim(),
                            appKey?.GetValue("Publisher")?.ToString()?.Trim(),
                            fullKey);
                    }
                    catch
                    {
                        // Sous-clé inaccessible.
                    }
                }
            }
            catch
            {
                // Ruche inaccessible.
            }
        }

        return map;
    }

    private static Dictionary<string, string> SnapshotRunEntries()
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (hive, view, subKey, prefix) in RunRoots)
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                using var key = baseKey.OpenSubKey(subKey, writable: false);
                if (key is null) continue;

                foreach (var valueName in key.GetValueNames())
                {
                    if (string.IsNullOrWhiteSpace(valueName)) continue;
                    var val = key.GetValue(valueName)?.ToString();
                    if (val is not null)
                    {
                        map[$"{prefix}|{valueName}"] = val;
                    }
                }
            }
            catch
            {
                // Ignoré.
            }
        }

        return map;
    }

    private static HashSet<string> SnapshotScheduledTasks()
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var tasksRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "Tasks");
            if (!Directory.Exists(tasksRoot))
            {
                return set;
            }

            var opts = new EnumerationOptions
            {
                RecurseSubdirectories = true,
                IgnoreInaccessible = true,
                AttributesToSkip = FileAttributes.ReparsePoint
            };

            foreach (var file in Directory.EnumerateFiles(tasksRoot, "*", opts))
            {
                set.Add(file);
            }
        }
        catch
        {
            // Dossier Tasks protégé sans droits élevés.
        }

        return set;
    }

    private static string ExtractTaskRelativeName(string fullPath)
    {
        var tasksRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "Tasks");
        return fullPath.StartsWith(tasksRoot, StringComparison.OrdinalIgnoreCase)
            ? fullPath[tasksRoot.Length..]
            : Path.GetFileName(fullPath);
    }

    private static string? TryReadTaskCommand(string taskFile)
    {
        try
        {
            var doc = XDocument.Load(taskFile);
            var cmd = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "Command")?.Value?.Trim();
            var args = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "Arguments")?.Value?.Trim();
            return string.IsNullOrWhiteSpace(args) ? cmd : $"{cmd} {args}";
        }
        catch
        {
            return null;
        }
    }

    private static string? ExtractExecutableFromCommand(string command)
    {
        if (string.IsNullOrWhiteSpace(command)) return null;
        var trimmed = command.Trim();
        if (trimmed.StartsWith('"'))
        {
            var end = trimmed.IndexOf('"', 1);
            return end > 1 ? trimmed[1..end] : trimmed.Trim('"');
        }

        var space = trimmed.IndexOf(' ');
        return space > 0 ? trimmed[..space] : trimmed;
    }

    public void Dispose()
    {
        _cts?.Cancel();
        _cts?.Dispose();
    }

    private sealed record InstalledAppInfo(string Name, string? Version, string? Publisher, string RegistryKey);
}
