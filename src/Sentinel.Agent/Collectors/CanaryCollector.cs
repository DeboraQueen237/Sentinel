using System.Collections.Concurrent;
using System.Globalization;
using Microsoft.Extensions.Logging;
using Sentinel.Agent.Configuration;
using Sentinel.Agent.Pipeline;
using Sentinel.Shared.Models;

namespace Sentinel.Agent.Collectors;

/// <summary>
/// Collecteur anti-ransomware surveillant les fichiers canari déployés par <see cref="CanaryManager"/> (v2 Mission 6).
/// Toute modification, renommage, chiffrement ou suppression d'un canari déclenche immédiatement un événement
/// critique (<see cref="EventCategory.Canary"/>) pour enclencher la réponse réversible graduée.
/// </summary>
public sealed class CanaryCollector : IEventCollector, IDisposable
{
    private readonly CanaryManager _manager;
    private readonly IEventSink _sink;
    private readonly AgentStateStore _stateStore;
    private readonly ILogger<CanaryCollector> _logger;
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly ConcurrentDictionary<string, DateTimeOffset> _recentAlerts = new(StringComparer.OrdinalIgnoreCase);

    private CanarySettings _settings = new();
    private CancellationTokenSource? _cts;
    private Task? _periodicCheckTask;
    private volatile bool _isRunning;
    private volatile string? _lastError;
    private long _eventsProduced;

    public string Name => "Canary";
    public bool IsRunning => _isRunning;
    public string? LastError => _lastError;
    public long EventsProduced => Interlocked.Read(ref _eventsProduced);

    public CanaryCollector(
        CanaryManager manager,
        IEventSink sink,
        AgentStateStore stateStore,
        ILogger<CanaryCollector> logger)
    {
        _manager = manager;
        _sink = sink;
        _stateStore = stateStore;
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _settings = _stateStore.CurrentSettings.Canaries ?? new CanarySettings();
        if (!_settings.Enabled)
        {
            _isRunning = false;
            _lastError = "Fichiers canari désactivés par configuration.";
            return Task.CompletedTask;
        }

        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var deployed = _manager.EnsureDeployed(_settings);
        SetupWatchers(deployed);

        _isRunning = true;
        _lastError = deployed.Count == 0 ? "Aucun dossier canari accessible." : null;
        _periodicCheckTask = Task.Run(() => PeriodicIntegrityLoopAsync(_cts.Token), _cts.Token);
        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        _isRunning = false;
        _cts?.Cancel();
        DisposeWatchers();

        if (_periodicCheckTask is not null)
        {
            try { await _periodicCheckTask.WaitAsync(TimeSpan.FromSeconds(3), cancellationToken); } catch { /* ignoré */ }
            _periodicCheckTask = null;
        }
    }

    public void UpdateSettings(SentinelSettings settings)
    {
        _settings = settings.Canaries ?? new CanarySettings();
        if (!_settings.Enabled)
        {
            DisposeWatchers();
            _isRunning = false;
            _lastError = "Fichiers canari désactivés.";
            return;
        }

        if (_isRunning)
        {
            var deployed = _manager.EnsureDeployed(_settings);
            SetupWatchers(deployed);
        }
    }

    private void SetupWatchers(IReadOnlyList<CanaryRecord> records)
    {
        DisposeWatchers();

        var folders = records
            .Select(r => r.Folder)
            .Where(Directory.Exists)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        foreach (var folder in folders)
        {
            try
            {
                var w = new FileSystemWatcher(folder)
                {
                    IncludeSubdirectories = false,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.Security
                };

                w.Changed += (_, e) => OnCanaryFileTouched(e.FullPath, isDelete: false, renamedTo: null);
                w.Deleted += (_, e) => OnCanaryFileTouched(e.FullPath, isDelete: true, renamedTo: null);
                w.Renamed += (_, e) => OnCanaryFileTouched(e.OldFullPath, isDelete: false, renamedTo: e.FullPath);
                w.EnableRaisingEvents = true;
                _watchers.Add(w);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Impossible de surveiller le dossier canari {Folder}.", folder);
            }
        }
    }

    private void OnCanaryFileTouched(string path, bool isDelete, string? renamedTo)
    {
        if (!_isRunning || !_settings.Enabled) return;
        var rec = _manager.FindByPath(path);
        if (rec is null) return;

        if (renamedTo is not null)
        {
            double? entropy = null;
            string? observedHash = null;
            try
            {
                if (File.Exists(renamedTo))
                {
                    var bytes = File.ReadAllBytes(renamedTo);
                    observedHash = CanaryManager.ComputeSha256Hex(bytes);
                    entropy = CanaryManager.ComputeShannonEntropy(bytes);
                }
            }
            catch { /* ignoré */ }

            var eventType = entropy is >= 7.2 ? EventTypes.CanaryEncrypted : EventTypes.CanaryRenamed;
            EmitCanaryAlert(
                rec,
                eventType,
                observedHash,
                entropy,
                $"Fichier canari renommé ({Path.GetFileName(rec.FilePath)} → {Path.GetFileName(renamedTo)})",
                renamedTo);
            return;
        }

        if (isDelete)
        {
            EmitCanaryAlert(rec, EventTypes.CanaryDeleted, null, null, $"Fichier canari supprimé : {rec.FilePath}", null);
            return;
        }

        var finding = _manager.VerifySingle(rec);
        if (finding is not null)
        {
            EmitCanaryAlert(rec, finding.EventType, finding.ObservedSha256, finding.ObservedEntropy, finding.Reason, null);
        }
    }

    private async Task PeriodicIntegrityLoopAsync(CancellationToken ct)
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

            if (!_isRunning || !_settings.Enabled) continue;

            foreach (var finding in _manager.VerifyAll())
            {
                EmitCanaryAlert(
                    finding.Record,
                    finding.EventType,
                    finding.ObservedSha256,
                    finding.ObservedEntropy,
                    finding.Reason,
                    null);
            }
        }
    }

    private void EmitCanaryAlert(
        CanaryRecord rec,
        string eventType,
        string? observedHash,
        double? entropy,
        string reason,
        string? newPath)
    {
        var dedupKey = $"{rec.Id}|{eventType}";
        var now = DateTimeOffset.UtcNow;
        if (_recentAlerts.TryGetValue(dedupKey, out var last) && (now - last).TotalSeconds < 10)
        {
            return;
        }
        _recentAlerts[dedupKey] = now;

        var attrs = new Dictionary<string, string>
        {
            [AttributeKeys.CanaryId] = rec.Id,
            [AttributeKeys.CanaryFolder] = rec.Folder,
            [AttributeKeys.CanaryExpectedHash] = rec.ExpectedSha256,
            [AttributeKeys.FilePath] = newPath ?? rec.FilePath,
            [AttributeKeys.OldFilePath] = rec.FilePath,
            [AttributeKeys.FileName] = Path.GetFileName(newPath ?? rec.FilePath),
            [AttributeKeys.WatchedFolder] = Path.GetFileName(rec.Folder),
            [AttributeKeys.Reason] = reason,
            [AttributeKeys.CollectorSource] = "CanaryCollector",
            [AttributeKeys.EventSources] = "CanaryCollector"
        };

        if (!string.IsNullOrWhiteSpace(observedHash)) attrs[AttributeKeys.CanaryObservedHash] = observedHash;
        if (entropy.HasValue) attrs[AttributeKeys.Entropy] = entropy.Value.ToString("F2", CultureInfo.InvariantCulture);

        var evt = SecurityEvent.Create(
            _stateStore.HostId,
            Environment.UserName,
            EventCategory.Canary,
            eventType,
            rec.FilePath,
            attrs,
            $"canary:{rec.Id};folder:{rec.Folder}",
            now);

        if (_sink.Publish(evt))
        {
            Interlocked.Increment(ref _eventsProduced);
        }
    }

    private void DisposeWatchers()
    {
        foreach (var w in _watchers)
        {
            try { w.EnableRaisingEvents = false; } catch { /* ignoré */ }
            try { w.Dispose(); } catch { /* ignoré */ }
        }
        _watchers.Clear();
    }

    public void Dispose()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        DisposeWatchers();
    }
}
