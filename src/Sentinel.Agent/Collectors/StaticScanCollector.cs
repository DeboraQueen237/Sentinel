using System.Collections.Concurrent;
using System.Globalization;
using Microsoft.Extensions.Logging;
using Sentinel.Agent.Configuration;
using Sentinel.Agent.Pipeline;
using Sentinel.Detection.Static;
using Sentinel.ML;
using Sentinel.Shared.Infrastructure;
using Sentinel.Shared.Models;

namespace Sentinel.Agent.Collectors;

/// <summary>
/// Collecteur d'analyse statique PE + YARA + ML.NET déclenchée par événements et planifiée (v2 Missions 3 &amp; 5).
/// Scanne UNIQUEMENT les nouveaux fichiers éligibles dans les dossiers surveillés (jamais un scan permanent de tout le disque)
/// avec limites strictes de taille, timeout, parallélisme et priorité basse.
/// </summary>
public sealed class StaticScanCollector : IEventCollector, IDisposable
{
    private readonly IStaticFileScanner _scanner;
    private readonly IPeMlClassifier _ml;
    private readonly IEventSink _sink;
    private readonly AgentStateStore _stateStore;
    private readonly ILogger<StaticScanCollector> _logger;
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly ConcurrentDictionary<string, DateTimeOffset> _recentScans = new(StringComparer.OrdinalIgnoreCase);

    private SentinelSettings _settings = new();
    private CancellationTokenSource? _cts;
    private Task? _scheduledTask;
    private volatile bool _isRunning;
    private volatile string? _lastError;
    private long _eventsProduced;

    public string Name => "StaticAnalysis";
    public bool IsRunning => _isRunning;
    public string? LastError => _lastError;
    public long EventsProduced => Interlocked.Read(ref _eventsProduced);

    public StaticScanCollector(
        IStaticFileScanner scanner,
        IPeMlClassifier ml,
        IEventSink sink,
        AgentStateStore stateStore,
        ILogger<StaticScanCollector> logger)
    {
        _scanner = scanner;
        _ml = ml;
        _sink = sink;
        _stateStore = stateStore;
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _settings = _stateStore.CurrentSettings;
        if (!_settings.StaticScan.Enabled)
        {
            _isRunning = false;
            _lastError = "Analyse statique désactivée par configuration.";
            return Task.CompletedTask;
        }

        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        // Charge les règles YARA locales si présentes
        var yaraDirs = new[]
        {
            SentinelPaths.YaraRules,
            Path.Combine(AppContext.BaseDirectory, "rules", "yara")
        }.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        if (yaraDirs.Count > 0)
        {
            _scanner.YaraScanner.LoadFromDirectories(yaraDirs);
        }

        if (_settings.StaticScan.ScanOnFileEvent)
        {
            SetupWatchers(_settings.WatchedFolders);
        }

        _isRunning = true;
        _lastError = _scanner.YaraScanner.IsUsingFallback
            ? $"Actif ({_scanner.YaraScanner.EngineName})"
            : null;

        if (_settings.StaticScan.ScheduledScanIntervalHours > 0)
        {
            _scheduledTask = Task.Run(() => ScheduledLoopAsync(_cts.Token), _cts.Token);
        }

        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        _isRunning = false;
        _cts?.Cancel();
        DisposeWatchers();

        if (_scheduledTask is not null)
        {
            try { await _scheduledTask.WaitAsync(TimeSpan.FromSeconds(3), cancellationToken); } catch { /* ignoré */ }
            _scheduledTask = null;
        }
    }

    public void UpdateSettings(SentinelSettings settings)
    {
        _settings = settings;
        if (!_settings.StaticScan.Enabled)
        {
            DisposeWatchers();
            _isRunning = false;
            return;
        }
        if (_isRunning && _settings.StaticScan.ScanOnFileEvent)
        {
            SetupWatchers(_settings.WatchedFolders);
        }
    }

    private void SetupWatchers(IEnumerable<string> rawFolders)
    {
        DisposeWatchers();
        var folders = rawFolders
            .Where(f => !string.IsNullOrWhiteSpace(f))
            .Select(f => Environment.ExpandEnvironmentVariables(f.Trim()))
            .Where(Directory.Exists)
            .Distinct(StringComparer.OrdinalIgnoreCase);

        foreach (var folder in folders)
        {
            try
            {
                var w = new FileSystemWatcher(folder)
                {
                    IncludeSubdirectories = false,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size
                };
                w.Created += (_, e) => TriggerScanFireAndForget(e.FullPath);
                w.Renamed += (_, e) => TriggerScanFireAndForget(e.FullPath);
                w.EnableRaisingEvents = true;
                _watchers.Add(w);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Watcher statique non initialisé pour {Folder}.", folder);
            }
        }
    }

    private void TriggerScanFireAndForget(string filePath)
    {
        if (!_isRunning || !_settings.StaticScan.Enabled || !_scanner.IsEligibleExtension(filePath)) return;

        var now = DateTimeOffset.UtcNow;
        if (_recentScans.TryGetValue(filePath, out var last) && (now - last).TotalSeconds < 15) return;
        _recentScans[filePath] = now;

        var ct = _cts?.Token ?? CancellationToken.None;
        _ = Task.Run(async () =>
        {
            try
            {
                // Laisse le fichier terminer son écriture initiale
                await Task.Delay(350, ct);
                await ScanAndEmitAsync(filePath, ct);
            }
            catch { /* ignoré */ }
        }, ct);
    }

    private async Task ScheduledLoopAsync(CancellationToken ct)
    {
        var interval = TimeSpan.FromHours(Math.Clamp(_settings.StaticScan.ScheduledScanIntervalHours, 1, 168));
        var scheduled = new ScheduledStaticScanner(_scanner);

        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(interval, ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            if (!_isRunning || !_settings.StaticScan.Enabled) continue;

            try
            {
                var folders = _settings.WatchedFolders
                    .Select(f => Environment.ExpandEnvironmentVariables(f.Trim()))
                    .Where(Directory.Exists)
                    .ToArray();

                var summary = await scheduled.ScanWatchedFoldersAsync(
                    folders,
                    excludedPaths: _settings.ExcludedPaths,
                    excludedHashes: _settings.ExcludedHashes,
                    ct: ct);
                foreach (var outcome in summary.Findings)
                {
                    EmitOutcome(outcome);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Erreur lors du scan statique planifié.");
            }
        }
    }

    private async Task ScanAndEmitAsync(string filePath, CancellationToken ct)
    {
        var outcome = await _scanner.ScanIfEligibleAsync(filePath, ct);
        if (outcome is null) return;
        EmitOutcome(outcome);
    }

    private void EmitOutcome(StaticScanOutcome outcome)
    {
        var events = _scanner.ToSecurityEvents(outcome, _stateStore.HostId, Environment.UserName);
        foreach (var evt in events)
        {
            var enrichedEvt = evt;
            if (outcome.Result.IsPe && _settings.MachineLearning.Enabled && File.Exists(outcome.Result.FilePath))
            {
                var mlPred = _ml.PredictFile(outcome.Result.FilePath);
                if (mlPred.ModelLoaded && mlPred.MaliciousProbability >= _settings.MachineLearning.SuspiciousProbabilityThreshold)
                {
                    var attrs = new Dictionary<string, string>(evt.Attributes, StringComparer.OrdinalIgnoreCase)
                    {
                        [AttributeKeys.MlScore] = mlPred.MaliciousProbability.ToString("F4", CultureInfo.InvariantCulture),
                        [AttributeKeys.MlModelVersion] = mlPred.ModelVersion,
                        [AttributeKeys.MlTopFeatures] = string.Join(", ", mlPred.TopContributingFeatures.Take(4))
                    };
                    enrichedEvt = evt with { Attributes = attrs };
                }
            }

            if (_sink.Publish(enrichedEvt))
            {
                Interlocked.Increment(ref _eventsProduced);
            }
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
