using System.Collections.Concurrent;
using System.Globalization;
using Microsoft.Extensions.Logging;
using Sentinel.Agent.Configuration;
using Sentinel.Agent.Pipeline;
using Sentinel.Shared.Infrastructure;
using Sentinel.Shared.Models;

namespace Sentinel.Agent.Collectors;

/// <summary>
/// Collecteur système de fichiers (doc §6.4) : surveille les dossiers configurés via
/// <see cref="FileSystemWatcher"/>, calcule entropie, double extension, SHA-256 (exécutables/petits fichiers)
/// et détecte les rafales ransomware via <see cref="RansomwareBurstDetector"/>.
/// </summary>
public sealed class FileSystemCollector : IEventCollector, IDisposable
{
    private readonly IEventSink _sink;
    private readonly AgentStateStore _stateStore;
    private readonly ILogger<FileSystemCollector> _logger;
    private readonly RansomwareBurstDetector _burstDetector = new();
    private readonly ConcurrentDictionary<string, FileSystemWatcher> _watchers = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DateTimeOffset> _debounceCache = new(StringComparer.OrdinalIgnoreCase);

    private volatile SentinelSettings _settings;
    private readonly string _sentinelRoot;
    private long _eventsProduced;
    private volatile bool _isRunning;
    private volatile string? _lastError;

    public string Name => "FileSystem";
    public bool IsRunning => _isRunning;
    public string? LastError => _lastError;
    public long EventsProduced => Interlocked.Read(ref _eventsProduced);

    public FileSystemCollector(
        IEventSink sink,
        AgentStateStore stateStore,
        ILogger<FileSystemCollector> logger)
    {
        _sink = sink;
        _stateStore = stateStore;
        _logger = logger;
        _settings = stateStore.CurrentSettings;
        _sentinelRoot = Path.GetFullPath(SentinelPaths.Root).TrimEnd('\\') + "\\";
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _isRunning = true;
        _lastError = null;
        ReconcileWatchers(_settings.WatchedFolders);
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _isRunning = false;
        ClearWatchers();
        return Task.CompletedTask;
    }

    public void UpdateSettings(SentinelSettings settings)
    {
        _settings = settings;
        if (_isRunning)
        {
            ReconcileWatchers(settings.WatchedFolders);
        }
    }

    private void ReconcileWatchers(IEnumerable<string>? configuredFolders)
    {
        var desired = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (configuredFolders is not null)
        {
            foreach (var raw in configuredFolders)
            {
                if (string.IsNullOrWhiteSpace(raw))
                {
                    continue;
                }

                try
                {
                    var expanded = Environment.ExpandEnvironmentVariables(raw).Trim();
                    if (Directory.Exists(expanded))
                    {
                        desired.Add(Path.GetFullPath(expanded));
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Dossier surveillé invalide ignoré : {Folder}.", raw);
                }
            }
        }

        // Supprime les watchers qui ne sont plus configurés.
        foreach (var existing in _watchers.Keys.ToArray())
        {
            if (!desired.Contains(existing) && _watchers.TryRemove(existing, out var removed))
            {
                removed.EnableRaisingEvents = false;
                removed.Dispose();
            }
        }

        var errors = new List<string>();
        foreach (var folder in desired)
        {
            if (_watchers.ContainsKey(folder))
            {
                continue;
            }

            try
            {
                var watcher = new FileSystemWatcher(folder)
                {
                    IncludeSubdirectories = true,
                    InternalBufferSize = 32 * 1024,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.CreationTime
                };

                watcher.Created += (_, e) => HandleFileEvent(EventTypes.FileCreated, e.FullPath, oldPath: null);
                watcher.Changed += (_, e) => HandleFileEvent(EventTypes.FileModified, e.FullPath, oldPath: null);
                watcher.Renamed += (_, e) => HandleFileEvent(EventTypes.FileRenamed, e.FullPath, oldPath: e.OldFullPath);
                watcher.Deleted += (_, e) => HandleFileEvent(EventTypes.FileDeleted, e.FullPath, oldPath: null);
                watcher.Error += (_, e) => _logger.LogWarning(e.GetException(), "Débordement de tampon FileSystemWatcher sur {Folder}.", folder);
                watcher.EnableRaisingEvents = true;

                _watchers[folder] = watcher;
            }
            catch (Exception ex)
            {
                errors.Add($"{folder}: {ex.Message}");
                _logger.LogWarning(ex, "Impossible de surveiller le dossier {Folder}.", folder);
            }
        }

        _lastError = errors.Count > 0 ? string.Join(" ; ", errors) : null;
    }

    private void HandleFileEvent(string eventType, string fullPath, string? oldPath)
    {
        if (!_isRunning || string.IsNullOrWhiteSpace(fullPath))
        {
            return;
        }

        if (IsExcludedPath(fullPath))
        {
            return;
        }

        // Anti-rebond (500 ms par chemin+type) pour éviter le bruit OS sur une écriture continue.
        var debounceKey = $"{eventType}|{fullPath}";
        var now = DateTimeOffset.UtcNow;
        if (_debounceCache.TryGetValue(debounceKey, out var last) && (now - last).TotalMilliseconds < 500)
        {
            return;
        }
        _debounceCache[debounceKey] = now;
        if (_debounceCache.Count > 4096)
        {
            PruneDebounceCache(now);
        }

        // Traitement asynchrone léger pour ne jamais bloquer le thread interne de FileSystemWatcher.
        ThreadPool.QueueUserWorkItem(_ => ProcessFileEvent(eventType, fullPath, oldPath, now));
    }

    private void ProcessFileEvent(string eventType, string fullPath, string? oldPath, DateTimeOffset timestamp)
    {
        try
        {
            if (Directory.Exists(fullPath))
            {
                return;
            }

            var ext = Path.GetExtension(fullPath);
            var isExec = FileAnalyzer.IsExecutableExtension(fullPath);
            var isArchive = FileAnalyzer.IsArchiveExtension(fullPath);
            var doubleExt = FileAnalyzer.HasDoubleExtension(fullPath);
            var watchedFolder = FileAnalyzer.ClassifyWatchedFolder(fullPath);

            long fileSize = 0;
            double entropy = 0.0;
            string? sha256 = null;

            if (eventType != EventTypes.FileDeleted && File.Exists(fullPath))
            {
                try
                {
                    var fi = new FileInfo(fullPath);
                    fileSize = fi.Length;
                    if (fileSize > 0)
                    {
                        entropy = FileAnalyzer.ComputeFileEntropy(fullPath);
                        if (isExec || doubleExt || fileSize <= 10L * 1024 * 1024)
                        {
                            sha256 = FileAnalyzer.ComputeSha256Bounded(fullPath, maxBytes: 25L * 1024 * 1024);
                        }
                    }
                }
                catch (IOException)
                {
                    // Fichier encore verrouillé en écriture : on publie tout de même les métadonnées de chemin/extension.
                }
                catch (UnauthorizedAccessException)
                {
                    // Accès refusé : on ne lit pas le fichier.
                }
            }

            var attrs = new Dictionary<string, string>
            {
                [AttributeKeys.FilePath] = fullPath,
                [AttributeKeys.Extension] = ext,
                [AttributeKeys.FileSize] = fileSize.ToString(CultureInfo.InvariantCulture),
                [AttributeKeys.Entropy] = entropy.ToString("0.###", CultureInfo.InvariantCulture),
                [AttributeKeys.DoubleExtension] = doubleExt ? "true" : "false",
                [AttributeKeys.IsExecutable] = isExec ? "true" : "false",
                [AttributeKeys.IsArchive] = isArchive ? "true" : "false",
                [AttributeKeys.WatchedFolder] = watchedFolder
            };

            if (!string.IsNullOrWhiteSpace(oldPath))
            {
                attrs[AttributeKeys.OldFilePath] = oldPath;
                attrs[AttributeKeys.OldExtension] = Path.GetExtension(oldPath);
            }

            if (!string.IsNullOrEmpty(sha256))
            {
                attrs[AttributeKeys.Sha256] = sha256;
            }

            var hints = string.IsNullOrEmpty(sha256)
                ? $"file:{Path.GetFileName(fullPath)};folder:{watchedFolder}"
                : $"hash:{sha256};file:{Path.GetFileName(fullPath)};folder:{watchedFolder}";

            var evt = SecurityEvent.Create(
                _stateStore.HostId,
                Environment.UserName,
                EventCategory.File,
                eventType,
                fullPath,
                attrs,
                hints,
                timestamp);

            if (_sink.Publish(evt))
            {
                Interlocked.Increment(ref _eventsProduced);
            }

            if (eventType is EventTypes.FileCreated or EventTypes.FileModified or EventTypes.FileRenamed)
            {
                var burst = _burstDetector.RecordActivity(
                    fullPath,
                    ext,
                    entropy,
                    isRename: eventType == EventTypes.FileRenamed,
                    timestamp: timestamp);

                if (burst is not null)
                {
                    var burstEvent = RansomwareBurstDetector.ToSecurityEvent(_stateStore.HostId, Environment.UserName, burst);
                    if (_sink.Publish(burstEvent))
                    {
                        Interlocked.Increment(ref _eventsProduced);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Erreur lors de l'analyse du fichier {Path}.", fullPath);
        }
    }

    private bool IsExcludedPath(string fullPath)
    {
        if (fullPath.StartsWith(_sentinelRoot, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // Ignore les fichiers temporaires SQLite/browser triviaux.
        if (fullPath.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase) &&
            fullPath.Contains(@"\AppData\Local\Temp\", StringComparison.OrdinalIgnoreCase))
        {
            return false; // Temp reste analysé sauf exclusions explicites
        }

        foreach (var excluded in _settings.ExcludedPaths)
        {
            if (string.IsNullOrWhiteSpace(excluded))
            {
                continue;
            }
            var expanded = Environment.ExpandEnvironmentVariables(excluded);
            if (fullPath.StartsWith(expanded, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private void PruneDebounceCache(DateTimeOffset now)
    {
        foreach (var kv in _debounceCache)
        {
            if ((now - kv.Value).TotalSeconds > 10)
            {
                _debounceCache.TryRemove(kv.Key, out _);
            }
        }
    }

    private void ClearWatchers()
    {
        foreach (var kv in _watchers.ToArray())
        {
            if (_watchers.TryRemove(kv.Key, out var watcher))
            {
                watcher.EnableRaisingEvents = false;
                watcher.Dispose();
            }
        }
    }

    public void Dispose() => ClearWatchers();
}
