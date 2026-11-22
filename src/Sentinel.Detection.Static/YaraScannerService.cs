using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using dnYara;
using dnYara.Exceptions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Shared.Api;
using Sentinel.Shared.Infrastructure;

namespace Sentinel.Detection.Static;

/// <summary>
/// Service d'analyse YARA pour SENTINEL v2.
/// Tente d'initialiser <c>dnYara</c> (<c>libyara</c> natif) et bascule automatiquement,
/// de facon transparente et explicitement tracee, sur <see cref="ManagedYaraFallbackEngine"/>
/// lorsque la bibliotheque native est absente ou incompatible.
/// </summary>
public sealed class YaraScannerService : IYaraScanner
{
    private readonly ILogger<YaraScannerService> _logger;
    private readonly ManagedYaraFallbackEngine _fallbackEngine = new();
    private readonly bool _preferNativeDnYara;
    private readonly ReaderWriterLockSlim _rwLock = new(LockRecursionPolicy.NoRecursion);

    private readonly List<string> _loadedDirectories = new();
    private readonly List<(string SourceName, string SourceText)> _inMemorySources = new();
    private readonly HashSet<string> _disabledRuleIds = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, long> _matchCounts = new(StringComparer.OrdinalIgnoreCase);

    private List<ParsedYaraRule> _managedRules = new();
    private Dictionary<string, ParsedYaraRule> _ruleLookup = new(StringComparer.OrdinalIgnoreCase);
    private IReadOnlyList<YaraLoadError> _loadErrors = Array.Empty<YaraLoadError>();

    // Etat natif dnYara (protege par _rwLock)
    private YaraContext? _nativeContext;
    private CompiledRules? _nativeCompiledRules;
    private bool _nativePermanentlyUnavailable;
    private bool _isUsingFallback;
    private string? _fallbackReason;

    // Rechargement a chaud
    private FileSystemWatcher? _watcher;
    private Timer? _debounceTimer;
    private int _debounceMs = 300;
    private bool _disposed;

    public YaraScannerService(ILogger<YaraScannerService>? logger = null, bool preferNativeDnYara = true)
    {
        _logger = logger ?? NullLogger<YaraScannerService>.Instance;
        _preferNativeDnYara = preferNativeDnYara;

        if (!preferNativeDnYara)
        {
            _nativePermanentlyUnavailable = true;
            _isUsingFallback = true;
            _fallbackReason = "Repli manage force par configuration.";
            _logger.LogInformation("Moteur YARA configure en mode {Engine} ({Reason}).", EngineName, _fallbackReason);
        }
        else
        {
            TryProbeNativeContext();
        }
    }

    /// <inheritdoc />
    public string EngineName => _isUsingFallback ? YaraEngineNames.ManagedFallback : YaraEngineNames.Native;

    /// <inheritdoc />
    public bool IsUsingFallback => _isUsingFallback;

    /// <inheritdoc />
    public string? FallbackReason => _fallbackReason;

    /// <inheritdoc />
    public int RuleCount
    {
        get
        {
            _rwLock.EnterReadLock();
            try { return _managedRules.Count; }
            finally { _rwLock.ExitReadLock(); }
        }
    }

    /// <inheritdoc />
    public int EnabledRuleCount
    {
        get
        {
            _rwLock.EnterReadLock();
            try { return _managedRules.Count(r => !_disabledRuleIds.Contains(r.Identifier)); }
            finally { _rwLock.ExitReadLock(); }
        }
    }

    /// <inheritdoc />
    public IReadOnlyList<YaraLoadError> LoadErrors
    {
        get
        {
            _rwLock.EnterReadLock();
            try { return _loadErrors; }
            finally { _rwLock.ExitReadLock(); }
        }
    }

    /// <inheritdoc />
    public event EventHandler<YaraRuleLoadResult>? RulesReloaded;

    /// <inheritdoc />
    public YaraRuleLoadResult LoadFromDirectory(string? directory = null)
    {
        var target = string.IsNullOrWhiteSpace(directory) ? SentinelPaths.YaraRules : directory;
        return LoadFromDirectories([target]);
    }

    /// <inheritdoc />
    public YaraRuleLoadResult LoadFromDirectories(IEnumerable<string> directories)
    {
        ArgumentNullException.ThrowIfNull(directories);
        ObjectDisposedException.ThrowIf(_disposed, this);

        var normalizedDirs = directories
            .Where(d => !string.IsNullOrWhiteSpace(d))
            .Select(Path.GetFullPath)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var sources = new List<(string FilePath, string Content)>();
        var errors = new List<YaraLoadError>();

        foreach (var dir in normalizedDirs)
        {
            if (!Directory.Exists(dir))
            {
                var err = new YaraLoadError(dir, $"Repertoire de regles YARA introuvable : '{dir}'.");
                errors.Add(err);
                _logger.LogWarning("Repertoire de regles YARA introuvable : {Directory}", dir);
                continue;
            }

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(dir, "*.*", SearchOption.AllDirectories)
                    .Where(f => f.EndsWith(".yar", StringComparison.OrdinalIgnoreCase) ||
                                f.EndsWith(".yara", StringComparison.OrdinalIgnoreCase))
                    .OrderBy(f => f, StringComparer.OrdinalIgnoreCase);
            }
            catch (Exception ex)
            {
                errors.Add(new YaraLoadError(dir, $"Impossible d'enumerer '{dir}' : {ex.Message}", ex));
                _logger.LogWarning(ex, "Erreur lors de l'enumeration du repertoire YARA {Directory}", dir);
                continue;
            }

            foreach (var file in files)
            {
                try
                {
                    var text = ReadFileWithRetry(file);
                    sources.Add((file, text));
                }
                catch (Exception ex)
                {
                    errors.Add(new YaraLoadError(file, $"Lecture impossible de '{file}' : {ex.Message}", ex));
                    _logger.LogWarning(ex, "Erreur de lecture de la regle YARA {File}", file);
                }
            }
        }

        return ApplyLoadedSources(normalizedDirs, inMemoryOnly: false, sources, errors);
    }

    /// <inheritdoc />
    public YaraRuleLoadResult LoadRuleString(string yaraSource, string sourceName = "<memory>")
    {
        ArgumentNullException.ThrowIfNull(yaraSource);
        ObjectDisposedException.ThrowIf(_disposed, this);

        var errors = new List<YaraLoadError>();
        List<(string, string)> combined;

        _rwLock.EnterReadLock();
        try
        {
            combined = new List<(string, string)>(_inMemorySources.Count + 1);
            combined.AddRange(_inMemorySources);
            combined.Add((sourceName, yaraSource));
        }
        finally
        {
            _rwLock.ExitReadLock();
        }

        return ApplyLoadedSources(Array.Empty<string>(), inMemoryOnly: true, combined, errors);
    }

    /// <inheritdoc />
    public YaraRuleLoadResult Reload()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        List<string> dirs;
        List<(string, string)> memSources;
        _rwLock.EnterReadLock();
        try
        {
            dirs = new List<string>(_loadedDirectories);
            memSources = new List<(string, string)>(_inMemorySources);
        }
        finally
        {
            _rwLock.ExitReadLock();
        }

        YaraRuleLoadResult result;
        if (dirs.Count > 0)
        {
            result = LoadFromDirectories(dirs);
        }
        else if (memSources.Count > 0)
        {
            result = ApplyLoadedSources(Array.Empty<string>(), inMemoryOnly: true, memSources, new List<YaraLoadError>());
        }
        else
        {
            result = new YaraRuleLoadResult(0, EngineName, _isUsingFallback, Array.Empty<YaraLoadError>());
        }

        return result;
    }

    /// <inheritdoc />
    public void EnableHotReload(string? directory = null, int debounceMs = 300)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var target = Path.GetFullPath(string.IsNullOrWhiteSpace(directory) ? SentinelPaths.YaraRules : directory);
        Directory.CreateDirectory(target);

        _rwLock.EnterWriteLock();
        try
        {
            DisableHotReloadLocked();
            _debounceMs = Math.Max(50, debounceMs);

            if (!_loadedDirectories.Contains(target, StringComparer.OrdinalIgnoreCase))
                _loadedDirectories.Add(target);

            var watcher = new FileSystemWatcher(target)
            {
                IncludeSubdirectories = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime | NotifyFilters.Size,
                Filter = "*.yar*"
            };
            watcher.Created += OnWatcherEvent;
            watcher.Changed += OnWatcherEvent;
            watcher.Deleted += OnWatcherEvent;
            watcher.Renamed += OnWatcherEvent;
            watcher.EnableRaisingEvents = true;

            _watcher = watcher;
            _logger.LogInformation("Rechargement a chaud YARA active sur {Directory} (debounce {DebounceMs} ms).", target, _debounceMs);
        }
        finally
        {
            _rwLock.ExitWriteLock();
        }
    }

    /// <inheritdoc />
    public void DisableHotReload()
    {
        _rwLock.EnterWriteLock();
        try { DisableHotReloadLocked(); }
        finally { _rwLock.ExitWriteLock(); }
    }

    /// <inheritdoc />
    public bool SetRuleEnabled(string ruleId, bool enabled)
    {
        if (string.IsNullOrWhiteSpace(ruleId))
            return false;

        _rwLock.EnterWriteLock();
        try
        {
            if (!_ruleLookup.ContainsKey(ruleId))
                return false;

            if (enabled)
                _disabledRuleIds.Remove(ruleId);
            else
                _disabledRuleIds.Add(ruleId);

            return true;
        }
        finally
        {
            _rwLock.ExitWriteLock();
        }
    }

    /// <inheritdoc />
    public void SetDisabledRules(IEnumerable<string> disabledRuleIds)
    {
        ArgumentNullException.ThrowIfNull(disabledRuleIds);

        _rwLock.EnterWriteLock();
        try
        {
            _disabledRuleIds.Clear();
            foreach (var id in disabledRuleIds)
            {
                if (!string.IsNullOrWhiteSpace(id))
                    _disabledRuleIds.Add(id.Trim());
            }
        }
        finally
        {
            _rwLock.ExitWriteLock();
        }
    }

    /// <inheritdoc />
    public IReadOnlyList<RuleSummaryDto> GetRuleSummaries()
    {
        _rwLock.EnterReadLock();
        try
        {
            var list = new List<RuleSummaryDto>(_managedRules.Count);
            foreach (var rule in _managedRules)
            {
                var enabled = !_disabledRuleIds.Contains(rule.Identifier);
                var matches = _matchCounts.TryGetValue(rule.Identifier, out var count) ? count : 0;
                list.Add(new RuleSummaryDto(
                    Id: rule.Identifier,
                    Engine: EngineName,
                    Title: rule.Identifier,
                    Level: rule.Level,
                    Enabled: enabled,
                    SourceFile: rule.SourceFile,
                    MitreTechniques: rule.MitreTechniques,
                    MatchCount: matches,
                    Description: rule.Description));
            }
            return list;
        }
        finally
        {
            _rwLock.ExitReadLock();
        }
    }

    /// <inheritdoc />
    public YaraScanReport ScanFile(string filePath, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        ObjectDisposedException.ThrowIf(_disposed, this);

        var sw = Stopwatch.StartNew();
        ct.ThrowIfCancellationRequested();

        if (!File.Exists(filePath))
        {
            return new YaraScanReport(
                Array.Empty<YaraMatchResult>(),
                EngineName,
                _isUsingFallback,
                sw.Elapsed.TotalMilliseconds,
                $"Fichier introuvable : '{filePath}'.");
        }

        // Essai natif dnYara si disponible et compile
        var (usedNative, nativeResults) = TryScanNativeFile(filePath, ct);
        if (usedNative)
        {
            sw.Stop();
            return new YaraScanReport(nativeResults, YaraEngineNames.Native, UsedFallback: false, sw.Elapsed.TotalMilliseconds);
        }

        ct.ThrowIfCancellationRequested();
        byte[] bytes;
        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            bytes = new byte[fs.Length];
            var readTotal = 0;
            while (readTotal < bytes.Length)
            {
                ct.ThrowIfCancellationRequested();
                var n = fs.Read(bytes, readTotal, bytes.Length - readTotal);
                if (n <= 0) break;
                readTotal += n;
            }
            if (readTotal != bytes.Length)
                Array.Resize(ref bytes, readTotal);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            sw.Stop();
            return new YaraScanReport(
                Array.Empty<YaraMatchResult>(),
                EngineName,
                _isUsingFallback,
                sw.Elapsed.TotalMilliseconds,
                $"Erreur de lecture du fichier : {ex.Message}");
        }

        return ScanBytesCore(bytes, sw, ct);
    }

    /// <inheritdoc />
    public YaraScanReport ScanBytes(byte[] data, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(data);
        ObjectDisposedException.ThrowIf(_disposed, this);

        var sw = Stopwatch.StartNew();
        ct.ThrowIfCancellationRequested();

        var (usedNative, nativeResults) = TryScanNativeBytes(data, ct);
        if (usedNative)
        {
            sw.Stop();
            return new YaraScanReport(nativeResults, YaraEngineNames.Native, UsedFallback: false, sw.Elapsed.TotalMilliseconds);
        }

        return ScanBytesCore(data, sw, ct);
    }

    public void Dispose()
    {
        if (_disposed)
            return;

        _rwLock.EnterWriteLock();
        try
        {
            if (_disposed)
                return;
            _disposed = true;
            DisableHotReloadLocked();
            DisposeNativeLocked();
        }
        finally
        {
            _rwLock.ExitWriteLock();
        }

        _rwLock.Dispose();
    }

    // =========================================================================
    //  Compilation & gestion native dnYara avec bascule securisee
    // =========================================================================

    private void TryProbeNativeContext()
    {
        // Verifie la presence de la bibliotheque native AVANT toute instanciation de dnYara.YaraContext :
        // si le constructeur de YaraContext echoue par DllNotFoundException, son finaliseur (~YaraContext)
        // appellerait yr_finalize() lors du GC et ferait planter le processus hote.
        if (!NativeLibrary.TryLoad("libyara", typeof(YaraScannerService).Assembly, null, out var libHandle))
        {
            _nativePermanentlyUnavailable = true;
            _isUsingFallback = true;
            _fallbackReason = "Bibliotheque native libyara introuvable (NativeLibrary.TryLoad).";
            _logger.LogWarning(
                "Bibliotheque native libyara (dnYara) indisponible ({Reason}). Bascule automatique sur {Engine}.",
                _fallbackReason,
                YaraEngineNames.ManagedFallback);
            return;
        }

        NativeLibrary.Free(libHandle);

        try
        {
            _nativeContext = new YaraContext();
            _isUsingFallback = false;
            _fallbackReason = null;
            _logger.LogInformation("Moteur YARA natif initialise : {Engine}.", YaraEngineNames.Native);
        }
        catch (Exception ex) when (IsNativeUnavailableException(ex))
        {
            SwitchToPermanentFallback(ex);
        }
        catch (Exception ex)
        {
            SwitchToPermanentFallback(ex);
        }
    }

    private YaraRuleLoadResult ApplyLoadedSources(
        IReadOnlyList<string> directories,
        bool inMemoryOnly,
        List<(string SourceName, string SourceText)> sources,
        List<YaraLoadError> errors)
    {
        var parsedRules = new List<ParsedYaraRule>();
        var validSourcesForNative = new List<(string SourceName, string SourceText)>();

        foreach (var (sourceName, sourceText) in sources)
        {
            try
            {
                var rules = ManagedYaraFallbackEngine.ParseSource(sourceText, sourceName);
                parsedRules.AddRange(rules);
                if (rules.Count > 0)
                    validSourcesForNative.Add((sourceName, sourceText));
            }
            catch (Exception ex)
            {
                errors.Add(new YaraLoadError(sourceName, $"Erreur d'analyse de la regle YARA : {ex.Message}", ex));
                _logger.LogWarning(ex, "Regle YARA ignoree ({Source}) : {Message}", sourceName, ex.Message);
            }
        }

        var lookup = new Dictionary<string, ParsedYaraRule>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in parsedRules)
            lookup[r.Identifier] = r;

        _rwLock.EnterWriteLock();
        try
        {
            if (!inMemoryOnly)
            {
                _loadedDirectories.Clear();
                _loadedDirectories.AddRange(directories);
                _inMemorySources.Clear();
            }
            else
            {
                _inMemorySources.Clear();
                _inMemorySources.AddRange(sources);
            }

            _managedRules = parsedRules;
            _ruleLookup = lookup;

            // Tente la compilation native dnYara si possible
            TryCompileNativeLocked(validSourcesForNative, errors);

            _loadErrors = errors.ToArray();

            var summary = new YaraRuleLoadResult(
                parsedRules.Count,
                EngineName,
                _isUsingFallback,
                _loadErrors);

            _logger.LogInformation(
                "Regles YARA chargees : {Count} regle(s), moteur={Engine}, erreurs={ErrorCount}.",
                summary.LoadedCount, summary.EngineName, summary.Errors.Count);

            return summary;
        }
        finally
        {
            _rwLock.ExitWriteLock();
        }
    }

    private void TryCompileNativeLocked(
        List<(string SourceName, string SourceText)> validSources,
        List<YaraLoadError> errors)
    {
        if (_nativeCompiledRules is not null)
        {
            try { _nativeCompiledRules.Dispose(); } catch { /* ignore */ }
            _nativeCompiledRules = null;
        }

        if (!_preferNativeDnYara || _nativePermanentlyUnavailable)
        {
            _isUsingFallback = true;
            return;
        }

        if (validSources.Count == 0)
        {
            _isUsingFallback = false;
            return;
        }

        try
        {
            _nativeContext ??= new YaraContext();

            using var compiler = new Compiler();
            var addedAny = false;

            foreach (var (sourceName, sourceText) in validSources)
            {
                try
                {
                    compiler.AddRuleString(sourceText);
                    addedAny = true;
                }
                catch (CompilationException cex)
                {
                    errors.Add(new YaraLoadError(sourceName, $"Erreur de compilation libyara : {cex.Message}", cex));
                    _logger.LogWarning(cex, "Erreur de compilation libyara sur {Source}", sourceName);
                }
            }

            if (addedAny)
            {
                _nativeCompiledRules = compiler.Compile();
                _isUsingFallback = false;
                _fallbackReason = null;
            }
            else
            {
                _isUsingFallback = true;
                _fallbackReason = "Aucune regle compilee par libyara ; utilisation du repli manage.";
                _logger.LogWarning("Aucune regle compilee par dnYara ; bascule sur {Engine}.", YaraEngineNames.ManagedFallback);
            }
        }
        catch (Exception ex) when (IsNativeUnavailableException(ex))
        {
            SwitchToPermanentFallback(ex);
        }
        catch (CompilationException cex)
        {
            errors.Add(new YaraLoadError("<compiler>", $"Compilation libyara echouee : {cex.Message}", cex));
            _isUsingFallback = true;
            _fallbackReason = $"Echec de compilation libyara : {cex.Message}";
            _logger.LogWarning(cex, "Compilation libyara echouee ; bascule sur {Engine}.", YaraEngineNames.ManagedFallback);
        }
        catch (YaraException yex)
        {
            errors.Add(new YaraLoadError("<libyara>", $"Erreur libyara ({yex.YRError}) : {yex.Message}", yex));
            _isUsingFallback = true;
            _fallbackReason = $"Erreur libyara ({yex.YRError})";
            _logger.LogWarning(yex, "Erreur libyara ; bascule sur {Engine}.", YaraEngineNames.ManagedFallback);
        }
        catch (Exception ex)
        {
            SwitchToPermanentFallback(ex);
        }
    }

    private (bool UsedNative, IReadOnlyList<YaraMatchResult> Matches) TryScanNativeFile(string filePath, CancellationToken ct)
    {
        if (_isUsingFallback || _nativePermanentlyUnavailable)
            return (false, Array.Empty<YaraMatchResult>());

        _rwLock.EnterReadLock();
        try
        {
            if (_isUsingFallback || _nativeCompiledRules is null)
                return (false, Array.Empty<YaraMatchResult>());

            ct.ThrowIfCancellationRequested();
            var scanner = new Scanner();
            var nativeHits = scanner.ScanFile(filePath, _nativeCompiledRules);
            return (true, ConvertNativeHitsLocked(nativeHits));
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex) when (IsNativeUnavailableException(ex) || ex is YaraException)
        {
            _logger.LogWarning(ex, "Echec du scan natif dnYara sur {File} ; bascule sur {Engine}.", filePath, YaraEngineNames.ManagedFallback);
            // Bascule en dehors du read lock
        }
        finally
        {
            _rwLock.ExitReadLock();
        }

        MarkNativeUnavailableAfterRuntimeFailure("Echec d'execution du scan natif libyara.");
        return (false, Array.Empty<YaraMatchResult>());
    }

    private (bool UsedNative, IReadOnlyList<YaraMatchResult> Matches) TryScanNativeBytes(byte[] data, CancellationToken ct)
    {
        if (_isUsingFallback || _nativePermanentlyUnavailable)
            return (false, Array.Empty<YaraMatchResult>());

        _rwLock.EnterReadLock();
        try
        {
            if (_isUsingFallback || _nativeCompiledRules is null)
                return (false, Array.Empty<YaraMatchResult>());

            ct.ThrowIfCancellationRequested();
            var scanner = new Scanner();
            var buffer = data;
            var nativeHits = scanner.ScanMemory(ref buffer, _nativeCompiledRules);
            return (true, ConvertNativeHitsLocked(nativeHits));
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex) when (IsNativeUnavailableException(ex) || ex is YaraException)
        {
            _logger.LogWarning(ex, "Echec du scan memoire natif dnYara ; bascule sur {Engine}.", YaraEngineNames.ManagedFallback);
        }
        finally
        {
            _rwLock.ExitReadLock();
        }

        MarkNativeUnavailableAfterRuntimeFailure("Echec d'execution du scan memoire libyara.");
        return (false, Array.Empty<YaraMatchResult>());
    }

    private IReadOnlyList<YaraMatchResult> ConvertNativeHitsLocked(List<ScanResult>? nativeHits)
    {
        if (nativeHits is null || nativeHits.Count == 0)
            return Array.Empty<YaraMatchResult>();

        var results = new List<YaraMatchResult>(nativeHits.Count);
        foreach (var hit in nativeHits)
        {
            var ruleId = hit.MatchingRule?.Identifier;
            if (string.IsNullOrWhiteSpace(ruleId) || _disabledRuleIds.Contains(ruleId))
                continue;

            _matchCounts.AddOrUpdate(ruleId, 1, static (_, c) => c + 1);

            _ruleLookup.TryGetValue(ruleId, out var parsed);
            var matchedStrings = hit.Matches is not null
                ? hit.Matches.Keys.ToArray()
                : Array.Empty<string>();

            var metadata = parsed?.Metadata ?? ExtractNativeMetas(hit.MatchingRule?.Metas);
            var tags = parsed?.Tags ?? (IReadOnlyList<string>)(hit.MatchingRule?.Tags?.ToArray() ?? Array.Empty<string>());
            var level = parsed?.Level ?? YaraSeverityLevels.High;
            var score = parsed?.Score ?? YaraSeverityLevels.ToScore(level);
            var mitre = parsed?.MitreTechniques ?? ParsedYaraRule.ExtractMitreTechniques(metadata, tags);

            results.Add(new YaraMatchResult(
                RuleId: ruleId,
                Namespace: parsed?.Namespace ?? "default",
                SourceFile: parsed?.SourceFile ?? "<native>",
                Level: level,
                Score: score,
                Description: parsed?.Description ?? (metadata.TryGetValue("description", out var d) ? d : null),
                Tags: tags,
                MitreTechniques: mitre,
                MatchedStrings: matchedStrings,
                Metadata: metadata,
                EngineName: YaraEngineNames.Native));
        }

        return results;
    }

    private YaraScanReport ScanBytesCore(byte[] data, Stopwatch sw, CancellationToken ct)
    {
        List<ParsedYaraRule> rulesSnapshot;
        HashSet<string> disabledSnapshot;

        _rwLock.EnterReadLock();
        try
        {
            rulesSnapshot = new List<ParsedYaraRule>(_managedRules);
            disabledSnapshot = new HashSet<string>(_disabledRuleIds, StringComparer.OrdinalIgnoreCase);
        }
        finally
        {
            _rwLock.ExitReadLock();
        }

        var matches = _fallbackEngine.ScanBytes(data, rulesSnapshot, disabledSnapshot, ct);
        foreach (var m in matches)
            _matchCounts.AddOrUpdate(m.RuleId, 1, static (_, c) => c + 1);

        sw.Stop();
        return new YaraScanReport(matches, YaraEngineNames.ManagedFallback, UsedFallback: true, sw.Elapsed.TotalMilliseconds);
    }

    private static IReadOnlyDictionary<string, string> ExtractNativeMetas(IDictionary<string, object>? metas)
    {
        if (metas is null || metas.Count == 0)
            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in metas)
            dict[kv.Key] = kv.Value?.ToString() ?? string.Empty;
        return dict;
    }

    private void SwitchToPermanentFallback(Exception ex)
    {
        _nativePermanentlyUnavailable = true;
        _isUsingFallback = true;
        _fallbackReason = $"{ex.GetType().Name}: {ex.Message}";
        DisposeNativeLocked();
        _logger.LogWarning(
            "Bibliotheque native libyara (dnYara) indisponible ({Reason}). Bascule automatique sur {Engine}.",
            _fallbackReason,
            YaraEngineNames.ManagedFallback);
    }

    private void MarkNativeUnavailableAfterRuntimeFailure(string reason)
    {
        _rwLock.EnterWriteLock();
        try
        {
            _nativePermanentlyUnavailable = true;
            _isUsingFallback = true;
            _fallbackReason = reason;
            DisposeNativeLocked();
        }
        finally
        {
            _rwLock.ExitWriteLock();
        }
    }

    private void DisposeNativeLocked()
    {
        if (_nativeCompiledRules is not null)
        {
            try { _nativeCompiledRules.Dispose(); } catch { /* ignore */ }
            _nativeCompiledRules = null;
        }
        if (_nativeContext is not null)
        {
            try { _nativeContext.Dispose(); } catch { /* ignore */ }
            _nativeContext = null;
        }
    }

    private static bool IsNativeUnavailableException(Exception ex)
    {
        for (Exception? cur = ex; cur is not null; cur = cur.InnerException)
        {
            if (cur is DllNotFoundException or BadImageFormatException or TypeInitializationException or EntryPointNotFoundException)
                return true;
        }
        return false;
    }

    private void OnWatcherEvent(object sender, FileSystemEventArgs e)
    {
        if (_disposed)
            return;

        if (!e.FullPath.EndsWith(".yar", StringComparison.OrdinalIgnoreCase) &&
            !e.FullPath.EndsWith(".yara", StringComparison.OrdinalIgnoreCase))
            return;

        try
        {
            _debounceTimer ??= new Timer(OnDebounceElapsed, null, Timeout.Infinite, Timeout.Infinite);
            _debounceTimer.Change(_debounceMs, Timeout.Infinite);
        }
        catch (ObjectDisposedException)
        {
            // En cours de fermeture
        }
    }

    private void OnDebounceElapsed(object? state)
    {
        if (_disposed)
            return;

        try
        {
            var result = Reload();
            RulesReloaded?.Invoke(this, result);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Erreur lors du rechargement a chaud des regles YARA.");
        }
    }

    private void DisableHotReloadLocked()
    {
        if (_watcher is not null)
        {
            _watcher.EnableRaisingEvents = false;
            _watcher.Created -= OnWatcherEvent;
            _watcher.Changed -= OnWatcherEvent;
            _watcher.Deleted -= OnWatcherEvent;
            _watcher.Renamed -= OnWatcherEvent;
            _watcher.Dispose();
            _watcher = null;
        }

        if (_debounceTimer is not null)
        {
            _debounceTimer.Dispose();
            _debounceTimer = null;
        }
    }

    private static string ReadFileWithRetry(string path)
    {
        for (var attempt = 0; attempt < 3; attempt++)
        {
            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using var sr = new StreamReader(fs);
                return sr.ReadToEnd();
            }
            catch (IOException) when (attempt < 2)
            {
                Thread.Sleep(40);
            }
        }
        return File.ReadAllText(path);
    }
}
