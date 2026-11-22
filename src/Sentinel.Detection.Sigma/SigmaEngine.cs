using System.Buffers;
using System.Numerics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Shared.Api;
using Sentinel.Shared.Models;

namespace Sentinel.Detection.Sigma;

/// <summary>
/// Moteur natif C# d'evaluation de regles Sigma pour SENTINEL v2.
/// Thread-safe (lectures sans verrou via instantanes immuables), indexe par <see cref="EventCategory"/>
/// et accelere par un pre-filtre multi-motifs Aho-Corasick garantissant zero faux negatif.
/// </summary>
public sealed class SigmaEngine : ISigmaEngine
{
    private const int CategorySlotCount = 16;
    private const int MaxStackBitsetWords = 64; // Jusqu'a 4 096 regles par categorie sur la pile (0 allocation)

    private readonly SigmaRuleParser _parser;
    private readonly ILogger<SigmaEngine> _logger;
    private readonly object _stateLock = new();

    private readonly List<string> _loadedDirectories = new();
    private readonly List<RuleSlot> _allSlots = new();
    private readonly Dictionary<string, long> _preservedMatchCounts = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _disabledRuleIds = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<string> _excludedTargets = new();
    private IReadOnlyList<SigmaLoadError> _loadErrors = Array.Empty<SigmaLoadError>();

    private volatile EngineSnapshot _snapshot = EngineSnapshot.Empty;
    private FileSystemWatcher? _watcher;
    private Timer? _debounceTimer;
    private int _debounceMs = 300;
    private bool _disposed;

    public SigmaEngine(ILogger<SigmaEngine>? logger = null, SigmaRuleParser? parser = null)
    {
        _logger = logger ?? NullLogger<SigmaEngine>.Instance;
        _parser = parser ?? new SigmaRuleParser();
    }

    /// <inheritdoc />
    public int RuleCount => _snapshot.AllSlots.Length;

    /// <inheritdoc />
    public int EnabledRuleCount => _snapshot.EnabledRuleCount;

    /// <inheritdoc />
    public IReadOnlyList<SigmaRule> Rules => _snapshot.AllRules;

    /// <inheritdoc />
    public IReadOnlyList<SigmaLoadError> LoadErrors
    {
        get
        {
            lock (_stateLock)
                return _loadErrors;
        }
    }

    /// <inheritdoc />
    public event EventHandler<SigmaRuleLoadResult>? RulesReloaded;

    /// <inheritdoc />
    public SigmaRuleLoadResult LoadFromDirectory(string dir)
    {
        if (string.IsNullOrWhiteSpace(dir))
            throw new ArgumentException("Le chemin du repertoire Sigma ne peut pas etre vide.", nameof(dir));

        return LoadFromDirectories([dir]);
    }

    /// <inheritdoc />
    public SigmaRuleLoadResult LoadFromDirectories(IEnumerable<string> directories)
    {
        ArgumentNullException.ThrowIfNull(directories);
        ObjectDisposedException.ThrowIf(_disposed, this);

        var dirs = directories
            .Where(d => !string.IsNullOrWhiteSpace(d))
            .Select(Path.GetFullPath)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var loadedRules = new List<SigmaRule>();
        var errors = new List<SigmaLoadError>();

        foreach (var dir in dirs)
        {
            if (!Directory.Exists(dir))
            {
                var err = new SigmaLoadError(dir, $"Repertoire de regles Sigma introuvable : '{dir}'.");
                errors.Add(err);
                _logger.LogWarning("Repertoire Sigma introuvable : {Directory}", dir);
                continue;
            }

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(dir, "*.*", SearchOption.AllDirectories)
                    .Where(f => f.EndsWith(".yml", StringComparison.OrdinalIgnoreCase) ||
                                f.EndsWith(".yaml", StringComparison.OrdinalIgnoreCase))
                    .OrderBy(f => f, StringComparer.OrdinalIgnoreCase);
            }
            catch (Exception ex)
            {
                errors.Add(new SigmaLoadError(dir, $"Impossible d'enumerer le repertoire '{dir}' : {ex.Message}", ex));
                _logger.LogWarning(ex, "Erreur lors de l'enumeration du repertoire Sigma {Directory}", dir);
                continue;
            }

            foreach (var file in files)
            {
                try
                {
                    var parsed = ParseFileWithRetry(file);
                    loadedRules.AddRange(parsed);
                }
                catch (Exception ex)
                {
                    errors.Add(new SigmaLoadError(file, ex.Message, ex));
                    _logger.LogWarning(ex, "Regle Sigma ignoree (invalide) : {File}", file);
                }
            }
        }

        lock (_stateLock)
        {
            _loadedDirectories.Clear();
            _loadedDirectories.AddRange(dirs);
            _loadErrors = errors.ToArray();
            ReplaceRulesLocked(loadedRules);
        }

        _logger.LogInformation(
            "Moteur Sigma charge : {LoadedCount} regles ({EnabledCount} actives), {ErrorCount} erreur(s).",
            loadedRules.Count, EnabledRuleCount, errors.Count);

        return new SigmaRuleLoadResult(loadedRules.Count, errors.ToArray());
    }

    /// <inheritdoc />
    public void LoadRules(IEnumerable<SigmaRule> rules)
    {
        ArgumentNullException.ThrowIfNull(rules);
        ObjectDisposedException.ThrowIf(_disposed, this);

        var list = rules.Where(r => r is not null).ToList();
        lock (_stateLock)
        {
            _loadErrors = Array.Empty<SigmaLoadError>();
            ReplaceRulesLocked(list);
        }
    }

    /// <inheritdoc />
    public SigmaRule LoadRuleYaml(string yamlContent, string sourceFile = "<memory>")
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var rule = _parser.Parse(yamlContent, sourceFile);
        lock (_stateLock)
        {
            var merged = _allSlots
                .Select(s => s.Rule)
                .Where(r => !r.Id.Equals(rule.Id, StringComparison.OrdinalIgnoreCase))
                .ToList();
            merged.Add(rule);
            ReplaceRulesLocked(merged);
        }
        return rule;
    }

    /// <inheritdoc />
    public SigmaRuleLoadResult Reload()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        string[] dirs;
        lock (_stateLock)
        {
            dirs = _loadedDirectories.ToArray();
        }

        if (dirs.Length == 0)
            return new SigmaRuleLoadResult(RuleCount, LoadErrors);

        return LoadFromDirectories(dirs);
    }

    /// <inheritdoc />
    public void EnableHotReload(string directory, int debounceMs = 300)
    {
        if (string.IsNullOrWhiteSpace(directory))
            throw new ArgumentException("Le repertoire a surveiller ne peut pas etre vide.", nameof(directory));

        ObjectDisposedException.ThrowIf(_disposed, this);

        var fullDir = Path.GetFullPath(directory);
        Directory.CreateDirectory(fullDir);

        lock (_stateLock)
        {
            DisableHotReloadLocked();

            if (!_loadedDirectories.Contains(fullDir, StringComparer.OrdinalIgnoreCase))
                _loadedDirectories.Add(fullDir);

            _debounceMs = Math.Max(50, debounceMs);
            _debounceTimer = new Timer(OnDebounceTimerElapsed, null, Timeout.Infinite, Timeout.Infinite);

            var watcher = new FileSystemWatcher(fullDir)
            {
                IncludeSubdirectories = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime | NotifyFilters.Size,
                Filter = "*.*"
            };

            watcher.Created += OnFileSystemChanged;
            watcher.Changed += OnFileSystemChanged;
            watcher.Deleted += OnFileSystemChanged;
            watcher.Renamed += OnFileSystemRenamed;
            watcher.EnableRaisingEvents = true;

            _watcher = watcher;
        }
    }

    /// <inheritdoc />
    public void DisableHotReload()
    {
        lock (_stateLock)
            DisableHotReloadLocked();
    }

    /// <inheritdoc />
    public IReadOnlyList<SigmaMatch> Evaluate(SecurityEvent evt)
    {
        ArgumentNullException.ThrowIfNull(evt);

        var snapshot = _snapshot;
        var catIdx = (int)evt.Category;
        if ((uint)catIdx >= (uint)snapshot.Buckets.Length)
            return Array.Empty<SigmaMatch>();

        var bucket = snapshot.Buckets[catIdx];
        if (bucket is null || bucket.Slots.Length == 0)
            return Array.Empty<SigmaMatch>();

        if (snapshot.ExcludedTargets.Length > 0 && IsEventExcluded(evt, snapshot.ExcludedTargets))
            return Array.Empty<SigmaMatch>();

        var slots = bucket.Slots;
        var wordCount = (slots.Length + 63) >> 6;
        ulong[]? rented = null;
        Span<ulong> candidateBits = wordCount <= MaxStackBitsetWords
            ? stackalloc ulong[wordCount]
            : (rented = ArrayPool<ulong>.Shared.Rent(wordCount)).AsSpan(0, wordCount);

        candidateBits.Clear();

        try
        {
            // 1. Pre-filtrage Aho-Corasick O(n) sur les champs textuels de l'evenement
            if (!bucket.Automaton.IsEmpty)
            {
                ScanEventWithAutomaton(bucket.Automaton, evt, candidateBits);
            }

            // 2. Ajout des regles non indexables (regex pures, CIDR, null, EventID seul, etc.)
            var alwaysBits = bucket.AlwaysEvaluateBits;
            for (var w = 0; w < wordCount; w++)
                candidateBits[w] |= alwaysBits[w];

            // 3. Evaluation complete uniquement des regles candidates
            List<SigmaMatch>? matches = null;

            for (var w = 0; w < wordCount; w++)
            {
                var word = candidateBits[w];
                while (word != 0)
                {
                    var bit = BitOperations.TrailingZeroCount(word);
                    word &= word - 1;

                    var ruleIdx = (w << 6) + bit;
                    if (ruleIdx >= slots.Length)
                        break;

                    var slot = slots[ruleIdx];
                    var rule = slot.Rule;

                    // Ne pas declencher une regle process_creation sur un evenement ProcessStop
                    if (slot.IsProcessCreationOnly && evt.EventType == EventTypes.ProcessStop)
                        continue;

                    if (EvaluateCompiledRule(rule, evt, out var matchedSelections))
                    {
                        slot.IncrementMatches();
                        matches ??= new List<SigmaMatch>(2);
                        matches.Add(new SigmaMatch(
                            rule.Id,
                            rule.Title,
                            rule.Level,
                            rule.Score,
                            rule.SourceFile,
                            rule.MitreTechniques,
                            rule.MitreTactics,
                            matchedSelections,
                            rule.Description));
                    }
                }
            }

            return matches is null ? Array.Empty<SigmaMatch>() : matches;
        }
        finally
        {
            if (rented is not null)
                ArrayPool<ulong>.Shared.Return(rented);
        }
    }

    /// <inheritdoc />
    public ThreatAssessment? EvaluateAsAssessment(SecurityEvent evt)
    {
        var matches = Evaluate(evt);
        if (matches.Count == 0)
            return null;

        var primary = matches[0];
        for (var i = 1; i < matches.Count; i++)
        {
            if (matches[i].Score > primary.Score)
                primary = matches[i];
        }

        // Score derive du niveau Sigma (informational=15, low=35, medium=60, high=80, critical=95)
        // + leger bonus plafonne si plusieurs regles distinctes corroborent l'evenement
        var multiRuleBonus = matches.Count > 1 ? Math.Min(10, (matches.Count - 1) * 5) : 0;
        var score = Math.Clamp(primary.Score + multiRuleBonus, 0, 100);

        var mitreSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var tacticsSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var ruleIds = new string[matches.Count];
        var signals = new string[matches.Count];

        for (var i = 0; i < matches.Count; i++)
        {
            var m = matches[i];
            ruleIds[i] = m.RuleId;
            signals[i] = $"[{m.Level}] {m.Title} ({m.RuleId})";

            for (var j = 0; j < m.MitreTechniques.Count; j++)
                mitreSet.Add(m.MitreTechniques[j]);
            for (var j = 0; j < m.MitreTactics.Count; j++)
                tacticsSet.Add(m.MitreTactics[j]);
        }

        var mitre = mitreSet.Count == 0 ? Array.Empty<string>() : mitreSet.ToArray();
        var tactics = tacticsSet.Count == 0 ? Array.Empty<string>() : tacticsSet.ToArray();
        var threatType = SigmaLevels.InferThreatType(mitre, tactics, primary.Level);
        var confidence = Math.Min(0.99, SigmaLevels.ToConfidence(primary.Level) + (matches.Count > 1 ? 0.03 : 0.0));

        var mitreSuffix = mitre.Length > 0 ? $" ({string.Join(", ", mitre)})" : string.Empty;
        var justification = matches.Count == 1
            ? $"Sigma [{primary.Level}] : {primary.Title}{mitreSuffix}"
            : $"Sigma ({matches.Count} regles, max [{primary.Level}]) : {string.Join(" ; ", matches.Select(m => m.Title))}{mitreSuffix}";

        var contribution = new ScoreContribution(
            Engine: "Sigma",
            Score: score,
            Weight: 1.0,
            Summary: justification,
            Signals: signals);

        return new ThreatAssessment(
            EventId: evt.Id,
            Score: score,
            Type: threatType,
            Justification: justification,
            Source: AssessmentSource.Sigma,
            Confidence: confidence)
        {
            MatchedRules = ruleIds,
            MitreTechniques = mitre,
            ScoreContributions = [contribution]
        };
    }

    /// <inheritdoc />
    public bool SetRuleEnabled(string ruleId, bool enabled)
    {
        if (string.IsNullOrWhiteSpace(ruleId))
            return false;

        lock (_stateLock)
        {
            if (enabled)
                _disabledRuleIds.Remove(ruleId);
            else
                _disabledRuleIds.Add(ruleId);

            var found = false;
            for (var i = 0; i < _allSlots.Count; i++)
            {
                if (_allSlots[i].Rule.Id.Equals(ruleId, StringComparison.OrdinalIgnoreCase))
                {
                    _allSlots[i].Rule.Enabled = enabled;
                    found = true;
                }
            }

            if (found)
                RebuildSnapshotLocked();

            return found;
        }
    }

    /// <inheritdoc />
    public void SetExclusions(IEnumerable<string> disabledIds, IEnumerable<string> excludedTargets)
    {
        ArgumentNullException.ThrowIfNull(disabledIds);
        ArgumentNullException.ThrowIfNull(excludedTargets);

        lock (_stateLock)
        {
            _disabledRuleIds.Clear();
            foreach (var id in disabledIds)
            {
                if (!string.IsNullOrWhiteSpace(id))
                    _disabledRuleIds.Add(id.Trim());
            }

            _excludedTargets.Clear();
            foreach (var target in excludedTargets)
            {
                if (!string.IsNullOrWhiteSpace(target))
                    _excludedTargets.Add(target.Trim());
            }

            for (var i = 0; i < _allSlots.Count; i++)
            {
                var rule = _allSlots[i].Rule;
                rule.Enabled = !_disabledRuleIds.Contains(rule.Id);
            }

            RebuildSnapshotLocked();
        }
    }

    /// <inheritdoc />
    public IReadOnlyList<RuleSummaryDto> GetRuleSummaries()
    {
        var slots = _snapshot.AllSlots;
        if (slots.Length == 0)
            return Array.Empty<RuleSummaryDto>();

        var summaries = new RuleSummaryDto[slots.Length];
        for (var i = 0; i < slots.Length; i++)
        {
            var slot = slots[i];
            var r = slot.Rule;
            summaries[i] = new RuleSummaryDto(
                Id: r.Id,
                Engine: "Sigma",
                Title: r.Title,
                Level: r.Level,
                Enabled: r.Enabled,
                SourceFile: r.SourceFile,
                MitreTechniques: r.MitreTechniques,
                MatchCount: slot.MatchCount,
                Description: string.IsNullOrEmpty(r.Description) ? null : r.Description);
        }

        return summaries;
    }

    public void Dispose()
    {
        lock (_stateLock)
        {
            if (_disposed)
                return;
            _disposed = true;
            DisableHotReloadLocked();
        }
    }

    private IReadOnlyList<SigmaRule> ParseFileWithRetry(string file)
    {
        const int maxAttempts = 3;
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                return _parser.ParseFile(file);
            }
            catch (IOException) when (attempt < maxAttempts)
            {
                Thread.Sleep(50 * attempt);
            }
        }
    }

    private void ReplaceRulesLocked(List<SigmaRule> newRules)
    {
        // Preserver les compteurs MatchCount des regles conservees entre rechargements
        for (var i = 0; i < _allSlots.Count; i++)
            _preservedMatchCounts[_allSlots[i].Rule.Id] = _allSlots[i].MatchCount;

        _allSlots.Clear();
        var seenIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        for (var i = 0; i < newRules.Count; i++)
        {
            var rule = newRules[i];
            if (!seenIds.Add(rule.Id))
                continue;

            if (_disabledRuleIds.Contains(rule.Id))
                rule.Enabled = false;

            _preservedMatchCounts.TryGetValue(rule.Id, out var prevCount);
            _allSlots.Add(new RuleSlot(rule, prevCount));
        }

        RebuildSnapshotLocked();
    }

    private void RebuildSnapshotLocked()
    {
        var allSlots = _allSlots.ToArray();
        var allRules = new SigmaRule[allSlots.Length];
        var perCategory = new List<RuleSlot>[CategorySlotCount];
        var enabledCount = 0;

        for (var i = 0; i < allSlots.Length; i++)
        {
            var slot = allSlots[i];
            var rule = slot.Rule;
            allRules[i] = rule;

            if (!rule.Enabled)
                continue;

            enabledCount++;
            var categories = SigmaFieldMapper.MapLogSourceToCategories(rule.LogSource);
            for (var c = 0; c < categories.Length; c++)
            {
                var catIdx = (int)categories[c];
                if ((uint)catIdx >= CategorySlotCount)
                    continue;
                perCategory[catIdx] ??= new List<RuleSlot>();
                perCategory[catIdx].Add(slot);
            }
        }

        var buckets = new CategoryBucket?[CategorySlotCount];
        for (var c = 0; c < CategorySlotCount; c++)
        {
            var list = perCategory[c];
            if (list is null || list.Count == 0)
                continue;

            var bucketSlots = list.ToArray();
            var wordCount = (bucketSlots.Length + 63) >> 6;
            var alwaysBits = new ulong[wordCount];
            var anchorEntries = new List<(string Pattern, int RuleIndex)>(bucketSlots.Length * 2);

            for (var rIdx = 0; rIdx < bucketSlots.Length; rIdx++)
            {
                var anchors = bucketSlots[rIdx].CachedAnchors;
                if (anchors is null || anchors.Length == 0)
                {
                    alwaysBits[rIdx >> 6] |= 1UL << (rIdx & 63);
                }
                else
                {
                    for (var a = 0; a < anchors.Length; a++)
                        anchorEntries.Add((anchors[a], rIdx));
                }
            }

            var automaton = AhoCorasickAutomaton.Build(anchorEntries);
            buckets[c] = new CategoryBucket(bucketSlots, automaton, alwaysBits);
        }

        _snapshot = new EngineSnapshot(
            buckets,
            allSlots,
            allRules,
            enabledCount,
            _excludedTargets.ToArray());
    }

    private static void ScanEventWithAutomaton(
        AhoCorasickAutomaton automaton,
        SecurityEvent evt,
        Span<ulong> candidateBits)
    {
        if (!string.IsNullOrEmpty(evt.Subject))
            automaton.Scan(evt.Subject.AsSpan(), candidateBits);

        if (!string.IsNullOrEmpty(evt.UserId))
            automaton.Scan(evt.UserId.AsSpan(), candidateBits);

        if (!string.IsNullOrEmpty(evt.EventType))
            automaton.Scan(evt.EventType.AsSpan(), candidateBits);

        foreach (var kv in evt.Attributes)
        {
            if (!string.IsNullOrEmpty(kv.Value))
                automaton.Scan(kv.Value.AsSpan(), candidateBits);
        }
    }

    private static bool EvaluateCompiledRule(
        SigmaRule rule,
        SecurityEvent evt,
        out IReadOnlyList<string> matchedSelections)
    {
        var selections = rule.IndexedSelections;
        Span<byte> states = selections.Length <= 64
            ? stackalloc byte[selections.Length]
            : new byte[selections.Length];
        states.Clear();

        var ctx = new SelectionEvalContext(selections, evt, states);
        if (rule.ConditionAst.Evaluate(ref ctx))
        {
            matchedSelections = ctx.GetMatchedSelectionNames();
            return true;
        }

        matchedSelections = Array.Empty<string>();
        return false;
    }

    private static bool IsEventExcluded(SecurityEvent evt, string[] excludedTargets)
    {
        // Verifier uniquement les identifiants de cible (jamais CommandLine pour eviter le contournement par commentaire)
        var image = evt.Attr(AttributeKeys.ProcessPath);
        var procName = evt.Attr(AttributeKeys.ProcessName);
        var filePath = evt.Attr(AttributeKeys.FilePath);
        var domain = evt.Attr(AttributeKeys.Domain);

        for (var i = 0; i < excludedTargets.Length; i++)
        {
            var target = excludedTargets[i];
            if (MatchesExcludedTarget(evt.Subject, target) ||
                MatchesExcludedTarget(image, target) ||
                MatchesExcludedTarget(procName, target) ||
                MatchesExcludedTarget(filePath, target) ||
                MatchesExcludedTarget(domain, target) ||
                MatchesExcludedTarget(evt.UserId, target))
            {
                return true;
            }
        }

        return false;
    }

    private static bool MatchesExcludedTarget(string? value, string target)
    {
        if (string.IsNullOrEmpty(value))
            return false;
        return value.Contains(target, StringComparison.OrdinalIgnoreCase);
    }

    private void OnFileSystemChanged(object sender, FileSystemEventArgs e)
    {
        if (!IsYamlFile(e.FullPath))
            return;
        ScheduleDebouncedReload();
    }

    private void OnFileSystemRenamed(object sender, RenamedEventArgs e)
    {
        if (!IsYamlFile(e.FullPath) && !IsYamlFile(e.OldFullPath))
            return;
        ScheduleDebouncedReload();
    }

    private static bool IsYamlFile(string? path) =>
        !string.IsNullOrEmpty(path) &&
        (path.EndsWith(".yml", StringComparison.OrdinalIgnoreCase) ||
         path.EndsWith(".yaml", StringComparison.OrdinalIgnoreCase));

    private void ScheduleDebouncedReload()
    {
        lock (_stateLock)
        {
            if (_disposed || _debounceTimer is null)
                return;
            _debounceTimer.Change(_debounceMs, Timeout.Infinite);
        }
    }

    private void OnDebounceTimerElapsed(object? state)
    {
        lock (_stateLock)
        {
            if (_disposed)
                return;
        }

        try
        {
            var result = Reload();
            RulesReloaded?.Invoke(this, result);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Erreur lors du rechargement a chaud des regles Sigma.");
        }
    }

    private void DisableHotReloadLocked()
    {
        if (_watcher is not null)
        {
            _watcher.EnableRaisingEvents = false;
            _watcher.Created -= OnFileSystemChanged;
            _watcher.Changed -= OnFileSystemChanged;
            _watcher.Deleted -= OnFileSystemChanged;
            _watcher.Renamed -= OnFileSystemRenamed;
            _watcher.Dispose();
            _watcher = null;
        }

        if (_debounceTimer is not null)
        {
            _debounceTimer.Change(Timeout.Infinite, Timeout.Infinite);
            _debounceTimer.Dispose();
            _debounceTimer = null;
        }
    }

    private sealed class RuleSlot
    {
        private long _matchCount;

        public SigmaRule Rule { get; }
        public string[]? CachedAnchors { get; }
        public bool IsProcessCreationOnly { get; }
        public long MatchCount => Interlocked.Read(ref _matchCount);

        public RuleSlot(SigmaRule rule, long initialMatchCount)
        {
            Rule = rule;
            _matchCount = initialMatchCount;
            CachedAnchors = SigmaAnchorExtractor.ExtractRuleAnchors(rule);
            IsProcessCreationOnly = string.Equals(
                rule.LogSource.Category,
                "process_creation",
                StringComparison.OrdinalIgnoreCase);
        }

        public void IncrementMatches() => Interlocked.Increment(ref _matchCount);
    }

    private sealed class CategoryBucket
    {
        public RuleSlot[] Slots { get; }
        public AhoCorasickAutomaton Automaton { get; }
        public ulong[] AlwaysEvaluateBits { get; }

        public CategoryBucket(RuleSlot[] slots, AhoCorasickAutomaton automaton, ulong[] alwaysEvaluateBits)
        {
            Slots = slots;
            Automaton = automaton;
            AlwaysEvaluateBits = alwaysEvaluateBits;
        }
    }

    private sealed class EngineSnapshot
    {
        public static readonly EngineSnapshot Empty = new(
            new CategoryBucket?[CategorySlotCount],
            Array.Empty<RuleSlot>(),
            Array.Empty<SigmaRule>(),
            0,
            Array.Empty<string>());

        public CategoryBucket?[] Buckets { get; }
        public RuleSlot[] AllSlots { get; }
        public SigmaRule[] AllRules { get; }
        public int EnabledRuleCount { get; }
        public string[] ExcludedTargets { get; }

        public EngineSnapshot(
            CategoryBucket?[] buckets,
            RuleSlot[] allSlots,
            SigmaRule[] allRules,
            int enabledRuleCount,
            string[] excludedTargets)
        {
            Buckets = buckets;
            AllSlots = allSlots;
            AllRules = allRules;
            EnabledRuleCount = enabledRuleCount;
            ExcludedTargets = excludedTargets;
        }
    }
}
