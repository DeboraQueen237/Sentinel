using System.Globalization;
using Sentinel.Shared.Models;

namespace Sentinel.Agent.Pipeline;

/// <summary>
/// Dédoublonneur multi-sources (v2 Mission 1) :
/// Lorsqu'un même fait système est observé par plusieurs collecteurs dans une fenêtre rapprochée
/// (ex. <c>ProcessCollector</c> + <c>Sysmon</c> sur un même PID/exécutable, <c>FileSystemCollector</c> + <c>Sysmon</c>
/// sur un même fichier, ou <c>DefenderWMI</c> + <c>DefenderEventLog</c> sur une même détection),
/// les événements sont fusionnés en un seul événement enrichi mentionnant toutes ses sources
/// dans <see cref="AttributeKeys.EventSources"/>.
/// </summary>
public sealed class EventDeduplicator
{
    private readonly TimeSpan _window;
    private readonly int _maxEntries;
    private readonly object _gate = new();
    private readonly Dictionary<string, DeduplicatedEntry> _entries = new(StringComparer.OrdinalIgnoreCase);

    public EventDeduplicator(TimeSpan? window = null, int maxEntries = 8192)
    {
        _window = window ?? TimeSpan.FromSeconds(5);
        _maxEntries = Math.Max(128, maxEntries);
    }

    /// <summary>
    /// Traite un lot d'événements en fusionnant les doublons multi-sources intra-lot et inter-lots récents.
    /// Retourne uniquement les événements uniques (ou enrichis par fusion multi-sources).
    /// </summary>
    public IReadOnlyList<SecurityEvent> DeduplicateBatch(IEnumerable<SecurityEvent> batch)
    {
        ArgumentNullException.ThrowIfNull(batch);

        var output = new List<SecurityEvent>();
        var batchIndexByKey = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        lock (_gate)
        {
            foreach (var raw in batch)
            {
                if (raw is null) continue;
                var evt = EnsureSourceAttribute(raw);
                var key = BuildFingerprint(evt);
                if (key is null)
                {
                    output.Add(evt);
                    continue;
                }

                // 1. Doublon dans le même micro-lot : fusion directe en place
                if (batchIndexByKey.TryGetValue(key, out var existingIdx))
                {
                    var mergedInBatch = MergeEvents(output[existingIdx], evt);
                    output[existingIdx] = mergedInBatch;
                    _entries[key] = new DeduplicatedEntry(mergedInBatch, evt.Timestamp);
                    continue;
                }

                // 2. Doublon par rapport à un lot récent dans la fenêtre glissante
                if (_entries.TryGetValue(key, out var recent) &&
                    (evt.Timestamp - recent.LastSeen).Duration() <= _window)
                {
                    var prevSources = ParseSources(recent.Merged);
                    var incomingSources = ParseSources(evt);
                    var hasNewSource = incomingSources.Any(s => !prevSources.Contains(s));

                    var merged = MergeEvents(recent.Merged, evt);
                    _entries[key] = new DeduplicatedEntry(merged, evt.Timestamp);

                    // Si une nouvelle source enrichit un fait déjà vu récemment, on émet l'événement fusionné
                    // enrichi portant la liste complète des sources ; si même source répétée, on supprime le doublon.
                    if (hasNewSource)
                    {
                        batchIndexByKey[key] = output.Count;
                        output.Add(merged);
                    }
                    continue;
                }

                // 3. Nouvel événement unique
                _entries[key] = new DeduplicatedEntry(evt, evt.Timestamp);
                batchIndexByKey[key] = output.Count;
                output.Add(evt);
            }

            if (_entries.Count > _maxEntries)
            {
                PruneExpiredLocked(DateTimeOffset.UtcNow);
            }
        }

        return output;
    }

    /// <summary>
    /// Fusionne un événement isolé dans l'état interne. Retourne <c>Merged</c> et indique si un doublon a été absorbé.
    /// </summary>
    public (SecurityEvent Event, bool WasMerged, bool ShouldSuppressDuplicate) ProcessSingle(SecurityEvent raw)
    {
        ArgumentNullException.ThrowIfNull(raw);
        var evt = EnsureSourceAttribute(raw);
        var key = BuildFingerprint(evt);
        if (key is null)
        {
            return (evt, false, false);
        }

        lock (_gate)
        {
            if (_entries.TryGetValue(key, out var recent) &&
                (evt.Timestamp - recent.LastSeen).Duration() <= _window)
            {
                var prevSources = ParseSources(recent.Merged);
                var incomingSources = ParseSources(evt);
                var hasNewSource = incomingSources.Any(s => !prevSources.Contains(s));

                var merged = MergeEvents(recent.Merged, evt);
                _entries[key] = new DeduplicatedEntry(merged, evt.Timestamp);
                return (merged, true, !hasNewSource);
            }

            _entries[key] = new DeduplicatedEntry(evt, evt.Timestamp);
            if (_entries.Count > _maxEntries)
            {
                PruneExpiredLocked(evt.Timestamp);
            }
            return (evt, false, false);
        }
    }

    public static string? BuildFingerprint(SecurityEvent evt)
    {
        var host = (evt.HostId ?? string.Empty).Trim().ToLowerInvariant();
        return evt.Category switch
        {
            EventCategory.Process when evt.EventType == EventTypes.ProcessStart =>
                BuildKey("proc", host, evt.Attr(AttributeKeys.ProcessId), NormalizePath(evt.Attr(AttributeKeys.ProcessPath) ?? evt.Subject)),

            EventCategory.Network when evt.EventType == EventTypes.NetworkConnection =>
                BuildKey("net", host, evt.Attr(AttributeKeys.ProcessId), evt.Attr(AttributeKeys.RemoteIp), evt.Attr(AttributeKeys.RemotePort)),

            EventCategory.Network when evt.EventType == EventTypes.DnsQuery =>
                BuildKey("dns", host, evt.Attr(AttributeKeys.ProcessId), (evt.Attr(AttributeKeys.Domain) ?? evt.Subject).Trim().ToLowerInvariant()),

            EventCategory.File when evt.EventType is EventTypes.FileCreated or EventTypes.FileModified =>
                BuildKey("file", host, evt.EventType, NormalizePath(evt.Attr(AttributeKeys.FilePath) ?? evt.Subject)),

            EventCategory.Defender when evt.EventType is EventTypes.DefenderThreatDetected or EventTypes.DefenderActionTaken =>
                BuildKey("def", host, evt.Attr(AttributeKeys.DefenderThreatId) ?? evt.Attr(AttributeKeys.DefenderThreatName), NormalizePath(evt.Attr(AttributeKeys.FilePath) ?? evt.Subject)),

            EventCategory.Defender =>
                BuildKey("def-weak", host, evt.EventType, evt.Subject.Trim().ToLowerInvariant()),

            EventCategory.Installation when evt.EventType is EventTypes.StartupEntryAdded or EventTypes.ScheduledTaskCreated =>
                BuildKey("pers", host, evt.EventType, NormalizePath(evt.Attr(AttributeKeys.RegistryKey) ?? evt.Attr(AttributeKeys.TaskName) ?? evt.Subject)),

            _ => null
        };
    }

    public static SecurityEvent MergeEvents(SecurityEvent first, SecurityEvent second)
    {
        var attrs = new Dictionary<string, string>(first.Attributes, StringComparer.OrdinalIgnoreCase);

        foreach (var kv in second.Attributes)
        {
            if (kv.Key.Equals(AttributeKeys.EventSources, StringComparison.OrdinalIgnoreCase) ||
                kv.Key.Equals(AttributeKeys.DeduplicatedCount, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!attrs.TryGetValue(kv.Key, out var existing) || string.IsNullOrWhiteSpace(existing))
            {
                attrs[kv.Key] = kv.Value;
            }
            else if (kv.Key.Equals(AttributeKeys.CommandLine, StringComparison.OrdinalIgnoreCase) &&
                     kv.Value.Length > existing.Length)
            {
                // Conserve la ligne de commande la plus complète (ex. Sysmon vs WMI)
                attrs[kv.Key] = kv.Value;
            }
        }

        var sources = ParseSources(first);
        foreach (var s in ParseSources(second))
        {
            sources.Add(s);
        }

        var orderedSources = sources.OrderBy(s => s, StringComparer.OrdinalIgnoreCase).ToArray();
        attrs[AttributeKeys.EventSources] = string.Join(",", orderedSources);

        var prevCount = first.AttrLong(AttributeKeys.DeduplicatedCount) ?? 1;
        attrs[AttributeKeys.DeduplicatedCount] = (prevCount + 1).ToString(CultureInfo.InvariantCulture);

        var mergedHints = MergeHints(first.CorrelationHints, second.CorrelationHints);
        var earliestTs = first.Timestamp <= second.Timestamp ? first.Timestamp : second.Timestamp;

        return first with
        {
            Timestamp = earliestTs,
            Attributes = attrs,
            CorrelationHints = mergedHints
        };
    }

    private static SecurityEvent EnsureSourceAttribute(SecurityEvent evt)
    {
        if (evt.Attributes.ContainsKey(AttributeKeys.EventSources))
        {
            return evt;
        }

        var source = evt.Attr(AttributeKeys.CollectorSource) ?? $"Sentinel.{evt.Category}";
        var attrs = new Dictionary<string, string>(evt.Attributes, StringComparer.OrdinalIgnoreCase)
        {
            [AttributeKeys.CollectorSource] = source,
            [AttributeKeys.EventSources] = source
        };
        return evt with { Attributes = attrs };
    }

    private static HashSet<string> ParseSources(SecurityEvent evt)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var raw = evt.Attr(AttributeKeys.EventSources) ?? evt.Attr(AttributeKeys.CollectorSource);
        if (!string.IsNullOrWhiteSpace(raw))
        {
            foreach (var part in raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                set.Add(part);
            }
        }
        if (set.Count == 0)
        {
            set.Add($"Sentinel.{evt.Category}");
        }
        return set;
    }

    private static string? MergeHints(string? a, string? b)
    {
        if (string.IsNullOrWhiteSpace(a)) return b;
        if (string.IsNullOrWhiteSpace(b)) return a;
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var token in a.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)) set.Add(token);
        foreach (var token in b.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)) set.Add(token);
        return string.Join(";", set);
    }

    private static string? BuildKey(params string?[] parts)
    {
        if (parts.Length < 3 || parts.Skip(2).All(string.IsNullOrWhiteSpace)) return null;
        return string.Join("|", parts.Select(p => (p ?? string.Empty).Trim().ToLowerInvariant()));
    }

    private static string NormalizePath(string? path) =>
        string.IsNullOrWhiteSpace(path) ? string.Empty : path.Trim().Trim('"').Replace('/', '\\').ToLowerInvariant();

    private void PruneExpiredLocked(DateTimeOffset now)
    {
        var cutoff = now - TimeSpan.FromSeconds(Math.Max(10, _window.TotalSeconds * 4));
        var expired = _entries.Where(kv => kv.Value.LastSeen < cutoff).Select(kv => kv.Key).ToList();
        foreach (var k in expired) _entries.Remove(k);

        if (_entries.Count > _maxEntries)
        {
            var oldest = _entries.OrderBy(kv => kv.Value.LastSeen).Take(_entries.Count - (_maxEntries / 2)).Select(kv => kv.Key).ToList();
            foreach (var k in oldest) _entries.Remove(k);
        }
    }

    private readonly record struct DeduplicatedEntry(SecurityEvent Merged, DateTimeOffset LastSeen);
}
