using System.Text.Json;
using Sentinel.Core.Enrichment;
using Sentinel.Shared.Api;
using Sentinel.Shared.Json;
using Sentinel.Shared.Models;

namespace Sentinel.Core.Baseline;

/// <summary>Résultat de la mesure d'écart par rapport au profil comportemental habituel (doc §7.1-2).</summary>
public sealed record BaselineDeviation(
    int Bonus,
    IReadOnlyList<string> RuleIds,
    IReadOnlyList<string> Reasons)
{
    public static BaselineDeviation None { get; } = new(0, Array.Empty<string>(), Array.Empty<string>());
}

/// <summary>
/// Baseline comportementale en mémoire par couple <c>(hostId, userId)</c> (doc §7.1-2 &amp; §9.4).
/// Suit l'histogramme horaire (24 créneaux), les top-N processus/domaines fréquents, la cadence moyenne
/// d'événements/heure et les statistiques en ligne de Welford sur le rythme de frappe (<c>typing.kps</c>).
/// </summary>
public sealed class BehavioralBaseline
{
    private const int MaxProfiles = 500;
    private const int MaxTrackedEntitiesPerProfile = 500;
    private const int MinEventsForHourDeviation = 20;
    private const int MinProcessesForNovelty = 25;
    private const int MinDomainsForNovelty = 20;
    private const int MinTypingSamples = 10;
    private const int MaxBaselineBonus = 25;

    private readonly object _gate = new();
    private readonly Dictionary<string, UserProfile> _profiles = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Évalue l'écart comportemental avant apprentissage de l'événement courant.</summary>
    public BaselineDeviation Evaluate(EnrichedEvent enriched)
    {
        ArgumentNullException.ThrowIfNull(enriched);
        var evt = enriched.Event;
        var key = MakeKey(evt.HostId, evt.UserId);

        lock (_gate)
        {
            if (!_profiles.TryGetValue(key, out var profile))
            {
                return BaselineDeviation.None;
            }

            if (IsProfileBenign(profile, enriched))
            {
                return BaselineDeviation.None;
            }

            var bonus = 0;
            var ruleIds = new List<string>(3);
            var reasons = new List<string>(3);

            // 1. Écart horaire (histogramme 24h)
            if (profile.TotalEvents >= MinEventsForHourDeviation &&
                evt.Category is EventCategory.Session or EventCategory.Process or EventCategory.Network
                    or EventCategory.File or EventCategory.Device or EventCategory.Installation)
            {
                var hour = evt.Timestamp.Hour;
                var hourRatio = (double)profile.HourHistogram[hour] / profile.TotalEvents;
                if (hourRatio < 0.01)
                {
                    bonus += 15;
                    ruleIds.Add("BASE-UNUSUAL-HOUR");
                    reasons.Add($"Activité hors horaires habituels pour {evt.UserId} ({hour:D2}h)");
                }
            }

            // 2. Processus jamais observé (uniquement si non signé par éditeur de confiance)
            if (evt.Category == EventCategory.Process &&
                evt.EventType == EventTypes.ProcessStart &&
                !string.IsNullOrWhiteSpace(enriched.ProcessName) &&
                !enriched.IsTrustedPublisher &&
                profile.TotalProcessObservations >= MinProcessesForNovelty &&
                !profile.ProcessCounts.ContainsKey(enriched.ProcessName))
            {
                bonus += 8;
                ruleIds.Add("BASE-NEW-PROCESS");
                reasons.Add($"Processus jamais observé dans la baseline ({enriched.ProcessName})");
            }

            // 3. Domaine jamais consulté par cet utilisateur
            if (!string.IsNullOrWhiteSpace(enriched.Domain) &&
                evt.Category is EventCategory.Network or EventCategory.Browser or EventCategory.Clipboard &&
                profile.TotalDomainObservations >= MinDomainsForNovelty &&
                !profile.DomainCounts.ContainsKey(enriched.Domain))
            {
                bonus += 8;
                ruleIds.Add("BASE-NEW-DOMAIN");
                reasons.Add($"Domaine inédit pour ce profil ({enriched.Domain})");
            }

            // 4. Écart de dynamique de saisie (algorithme de Welford en ligne sur typing.kps)
            if (evt.Category == EventCategory.Typing &&
                evt.AttrDouble(AttributeKeys.KeysPerSecond) is { } kps &&
                profile.TypingSamples >= MinTypingSamples)
            {
                var stdDev = profile.TypingStdDev;
                if (stdDev > 0.1 && kps > profile.TypingKpsMean + 3.0)
                {
                    var zScore = (kps - profile.TypingKpsMean) / stdDev;
                    if (zScore >= 3.5)
                    {
                        bonus += 15;
                        ruleIds.Add("BASE-TYPING-ANOMALY");
                        reasons.Add($"Rythme de saisie très supérieur à la baseline ({kps:F1} t/s vs moy. {profile.TypingKpsMean:F1} t/s)");
                    }
                }
            }

            if (bonus == 0) return BaselineDeviation.None;
            return new BaselineDeviation(Math.Min(bonus, MaxBaselineBonus), ruleIds, reasons);
        }
    }

    /// <summary>Vérifie si l'événement correspond à un élément appris comme faux positif pour ce profil.</summary>
    public bool IsLearnedBenign(EnrichedEvent enriched)
    {
        ArgumentNullException.ThrowIfNull(enriched);
        var evt = enriched.Event;
        if (evt.Category == EventCategory.System) return false;

        lock (_gate)
        {
            if (!_profiles.TryGetValue(MakeKey(evt.HostId, evt.UserId), out var profile))
            {
                return false;
            }
            return IsProfileBenign(profile, enriched);
        }
    }

    /// <summary>Intègre un événement normal/faible dans la baseline comportementale.</summary>
    public void Observe(EnrichedEvent enriched)
    {
        ArgumentNullException.ThrowIfNull(enriched);
        var evt = enriched.Event;

        lock (_gate)
        {
            var profile = GetOrCreateProfile(evt.HostId, evt.UserId, evt.Timestamp);
            profile.TotalEvents++;
            profile.HourHistogram[evt.Timestamp.Hour]++;
            if (evt.Timestamp < profile.FirstSeen) profile.FirstSeen = evt.Timestamp;
            if (evt.Timestamp > profile.LastSeen) profile.LastSeen = evt.Timestamp;

            if (!string.IsNullOrWhiteSpace(enriched.ProcessName))
            {
                profile.TotalProcessObservations++;
                IncrementBounded(profile.ProcessCounts, enriched.ProcessName);
            }

            if (!string.IsNullOrWhiteSpace(enriched.Domain))
            {
                profile.TotalDomainObservations++;
                IncrementBounded(profile.DomainCounts, enriched.Domain);
            }

            if (evt.Category == EventCategory.Typing &&
                evt.AttrDouble(AttributeKeys.KeysPerSecond) is { } kps &&
                kps > 0 && kps < 15.0 &&
                !evt.AttrIsTrue(AttributeKeys.Injected))
            {
                profile.ObserveTypingKps(kps);
            }
        }
    }

    /// <summary>
    /// Réinjecte un faux positif signalé par l'administrateur dans la baseline (doc §9.4).
    /// </summary>
    public void RecordFalsePositive(
        string hostId,
        string? userId,
        string? processName = null,
        string? domain = null,
        string? sha256 = null,
        string? subject = null)
    {
        lock (_gate)
        {
            var profile = GetOrCreateProfile(hostId, userId ?? string.Empty, DateTimeOffset.UtcNow);

            if (!string.IsNullOrWhiteSpace(processName))
            {
                var norm = ThreatIndicators.NormalizeProcessName(processName);
                profile.BenignProcesses.Add(norm);
                IncrementBounded(profile.ProcessCounts, norm, delta: 10);
                profile.TotalProcessObservations += 10;
            }

            if (!string.IsNullOrWhiteSpace(domain))
            {
                var norm = domain.Trim().TrimEnd('.').ToLowerInvariant();
                profile.BenignDomains.Add(norm);
                IncrementBounded(profile.DomainCounts, norm, delta: 10);
                profile.TotalDomainObservations += 10;
            }

            if (!string.IsNullOrWhiteSpace(sha256))
            {
                var norm = sha256.Trim();
                if (!norm.Equals(ThreatIndicators.EicarSha256, StringComparison.OrdinalIgnoreCase))
                {
                    profile.BenignHashes.Add(norm);
                }
            }

            if (!string.IsNullOrWhiteSpace(subject))
            {
                profile.BenignSubjects.Add(subject.Trim());
            }
        }
    }

    /// <summary>Réinjecte directement un <see cref="SecurityEvent"/> marqué comme faux positif.</summary>
    public void RecordFalsePositive(SecurityEvent evt)
    {
        ArgumentNullException.ThrowIfNull(evt);
        var processName = evt.Attr(AttributeKeys.ProcessName) ?? evt.Attr(AttributeKeys.ProcessPath);
        var domain = evt.Attr(AttributeKeys.Domain)
                     ?? ThreatIndicators.ExtractDomain(evt.Attr(AttributeKeys.Url))
                     ?? ThreatIndicators.ExtractDomain(evt.Subject);
        var sha256 = evt.Attr(AttributeKeys.Sha256) ?? evt.Attr(AttributeKeys.ContentHash);

        RecordFalsePositive(evt.HostId, evt.UserId, processName, domain, sha256, evt.Subject);
    }

    /// <summary>Retourne le résumé de baseline d'un couple poste/utilisateur (ou du poste si <paramref name="userId"/> est null).</summary>
    public BaselineSummaryDto? GetSummary(string hostId, string? userId = null)
    {
        if (string.IsNullOrWhiteSpace(hostId)) return null;

        lock (_gate)
        {
            UserProfile? profile;
            if (!string.IsNullOrWhiteSpace(userId))
            {
                _profiles.TryGetValue(MakeKey(hostId, userId), out profile);
            }
            else
            {
                profile = _profiles.Values
                    .Where(p => p.HostId.Equals(hostId, StringComparison.OrdinalIgnoreCase))
                    .OrderByDescending(p => p.TotalEvents)
                    .FirstOrDefault();
            }

            if (profile is null) return null;

            var usualHours = new List<int>(24);
            if (profile.TotalEvents > 0)
            {
                var minCount = profile.TotalEvents >= 10 ? 2L : 1L;
                for (var h = 0; h < 24; h++)
                {
                    var ratio = (double)profile.HourHistogram[h] / profile.TotalEvents;
                    if (profile.HourHistogram[h] >= minCount && ratio >= 0.02)
                    {
                        usualHours.Add(h);
                    }
                }
            }

            var frequentProcesses = profile.ProcessCounts
                .OrderByDescending(kv => kv.Value)
                .Take(15)
                .Select(kv => kv.Key)
                .ToArray();

            var frequentDomains = profile.DomainCounts
                .OrderByDescending(kv => kv.Value)
                .Take(15)
                .Select(kv => kv.Key)
                .ToArray();

            var spanHours = Math.Max(1.0, (profile.LastSeen - profile.FirstSeen).TotalHours);
            var avgPerHour = Math.Round(profile.TotalEvents / spanHours, 2);

            return new BaselineSummaryDto(
                usualHours,
                frequentProcesses,
                frequentDomains,
                avgPerHour,
                Math.Round(profile.TypingKpsMean, 2),
                profile.LastSeen);
        }
    }

    /// <summary>Formate un résumé textuel compact du profil pour le contexte LLM (§7.3).</summary>
    public string FormatForPrompt(string hostId, string? userId)
    {
        var summary = GetSummary(hostId, userId);
        if (summary is null) return "Aucun profil établi.";

        var hours = summary.UsualHours.Count > 0
            ? string.Join(",", summary.UsualHours.Select(h => $"{h:D2}h"))
            : "non déterminées";
        var procs = summary.FrequentProcesses.Count > 0
            ? string.Join(", ", summary.FrequentProcesses.Take(6))
            : "aucun";
        var domains = summary.FrequentDomains.Count > 0
            ? string.Join(", ", summary.FrequentDomains.Take(6))
            : "aucun";

        return $"Heures habituelles=[{hours}]; Proc fréquents=[{procs}]; Domaines fréquents=[{domains}]; " +
               $"Moy={summary.AvgEventsPerHour:F1} evt/h; Frappe={summary.TypingKpsMean:F1} t/s";
    }

    /// <summary>Exporte l'intégralité de la baseline en JSON pour persistance périodique.</summary>
    public string ExportJson()
    {
        lock (_gate)
        {
            var snapshot = new BaselineSnapshot
            {
                Version = 1,
                Profiles = _profiles.Values.Select(p => new ProfileSnapshot
                {
                    HostId = p.HostId,
                    UserId = p.UserId,
                    FirstSeen = p.FirstSeen,
                    LastSeen = p.LastSeen,
                    TotalEvents = p.TotalEvents,
                    TotalProcessObservations = p.TotalProcessObservations,
                    TotalDomainObservations = p.TotalDomainObservations,
                    HourHistogram = (long[])p.HourHistogram.Clone(),
                    ProcessCounts = new Dictionary<string, long>(p.ProcessCounts),
                    DomainCounts = new Dictionary<string, long>(p.DomainCounts),
                    TypingSamples = p.TypingSamples,
                    TypingKpsMean = p.TypingKpsMean,
                    TypingKpsM2 = p.TypingKpsM2,
                    BenignProcesses = p.BenignProcesses.ToList(),
                    BenignDomains = p.BenignDomains.ToList(),
                    BenignHashes = p.BenignHashes.ToList(),
                    BenignSubjects = p.BenignSubjects.ToList()
                }).ToList()
            };

            return JsonSerializer.Serialize(snapshot, SentinelJson.Options);
        }
    }

    /// <summary>Recharge la baseline à partir d'un instantané JSON précédemment exporté.</summary>
    public void ImportJson(string json)
    {
        if (string.IsNullOrWhiteSpace(json)) return;
        var snapshot = JsonSerializer.Deserialize<BaselineSnapshot>(json, SentinelJson.Options);
        if (snapshot?.Profiles is null) return;

        lock (_gate)
        {
            _profiles.Clear();
            foreach (var sp in snapshot.Profiles.Take(MaxProfiles))
            {
                var profile = new UserProfile(sp.HostId ?? string.Empty, sp.UserId ?? string.Empty, sp.FirstSeen)
                {
                    LastSeen = sp.LastSeen,
                    TotalEvents = sp.TotalEvents,
                    TotalProcessObservations = sp.TotalProcessObservations,
                    TotalDomainObservations = sp.TotalDomainObservations,
                    TypingSamples = sp.TypingSamples,
                    TypingKpsMean = sp.TypingKpsMean,
                    TypingKpsM2 = sp.TypingKpsM2
                };

                if (sp.HourHistogram is { Length: 24 })
                {
                    Array.Copy(sp.HourHistogram, profile.HourHistogram, 24);
                }

                if (sp.ProcessCounts is not null)
                {
                    foreach (var kv in sp.ProcessCounts.Take(MaxTrackedEntitiesPerProfile))
                        profile.ProcessCounts[kv.Key] = kv.Value;
                }

                if (sp.DomainCounts is not null)
                {
                    foreach (var kv in sp.DomainCounts.Take(MaxTrackedEntitiesPerProfile))
                        profile.DomainCounts[kv.Key] = kv.Value;
                }

                if (sp.BenignProcesses is not null) foreach (var s in sp.BenignProcesses) profile.BenignProcesses.Add(s);
                if (sp.BenignDomains is not null) foreach (var s in sp.BenignDomains) profile.BenignDomains.Add(s);
                if (sp.BenignHashes is not null) foreach (var s in sp.BenignHashes) profile.BenignHashes.Add(s);
                if (sp.BenignSubjects is not null) foreach (var s in sp.BenignSubjects) profile.BenignSubjects.Add(s);

                _profiles[MakeKey(profile.HostId, profile.UserId)] = profile;
            }
        }
    }

    private static bool IsProfileBenign(UserProfile profile, EnrichedEvent enriched)
    {
        if (!string.IsNullOrWhiteSpace(enriched.Sha256) && profile.BenignHashes.Contains(enriched.Sha256))
            return true;
        if (!string.IsNullOrWhiteSpace(enriched.Domain) && profile.BenignDomains.Contains(enriched.Domain))
            return true;
        if (!string.IsNullOrWhiteSpace(enriched.ProcessName) &&
            enriched.Event.Category == EventCategory.Process &&
            profile.BenignProcesses.Contains(enriched.ProcessName))
            return true;
        if (!string.IsNullOrWhiteSpace(enriched.Event.Subject) &&
            profile.BenignSubjects.Contains(enriched.Event.Subject.Trim()))
            return true;
        return false;
    }

    private UserProfile GetOrCreateProfile(string hostId, string userId, DateTimeOffset now)
    {
        var key = MakeKey(hostId, userId);
        if (_profiles.TryGetValue(key, out var existing)) return existing;

        if (_profiles.Count >= MaxProfiles)
        {
            var oldest = _profiles.OrderBy(kv => kv.Value.LastSeen).First().Key;
            _profiles.Remove(oldest);
        }

        var created = new UserProfile(hostId, userId, now);
        _profiles[key] = created;
        return created;
    }

    private static void IncrementBounded(Dictionary<string, long> dict, string key, long delta = 1)
    {
        if (dict.TryGetValue(key, out var count))
        {
            dict[key] = count + delta;
            return;
        }

        if (dict.Count >= MaxTrackedEntitiesPerProfile)
        {
            // Éviction de l'entrée la moins fréquente pour borner la mémoire
            string? minKey = null;
            var minVal = long.MaxValue;
            foreach (var kv in dict)
            {
                if (kv.Value < minVal)
                {
                    minVal = kv.Value;
                    minKey = kv.Key;
                }
            }
            if (minKey is not null) dict.Remove(minKey);
        }

        dict[key] = delta;
    }

    private static string MakeKey(string hostId, string? userId) =>
        $"{(hostId ?? string.Empty).Trim().ToLowerInvariant()}|{(userId ?? string.Empty).Trim().ToLowerInvariant()}";

    private sealed class UserProfile(string hostId, string userId, DateTimeOffset firstSeen)
    {
        public string HostId { get; } = hostId;
        public string UserId { get; } = userId;
        public DateTimeOffset FirstSeen { get; set; } = firstSeen;
        public DateTimeOffset LastSeen { get; set; } = firstSeen;
        public long TotalEvents { get; set; }
        public long TotalProcessObservations { get; set; }
        public long TotalDomainObservations { get; set; }
        public long[] HourHistogram { get; } = new long[24];
        public Dictionary<string, long> ProcessCounts { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, long> DomainCounts { get; } = new(StringComparer.OrdinalIgnoreCase);

        public long TypingSamples { get; set; }
        public double TypingKpsMean { get; set; }
        public double TypingKpsM2 { get; set; }

        public double TypingStdDev => TypingSamples > 1 ? Math.Sqrt(TypingKpsM2 / (TypingSamples - 1)) : 0.0;

        public HashSet<string> BenignProcesses { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> BenignDomains { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> BenignHashes { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> BenignSubjects { get; } = new(StringComparer.OrdinalIgnoreCase);

        public void ObserveTypingKps(double kps)
        {
            TypingSamples++;
            var delta = kps - TypingKpsMean;
            TypingKpsMean += delta / TypingSamples;
            var delta2 = kps - TypingKpsMean;
            TypingKpsM2 += delta * delta2;
        }
    }

    private sealed class BaselineSnapshot
    {
        public int Version { get; set; } = 1;
        public List<ProfileSnapshot> Profiles { get; set; } = new();
    }

    private sealed class ProfileSnapshot
    {
        public string? HostId { get; set; }
        public string? UserId { get; set; }
        public DateTimeOffset FirstSeen { get; set; }
        public DateTimeOffset LastSeen { get; set; }
        public long TotalEvents { get; set; }
        public long TotalProcessObservations { get; set; }
        public long TotalDomainObservations { get; set; }
        public long[]? HourHistogram { get; set; }
        public Dictionary<string, long>? ProcessCounts { get; set; }
        public Dictionary<string, long>? DomainCounts { get; set; }
        public long TypingSamples { get; set; }
        public double TypingKpsMean { get; set; }
        public double TypingKpsM2 { get; set; }
        public List<string>? BenignProcesses { get; set; }
        public List<string>? BenignDomains { get; set; }
        public List<string>? BenignHashes { get; set; }
        public List<string>? BenignSubjects { get; set; }
    }
}
