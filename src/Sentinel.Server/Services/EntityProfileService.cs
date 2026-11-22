using Microsoft.EntityFrameworkCore;
using Sentinel.Core.Abstractions;
using Sentinel.Shared.Api;
using Sentinel.Shared.Json;
using Sentinel.Shared.Models;
using Sentinel.Storage;
using Sentinel.Storage.Entities;
using Sentinel.Storage.Mapping;

namespace Sentinel.Server.Services;

/// <summary>
/// Agrégation des postes supervisés et fiches d'entités (Host, User, Domain, Process, File, Device, IP — doc §10.1-4).
/// </summary>
public sealed class EntityProfileService
{
    private static readonly TimeSpan HostOnlineWindow = TimeSpan.FromSeconds(60);

    private readonly IDbContextFactory<SentinelDbContext> _dbFactory;
    private readonly IThreatPipeline _pipeline;
    private readonly AgentCommandHub _commandHub;

    public EntityProfileService(
        IDbContextFactory<SentinelDbContext> dbFactory,
        IThreatPipeline pipeline,
        AgentCommandHub commandHub)
    {
        _dbFactory = dbFactory;
        _pipeline = pipeline;
        _commandHub = commandHub;
    }

    public async Task<IReadOnlyList<HostDto>> GetHostsAsync(CancellationToken ct = default)
    {
        var now = DateTimeOffset.UtcNow;
        var onlineCutoffMs = now.Subtract(HostOnlineWindow).ToUnixTimeMilliseconds();

        await using var db = await _dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);

        var hosts = await db.Hosts
            .AsNoTracking()
            .OrderByDescending(h => h.LastSeenUnixMs)
            .ToListAsync(ct)
            .ConfigureAwait(false);

        var openAlertCounts = await db.Alerts
            .AsNoTracking()
            .Where(a => a.Status == AlertStatus.Open || a.Status == AlertStatus.Acknowledged)
            .GroupBy(a => a.HostId)
            .Select(g => new { HostId = g.Key, Count = g.Count() })
            .ToDictionaryAsync(x => x.HostId, x => x.Count, StringComparer.OrdinalIgnoreCase, ct)
            .ConfigureAwait(false);

        return hosts
            .Select(h => h.ToDto(
                online: h.LastSeenUnixMs >= onlineCutoffMs || _commandHub.IsConnected(h.HostId),
                openAlerts: openAlertCounts.GetValueOrDefault(h.HostId)))
            .ToArray();
    }

    public async Task<IReadOnlyList<EntitySummaryDto>> ListEntitiesAsync(
        EntityKind? kind,
        string? search,
        int limit = 100,
        CancellationToken ct = default)
    {
        var clampedLimit = Math.Clamp(limit <= 0 ? 100 : limit, 1, 500);
        await using var db = await _dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);

        var map = new Dictionary<(EntityKind Kind, string NormKey), EntityAccumulator>();

        void Record(EntityKind k, string key, string label, int score, DateTimeOffset ts, int alertDelta = 0, int eventDelta = 1)
        {
            if (kind.HasValue && kind.Value != k) return;
            if (string.IsNullOrWhiteSpace(key)) return;

            var trimmedKey = key.Trim();
            var norm = trimmedKey.ToLowerInvariant();
            if (!map.TryGetValue((k, norm), out var acc))
            {
                acc = new EntityAccumulator(k, trimmedKey, string.IsNullOrWhiteSpace(label) ? trimmedKey : label.Trim(), ts);
                map[(k, norm)] = acc;
            }
            if (score > acc.RiskScore) acc.RiskScore = score;
            if (ts > acc.LastSeen) acc.LastSeen = ts;
            acc.EventCount += eventDelta;
            acc.AlertCount += alertDelta;
        }

        // 1. Postes enregistrés
        if (!kind.HasValue || kind == EntityKind.Host)
        {
            var hosts = await db.Hosts.AsNoTracking().ToListAsync(ct).ConfigureAwait(false);
            foreach (var h in hosts)
            {
                Record(EntityKind.Host, h.HostId, h.MachineName, h.RiskScore, h.LastSeen, alertDelta: 0, eventDelta: 0);
            }
        }

        // 2. Alertes par Host et User
        var alerts = await db.Alerts
            .AsNoTracking()
            .Select(a => new { a.HostId, a.UserId, a.Score, a.UpdatedAt })
            .ToListAsync(ct)
            .ConfigureAwait(false);

        foreach (var a in alerts)
        {
            Record(EntityKind.Host, a.HostId, a.HostId, a.Score, a.UpdatedAt, alertDelta: 1, eventDelta: 0);
            if (!string.IsNullOrWhiteSpace(a.UserId))
                Record(EntityKind.User, a.UserId, a.UserId, a.Score, a.UpdatedAt, alertDelta: 1, eventDelta: 0);
        }

        // 3. Événements récents (jusqu'à 5 000 derniers)
        var recentEvents = await db.Events
            .AsNoTracking()
            .OrderByDescending(e => e.TimestampUnixMs)
            .Take(5000)
            .ToListAsync(ct)
            .ConfigureAwait(false);

        foreach (var e in recentEvents)
        {
            var attrs = DeserializeDict(e.AttributesJson);

            Record(EntityKind.Host, e.HostId, e.HostId, e.Score, e.Timestamp);
            if (!string.IsNullOrWhiteSpace(e.UserId) && !e.UserId.Equals("unknown", StringComparison.OrdinalIgnoreCase))
                Record(EntityKind.User, e.UserId, e.UserId, e.Score, e.Timestamp);

            if (!kind.HasValue || kind == EntityKind.Domain)
            {
                var domain = ExtractDomain(e, attrs);
                if (!string.IsNullOrWhiteSpace(domain))
                    Record(EntityKind.Domain, domain, domain, e.Score, e.Timestamp);
            }

            if (!kind.HasValue || kind == EntityKind.Process)
            {
                var (procKey, procLabel) = ExtractProcess(e, attrs);
                if (!string.IsNullOrWhiteSpace(procKey))
                    Record(EntityKind.Process, procKey, procLabel, e.Score, e.Timestamp);
            }

            if (!kind.HasValue || kind == EntityKind.File)
            {
                var (fileKey, fileLabel) = ExtractFile(e, attrs);
                if (!string.IsNullOrWhiteSpace(fileKey))
                    Record(EntityKind.File, fileKey, fileLabel, e.Score, e.Timestamp);
            }

            if (!kind.HasValue || kind == EntityKind.Device)
            {
                var (devKey, devLabel) = ExtractDevice(e, attrs);
                if (!string.IsNullOrWhiteSpace(devKey))
                    Record(EntityKind.Device, devKey, devLabel, e.Score, e.Timestamp);
            }

            if (!kind.HasValue || kind == EntityKind.Ip)
            {
                var ip = ExtractIp(attrs);
                if (!string.IsNullOrWhiteSpace(ip))
                    Record(EntityKind.Ip, ip, ip, e.Score, e.Timestamp);
            }
        }

        IEnumerable<EntityAccumulator> query = map.Values;
        if (!string.IsNullOrWhiteSpace(search))
        {
            var term = search.Trim();
            query = query.Where(x =>
                x.Key.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                x.Label.Contains(term, StringComparison.OrdinalIgnoreCase));
        }

        return query
            .OrderByDescending(x => x.RiskScore)
            .ThenByDescending(x => x.LastSeen)
            .Take(clampedLimit)
            .Select(x => new EntitySummaryDto(x.Kind, x.Key, x.Label, x.RiskScore, x.EventCount, x.AlertCount, x.LastSeen))
            .ToArray();
    }

    public async Task<EntityProfileDto?> GetProfileAsync(EntityKind kind, string rawKey, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(rawKey))
            return null;

        var key = rawKey.Trim();
        var now = DateTimeOffset.UtcNow;

        await using var db = await _dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);

        HostEntity? hostEntity = null;
        List<EventEntity> matchedEvents;

        if (kind == EntityKind.Host)
        {
            hostEntity = await db.Hosts
                .AsNoTracking()
                .FirstOrDefaultAsync(h => h.HostId == key, ct)
                .ConfigureAwait(false);

            matchedEvents = await db.Events
                .AsNoTracking()
                .Where(e => e.HostId == key)
                .OrderByDescending(e => e.TimestampUnixMs)
                .Take(1000)
                .ToListAsync(ct)
                .ConfigureAwait(false);
        }
        else if (kind == EntityKind.User)
        {
            matchedEvents = await db.Events
                .AsNoTracking()
                .Where(e => e.UserId == key)
                .OrderByDescending(e => e.TimestampUnixMs)
                .Take(1000)
                .ToListAsync(ct)
                .ConfigureAwait(false);
        }
        else
        {
            var candidates = await db.Events
                .AsNoTracking()
                .OrderByDescending(e => e.TimestampUnixMs)
                .Take(5000)
                .ToListAsync(ct)
                .ConfigureAwait(false);

            var normTarget = NormalizePathOrKey(key);
            matchedEvents = candidates
                .Where(e => EventMatchesEntity(e, kind, key, normTarget))
                .Take(1000)
                .ToList();
        }

        if (hostEntity is null && matchedEvents.Count == 0)
            return null;

        // Alertes associées
        List<AlertEntity> relatedAlerts;
        if (kind == EntityKind.Host)
        {
            relatedAlerts = await db.Alerts
                .AsNoTracking()
                .Where(a => a.HostId == key)
                .OrderByDescending(a => a.UpdatedAtUnixMs)
                .Take(50)
                .ToListAsync(ct)
                .ConfigureAwait(false);
        }
        else if (kind == EntityKind.User)
        {
            relatedAlerts = await db.Alerts
                .AsNoTracking()
                .Where(a => a.UserId == key)
                .OrderByDescending(a => a.UpdatedAtUnixMs)
                .Take(50)
                .ToListAsync(ct)
                .ConfigureAwait(false);
        }
        else
        {
            var eventIds = matchedEvents.Select(e => e.Id).ToList();
            var alertIds = eventIds.Count == 0
                ? new List<Guid>()
                : await db.AlertEvents
                    .AsNoTracking()
                    .Where(ae => eventIds.Contains(ae.EventId))
                    .Select(ae => ae.AlertId)
                    .Distinct()
                    .ToListAsync(ct)
                    .ConfigureAwait(false);

            relatedAlerts = alertIds.Count == 0
                ? new List<AlertEntity>()
                : await db.Alerts
                    .AsNoTracking()
                    .Where(a => alertIds.Contains(a.Id))
                    .OrderByDescending(a => a.UpdatedAtUnixMs)
                    .Take(50)
                    .ToListAsync(ct)
                    .ConfigureAwait(false);
        }

        var alertIdsForCounts = relatedAlerts.Select(a => a.Id).ToList();
        var pendingByAlert = alertIdsForCounts.Count == 0
            ? new Dictionary<Guid, int>()
            : await db.ActionTickets
                .AsNoTracking()
                .Where(t => t.AlertId != null && alertIdsForCounts.Contains(t.AlertId.Value) &&
                            (t.Status == ActionStatus.Proposed || t.Status == ActionStatus.Pending))
                .GroupBy(t => t.AlertId!.Value)
                .Select(g => new { AlertId = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.AlertId, x => x.Count, ct)
                .ConfigureAwait(false);

        var alertDtos = relatedAlerts
            .Select(a => a.ToDto(pendingByAlert.GetValueOrDefault(a.Id)))
            .ToArray();

        // Statistiques globales de la fiche
        var firstSeen = matchedEvents.Count > 0
            ? matchedEvents.Min(e => e.Timestamp)
            : hostEntity!.FirstSeen;
        if (hostEntity is not null && hostEntity.FirstSeen < firstSeen)
            firstSeen = hostEntity.FirstSeen;

        var lastSeen = matchedEvents.Count > 0
            ? matchedEvents.Max(e => e.Timestamp)
            : hostEntity!.LastSeen;
        if (hostEntity is not null && hostEntity.LastSeen > lastSeen)
            lastSeen = hostEntity.LastSeen;

        var riskScore = Math.Max(
            hostEntity?.RiskScore ?? 0,
            Math.Max(
                matchedEvents.Count > 0 ? matchedEvents.Max(e => e.Score) : 0,
                relatedAlerts.Count > 0 ? relatedAlerts.Max(a => a.Score) : 0));

        // Activité 24h (24 tranches horaires)
        var activity = BuildEntityActivity24h(matchedEvents, relatedAlerts, now);

        // Baseline comportementale depuis le pipeline
        BaselineSummaryDto? baseline = kind switch
        {
            EntityKind.Host => _pipeline.GetBaseline(key, null),
            EntityKind.User => matchedEvents.FirstOrDefault()?.HostId is { } userHost
                ? _pipeline.GetBaseline(userHost, key)
                : null,
            _ => null
        };

        // Propriétés techniques enrichies
        var props = BuildProperties(kind, key, hostEntity, matchedEvents, now);
        var label = ResolveLabel(kind, key, hostEntity, matchedEvents);

        return new EntityProfileDto(
            Kind: kind,
            Key: key,
            Label: label,
            RiskScore: Math.Clamp(riskScore, 0, 100),
            FirstSeen: firstSeen,
            LastSeen: lastSeen,
            EventCount: matchedEvents.Count,
            Alerts: alertDtos,
            RecentEvents: matchedEvents.Take(50).Select(e => e.ToDto()).ToArray(),
            Activity: activity,
            Baseline: baseline,
            Properties: props);
    }

    private Dictionary<string, string> BuildProperties(
        EntityKind kind,
        string key,
        HostEntity? host,
        List<EventEntity> events,
        DateTimeOffset now)
    {
        var props = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        if (kind == EntityKind.Host && host is not null)
        {
            var online = (now - host.LastSeen) < HostOnlineWindow || _commandHub.IsConnected(host.HostId);
            props["machineName"] = host.MachineName;
            props["osVersion"] = host.OsVersion;
            props["agentVersion"] = host.AgentVersion;
            props["online"] = online ? "true" : "false";
            props["cpuPercent"] = Math.Round(host.CpuPercent, 1).ToString(System.Globalization.CultureInfo.InvariantCulture);
            props["workingSetMb"] = (host.WorkingSetBytes / (1024 * 1024)).ToString(System.Globalization.CultureInfo.InvariantCulture);
            props["queueLength"] = host.QueueLength.ToString(System.Globalization.CultureInfo.InvariantCulture);
            if (!string.IsNullOrWhiteSpace(host.BinarySha256))
                props["binarySha256"] = host.BinarySha256;
        }

        if (events.Count > 0)
        {
            var hosts = events.Select(e => e.HostId).Distinct(StringComparer.OrdinalIgnoreCase).Take(10).ToArray();
            var users = events.Select(e => e.UserId).Where(u => !string.IsNullOrWhiteSpace(u)).Distinct(StringComparer.OrdinalIgnoreCase).Take(10).ToArray();
            props["observedHosts"] = string.Join(", ", hosts);
            if (users.Length > 0) props["observedUsers"] = string.Join(", ", users);

            var latestAttrs = DeserializeDict(events[0].AttributesJson);
            CopyIfPresent(latestAttrs, props, AttributeKeys.Sha256, "sha256");
            CopyIfPresent(latestAttrs, props, AttributeKeys.Signed, "signed");
            CopyIfPresent(latestAttrs, props, AttributeKeys.Publisher, "publisher");
            CopyIfPresent(latestAttrs, props, AttributeKeys.ProcessPath, "processPath");
            CopyIfPresent(latestAttrs, props, AttributeKeys.FilePath, "filePath");
            CopyIfPresent(latestAttrs, props, AttributeKeys.Entropy, "entropy");
            CopyIfPresent(latestAttrs, props, AttributeKeys.DeviceClass, "deviceClass");
            CopyIfPresent(latestAttrs, props, AttributeKeys.VendorId, "vendorId");
            CopyIfPresent(latestAttrs, props, AttributeKeys.ProductId, "productId");
            CopyIfPresent(latestAttrs, props, AttributeKeys.RemotePort, "remotePort");
            CopyIfPresent(latestAttrs, props, AttributeKeys.DomainAgeDays, "domainAgeDays");
        }

        return props;
    }

    private static string ResolveLabel(EntityKind kind, string key, HostEntity? host, List<EventEntity> events)
    {
        if (kind == EntityKind.Host && host is not null && !string.IsNullOrWhiteSpace(host.MachineName))
            return host.MachineName;

        if (kind is EntityKind.File or EntityKind.Process)
        {
            var name = Path.GetFileName(key.Replace('/', '\\'));
            if (!string.IsNullOrWhiteSpace(name))
                return name;
        }

        if (kind == EntityKind.Device && events.Count > 0)
        {
            var attrs = DeserializeDict(events[0].AttributesJson);
            if (attrs.TryGetValue(AttributeKeys.DeviceName, out var devName) && !string.IsNullOrWhiteSpace(devName))
                return devName;
        }

        return key;
    }

    private static IReadOnlyList<TimeSeriesPointDto> BuildEntityActivity24h(
        List<EventEntity> events,
        List<AlertEntity> alerts,
        DateTimeOffset now)
    {
        const int buckets = 24;
        var span = TimeSpan.FromHours(1);
        var currentTicks = now.UtcTicks - (now.UtcTicks % span.Ticks);
        var start = new DateTimeOffset(currentTicks, TimeSpan.Zero).AddHours(-(buckets - 1));
        var startMs = start.ToUnixTimeMilliseconds();
        var bucketMs = (long)span.TotalMilliseconds;

        var evCounts = new long[buckets];
        var scoreSum = new long[buckets];
        var maxScore = new int[buckets];
        var alertCounts = new int[buckets];

        foreach (var e in events)
        {
            var idx = (int)((e.TimestampUnixMs - startMs) / bucketMs);
            if (idx < 0 || idx >= buckets) continue;
            evCounts[idx]++;
            scoreSum[idx] += e.Score;
            if (e.Score > maxScore[idx]) maxScore[idx] = e.Score;
        }

        foreach (var a in alerts)
        {
            var idx = (int)((a.CreatedAtUnixMs - startMs) / bucketMs);
            if (idx < 0 || idx >= buckets) continue;
            alertCounts[idx]++;
        }

        var points = new TimeSeriesPointDto[buckets];
        for (var i = 0; i < buckets; i++)
        {
            var avg = evCounts[i] > 0 ? Math.Round((double)scoreSum[i] / evCounts[i], 1) : 0.0;
            points[i] = new TimeSeriesPointDto(start.AddHours(i), evCounts[i], alertCounts[i], maxScore[i], avg, 0);
        }

        return points;
    }

    private static bool EventMatchesEntity(EventEntity e, EntityKind kind, string key, string normTarget)
    {
        var attrs = DeserializeDict(e.AttributesJson);
        switch (kind)
        {
            case EntityKind.Domain:
                var dom = ExtractDomain(e, attrs);
                return dom is not null && dom.Equals(key, StringComparison.OrdinalIgnoreCase);

            case EntityKind.Process:
                var (pk, pl) = ExtractProcess(e, attrs);
                return (pk is not null && NormalizePathOrKey(pk) == normTarget) ||
                       (pl is not null && pl.Equals(key, StringComparison.OrdinalIgnoreCase));

            case EntityKind.File:
                var (fk, fl) = ExtractFile(e, attrs);
                return (fk is not null && NormalizePathOrKey(fk) == normTarget) ||
                       (fl is not null && fl.Equals(key, StringComparison.OrdinalIgnoreCase));

            case EntityKind.Device:
                var (dk, dl) = ExtractDevice(e, attrs);
                return (dk is not null && dk.Equals(key, StringComparison.OrdinalIgnoreCase)) ||
                       (dl is not null && dl.Equals(key, StringComparison.OrdinalIgnoreCase));

            case EntityKind.Ip:
                var ip = ExtractIp(attrs);
                return ip is not null && ip.Equals(key, StringComparison.OrdinalIgnoreCase);

            default:
                return false;
        }
    }

    private static string? ExtractDomain(EventEntity e, Dictionary<string, string> attrs)
    {
        if (attrs.TryGetValue(AttributeKeys.Domain, out var d) && !string.IsNullOrWhiteSpace(d))
            return d.Trim().ToLowerInvariant();
        if (attrs.TryGetValue(AttributeKeys.Url, out var u) && ActionPolicyHelper.TryExtractDomain(u) is { } du)
            return du;
        if (e.Category is (int)EventCategory.Browser or (int)EventCategory.Clipboard or (int)EventCategory.Network)
            return ActionPolicyHelper.TryExtractDomain(e.Subject);
        return null;
    }

    private static (string? Key, string Label) ExtractProcess(EventEntity e, Dictionary<string, string> attrs)
    {
        attrs.TryGetValue(AttributeKeys.ProcessPath, out var path);
        attrs.TryGetValue(AttributeKeys.ProcessName, out var name);
        if (string.IsNullOrWhiteSpace(path) && e.Category == (int)EventCategory.Process)
            path = e.Subject;
        var key = !string.IsNullOrWhiteSpace(path) ? path.Trim() : name?.Trim();
        var label = !string.IsNullOrWhiteSpace(name) ? name.Trim() : (key is not null ? Path.GetFileName(key) : string.Empty);
        return (key, string.IsNullOrWhiteSpace(label) ? key ?? string.Empty : label);
    }

    private static (string? Key, string Label) ExtractFile(EventEntity e, Dictionary<string, string> attrs)
    {
        attrs.TryGetValue(AttributeKeys.FilePath, out var path);
        attrs.TryGetValue(AttributeKeys.FileName, out var name);
        if (string.IsNullOrWhiteSpace(path) && e.Category == (int)EventCategory.File)
            path = e.Subject;
        var key = !string.IsNullOrWhiteSpace(path) ? path.Trim() : name?.Trim();
        var label = !string.IsNullOrWhiteSpace(name) ? name.Trim() : (key is not null ? Path.GetFileName(key) : string.Empty);
        return (key, string.IsNullOrWhiteSpace(label) ? key ?? string.Empty : label);
    }

    private static (string? Key, string Label) ExtractDevice(EventEntity e, Dictionary<string, string> attrs)
    {
        attrs.TryGetValue(AttributeKeys.DeviceId, out var devId);
        attrs.TryGetValue(AttributeKeys.DeviceName, out var devName);
        if (string.IsNullOrWhiteSpace(devId) && e.Category == (int)EventCategory.Device)
            devId = e.Subject;
        var key = devId?.Trim();
        var label = !string.IsNullOrWhiteSpace(devName) ? devName.Trim() : (key ?? string.Empty);
        return (key, label);
    }

    private static string? ExtractIp(Dictionary<string, string> attrs)
    {
        if (attrs.TryGetValue(AttributeKeys.RemoteIp, out var remote) && !string.IsNullOrWhiteSpace(remote))
            return remote.Trim();
        if (attrs.TryGetValue(AttributeKeys.SourceIp, out var src) && !string.IsNullOrWhiteSpace(src))
            return src.Trim();
        return null;
    }

    private static string NormalizePathOrKey(string value) =>
        value.Trim().Replace('/', '\\').ToLowerInvariant();

    private static void CopyIfPresent(Dictionary<string, string> src, Dictionary<string, string> dst, string srcKey, string dstKey)
    {
        if (src.TryGetValue(srcKey, out var val) && !string.IsNullOrWhiteSpace(val))
            dst[dstKey] = val;
    }

    private static Dictionary<string, string> DeserializeDict(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var dict = SentinelJson.Deserialize<Dictionary<string, string>>(json);
            return dict is null
                ? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                : new Dictionary<string, string>(dict, StringComparer.OrdinalIgnoreCase);
        }
        catch
        {
            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }
    }

    private sealed class EntityAccumulator(EntityKind kind, string key, string label, DateTimeOffset lastSeen)
    {
        public EntityKind Kind { get; } = kind;
        public string Key { get; } = key;
        public string Label { get; } = label;
        public int RiskScore { get; set; }
        public long EventCount { get; set; }
        public int AlertCount { get; set; }
        public DateTimeOffset LastSeen { get; set; } = lastSeen;
    }
}
