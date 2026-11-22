using Microsoft.EntityFrameworkCore;
using Sentinel.Shared.Api;
using Sentinel.Shared.Json;
using Sentinel.Shared.Models;
using Sentinel.Storage;
using Sentinel.Storage.Entities;
using Sentinel.Storage.Mapping;

namespace Sentinel.Server.Services;

/// <summary>
/// Construit le graphe de corrélation complet (doc §5.3, exigence F9) pour Cytoscape.js :
/// nœuds dédupliqués (<c>Event</c>, <c>Process</c>, <c>File</c>, <c>Domain</c>, <c>IP</c>, <c>User</c>, <c>Device</c>, <c>Threat</c>, <c>Host</c>)
/// et arêtes typées issues des <c>ClusterLinks</c> et des entités extraites des événements.
/// </summary>
public sealed class GraphBuilderService
{
    private readonly IDbContextFactory<SentinelDbContext> _dbFactory;

    public GraphBuilderService(IDbContextFactory<SentinelDbContext> dbFactory)
    {
        _dbFactory = dbFactory;
    }

    public async Task<GraphDto> BuildGraphAsync(
        DateTimeOffset? from,
        DateTimeOffset? to,
        string? hostId,
        int? minScore,
        Guid? clusterId,
        int limit = 150,
        CancellationToken ct = default)
    {
        var clampedLimit = Math.Clamp(limit <= 0 ? 150 : limit, 1, 500);

        await using var db = await _dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);

        List<EventEntity> events;
        List<ClusterEntity> clusters;

        if (clusterId is { } cid)
        {
            var cluster = await db.Clusters
                .AsNoTracking()
                .Include(c => c.Links)
                .FirstOrDefaultAsync(c => c.Id == cid, ct)
                .ConfigureAwait(false);

            clusters = cluster is not null ? [cluster] : [];

            var linkedEventIds = new HashSet<Guid>();
            if (cluster is not null)
            {
                foreach (var l in cluster.Links)
                {
                    linkedEventIds.Add(l.FromEventId);
                    linkedEventIds.Add(l.ToEventId);
                }
            }

            var q = db.Events.AsNoTracking().Where(e => e.ClusterId == cid || linkedEventIds.Contains(e.Id));
            if (minScore is > 0)
                q = q.Where(e => e.Score >= minScore.Value);

            events = await q
                .OrderBy(e => e.TimestampUnixMs)
                .Take(clampedLimit)
                .ToListAsync(ct)
                .ConfigureAwait(false);
        }
        else
        {
            var effectiveTo = to ?? DateTimeOffset.UtcNow;
            var effectiveFrom = from ?? effectiveTo.AddHours(-24);
            var fromMs = effectiveFrom.ToUnixTimeMilliseconds();
            var toMs = effectiveTo.ToUnixTimeMilliseconds();

            var q = db.Events.AsNoTracking()
                .Where(e => e.TimestampUnixMs >= fromMs && e.TimestampUnixMs <= toMs);

            if (!string.IsNullOrWhiteSpace(hostId))
                q = q.Where(e => e.HostId == hostId.Trim());

            if (minScore is > 0)
                q = q.Where(e => e.Score >= minScore.Value);

            events = await q
                .OrderByDescending(e => e.Score)
                .ThenByDescending(e => e.TimestampUnixMs)
                .Take(clampedLimit)
                .ToListAsync(ct)
                .ConfigureAwait(false);

            var clusterIds = events
                .Where(e => e.ClusterId.HasValue)
                .Select(e => e.ClusterId!.Value)
                .Distinct()
                .ToList();

            clusters = clusterIds.Count == 0
                ? []
                : await db.Clusters
                    .AsNoTracking()
                    .Include(c => c.Links)
                    .Where(c => clusterIds.Contains(c.Id))
                    .ToListAsync(ct)
                    .ConfigureAwait(false);
        }

        var nodes = new Dictionary<string, MutableNode>(StringComparer.OrdinalIgnoreCase);
        var edges = new Dictionary<string, GraphEdgeDto>(StringComparer.OrdinalIgnoreCase);
        var includedEventIds = new HashSet<Guid>(events.Select(e => e.Id));

        MutableNode UpsertNode(
            string id,
            GraphNodeType type,
            string label,
            int score,
            Guid? nodeClusterId,
            DateTimeOffset? timestamp,
            Action<Dictionary<string, string>>? enrichData = null)
        {
            if (!nodes.TryGetValue(id, out var node))
            {
                node = new MutableNode(id, type, label, score, nodeClusterId, timestamp);
                nodes[id] = node;
            }
            else
            {
                if (score > node.Score) node.Score = score;
                node.ClusterId ??= nodeClusterId;
                if (timestamp.HasValue && (!node.Timestamp.HasValue || timestamp.Value > node.Timestamp.Value))
                    node.Timestamp = timestamp;
            }

            enrichData?.Invoke(node.Data);
            return node;
        }

        void AddEdge(string source, string target, GraphEdgeType type, double weight, string? label = null)
        {
            if (string.Equals(source, target, StringComparison.OrdinalIgnoreCase))
                return;

            var edgeKey = $"{source}|{target}|{(int)type}";
            if (!edges.ContainsKey(edgeKey))
            {
                edges[edgeKey] = new GraphEdgeDto(
                    $"edge:{edges.Count + 1}",
                    source,
                    target,
                    type,
                    Math.Round(weight, 2),
                    label);
            }
        }

        // 1. Nœuds Événements et Entités associées
        foreach (var e in events)
        {
            var attrs = DeserializeDict(e.AttributesJson);
            var eventNodeId = $"event:{e.Id:D}";

            UpsertNode(
                eventNodeId,
                GraphNodeType.Event,
                $"{e.EventType}: {Truncate(e.Subject, 42)}",
                e.Score,
                e.ClusterId,
                e.Timestamp,
                d =>
                {
                    d["eventId"] = e.Id.ToString("D");
                    d["category"] = ((EventCategory)e.Category).ToString();
                    d["eventType"] = e.EventType;
                    d["subject"] = e.Subject;
                    d["threatType"] = ((ThreatType)e.ThreatType).ToString();
                    d["justification"] = Truncate(e.Justification, 220);
                });

            // Host
            if (!string.IsNullOrWhiteSpace(e.HostId))
            {
                var hostNodeId = $"host:{e.HostId.Trim().ToLowerInvariant()}";
                UpsertNode(hostNodeId, GraphNodeType.Host, e.HostId.Trim(), e.Score, e.ClusterId, e.Timestamp,
                    d => d["hostId"] = e.HostId.Trim());
                AddEdge(eventNodeId, hostNodeId, GraphEdgeType.InvolvedIn, 0.5, "host");
            }

            // User
            if (!string.IsNullOrWhiteSpace(e.UserId) && !e.UserId.Equals("unknown", StringComparison.OrdinalIgnoreCase))
            {
                var userNodeId = $"user:{e.UserId.Trim().ToLowerInvariant()}";
                UpsertNode(userNodeId, GraphNodeType.User, e.UserId.Trim(), e.Score, e.ClusterId, e.Timestamp,
                    d => d["userId"] = e.UserId.Trim());
                AddEdge(userNodeId, eventNodeId, GraphEdgeType.InvolvedIn, 0.5, "user");
            }

            // Process + ParentProcess
            var procName = GetAttr(attrs, AttributeKeys.ProcessName);
            var procPath = GetAttr(attrs, AttributeKeys.ProcessPath) ?? (e.Category == (int)EventCategory.Process ? e.Subject : null);
            var procKey = !string.IsNullOrWhiteSpace(procPath) ? procPath : procName;
            string? procNodeId = null;

            if (!string.IsNullOrWhiteSpace(procKey))
            {
                var normProc = procKey.Trim().Replace('/', '\\').ToLowerInvariant();
                var procLabel = !string.IsNullOrWhiteSpace(procName) ? procName : Path.GetFileName(procKey);
                procNodeId = $"process:{normProc}";
                UpsertNode(procNodeId, GraphNodeType.Process, string.IsNullOrWhiteSpace(procLabel) ? procKey : procLabel, e.Score, e.ClusterId, e.Timestamp, d =>
                {
                    d["path"] = procKey;
                    if (GetAttr(attrs, AttributeKeys.ProcessId) is { } pid) d["pid"] = pid;
                    if (GetAttr(attrs, AttributeKeys.Sha256) is { } sha) d["sha256"] = sha;
                    if (GetAttr(attrs, AttributeKeys.Signed) is { } signed) d["signed"] = signed;
                });
                AddEdge(eventNodeId, procNodeId, GraphEdgeType.InvolvedIn, 0.8, "process");

                var parentName = GetAttr(attrs, AttributeKeys.ParentProcessName);
                var parentPath = GetAttr(attrs, AttributeKeys.ParentProcessPath);
                var parentKey = !string.IsNullOrWhiteSpace(parentPath) ? parentPath : parentName;
                if (!string.IsNullOrWhiteSpace(parentKey))
                {
                    var parentNodeId = $"process:{parentKey.Trim().Replace('/', '\\').ToLowerInvariant()}";
                    var parentLabel = !string.IsNullOrWhiteSpace(parentName) ? parentName : Path.GetFileName(parentKey);
                    UpsertNode(parentNodeId, GraphNodeType.Process, string.IsNullOrWhiteSpace(parentLabel) ? parentKey : parentLabel, e.Score, e.ClusterId, e.Timestamp,
                        d => d["path"] = parentKey);
                    AddEdge(parentNodeId, procNodeId, GraphEdgeType.Spawned, 0.85, "SPAWNED");
                }
            }

            // File
            var filePath = GetAttr(attrs, AttributeKeys.FilePath)
                           ?? GetAttr(attrs, AttributeKeys.FileName)
                           ?? (e.Category == (int)EventCategory.File ? e.Subject : null);
            if (!string.IsNullOrWhiteSpace(filePath))
            {
                var normFile = filePath.Trim().Replace('/', '\\').ToLowerInvariant();
                var fileNodeId = $"file:{normFile}";
                var fileLabel = Path.GetFileName(filePath);
                UpsertNode(fileNodeId, GraphNodeType.File, string.IsNullOrWhiteSpace(fileLabel) ? filePath : fileLabel, e.Score, e.ClusterId, e.Timestamp, d =>
                {
                    d["path"] = filePath;
                    if (GetAttr(attrs, AttributeKeys.Sha256) is { } sha) d["sha256"] = sha;
                    if (GetAttr(attrs, AttributeKeys.Entropy) is { } ent) d["entropy"] = ent;
                });
                AddEdge(eventNodeId, fileNodeId, GraphEdgeType.Wrote, 0.8, "WROTE");
                if (procNodeId is not null)
                    AddEdge(procNodeId, fileNodeId, GraphEdgeType.Wrote, 0.75, "WROTE");
            }

            // Domain
            var domain = GetAttr(attrs, AttributeKeys.Domain)
                         ?? ActionPolicyHelper.TryExtractDomain(GetAttr(attrs, AttributeKeys.Url))
                         ?? (e.Category is (int)EventCategory.Browser or (int)EventCategory.Clipboard or (int)EventCategory.Network
                             ? ActionPolicyHelper.TryExtractDomain(e.Subject)
                             : null);
            if (!string.IsNullOrWhiteSpace(domain))
            {
                var normDom = domain.Trim().ToLowerInvariant();
                var domNodeId = $"domain:{normDom}";
                UpsertNode(domNodeId, GraphNodeType.Domain, normDom, e.Score, e.ClusterId, e.Timestamp, d =>
                {
                    d["domain"] = normDom;
                    if (GetAttr(attrs, AttributeKeys.Url) is { } url) d["url"] = url;
                });

                var edgeType = (EventCategory)e.Category switch
                {
                    EventCategory.Clipboard => GraphEdgeType.CopiedFromClipboard,
                    EventCategory.Browser => GraphEdgeType.OpenedUrl,
                    EventCategory.Network => GraphEdgeType.ConnectedTo,
                    _ => GraphEdgeType.SameDomain
                };
                AddEdge(eventNodeId, domNodeId, edgeType, 0.85, edgeType.ToString());
                if (procNodeId is not null)
                    AddEdge(procNodeId, domNodeId, GraphEdgeType.ConnectedTo, 0.75, "CONNECTED_TO");
            }

            // IP
            var ip = GetAttr(attrs, AttributeKeys.RemoteIp) ?? GetAttr(attrs, AttributeKeys.SourceIp);
            if (!string.IsNullOrWhiteSpace(ip))
            {
                var normIp = ip.Trim();
                var ipNodeId = $"ip:{normIp}";
                UpsertNode(ipNodeId, GraphNodeType.Ip, normIp, e.Score, e.ClusterId, e.Timestamp, d =>
                {
                    d["ip"] = normIp;
                    if (GetAttr(attrs, AttributeKeys.RemotePort) is { } port) d["port"] = port;
                });
                AddEdge(eventNodeId, ipNodeId, GraphEdgeType.ConnectedTo, 0.8, "CONNECTED_TO");
                if (procNodeId is not null)
                    AddEdge(procNodeId, ipNodeId, GraphEdgeType.ConnectedTo, 0.8, "CONNECTED_TO");
            }

            // Device
            var devId = GetAttr(attrs, AttributeKeys.DeviceId) ?? (e.Category == (int)EventCategory.Device ? e.Subject : null);
            if (!string.IsNullOrWhiteSpace(devId))
            {
                var normDev = devId.Trim().ToLowerInvariant();
                var devNodeId = $"device:{normDev}";
                var devLabel = GetAttr(attrs, AttributeKeys.DeviceName) ?? devId;
                UpsertNode(devNodeId, GraphNodeType.Device, devLabel, e.Score, e.ClusterId, e.Timestamp, d =>
                {
                    d["deviceId"] = devId;
                    if (GetAttr(attrs, AttributeKeys.DeviceClass) is { } cls) d["class"] = cls;
                    if (GetAttr(attrs, AttributeKeys.VendorId) is { } vid) d["vid"] = vid;
                    if (GetAttr(attrs, AttributeKeys.ProductId) is { } pid) d["pid"] = pid;
                });
                AddEdge(eventNodeId, devNodeId, GraphEdgeType.InvolvedIn, 0.8, "device");
            }
        }

        // 2. Nœuds Menace (Clusters) + arêtes ClusterLinks + arêtes Sequence
        var eventsByCluster = events
            .Where(e => e.ClusterId.HasValue)
            .GroupBy(e => e.ClusterId!.Value)
            .ToDictionary(g => g.Key, g => g.OrderBy(e => e.TimestampUnixMs).ToList());

        foreach (var cluster in clusters)
        {
            var threatNodeId = $"threat:{cluster.Id:D}";
            var label = !string.IsNullOrWhiteSpace(cluster.ChainName)
                ? cluster.ChainName
                : $"{ActionPolicyHelper.ThreatTypeLabel(cluster.DominantType)} ({cluster.Score}/100)";

            UpsertNode(threatNodeId, GraphNodeType.Threat, label, cluster.Score, cluster.Id, cluster.LastSeen, d =>
            {
                d["clusterId"] = cluster.Id.ToString("D");
                d["dominantType"] = cluster.DominantType.ToString();
                d["eventCount"] = cluster.EventCount.ToString();
                d["escalated"] = cluster.Escalated ? "true" : "false";
                if (!string.IsNullOrWhiteSpace(cluster.ChainName)) d["chainName"] = cluster.ChainName;
                d["justification"] = Truncate(cluster.Justification, 260);
            });

            // Arêtes de corrélation persistées entre événements
            var directPairs = new HashSet<(Guid, Guid)>();
            foreach (var link in cluster.Links)
            {
                if (!includedEventIds.Contains(link.FromEventId) || !includedEventIds.Contains(link.ToEventId))
                    continue;

                AddEdge(
                    $"event:{link.FromEventId:D}",
                    $"event:{link.ToEventId:D}",
                    (GraphEdgeType)link.EdgeType,
                    link.Weight,
                    link.Key);
                directPairs.Add((link.FromEventId, link.ToEventId));
                directPairs.Add((link.ToEventId, link.FromEventId));
            }

            if (eventsByCluster.TryGetValue(cluster.Id, out var clusterEvts))
            {
                for (var i = 0; i < clusterEvts.Count; i++)
                {
                    var cur = clusterEvts[i];
                    AddEdge($"event:{cur.Id:D}", threatNodeId, GraphEdgeType.InvolvedIn, 0.9, "cluster");

                    if (i > 0)
                    {
                        var prev = clusterEvts[i - 1];
                        if (!directPairs.Contains((prev.Id, cur.Id)))
                        {
                            AddEdge($"event:{prev.Id:D}", $"event:{cur.Id:D}", GraphEdgeType.Sequence, 0.4, "SEQUENCE");
                        }
                    }
                }
            }
        }

        var nodeDtos = nodes.Values
            .Select(n => new GraphNodeDto(
                n.Id,
                n.Type,
                n.Label,
                n.Score,
                ThreatLevels.FromScore(n.Score),
                n.ClusterId,
                n.Timestamp,
                n.Data))
            .ToArray();

        var clusterDtos = clusters
            .OrderByDescending(c => c.Score)
            .ThenByDescending(c => c.LastSeenUnixMs)
            .Select(c => c.ToDto())
            .ToArray();

        return new GraphDto(nodeDtos, edges.Values.ToArray(), clusterDtos);
    }

    private static string? GetAttr(Dictionary<string, string> attrs, string key) =>
        attrs.TryGetValue(key, out var val) && !string.IsNullOrWhiteSpace(val) ? val.Trim() : null;

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

    private static string Truncate(string? value, int maxLen)
    {
        if (string.IsNullOrEmpty(value)) return string.Empty;
        return value.Length <= maxLen ? value : value[..(maxLen - 1)] + "…";
    }

    private sealed class MutableNode(
        string id,
        GraphNodeType type,
        string label,
        int score,
        Guid? clusterId,
        DateTimeOffset? timestamp)
    {
        public string Id { get; } = id;
        public GraphNodeType Type { get; } = type;
        public string Label { get; } = label;
        public int Score { get; set; } = score;
        public Guid? ClusterId { get; set; } = clusterId;
        public DateTimeOffset? Timestamp { get; set; } = timestamp;
        public Dictionary<string, string> Data { get; } = new(StringComparer.OrdinalIgnoreCase);
    }
}
