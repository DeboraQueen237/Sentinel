using Microsoft.EntityFrameworkCore;
using Sentinel.Shared.Api;
using Sentinel.Shared.Json;
using Sentinel.Shared.Models;
using Sentinel.Storage;
using Sentinel.Storage.Entities;
using Sentinel.Storage.Mapping;

namespace Sentinel.Server.Services;

/// <summary>
/// Construit un graphe de corrélation hiérarchique lisible en arbre causal :
/// <c>Racine (Poste)</c> → <c>Acteur (Utilisateur / Périphérique)</c> → <c>Vecteur (Processus parent / enfant)</c>
/// → <c>Événement dédupliqué (×N)</c> → <c>Cible (Fichier / Domaine / IP)</c> → <c>Menace / Alerte corrélée</c>,
/// en distinguant les flux causaux directs des flux indirects de corrélation.
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
            var now = DateTimeOffset.UtcNow;
            var effectiveTo = to ?? now.AddMinutes(5);
            var effectiveFrom = from ?? (to?.AddHours(-24) ?? now.AddHours(-24));
            var fromMs = effectiveFrom.ToUnixTimeMilliseconds();
            var toMs = effectiveTo.ToUnixTimeMilliseconds();

            var q = db.Events.AsNoTracking()
                .Where(e => e.TimestampUnixMs >= fromMs && e.TimestampUnixMs <= toMs);

            if (!string.IsNullOrWhiteSpace(hostId))
                q = q.Where(e => e.HostId == hostId.Trim());

            if (minScore is > 0)
                q = q.Where(e => e.Score >= minScore.Value);

            events = await q
                .OrderByDescending(e => e.TimestampUnixMs)
                .ThenByDescending(e => e.Score)
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
        var rawEventIdToAggNodeId = new Dictionary<Guid, string>();

        MutableNode UpsertNode(
            string id,
            GraphNodeType type,
            string label,
            int score,
            int rank,
            Guid? nodeClusterId,
            DateTimeOffset? timestamp,
            Action<Dictionary<string, string>>? enrichData = null)
        {
            if (!nodes.TryGetValue(id, out var node))
            {
                node = new MutableNode(id, type, label, score, rank, nodeClusterId, timestamp);
                node.Data["rank"] = rank.ToString();
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

        // Regroupement intelligent des rafales d'événements identiques (ex. 200 AgentTampering -> 1 seul nœud "×200")
        var groupedEvents = events
            .OrderBy(e => e.TimestampUnixMs)
            .GroupBy(e =>
                $"{e.HostId.Trim().ToLowerInvariant()}|{e.Category}|{e.EventType.Trim().ToLowerInvariant()}|{Truncate(e.Subject, 80).ToLowerInvariant()}|{e.ThreatType}|{e.ClusterId}")
            .ToList();

        var aggIndex = 0;
        foreach (var grp in groupedEvents)
        {
            aggIndex++;
            var representative = grp.OrderByDescending(x => x.Score).ThenByDescending(x => x.TimestampUnixMs).First();
            var firstTs = grp.First().Timestamp;
            var lastTs = grp.Last().Timestamp;
            var occurrences = grp.Count();

            var attrs = DeserializeDict(representative.AttributesJson);
            var mitreList = DeserializeList(representative.MitreTechniquesJson);

            // Conserve l'identifiant event:<guid> lorsqu'unique pour compatibilité totale, sinon event-group
            var eventNodeId = occurrences == 1
                ? $"event:{representative.Id:D}"
                : $"event:{representative.Id:D}";

            foreach (var member in grp)
            {
                rawEventIdToAggNodeId[member.Id] = eventNodeId;
            }

            var baseLabel = $"{representative.EventType}: {Truncate(representative.Subject, 34)}";
            var displayLabel = occurrences > 1 ? $"{baseLabel} (×{occurrences})" : baseLabel;

            UpsertNode(
                eventNodeId,
                GraphNodeType.Event,
                displayLabel,
                representative.Score,
                rank: 3,
                representative.ClusterId,
                lastTs,
                d =>
                {
                    d["eventId"] = representative.Id.ToString("D");
                    d["category"] = ((EventCategory)representative.Category).ToString();
                    d["eventType"] = representative.EventType;
                    d["subject"] = representative.Subject;
                    d["threatType"] = ((ThreatType)representative.ThreatType).ToString();
                    d["occurrences"] = occurrences.ToString();
                    if (occurrences > 1)
                    {
                        d["firstSeen"] = firstTs.ToString("O");
                        d["lastSeen"] = lastTs.ToString("O");
                    }
                    if (mitreList.Count > 0)
                        d["mitre"] = string.Join(",", mitreList);
                    d["justification"] = Truncate(representative.Justification, 240);
                });

            // Niveau 0 : Racine Poste (Host)
            string? upstreamAnchorId = null;
            if (!string.IsNullOrWhiteSpace(representative.HostId))
            {
                var hostTrim = representative.HostId.Trim();
                var hostNodeId = $"host:{hostTrim.ToLowerInvariant()}";
                UpsertNode(hostNodeId, GraphNodeType.Host, hostTrim, Math.Min(representative.Score, 65), rank: 0, null, lastTs,
                    d => d["hostId"] = hostTrim);
                upstreamAnchorId = hostNodeId;
            }

            // Niveau 1 : Branche Acteur (Utilisateur ou Périphérique USB)
            var devId = GetAttr(attrs, AttributeKeys.DeviceId) ?? (representative.Category == (int)EventCategory.Device ? representative.Subject : null);
            if (!string.IsNullOrWhiteSpace(devId))
            {
                var normDev = devId.Trim().ToLowerInvariant();
                var devNodeId = $"device:{normDev}";
                var devLabel = GetAttr(attrs, AttributeKeys.DeviceName) ?? Truncate(devId, 28);
                UpsertNode(devNodeId, GraphNodeType.Device, devLabel, representative.Score, rank: 1, representative.ClusterId, lastTs, d =>
                {
                    d["deviceId"] = devId;
                    if (GetAttr(attrs, AttributeKeys.DeviceClass) is { } cls) d["class"] = cls;
                });
                if (upstreamAnchorId is not null)
                    AddEdge(upstreamAnchorId, devNodeId, GraphEdgeType.InvolvedIn, 0.7, "port USB");
                upstreamAnchorId = devNodeId;
            }
            else if (!string.IsNullOrWhiteSpace(representative.UserId) &&
                     !representative.UserId.Equals("unknown", StringComparison.OrdinalIgnoreCase))
            {
                var userTrim = representative.UserId.Trim();
                var userNodeId = $"user:{userTrim.ToLowerInvariant()}";
                UpsertNode(userNodeId, GraphNodeType.User, userTrim, Math.Min(representative.Score, 50), rank: 1, null, lastTs,
                    d => d["userId"] = userTrim);
                if (upstreamAnchorId is not null)
                    AddEdge(upstreamAnchorId, userNodeId, GraphEdgeType.InvolvedIn, 0.6, "session");
                upstreamAnchorId = userNodeId;
            }

            // Niveau 2 : Branche Processus (Parent -> Enfant)
            var procName = GetAttr(attrs, AttributeKeys.ProcessName);
            var procPath = GetAttr(attrs, AttributeKeys.ProcessPath) ?? (representative.Category == (int)EventCategory.Process ? representative.Subject : null);
            var procKey = !string.IsNullOrWhiteSpace(procPath) ? procPath : procName;

            if (!string.IsNullOrWhiteSpace(procKey))
            {
                var parentName = GetAttr(attrs, AttributeKeys.ParentProcessName);
                var parentPath = GetAttr(attrs, AttributeKeys.ParentProcessPath);
                var parentKey = !string.IsNullOrWhiteSpace(parentPath) ? parentPath : parentName;
                if (!string.IsNullOrWhiteSpace(parentKey))
                {
                    var parentNodeId = $"process:{parentKey.Trim().Replace('/', '\\').ToLowerInvariant()}";
                    var parentLabel = !string.IsNullOrWhiteSpace(parentName) ? parentName : Path.GetFileName(parentKey);
                    UpsertNode(parentNodeId, GraphNodeType.Process, string.IsNullOrWhiteSpace(parentLabel) ? Truncate(parentKey, 28) : parentLabel, Math.Min(representative.Score, 60), rank: 2, representative.ClusterId, lastTs,
                        d => d["path"] = parentKey);
                    if (upstreamAnchorId is not null)
                        AddEdge(upstreamAnchorId, parentNodeId, GraphEdgeType.InvolvedIn, 0.7, "exécute");
                    upstreamAnchorId = parentNodeId;
                }

                var normProc = procKey.Trim().Replace('/', '\\').ToLowerInvariant();
                var procLabel = !string.IsNullOrWhiteSpace(procName) ? procName : Path.GetFileName(procKey);
                var procNodeId = $"process:{normProc}";
                UpsertNode(procNodeId, GraphNodeType.Process, string.IsNullOrWhiteSpace(procLabel) ? Truncate(procKey, 28) : procLabel, representative.Score, rank: 2, representative.ClusterId, lastTs, d =>
                {
                    d["path"] = procKey;
                    if (GetAttr(attrs, AttributeKeys.ProcessId) is { } pid) d["pid"] = pid;
                    if (GetAttr(attrs, AttributeKeys.Sha256) is { } sha) d["sha256"] = sha;
                    if (GetAttr(attrs, AttributeKeys.Signed) is { } signed) d["signed"] = signed;
                });

                if (upstreamAnchorId is not null)
                {
                    var isParentProc = upstreamAnchorId.StartsWith("process:", StringComparison.OrdinalIgnoreCase);
                    AddEdge(upstreamAnchorId, procNodeId, isParentProc ? GraphEdgeType.Spawned : GraphEdgeType.InvolvedIn, 0.85, isParentProc ? "lance" : "exécute");
                }
                upstreamAnchorId = procNodeId;
            }

            // Relie la branche amont vers le nœud Événement (flux direct)
            if (upstreamAnchorId is not null)
            {
                AddEdge(upstreamAnchorId, eventNodeId, GraphEdgeType.InvolvedIn, 0.85, "déclenche");
            }

            // Niveau 4 : Cibles aval de l'événement (Fichier, Domaine, IP)
            string? downstreamLeafId = eventNodeId;

            var filePath = GetAttr(attrs, AttributeKeys.FilePath)
                           ?? GetAttr(attrs, AttributeKeys.FileName)
                           ?? (representative.Category is (int)EventCategory.File or (int)EventCategory.Canary ? representative.Subject : null);
            if (!string.IsNullOrWhiteSpace(filePath))
            {
                var normFile = filePath.Trim().Replace('/', '\\').ToLowerInvariant();
                var fileNodeId = $"file:{normFile}";
                var fileLabel = Path.GetFileName(filePath);
                UpsertNode(fileNodeId, GraphNodeType.File, string.IsNullOrWhiteSpace(fileLabel) ? Truncate(filePath, 28) : fileLabel, representative.Score, rank: 4, representative.ClusterId, lastTs, d =>
                {
                    d["path"] = filePath;
                    if (GetAttr(attrs, AttributeKeys.Sha256) is { } sha) d["sha256"] = sha;
                    if (GetAttr(attrs, AttributeKeys.Entropy) is { } ent) d["entropy"] = ent;
                });
                AddEdge(eventNodeId, fileNodeId, GraphEdgeType.Wrote, 0.85, "modifie");
                downstreamLeafId = fileNodeId;
            }

            var domain = GetAttr(attrs, AttributeKeys.Domain)
                         ?? ActionPolicyHelper.TryExtractDomain(GetAttr(attrs, AttributeKeys.Url))
                         ?? (representative.Category is (int)EventCategory.Browser or (int)EventCategory.Clipboard or (int)EventCategory.Network
                             ? ActionPolicyHelper.TryExtractDomain(representative.Subject)
                             : null);
            if (!string.IsNullOrWhiteSpace(domain))
            {
                var normDom = domain.Trim().ToLowerInvariant();
                var domNodeId = $"domain:{normDom}";
                UpsertNode(domNodeId, GraphNodeType.Domain, normDom, representative.Score, rank: 4, representative.ClusterId, lastTs, d =>
                {
                    d["domain"] = normDom;
                    if (GetAttr(attrs, AttributeKeys.Url) is { } url) d["url"] = url;
                });

                var (edgeType, verb) = (EventCategory)representative.Category switch
                {
                    EventCategory.Clipboard => (GraphEdgeType.CopiedFromClipboard, "copie URL"),
                    EventCategory.Browser => (GraphEdgeType.OpenedUrl, "visite"),
                    EventCategory.Network => (GraphEdgeType.ConnectedTo, "résout DNS"),
                    _ => (GraphEdgeType.SameDomain, "cible")
                };
                AddEdge(eventNodeId, domNodeId, edgeType, 0.85, verb);
                downstreamLeafId = domNodeId;
            }

            var ip = GetAttr(attrs, AttributeKeys.RemoteIp) ?? GetAttr(attrs, AttributeKeys.SourceIp);
            if (!string.IsNullOrWhiteSpace(ip))
            {
                var normIp = ip.Trim();
                var portSuffix = GetAttr(attrs, AttributeKeys.RemotePort) is { } rp ? $":{rp}" : string.Empty;
                var ipNodeId = $"ip:{normIp}";
                UpsertNode(ipNodeId, GraphNodeType.Ip, normIp + portSuffix, representative.Score, rank: 4, representative.ClusterId, lastTs, d =>
                {
                    d["ip"] = normIp;
                    if (GetAttr(attrs, AttributeKeys.RemotePort) is { } port) d["port"] = port;
                });
                AddEdge(downstreamLeafId != eventNodeId && downstreamLeafId!.StartsWith("domain:", StringComparison.Ordinal) ? downstreamLeafId : eventNodeId,
                    ipNodeId, GraphEdgeType.ConnectedTo, 0.88, "connecte");
                downstreamLeafId = ipNodeId;
            }

            representative.AttributesJson = downstreamLeafId; // mémorisation temporaire du nœud aval pour liaison au cluster
            grp.Key.ToString();
        }

        // Niveau 5 : Nœuds Menace / Alerte corrélée + Flux indirects de corrélation entre étapes distinctes
        foreach (var cluster in clusters)
        {
            var threatNodeId = $"threat:{cluster.Id:D}";
            var clusterMitre = DeserializeList(cluster.MitreTechniquesJson);
            var label = !string.IsNullOrWhiteSpace(cluster.ChainName)
                ? cluster.ChainName
                : $"{ActionPolicyHelper.ThreatTypeLabel(cluster.DominantType)} ({cluster.Score}/100)";

            UpsertNode(threatNodeId, GraphNodeType.Threat, label, cluster.Score, rank: 5, cluster.Id, cluster.LastSeen, d =>
            {
                d["clusterId"] = cluster.Id.ToString("D");
                d["dominantType"] = cluster.DominantType.ToString();
                d["eventCount"] = cluster.EventCount.ToString();
                d["escalated"] = cluster.Escalated ? "true" : "false";
                if (!string.IsNullOrWhiteSpace(cluster.ChainName)) d["chainName"] = cluster.ChainName;
                if (clusterMitre.Count > 0) d["mitre"] = string.Join(",", clusterMitre);
                d["justification"] = Truncate(cluster.Justification, 260);
            });

            // Relie les étapes dédupliquées du cluster dans l'ordre chronologique (flux indirects de corrélation)
            var distinctAggNodes = events
                .Where(e => e.ClusterId == cluster.Id && rawEventIdToAggNodeId.ContainsKey(e.Id))
                .OrderBy(e => e.TimestampUnixMs)
                .Select(e => (AggId: rawEventIdToAggNodeId[e.Id], LeafId: e.AttributesJson ?? rawEventIdToAggNodeId[e.Id]))
                .DistinctBy(x => x.AggId)
                .ToList();

            for (var i = 0; i < distinctAggNodes.Count; i++)
            {
                var step = distinctAggNodes[i];
                var sourceForThreat = !string.IsNullOrWhiteSpace(step.LeafId) && nodes.ContainsKey(step.LeafId)
                    ? step.LeafId
                    : step.AggId;
                AddEdge(sourceForThreat, threatNodeId, GraphEdgeType.InvolvedIn, 0.9, "corrélé → alerte");

                if (i > 0)
                {
                    var prevAgg = distinctAggNodes[i - 1].AggId;
                    AddEdge(prevAgg, step.AggId, GraphEdgeType.Sequence, 0.55, $"étape {i}→{i + 1}");
                }
            }

            // Liens explicites persistés entre groupes d'événements distincts
            foreach (var link in cluster.Links)
            {
                if (!rawEventIdToAggNodeId.TryGetValue(link.FromEventId, out var fromAgg) ||
                    !rawEventIdToAggNodeId.TryGetValue(link.ToEventId, out var toAgg) ||
                    string.Equals(fromAgg, toAgg, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                AddEdge(fromAgg, toAgg, (GraphEdgeType)link.EdgeType, link.Weight, Truncate(link.Key, 24));
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

    private static List<string> DeserializeList(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return [];
        try { return SentinelJson.Deserialize<List<string>>(json) ?? []; }
        catch { return []; }
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
        int rank,
        Guid? clusterId,
        DateTimeOffset? timestamp)
    {
        public string Id { get; } = id;
        public GraphNodeType Type { get; } = type;
        public string Label { get; } = label;
        public int Score { get; set; } = score;
        public int Rank { get; } = rank;
        public Guid? ClusterId { get; set; } = clusterId;
        public DateTimeOffset? Timestamp { get; set; } = timestamp;
        public Dictionary<string, string> Data { get; } = new(StringComparer.OrdinalIgnoreCase);
    }
}
