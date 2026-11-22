using Sentinel.Core.Enrichment;
using Sentinel.Shared.Models;

namespace Sentinel.Core.Correlation;

/// <summary>Résultat de corrélation incluant le cluster mis à jour et les événements associés.</summary>
public sealed record CorrelationOutput(
    CorrelationCluster Cluster,
    IReadOnlyList<SecurityEvent> ClusterEvents);

/// <summary>
/// Moteur de corrélation par fenêtres glissantes et composantes connexes (doc §8, exigences F4 &amp; F5).
/// Utilise exclusivement <see cref="SecurityEvent.Timestamp"/> pour l'exactitude en temps réel comme en rejeu accéléré.
/// </summary>
public sealed class CorrelationEngine
{
    public const int MaxIndexedEvents = 50_000;
    public const int MaxActiveClusters = 2_000;
    private const int MaxEventsPerCluster = 200;
    private const int MaxNeighborsPerKey = 20;
    private const int MaxLinksPerEvent = 12;

    private readonly object _gate = new();
    private readonly Dictionary<Guid, CorrelatedNode> _nodes = new();
    private readonly Dictionary<string, List<Guid>> _keyIndex = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<Guid, MutableCluster> _clusters = new();
    private readonly AttackChainMarkovModel _markov;

    private DateTimeOffset _latestTimestamp = DateTimeOffset.MinValue;
    private int _insertionsSinceCleanup;

    public CorrelationEngine(AttackChainMarkovModel? markov = null)
    {
        _markov = markov ?? new AttackChainMarkovModel();
    }

    public AttackChainMarkovModel MarkovModel => _markov;

    public int ActiveClusterCount
    {
        get
        {
            lock (_gate) return _clusters.Count;
        }
    }

    public int IndexedEventCount
    {
        get
        {
            lock (_gate) return _nodes.Count;
        }
    }

    /// <summary>
    /// Corrèle un événement scoré avec les événements voisins dans les fenêtres configurées.
    /// Retourne <c>null</c> si la corrélation est désactivée, si le score est inférieur à <c>MinEventScore</c>,
    /// ou si l'événement est encore isolé (1 seul événement dans son contexte).
    /// </summary>
    public CorrelationOutput? Correlate(
        EnrichedEvent enriched,
        ThreatAssessment assessment,
        SentinelSettings settings)
    {
        ArgumentNullException.ThrowIfNull(enriched);
        ArgumentNullException.ThrowIfNull(assessment);
        ArgumentNullException.ThrowIfNull(settings);

        var cfg = settings.Correlation;
        if (!cfg.Enabled || assessment.Score < cfg.MinEventScore)
        {
            return null;
        }

        var keys = ExtractContextKeys(enriched, assessment);
        var node = new CorrelatedNode
        {
            Enriched = enriched,
            Assessment = assessment,
            Keys = keys
        };

        lock (_gate)
        {
            if (_nodes.ContainsKey(node.Id))
            {
                return null;
            }

            if (node.Timestamp > _latestTimestamp)
            {
                _latestTimestamp = node.Timestamp;
            }

            // Nettoyage périodique ou en cas de dépassement des bornes mémoire
            _insertionsSinceCleanup++;
            if (_insertionsSinceCleanup >= 256 || _nodes.Count >= MaxIndexedEvents || _clusters.Count >= MaxActiveClusters)
            {
                CleanupExpiredLocked(cfg);
                EnforceMemoryCapsLocked();
                _insertionsSinceCleanup = 0;
            }

            // Recherche des voisins éligibles dans les fenêtres glissantes (Short / Medium / Long)
            var matchedNeighbors = new Dictionary<Guid, (CorrelatedNode Node, CorrelationLink BestLink)>();

            foreach (var keyInfo in keys)
            {
                if (!_keyIndex.TryGetValue(keyInfo.Key, out var bucket) || bucket.Count == 0)
                {
                    continue;
                }

                var maxWindow = GetWindowDuration(keyInfo.Window, cfg);
                var inspected = 0;

                for (var i = bucket.Count - 1; i >= 0 && inspected < MaxNeighborsPerKey; i--)
                {
                    var neighborId = bucket[i];
                    if (!_nodes.TryGetValue(neighborId, out var neighbor))
                    {
                        bucket.RemoveAt(i);
                        continue;
                    }

                    // Strictement même poste
                    if (!neighbor.Event.HostId.Equals(node.Event.HostId, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    var delta = (node.Timestamp - neighbor.Timestamp).Duration();
                    if (delta > maxWindow)
                    {
                        continue;
                    }

                    inspected++;
                    var edgeType = ResolveEdgeType(neighbor, node, keyInfo);
                    var weight = keyInfo.IsEntityKey ? cfg.SameEntityWeight : cfg.SameTypeWeight;
                    var link = new CorrelationLink(neighbor.Id, node.Id, edgeType, weight, keyInfo.Key)
                    {
                        ObservedAt = node.Timestamp
                    };

                    if (!matchedNeighbors.TryGetValue(neighborId, out var existing) || link.Weight > existing.BestLink.Weight)
                    {
                        matchedNeighbors[neighborId] = (neighbor, link);
                    }
                }
            }

            // Indexation du nouvel événement
            _nodes[node.Id] = node;
            foreach (var keyInfo in keys)
            {
                if (!_keyIndex.TryGetValue(keyInfo.Key, out var bucket))
                {
                    bucket = new List<Guid>(4);
                    _keyIndex[keyInfo.Key] = bucket;
                }
                bucket.Add(node.Id);
            }

            if (matchedNeighbors.Count == 0)
            {
                // Premier événement isolé : indexé pour corrélation future, pas encore de cluster
                return null;
            }

            // Sélection des liens les plus pertinents (bornés pour performance)
            var topNeighbors = matchedNeighbors.Values
                .OrderByDescending(x => x.BestLink.Weight)
                .ThenByDescending(x => x.Node.Timestamp)
                .Take(MaxLinksPerEvent)
                .ToList();

            // Fusion / création de composante connexe (cluster)
            var targetCluster = MergeOrCreateClusterLocked(node, topNeighbors);

            // Recalcul exact du score, des chaînes d'attaque et de l'escalade précoce
            var snapshot = RecomputeClusterSnapshot(targetCluster, settings);
            targetCluster.Snapshot = snapshot;

            var events = targetCluster.Nodes
                .OrderBy(n => n.Timestamp)
                .Select(n => n.Event)
                .ToArray();

            return new CorrelationOutput(snapshot, events);
        }
    }

    public IReadOnlyList<CorrelationCluster> GetActiveClusters(string? hostId = null)
    {
        lock (_gate)
        {
            IEnumerable<MutableCluster> query = _clusters.Values;
            if (!string.IsNullOrWhiteSpace(hostId))
            {
                query = query.Where(c => c.HostId.Equals(hostId, StringComparison.OrdinalIgnoreCase));
            }
            return query
                .Where(c => c.Snapshot is not null)
                .OrderByDescending(c => c.Snapshot!.Score)
                .ThenByDescending(c => c.Snapshot!.LastSeen)
                .Select(c => c.Snapshot!)
                .ToArray();
        }
    }

    public CorrelationCluster? GetCluster(Guid clusterId)
    {
        lock (_gate)
        {
            return _clusters.TryGetValue(clusterId, out var c) ? c.Snapshot : null;
        }
    }

    public IReadOnlyList<SecurityEvent> GetClusterEvents(Guid clusterId)
    {
        lock (_gate)
        {
            if (!_clusters.TryGetValue(clusterId, out var c)) return Array.Empty<SecurityEvent>();
            return c.Nodes.OrderBy(n => n.Timestamp).Select(n => n.Event).ToArray();
        }
    }

    private MutableCluster MergeOrCreateClusterLocked(
        CorrelatedNode newNode,
        List<(CorrelatedNode Node, CorrelationLink BestLink)> neighbors)
    {
        // Identifier tous les clusters existants touchés par les voisins
        var existingClusterIds = neighbors
            .Where(x => x.Node.ClusterId.HasValue && _clusters.ContainsKey(x.Node.ClusterId.Value))
            .Select(x => x.Node.ClusterId!.Value)
            .Distinct()
            .ToList();

        MutableCluster primary;
        if (existingClusterIds.Count == 0)
        {
            primary = new MutableCluster(Guid.NewGuid(), newNode.Event.HostId);
            _clusters[primary.Id] = primary;
        }
        else
        {
            // Conserver le cluster le plus ancien comme cluster principal
            primary = existingClusterIds
                .Select(id => _clusters[id])
                .OrderBy(c => c.FirstSeen)
                .First();

            // Fusionner les autres composantes connexes dans le cluster principal
            foreach (var otherId in existingClusterIds)
            {
                if (otherId == primary.Id) continue;
                if (!_clusters.TryGetValue(otherId, out var other)) continue;

                foreach (var n in other.Nodes)
                {
                    AddNodeToCluster(primary, n);
                }
                foreach (var l in other.Links)
                {
                    primary.AddLink(l);
                }
                foreach (var ck in other.SharedKeys)
                {
                    primary.SharedKeys.Add(ck);
                }
                _clusters.Remove(otherId);
            }
        }

        // Ajouter les voisins encore hors cluster
        foreach (var (neighbor, link) in neighbors)
        {
            if (neighbor.ClusterId != primary.Id)
            {
                AddNodeToCluster(primary, neighbor);
            }
            primary.AddLink(link);
            primary.SharedKeys.Add(link.Key);
        }

        // Ajouter le nouvel événement
        AddNodeToCluster(primary, newNode);

        return primary;
    }

    private static void AddNodeToCluster(MutableCluster cluster, CorrelatedNode node)
    {
        if (cluster.NodeIds.Contains(node.Id))
        {
            node.ClusterId = cluster.Id;
            return;
        }

        if (cluster.Nodes.Count >= MaxEventsPerCluster)
        {
            // Éviction du nœud le plus ancien pour garder le cluster borné
            var oldest = cluster.Nodes[0];
            cluster.Nodes.RemoveAt(0);
            cluster.NodeIds.Remove(oldest.Id);
            oldest.ClusterId = null;
        }

        cluster.Nodes.Add(node);
        cluster.NodeIds.Add(node.Id);
        node.ClusterId = cluster.Id;

        if (node.Timestamp < cluster.FirstSeen) cluster.FirstSeen = node.Timestamp;
        if (node.Timestamp > cluster.LastSeen) cluster.LastSeen = node.Timestamp;
    }

    private CorrelationCluster RecomputeClusterSnapshot(MutableCluster cluster, SentinelSettings settings)
    {
        var cfg = settings.Correlation;
        var thresholds = settings.Thresholds;

        var orderedNodes = cluster.Nodes
            .OrderBy(n => n.Timestamp)
            .ToList();

        // Nœud au score individuel maximal (départage : événement le plus récent)
        var maxNode = orderedNodes[0];
        for (var i = 1; i < orderedNodes.Count; i++)
        {
            if (orderedNodes[i].Assessment.Score >= maxNode.Assessment.Score)
            {
                maxNode = orderedNodes[i];
            }
        }

        var maxEventScore = maxNode.Assessment.Score;
        var halfLife = Math.Max(0.1, cfg.DecayHalfLifeMinutes);

        // Poids maximal des liens pour chaque nœud (direct vers maxNode si relié, sinon max des liens incidents)
        var maxWeightByNode = new Dictionary<Guid, double>(orderedNodes.Count);
        foreach (var link in cluster.Links)
        {
            UpdateMaxWeight(maxWeightByNode, link.FromEventId, link.Weight);
            UpdateMaxWeight(maxWeightByNode, link.ToEventId, link.Weight);
        }

        // Formule EXACTE §8.2 :
        // ScoreCluster = min(100, round(max(score_i) + Σ_{j ≠ max} (score_j × poids_lien × facteur_temps) + bonus_séquence))
        // avec facteur_temps = 2^(-Δt_minutes / DecayHalfLifeMinutes)
        var contributionSum = 0.0;
        for (var i = 0; i < orderedNodes.Count; i++)
        {
            var n = orderedNodes[i];
            if (n.Id == maxNode.Id) continue;

            var linkWeight = maxWeightByNode.TryGetValue(n.Id, out var w) ? w : cfg.SameTypeWeight;
            var deltaMinutes = Math.Abs((maxNode.Timestamp - n.Timestamp).TotalMinutes);
            var timeFactor = Math.Pow(2.0, -deltaMinutes / halfLife);
            contributionSum += n.Assessment.Score * linkWeight * timeFactor;
        }

        // Détection des 7 chaînes d'attaque modélisées (§8.3) + modèle probabiliste Markov (v2 M8)
        var chainMatch = AttackChainMatcher.MatchBest(orderedNodes);
        var categorySequence = orderedNodes.Select(n => n.Event.Category).ToArray();
        var chainProbability = _markov.EstimateChainProbability(categorySequence);
        var markovBonus = _markov.ComputeSequenceBonus(chainProbability, orderedNodes.Count, chainMatch is not null);
        var sequenceBonus = (chainMatch?.Bonus ?? 0) + markovBonus;

        var formulaScore = Math.Clamp((int)Math.Round(maxEventScore + contributionSum + sequenceBonus), 0, 100);
        var baseLevel = thresholds.LevelOf(formulaScore);
        var finalScore = formulaScore;
        var finalLevel = baseLevel;
        var escalated = false;

        // Règle d'escalade précoce (§8.2-5) : dès le 2ᵉ événement similaire dans un même contexte
        if (cfg.EarlyEscalation && HasSimilarEventsInSameContext(orderedNodes, cluster.Links, cfg))
        {
            var raised = ThreatLevels.Raise(baseLevel);
            if (raised > baseLevel)
            {
                finalLevel = raised;
                finalScore = Math.Max(formulaScore, MinScoreForLevel(raised, thresholds));
                escalated = true;
            }
        }

        var dominantType = DetermineDominantType(orderedNodes, chainMatch);
        var mitre = orderedNodes
            .SelectMany(n => n.Assessment.MitreTechniques)
            .Concat(chainMatch?.MitreTechniques ?? Array.Empty<string>())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var tactics = ClusterNarrativeBuilder.ExtractMitreTactics(mitre);
        var contributions = ClusterNarrativeBuilder.AggregateContributions(orderedNodes, chainMatch, chainProbability, markovBonus);

        var contextKeys = cluster.SharedKeys
            .Select(FormatDisplayKey)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(12)
            .ToArray();

        var justification = BuildClusterJustification(
            cluster.HostId,
            orderedNodes.Count,
            maxEventScore,
            finalScore,
            finalLevel,
            chainMatch,
            contextKeys,
            escalated);

        var narrative = ClusterNarrativeBuilder.BuildNarrative(
            cluster.HostId,
            orderedNodes,
            chainMatch,
            chainProbability,
            tactics,
            finalScore,
            escalated);

        return new CorrelationCluster
        {
            Id = cluster.Id,
            HostId = cluster.HostId,
            FirstSeen = orderedNodes[0].Timestamp,
            LastSeen = orderedNodes[^1].Timestamp,
            Score = finalScore,
            Level = finalLevel,
            DominantType = dominantType,
            EventIds = orderedNodes.Select(n => n.Id).ToArray(),
            Links = cluster.Links.ToArray(),
            ContextKeys = contextKeys,
            Chain = chainMatch,
            Escalated = escalated,
            MaxEventScore = maxEventScore,
            Justification = justification,
            MitreTechniques = mitre,
            MitreTactics = tactics,
            Narrative = narrative,
            ChainProbability = chainProbability,
            ScoreContributions = contributions
        };
    }

    private static bool HasSimilarEventsInSameContext(
        List<CorrelatedNode> orderedNodes,
        List<CorrelationLink> links,
        CorrelationSettings cfg)
    {
        if (orderedNodes.Count < 2) return false;

        // 1. Lien d'entité partagée (même domaine, hash, PID/parent, fichier, URL, IP, périphérique...)
        for (var i = 0; i < links.Count; i++)
        {
            if (links[i].Weight >= cfg.SameEntityWeight - 1e-6 ||
                links[i].Type is GraphEdgeType.SameDomain or GraphEdgeType.SameHash or GraphEdgeType.SameEntity
                    or GraphEdgeType.Spawned or GraphEdgeType.Wrote or GraphEdgeType.CopiedFromClipboard
                    or GraphEdgeType.OpenedUrl or GraphEdgeType.ConnectedTo)
            {
                return true;
            }
        }

        // 2. Au moins 2 événements partageant le même type de menace (non None) dans la fenêtre
        var seenTypes = new HashSet<ThreatType>();
        for (var i = 0; i < orderedNodes.Count; i++)
        {
            var t = orderedNodes[i].Assessment.Type;
            if (t == ThreatType.None) continue;
            if (!seenTypes.Add(t)) return true;
        }

        return false;
    }

    private static ThreatType DetermineDominantType(List<CorrelatedNode> nodes, AttackChainMatch? chain)
    {
        if (nodes.Any(n => n.Assessment.Type == ThreatType.Tampering)) return ThreatType.Tampering;
        if (nodes.Any(n => n.Assessment.Type == ThreatType.Ransomware && n.Assessment.Score >= 65)) return ThreatType.Ransomware;
        if (chain is not null) return chain.Type;

        return nodes
            .Where(n => n.Assessment.Type != ThreatType.None)
            .GroupBy(n => n.Assessment.Type)
            .OrderByDescending(g => g.Sum(n => n.Assessment.Score))
            .ThenByDescending(g => g.Max(n => n.Assessment.Score))
            .Select(g => g.Key)
            .FirstOrDefault();
    }

    private static string BuildClusterJustification(
        string hostId,
        int eventCount,
        int maxEventScore,
        int clusterScore,
        ThreatLevel level,
        AttackChainMatch? chain,
        IReadOnlyList<string> contextKeys,
        bool escalated)
    {
        var parts = new List<string>(4)
        {
            $"Cluster de {eventCount} événements corrélés sur {hostId} (score max individuel : {maxEventScore}/100 → score corrélé : {clusterScore}/100, niveau {ThreatLevels.Label(level)})"
        };

        if (chain is not null)
        {
            parts.Add($"Chaîne détectée : {chain.Name} ({chain.StepsMatched}/{chain.TotalSteps} étapes, bonus +{chain.Bonus})");
        }

        if (escalated)
        {
            parts.Add("Escalade précoce appliquée (+1 niveau dès le 2ᵉ événement similaire)");
        }

        if (contextKeys.Count > 0)
        {
            parts.Add($"Contexte partagé : {string.Join(", ", contextKeys.Take(4))}");
        }

        return string.Join(". ", parts) + ".";
    }

    private static List<ContextKeyInfo> ExtractContextKeys(EnrichedEvent e, ThreatAssessment assessment)
    {
        var evt = e.Event;
        var host = (evt.HostId ?? string.Empty).Trim().ToLowerInvariant();
        var keys = new List<ContextKeyInfo>(8);
        var dedup = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Add(string key, GraphEdgeType edgeType, bool isEntity, ContextWindowKind window)
        {
            if (dedup.Add(key))
            {
                keys.Add(new ContextKeyInfo(key, edgeType, isEntity, window));
            }
        }

        if (!string.IsNullOrWhiteSpace(e.Domain))
        {
            Add($"domain:{host}:{e.Domain}", GraphEdgeType.SameDomain, true, ContextWindowKind.Long);
        }

        if (!string.IsNullOrWhiteSpace(e.Url))
        {
            var normUrl = e.Url.Trim().TrimEnd('/').ToLowerInvariant();
            Add($"url:{host}:{normUrl}", GraphEdgeType.OpenedUrl, true, ContextWindowKind.Medium);
        }

        if (!string.IsNullOrWhiteSpace(e.Sha256))
        {
            Add($"hash:{host}:{e.Sha256.Trim().ToLowerInvariant()}", GraphEdgeType.SameHash, true, ContextWindowKind.Long);
        }

        var pid = evt.Attr(AttributeKeys.ProcessId);
        if (!string.IsNullOrWhiteSpace(pid))
        {
            Add($"pid:{host}:{pid.Trim()}", GraphEdgeType.SameEntity, true, ContextWindowKind.Medium);
        }

        var parentPid = evt.Attr(AttributeKeys.ParentProcessId);
        if (!string.IsNullOrWhiteSpace(parentPid))
        {
            Add($"pid:{host}:{parentPid.Trim()}", GraphEdgeType.Spawned, true, ContextWindowKind.Medium);
        }

        var filePath = e.FilePath ?? e.ProcessPath;
        if (!string.IsNullOrWhiteSpace(filePath))
        {
            var normPath = filePath.Trim().Replace('/', '\\').ToLowerInvariant();
            Add($"file:{host}:{normPath}", GraphEdgeType.Wrote, true, ContextWindowKind.Medium);
        }

        if (!string.IsNullOrWhiteSpace(e.FileName) && e.FileName.Contains('.'))
        {
            var normName = e.FileName.Trim().ToLowerInvariant();
            // Évite les noms de binaires système trop génériques comme clé de fichier
            if (!ThreatIndicators.IsLolBin(normName))
            {
                Add($"filename:{host}:{normName}", GraphEdgeType.Wrote, true, ContextWindowKind.Medium);
            }
        }

        if (!string.IsNullOrWhiteSpace(e.RemoteIp))
        {
            Add($"ip:{host}:{e.RemoteIp.Trim()}", GraphEdgeType.ConnectedTo, true, ContextWindowKind.Long);
        }

        var deviceId = evt.Attr(AttributeKeys.DeviceId);
        if (!string.IsNullOrWhiteSpace(deviceId))
        {
            Add($"device:{host}:{deviceId.Trim().ToLowerInvariant()}", GraphEdgeType.SameEntity, true, ContextWindowKind.Medium);
        }

        var tabId = evt.Attr(AttributeKeys.TabId);
        if (!string.IsNullOrWhiteSpace(tabId))
        {
            Add($"tab:{host}:{tabId.Trim().ToLowerInvariant()}", GraphEdgeType.OpenedUrl, true, ContextWindowKind.Short);
        }

        // Indices explicites de corrélation transmis par les collecteurs
        if (!string.IsNullOrWhiteSpace(evt.CorrelationHints))
        {
            var tokens = evt.CorrelationHints.Split([',', ';', '|'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            foreach (var token in tokens)
            {
                if (token.Length is < 2 or > 160) continue;
                Add($"hint:{host}:{token.ToLowerInvariant()}", GraphEdgeType.SameEntity, true, ContextWindowKind.Medium);
            }
        }

        // Clé d'anomalie (même type de menace dans la fenêtre moyenne)
        if (assessment.Type != ThreatType.None)
        {
            Add($"type:{host}:{assessment.Type}", GraphEdgeType.SameAnomalyType, false, ContextWindowKind.Medium);
        }

        // Clé fenêtre courte par couple (poste, utilisateur) pour chaîner les attaques multi-catégories
        var user = (evt.UserId ?? string.Empty).Trim().ToLowerInvariant();
        Add($"user:{host}:{user}", GraphEdgeType.SameWindow, false, ContextWindowKind.Short);

        return keys;
    }

    private static GraphEdgeType ResolveEdgeType(CorrelatedNode from, CorrelatedNode to, ContextKeyInfo keyInfo)
    {
        if (keyInfo.Key.StartsWith("pid:", StringComparison.OrdinalIgnoreCase))
        {
            var fromPid = from.Event.Attr(AttributeKeys.ProcessId);
            var toParentPid = to.Event.Attr(AttributeKeys.ParentProcessId);
            if (!string.IsNullOrEmpty(fromPid) && string.Equals(fromPid, toParentPid, StringComparison.OrdinalIgnoreCase))
            {
                return GraphEdgeType.Spawned;
            }
            return GraphEdgeType.SameEntity;
        }

        if (keyInfo.Key.StartsWith("url:", StringComparison.OrdinalIgnoreCase) ||
            keyInfo.Key.StartsWith("domain:", StringComparison.OrdinalIgnoreCase))
        {
            if (from.Event.Category == EventCategory.Clipboard && to.Event.Category == EventCategory.Browser)
                return GraphEdgeType.CopiedFromClipboard;
            if (from.Event.Category == EventCategory.Browser && to.Event.Category is EventCategory.File or EventCategory.Network)
                return GraphEdgeType.OpenedUrl;
            if (to.Event.Category == EventCategory.Network || from.Event.Category == EventCategory.Network)
                return GraphEdgeType.ConnectedTo;
            return GraphEdgeType.SameDomain;
        }

        if (keyInfo.Key.StartsWith("file:", StringComparison.OrdinalIgnoreCase) ||
            keyInfo.Key.StartsWith("filename:", StringComparison.OrdinalIgnoreCase))
        {
            if (from.Event.Category is EventCategory.File or EventCategory.Browser &&
                to.Event.Category == EventCategory.Process)
            {
                return GraphEdgeType.Wrote;
            }
            return GraphEdgeType.SameEntity;
        }

        return keyInfo.DefaultEdgeType;
    }

    private static TimeSpan GetWindowDuration(ContextWindowKind window, CorrelationSettings cfg) => window switch
    {
        ContextWindowKind.Short => TimeSpan.FromMinutes(Math.Max(1, cfg.ShortWindowMinutes)),
        ContextWindowKind.Medium => TimeSpan.FromMinutes(Math.Max(1, cfg.MediumWindowMinutes)),
        ContextWindowKind.Long => TimeSpan.FromHours(Math.Max(1, cfg.LongWindowHours)),
        _ => TimeSpan.FromMinutes(30)
    };

    private static int MinScoreForLevel(ThreatLevel level, ThreatThresholds t) => level switch
    {
        ThreatLevel.Critical => t.Critical,
        ThreatLevel.High => t.High,
        ThreatLevel.Moderate => t.Moderate,
        ThreatLevel.Low => t.Low,
        _ => 0
    };

    private static void UpdateMaxWeight(Dictionary<Guid, double> map, Guid id, double weight)
    {
        if (!map.TryGetValue(id, out var existing) || weight > existing)
        {
            map[id] = weight;
        }
    }

    private static string FormatDisplayKey(string internalKey)
    {
        // "domain:host1:evil.xyz" -> "domain:evil.xyz"
        var firstColon = internalKey.IndexOf(':');
        if (firstColon < 0) return internalKey;
        var secondColon = internalKey.IndexOf(':', firstColon + 1);
        if (secondColon < 0) return internalKey;
        return string.Concat(internalKey.AsSpan(0, firstColon + 1), internalKey.AsSpan(secondColon + 1));
    }

    private void CleanupExpiredLocked(CorrelationSettings cfg)
    {
        if (_latestTimestamp == DateTimeOffset.MinValue) return;
        var cutoff = _latestTimestamp - TimeSpan.FromHours(Math.Max(1, cfg.LongWindowHours));

        var expiredNodeIds = new List<Guid>();
        foreach (var kv in _nodes)
        {
            if (kv.Value.Timestamp < cutoff)
            {
                expiredNodeIds.Add(kv.Key);
            }
        }

        foreach (var id in expiredNodeIds)
        {
            _nodes.Remove(id);
        }

        var expiredClusters = new List<Guid>();
        foreach (var kv in _clusters)
        {
            if (kv.Value.LastSeen < cutoff)
            {
                expiredClusters.Add(kv.Key);
            }
        }

        foreach (var cid in expiredClusters)
        {
            _clusters.Remove(cid);
        }

        // Purge les listes de clés vides ou périmées
        if (expiredNodeIds.Count > 0)
        {
            var emptyKeys = new List<string>();
            foreach (var kv in _keyIndex)
            {
                kv.Value.RemoveAll(id => !_nodes.ContainsKey(id));
                if (kv.Value.Count == 0) emptyKeys.Add(kv.Key);
            }
            foreach (var k in emptyKeys) _keyIndex.Remove(k);
        }
    }

    private void EnforceMemoryCapsLocked()
    {
        if (_clusters.Count > MaxActiveClusters)
        {
            var toRemove = _clusters.Count - MaxActiveClusters + (MaxActiveClusters / 10);
            var oldestClusters = _clusters.Values
                .OrderBy(c => c.LastSeen)
                .Take(toRemove)
                .Select(c => c.Id)
                .ToList();

            foreach (var cid in oldestClusters)
            {
                _clusters.Remove(cid);
            }
        }

        if (_nodes.Count > MaxIndexedEvents)
        {
            var toRemove = _nodes.Count - MaxIndexedEvents + (MaxIndexedEvents / 10);
            var oldestNodes = _nodes.Values
                .OrderBy(n => n.Timestamp)
                .Take(toRemove)
                .Select(n => n.Id)
                .ToList();

            foreach (var nid in oldestNodes)
            {
                _nodes.Remove(nid);
            }

            var emptyKeys = new List<string>();
            foreach (var kv in _keyIndex)
            {
                kv.Value.RemoveAll(id => !_nodes.ContainsKey(id));
                if (kv.Value.Count == 0) emptyKeys.Add(kv.Key);
            }
            foreach (var k in emptyKeys) _keyIndex.Remove(k);
        }
    }

    private sealed class MutableCluster(Guid id, string hostId)
    {
        private const int MaxLinks = 400;

        public Guid Id { get; } = id;
        public string HostId { get; } = hostId;
        public DateTimeOffset FirstSeen { get; set; } = DateTimeOffset.MaxValue;
        public DateTimeOffset LastSeen { get; set; } = DateTimeOffset.MinValue;
        public List<CorrelatedNode> Nodes { get; } = new(8);
        public HashSet<Guid> NodeIds { get; } = new();
        public List<CorrelationLink> Links { get; } = new(16);
        public HashSet<string> SharedKeys { get; } = new(StringComparer.OrdinalIgnoreCase);
        public CorrelationCluster? Snapshot { get; set; }

        public void AddLink(CorrelationLink link)
        {
            if (Links.Count >= MaxLinks)
            {
                Links.RemoveAt(0);
            }
            Links.Add(link);
        }
    }
}
