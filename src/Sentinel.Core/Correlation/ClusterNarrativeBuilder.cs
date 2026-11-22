using System.Text;
using Sentinel.Shared.Models;

namespace Sentinel.Core.Correlation;

/// <summary>
/// Génère le récit chronologique explicable d'un cluster de corrélation, dérive les tactiques MITRE ATT&amp;CK
/// et agrège les contributions par moteur de détection (v2 Mission 8).
/// </summary>
internal static class ClusterNarrativeBuilder
{
    public static IReadOnlyList<string> ExtractMitreTactics(IEnumerable<string> mitreTechniques)
    {
        var tactics = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var techId in mitreTechniques)
        {
            var info = MitreCatalog.TryGet(techId);
            if (info is null && techId.Contains('.'))
            {
                info = MitreCatalog.TryGet(techId[..techId.IndexOf('.')]);
            }

            if (info is not null && !string.IsNullOrWhiteSpace(info.Tactic) && seen.Add(info.Tactic))
            {
                tactics.Add(info.Tactic);
            }
        }

        return tactics;
    }

    public static IReadOnlyList<ScoreContribution> AggregateContributions(
        IReadOnlyList<CorrelatedNode> orderedNodes,
        AttackChainMatch? chain,
        double chainProbability,
        int markovBonus)
    {
        var byEngine = new Dictionary<string, (int MaxScore, double Weight, List<string> Signals)>(StringComparer.OrdinalIgnoreCase);

        foreach (var node in orderedNodes)
        {
            var contribs = node.Assessment.ScoreContributions;
            if (contribs.Count == 0)
            {
                AddContribution(byEngine, node.Assessment.Source.ToString(), node.Assessment.Score, 1.0, node.Assessment.MatchedRules);
            }
            else
            {
                foreach (var c in contribs)
                {
                    AddContribution(byEngine, c.Engine, c.Score, c.Weight, c.Signals);
                }
            }
        }

        var list = byEngine
            .Select(kv => new ScoreContribution(
                kv.Key,
                kv.Value.MaxScore,
                kv.Value.Weight,
                $"Contribution maximale {kv.Value.MaxScore}/100 ({kv.Value.Signals.Count} signal(aux))",
                kv.Value.Signals.Take(6).ToArray()))
            .OrderByDescending(c => c.Score)
            .ToList();

        if (chain is not null)
        {
            list.Add(new ScoreContribution(
                "CorrelationChain",
                chain.Bonus,
                1.0,
                $"Chaîne « {chain.Name} » ({chain.StepsMatched}/{chain.TotalSteps} étapes, +{chain.Bonus})",
                chain.MitreTechniques));
        }

        if (chainProbability > 0)
        {
            list.Add(new ScoreContribution(
                "MarkovModel",
                markovBonus,
                chainProbability,
                $"Probabilité de séquence markovienne {chainProbability:P0}" + (markovBonus > 0 ? $" (+{markovBonus})" : string.Empty)));
        }

        return list;
    }

    public static string BuildNarrative(
        string hostId,
        IReadOnlyList<CorrelatedNode> orderedNodes,
        AttackChainMatch? chain,
        double chainProbability,
        IReadOnlyList<string> tactics,
        int clusterScore,
        bool escalated)
    {
        var sb = new StringBuilder(512);
        sb.Append($"Chronologie sur {hostId} ({orderedNodes.Count} événements, score corrélé {clusterScore}/100) : ");

        var displayed = orderedNodes.Take(8).ToList();
        for (var i = 0; i < displayed.Count; i++)
        {
            var n = displayed[i];
            if (i > 0) sb.Append(" → ");
            var subject = n.Event.Subject.Length > 48 ? n.Event.Subject[..45] + "..." : n.Event.Subject;
            sb.Append($"[{n.Timestamp:HH:mm:ss}] {n.Event.Category}/{n.Event.EventType} « {subject} » ({n.Assessment.Score}/100)");
        }

        if (orderedNodes.Count > displayed.Count)
        {
            sb.Append($" → (+{orderedNodes.Count - displayed.Count} autre(s) événement(s))");
        }

        sb.Append('.');

        if (chain is not null)
        {
            sb.Append($" Séquence identifiée : {chain.Name} ({chain.StepsMatched}/{chain.TotalSteps} étapes).");
        }

        if (chainProbability > 0)
        {
            sb.Append($" Probabilité markovienne de chaîne d'attaque : {chainProbability:P0}.");
        }

        if (tactics.Count > 0)
        {
            sb.Append($" Tactiques MITRE ATT&CK : {string.Join(", ", tactics)}.");
        }

        if (escalated)
        {
            sb.Append(" Escalade précoce activée (+1 niveau dès le 2ᵉ événement corrélé).");
        }

        return sb.ToString();
    }

    private static void AddContribution(
        Dictionary<string, (int MaxScore, double Weight, List<string> Signals)> map,
        string engine,
        int score,
        double weight,
        IReadOnlyList<string>? signals)
    {
        if (!map.TryGetValue(engine, out var existing))
        {
            existing = (score, weight, new List<string>());
        }
        else if (score > existing.MaxScore)
        {
            existing = (score, Math.Max(existing.Weight, weight), existing.Signals);
        }

        if (signals is not null)
        {
            foreach (var s in signals)
            {
                if (!string.IsNullOrWhiteSpace(s) && !existing.Signals.Contains(s, StringComparer.OrdinalIgnoreCase))
                {
                    existing.Signals.Add(s);
                }
            }
        }

        map[engine] = existing;
    }
}
