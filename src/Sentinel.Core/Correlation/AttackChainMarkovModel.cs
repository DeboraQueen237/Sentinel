using Sentinel.Shared.Models;

namespace Sentinel.Core.Correlation;

/// <summary>
/// Modèle probabiliste par chaîne de Markov du 1er ordre sur les transitions de <see cref="EventCategory"/> (v2 Mission 8).
/// Initialisé avec des a priori issus des 7 chaînes d'attaque modélisées (plus les signaux v2 Defender/Script/Canary),
/// mis à jour par le retour analyste (VP/FP) de façon strictement historisée et réversible.
/// </summary>
public sealed class AttackChainMarkovModel
{
    private readonly object _gate = new();
    private readonly Dictionary<(EventCategory From, EventCategory To), TransitionStats> _transitions = new();
    private readonly Dictionary<Guid, FeedbackDelta> _appliedFeedback = new();

    public AttackChainMarkovModel()
    {
        SeedAttackChainPriors();
    }

    private void SeedAttackChainPriors()
    {
        // A priori dérivés des 7 chaînes d'attaque + signaux v2 : (poids malveillant, poids bénin)
        Seed(EventCategory.Clipboard, EventCategory.Browser, mal: 7.0, benign: 2.5);
        Seed(EventCategory.Browser, EventCategory.Browser, mal: 4.5, benign: 3.0);
        Seed(EventCategory.Browser, EventCategory.File, mal: 7.5, benign: 2.5);
        Seed(EventCategory.Browser, EventCategory.Process, mal: 7.8, benign: 1.8);
        Seed(EventCategory.File, EventCategory.Process, mal: 8.0, benign: 2.0);
        Seed(EventCategory.Process, EventCategory.Network, mal: 7.0, benign: 2.5);

        // BadUSB : Device -> Typing -> Process
        Seed(EventCategory.Device, EventCategory.Typing, mal: 9.0, benign: 1.0);
        Seed(EventCategory.Typing, EventCategory.Process, mal: 8.5, benign: 1.2);

        // Ransomware & Canaris
        Seed(EventCategory.File, EventCategory.File, mal: 6.5, benign: 3.0);
        Seed(EventCategory.Process, EventCategory.Canary, mal: 9.8, benign: 0.2);
        Seed(EventCategory.Canary, EventCategory.File, mal: 9.5, benign: 0.3);
        Seed(EventCategory.File, EventCategory.Canary, mal: 9.5, benign: 0.3);

        // Exfiltration : File -> Network / Device
        Seed(EventCategory.File, EventCategory.Network, mal: 7.2, benign: 2.2);
        Seed(EventCategory.File, EventCategory.Device, mal: 7.8, benign: 1.8);
        Seed(EventCategory.Device, EventCategory.File, mal: 6.0, benign: 2.5);

        // Brute force / Intrusion : Session -> Session -> Process
        Seed(EventCategory.Session, EventCategory.Session, mal: 7.5, benign: 2.0);
        Seed(EventCategory.Session, EventCategory.Process, mal: 7.8, benign: 2.0);

        // Persistance : Installation / File / Process
        Seed(EventCategory.File, EventCategory.Installation, mal: 8.0, benign: 1.5);
        Seed(EventCategory.Process, EventCategory.Installation, mal: 8.2, benign: 1.5);
        Seed(EventCategory.Installation, EventCategory.Process, mal: 7.2, benign: 2.0);

        // Chaînes v2 (Defender weakening, Scripts 4104, Analyse statique, Threat Intel)
        Seed(EventCategory.Defender, EventCategory.Process, mal: 9.0, benign: 0.8);
        Seed(EventCategory.Defender, EventCategory.File, mal: 8.5, benign: 1.0);
        Seed(EventCategory.Process, EventCategory.Defender, mal: 9.2, benign: 0.5);
        Seed(EventCategory.Script, EventCategory.Process, mal: 8.5, benign: 1.2);
        Seed(EventCategory.Script, EventCategory.Network, mal: 8.5, benign: 1.2);
        Seed(EventCategory.Script, EventCategory.Defender, mal: 9.4, benign: 0.4);
        Seed(EventCategory.StaticAnalysis, EventCategory.Process, mal: 8.8, benign: 1.0);
        Seed(EventCategory.ThreatIntel, EventCategory.Network, mal: 9.0, benign: 0.6);
        Seed(EventCategory.ThreatIntel, EventCategory.Process, mal: 9.0, benign: 0.6);
    }

    private void Seed(EventCategory from, EventCategory to, double mal, double benign) =>
        _transitions[(from, to)] = new TransitionStats(mal, benign);

    /// <summary>
    /// Calcule la probabilité moyenne (0..1) qu'une séquence chronologique de catégories appartienne à une chaîne d'attaque.
    /// </summary>
    public double EstimateChainProbability(IReadOnlyList<EventCategory> sequence)
    {
        if (sequence is null || sequence.Count < 2) return 0.0;

        lock (_gate)
        {
            double probSum = 0.0;
            int transitions = 0;

            for (var i = 1; i < sequence.Count; i++)
            {
                var key = (sequence[i - 1], sequence[i]);
                double p;
                if (_transitions.TryGetValue(key, out var stats))
                {
                    p = stats.Probability;
                }
                else
                {
                    // Transition non modélisée : a priori neutre-faible (lissage de Laplace)
                    p = 0.25;
                }

                probSum += p;
                transitions++;
            }

            if (transitions == 0) return 0.0;

            // Moyenne géométrique/arithmétique pondérée avec léger bonus de longueur pour les séquences >= 3 étapes cohérentes
            var mean = probSum / transitions;
            var lengthBoost = transitions >= 2 && mean >= 0.65 ? Math.Min(0.10, (transitions - 1) * 0.03) : 0.0;
            return Math.Round(Math.Clamp(mean + lengthBoost, 0.0, 0.99), 3);
        }
    }

    /// <summary>
    /// Bonus de score optionnel (0..12) lorsqu'une chaîne probabiliste forte est détectée même hors des 7 séquences rigides.
    /// </summary>
    public int ComputeSequenceBonus(double chainProbability, int eventCount, bool hasExplicitChain)
    {
        if (hasExplicitChain || eventCount < 2 || chainProbability < 0.72) return 0;
        var scaled = (chainProbability - 0.70) / 0.29;
        return Math.Clamp((int)Math.Round(scaled * 12.0), 0, 12);
    }

    /// <summary>
    /// Enregistre un retour analyste (VP ou FP) sur une séquence et conserve le delta exact pour réversibilité.
    /// </summary>
    public void ApplyFeedback(Guid feedbackId, IReadOnlyList<EventCategory> sequence, bool isFalsePositive)
    {
        if (sequence is null || sequence.Count < 2) return;

        var pairs = new List<(EventCategory, EventCategory)>(sequence.Count - 1);
        for (var i = 1; i < sequence.Count; i++)
        {
            pairs.Add((sequence[i - 1], sequence[i]));
        }

        const double step = 1.5;

        lock (_gate)
        {
            if (_appliedFeedback.ContainsKey(feedbackId)) return;

            foreach (var pair in pairs)
            {
                if (!_transitions.TryGetValue(pair, out var stats))
                {
                    stats = new TransitionStats(1.0, 3.0);
                    _transitions[pair] = stats;
                }

                if (isFalsePositive)
                    stats.BenignCount += step;
                else
                    stats.MaliciousCount += step;
            }

            _appliedFeedback[feedbackId] = new FeedbackDelta(pairs, isFalsePositive, step);
        }
    }

    /// <summary>Annule exactement l'effet d'un retour analyste précédemment appliqué.</summary>
    public bool RevertFeedback(Guid feedbackId)
    {
        lock (_gate)
        {
            if (!_appliedFeedback.Remove(feedbackId, out var delta))
            {
                return false;
            }

            foreach (var pair in delta.Transitions)
            {
                if (!_transitions.TryGetValue(pair, out var stats)) continue;
                if (delta.IsFalsePositive)
                    stats.BenignCount = Math.Max(0.1, stats.BenignCount - delta.Step);
                else
                    stats.MaliciousCount = Math.Max(0.1, stats.MaliciousCount - delta.Step);
            }

            return true;
        }
    }

    private sealed class TransitionStats(double maliciousCount, double benignCount)
    {
        public double MaliciousCount { get; set; } = maliciousCount;
        public double BenignCount { get; set; } = benignCount;

        public double Probability
        {
            get
            {
                var denom = MaliciousCount + BenignCount;
                return denom <= 0 ? 0.5 : MaliciousCount / denom;
            }
        }
    }

    private sealed record FeedbackDelta(
        IReadOnlyList<(EventCategory From, EventCategory To)> Transitions,
        bool IsFalsePositive,
        double Step);
}
