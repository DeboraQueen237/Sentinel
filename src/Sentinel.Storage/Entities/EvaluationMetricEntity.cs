namespace Sentinel.Storage.Entities;

/// <summary>Métrique d'évaluation d'un scénario simulé (comparaison configurations A/B/C, doc §8.4, §14).</summary>
public sealed class EvaluationMetricEntity
{
    public long Id { get; set; }

    public DateTimeOffset RunAt { get; set; }

    public string Scenario { get; set; } = string.Empty;

    public string Configuration { get; set; } = string.Empty;

    public bool Detected { get; set; }

    public int EventsBeforeAlert { get; set; }

    public double SecondsToDetect { get; set; }

    public int PeakScore { get; set; }

    public int FalsePositives { get; set; }
}
