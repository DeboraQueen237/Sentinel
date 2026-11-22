namespace Sentinel.Shared.Models;

/// <summary>Lien entre deux événements corrélés.</summary>
public sealed record CorrelationLink(
    Guid FromEventId,
    Guid ToEventId,
    GraphEdgeType Type,
    double Weight,
    string Key);

/// <summary>Correspondance avec une chaîne d'attaque modélisée (doc §8.3).</summary>
public sealed record AttackChainMatch(
    string ChainId,
    string Name,
    int StepsMatched,
    int TotalSteps,
    int Bonus,
    ThreatType Type,
    IReadOnlyList<string> MitreTechniques)
{
    public bool IsComplete => StepsMatched >= TotalSteps;
    public double Progress => TotalSteps == 0 ? 0 : (double)StepsMatched / TotalSteps;
}

/// <summary>
/// Cluster = composante connexe du graphe de corrélation (doc §8.2, exigences F4/F5).
/// Le score de cluster peut dépasser celui de chaque événement.
/// </summary>
public sealed record CorrelationCluster
{
    public required Guid Id { get; init; }
    public required string HostId { get; init; }
    public required DateTimeOffset FirstSeen { get; init; }
    public required DateTimeOffset LastSeen { get; init; }
    public required int Score { get; init; }
    public required ThreatLevel Level { get; init; }
    public required ThreatType DominantType { get; init; }
    public required IReadOnlyList<Guid> EventIds { get; init; }
    public required IReadOnlyList<CorrelationLink> Links { get; init; }
    /// <summary>Clés de contexte partagées (ex. "domain:bit.ly", "hash:ab12…", "parent:1234").</summary>
    public IReadOnlyList<string> ContextKeys { get; init; } = Array.Empty<string>();
    public AttackChainMatch? Chain { get; init; }
    /// <summary>Vrai si l'escalade précoce (2ᵉ événement similaire) a relevé le niveau.</summary>
    public bool Escalated { get; init; }
    /// <summary>Score maximal individuel (pour comparer avec l'analyse événement par événement).</summary>
    public int MaxEventScore { get; init; }
    public string Justification { get; init; } = string.Empty;
    public IReadOnlyList<string> MitreTechniques { get; init; } = Array.Empty<string>();
}

/// <summary>Action planifiée par le moteur de décision (doc §9.2).</summary>
public sealed record PlannedAction(
    ResponseActionType Type,
    string Target,
    IReadOnlyDictionary<string, string> Parameters,
    bool Automatic,
    string Rationale);

/// <summary>Décision déterministe produite pour un événement ou un cluster (doc §9).</summary>
public sealed record ResponseDecision
{
    public required Guid Id { get; init; }
    public required string HostId { get; init; }
    public required Guid TriggerEventId { get; init; }
    public Guid? ClusterId { get; init; }
    public required int Score { get; init; }
    public required ThreatLevel Level { get; init; }
    public required ThreatType Type { get; init; }
    public required IReadOnlyList<PlannedAction> Actions { get; init; }
    /// <summary>Niveau 3 : décision humaine requise.</summary>
    public bool RequiresHumanApproval { get; init; }
    /// <summary>Une alerte administrateur doit être créée / mise à jour.</summary>
    public bool AlertAdmin { get; init; }
    /// <summary>Notification discrète à l'utilisateur (niveau 2).</summary>
    public bool NotifyUser { get; init; }
    public required string Justification { get; init; }
    /// <summary>Mode effectif lors de la décision (apprentissage/simulation ⇒ aucune exécution).</summary>
    public OperatingMode Mode { get; init; }
}

/// <summary>Résultat complet du traitement d'un événement par le pipeline d'analyse.</summary>
public sealed record PipelineResult
{
    public required ScoredEvent Scored { get; init; }
    public CorrelationCluster? Cluster { get; init; }
    public ResponseDecision? Decision { get; init; }
    /// <summary>Durée de traitement (latence scoring + corrélation), en ms.</summary>
    public double ElapsedMs { get; init; }
    public bool LlmUsed { get; init; }
}

/// <summary>Retour administrateur réinjecté dans le moteur (doc §9.4).</summary>
public sealed record AnalystFeedback(
    Guid? AlertId,
    Guid? ClusterId,
    IReadOnlyList<Guid> EventIds,
    bool IsFalsePositive,
    string? Comment);
