using Sentinel.Shared.Api;
using Sentinel.Shared.Json;
using Sentinel.Shared.Models;
using Sentinel.Storage.Entities;

namespace Sentinel.Storage.Mapping;

/// <summary>
/// Extensions de projection entre entités EF Core (<c>Sentinel.Storage.Entities</c>)
/// et modèles/DTO partagés (<c>Sentinel.Shared</c>).
/// </summary>
public static class StorageMappers
{
    public static EventEntity ToEntity(this ScoredEvent scored, Guid? clusterId = null)
    {
        ArgumentNullException.ThrowIfNull(scored);
        var e = scored.Event;
        var a = scored.Assessment;

        return new EventEntity
        {
            Id = e.Id,
            Timestamp = e.Timestamp,
            TimestampUnixMs = e.Timestamp.ToUnixTimeMilliseconds(),
            HostId = e.HostId,
            UserId = e.UserId,
            Category = (int)e.Category,
            EventType = e.EventType,
            Subject = e.Subject,
            AttributesJson = SentinelJson.Serialize(e.Attributes),
            CorrelationHints = e.CorrelationHints,
            Score = a.Score,
            Level = (int)a.Level,
            ThreatType = (int)a.Type,
            Justification = a.Justification,
            Source = (int)a.Source,
            Confidence = a.Confidence,
            MatchedRulesJson = SentinelJson.Serialize(a.MatchedRules),
            MitreTechniquesJson = SentinelJson.Serialize(a.MitreTechniques),
            ClusterId = clusterId
        };
    }

    public static EventDto ToDto(this EventEntity e)
    {
        ArgumentNullException.ThrowIfNull(e);
        return new EventDto(
            e.Id,
            e.Timestamp,
            e.HostId,
            e.UserId,
            (EventCategory)e.Category,
            e.EventType,
            e.Subject,
            DeserializeDict(e.AttributesJson),
            e.Score,
            (ThreatLevel)e.Level,
            (ThreatType)e.ThreatType,
            e.Justification,
            (AssessmentSource)e.Source,
            e.Confidence,
            DeserializeList(e.MatchedRulesJson),
            DeserializeList(e.MitreTechniquesJson),
            e.ClusterId);
    }

    public static ScoredEvent ToScoredEvent(this EventEntity e)
    {
        ArgumentNullException.ThrowIfNull(e);
        var evt = new SecurityEvent(
            e.Id,
            e.Timestamp,
            e.HostId,
            e.UserId,
            (EventCategory)e.Category,
            e.EventType,
            e.Subject,
            DeserializeDict(e.AttributesJson),
            e.CorrelationHints);

        var assessment = new ThreatAssessment(
            e.Id,
            e.Score,
            (ThreatType)e.ThreatType,
            e.Justification,
            (AssessmentSource)e.Source,
            e.Confidence)
        {
            MatchedRules = DeserializeList(e.MatchedRulesJson),
            MitreTechniques = DeserializeList(e.MitreTechniquesJson)
        };

        return new ScoredEvent(evt, assessment);
    }

    public static ClusterEntity ToEntity(this CorrelationCluster cluster)
    {
        ArgumentNullException.ThrowIfNull(cluster);
        return new ClusterEntity
        {
            Id = cluster.Id,
            HostId = cluster.HostId,
            FirstSeen = cluster.FirstSeen,
            FirstSeenUnixMs = cluster.FirstSeen.ToUnixTimeMilliseconds(),
            LastSeen = cluster.LastSeen,
            LastSeenUnixMs = cluster.LastSeen.ToUnixTimeMilliseconds(),
            Score = cluster.Score,
            MaxEventScore = cluster.MaxEventScore,
            Level = cluster.Level,
            DominantType = cluster.DominantType,
            EventCount = cluster.EventIds.Count,
            Escalated = cluster.Escalated,
            ChainId = cluster.Chain?.ChainId,
            ChainName = cluster.Chain?.Name,
            ChainStepsMatched = cluster.Chain?.StepsMatched ?? 0,
            ChainTotalSteps = cluster.Chain?.TotalSteps ?? 0,
            ContextKeysJson = SentinelJson.Serialize(cluster.ContextKeys),
            MitreTechniquesJson = SentinelJson.Serialize(cluster.MitreTechniques),
            Justification = cluster.Justification,
            Links = cluster.Links.Select(l => new ClusterLinkEntity
            {
                ClusterId = cluster.Id,
                FromEventId = l.FromEventId,
                ToEventId = l.ToEventId,
                EdgeType = (int)l.Type,
                Weight = l.Weight,
                Key = l.Key
            }).ToList()
        };
    }

    public static ClusterDto ToDto(this ClusterEntity c)
    {
        ArgumentNullException.ThrowIfNull(c);
        return new ClusterDto(
            c.Id,
            c.HostId,
            c.FirstSeen,
            c.LastSeen,
            c.Score,
            c.MaxEventScore,
            c.Level,
            c.DominantType,
            c.EventCount,
            c.Escalated,
            c.ChainId,
            c.ChainName,
            c.ChainStepsMatched,
            c.ChainTotalSteps,
            DeserializeList(c.ContextKeysJson),
            DeserializeList(c.MitreTechniquesJson),
            c.Justification);
    }

    public static AlertDto ToDto(this AlertEntity a, int pendingActions = 0)
    {
        ArgumentNullException.ThrowIfNull(a);
        return new AlertDto(
            a.Id,
            a.CreatedAt,
            a.UpdatedAt,
            a.HostId,
            a.UserId,
            a.Title,
            a.Summary,
            a.Score,
            a.Level,
            a.ThreatType,
            a.Status,
            a.ClusterId,
            a.EventCount,
            pendingActions,
            a.RequiresDecision,
            DeserializeList(a.MitreTechniquesJson));
    }

    public static AlertHistoryEntryDto ToDto(this AlertHistoryEntity h)
    {
        ArgumentNullException.ThrowIfNull(h);
        return new AlertHistoryEntryDto(h.Timestamp, h.Actor, h.Action, h.Comment);
    }

    public static ActionTicketDto ToDto(this ActionTicketEntity t)
    {
        ArgumentNullException.ThrowIfNull(t);
        return new ActionTicketDto(
            t.Id,
            t.CreatedAt,
            t.ExecutedAt,
            t.RevertedAt,
            t.HostId,
            t.AlertId,
            (ResponseActionType)t.ActionType,
            t.Target,
            t.Status,
            t.Automatic,
            t.Reversible,
            t.Rationale,
            t.ResultMessage,
            DeserializeDict(t.ParametersJson));
    }

    public static HostDto ToDto(this HostEntity h, bool online, int openAlerts)
    {
        ArgumentNullException.ThrowIfNull(h);
        return new HostDto(
            h.HostId,
            h.MachineName,
            h.OsVersion,
            h.AgentVersion,
            h.FirstSeen,
            h.LastSeen,
            online,
            h.RiskScore,
            openAlerts,
            DeserializeList(h.UsersJson));
    }

    public static AuditEntryDto ToDto(this AuditEntryEntity a)
    {
        ArgumentNullException.ThrowIfNull(a);
        return new AuditEntryDto(
            a.Id,
            a.Timestamp,
            a.Actor,
            a.Action,
            a.Target,
            a.Details,
            a.IpAddress,
            a.Hash,
            a.PreviousHash);
    }

    public static ScenarioMetricDto ToDto(this EvaluationMetricEntity m)
    {
        ArgumentNullException.ThrowIfNull(m);
        return new ScenarioMetricDto(
            m.Scenario,
            m.Configuration,
            m.Detected,
            m.EventsBeforeAlert,
            m.SecondsToDetect,
            m.PeakScore,
            m.FalsePositives);
    }

    private static IReadOnlyDictionary<string, string> DeserializeDict(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return new Dictionary<string, string>();
        try
        {
            return SentinelJson.Deserialize<Dictionary<string, string>>(json) ?? new Dictionary<string, string>();
        }
        catch
        {
            return new Dictionary<string, string>();
        }
    }

    private static IReadOnlyList<string> DeserializeList(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return Array.Empty<string>();
        try
        {
            return SentinelJson.Deserialize<List<string>>(json) ?? (IReadOnlyList<string>)Array.Empty<string>();
        }
        catch
        {
            return Array.Empty<string>();
        }
    }
}
