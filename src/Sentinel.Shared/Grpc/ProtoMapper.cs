using Sentinel.Shared.Grpc;
using Sentinel.Shared.Models;

namespace Sentinel.Shared.Grpc;

/// <summary>Conversions SecurityEvent &lt;-&gt; ProtoEvent.</summary>
public static class ProtoMapper
{
    public static ProtoEvent ToProto(this SecurityEvent e)
    {
        var p = new ProtoEvent
        {
            Id = e.Id.ToString(),
            TimestampUnixMs = e.Timestamp.ToUnixTimeMilliseconds(),
            HostId = e.HostId ?? string.Empty,
            UserId = e.UserId ?? string.Empty,
            Category = (int)e.Category,
            EventType = e.EventType ?? string.Empty,
            Subject = e.Subject ?? string.Empty,
            CorrelationHints = e.CorrelationHints ?? string.Empty
        };
        foreach (var kv in e.Attributes)
        {
            if (kv.Key is not null && kv.Value is not null) p.Attributes[kv.Key] = kv.Value;
        }
        return p;
    }

    public static SecurityEvent ToModel(this ProtoEvent p) =>
        new(
            Guid.TryParse(p.Id, out var id) ? id : Guid.NewGuid(),
            DateTimeOffset.FromUnixTimeMilliseconds(p.TimestampUnixMs),
            p.HostId,
            p.UserId,
            Enum.IsDefined(typeof(EventCategory), p.Category) ? (EventCategory)p.Category : EventCategory.System,
            p.EventType,
            p.Subject,
            new Dictionary<string, string>(p.Attributes),
            string.IsNullOrEmpty(p.CorrelationHints) ? null : p.CorrelationHints);
}
