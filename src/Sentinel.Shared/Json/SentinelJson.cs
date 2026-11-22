using System.Text.Json;
using System.Text.Json.Serialization;

namespace Sentinel.Shared.Json;

/// <summary>Options JSON communes (REST, SignalR, IPC, gRPC settings_json).</summary>
public static class SentinelJson
{
    public static JsonSerializerOptions Options { get; } = Create();

    public static JsonSerializerOptions Create()
    {
        var o = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            WriteIndented = false
        };
        o.Converters.Add(new JsonStringEnumConverter());
        return o;
    }

    /// <summary>Applique la configuration commune à des options existantes (ex. ASP.NET Core).</summary>
    public static void Configure(JsonSerializerOptions o)
    {
        o.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
        o.PropertyNameCaseInsensitive = true;
        o.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
        if (!o.Converters.OfType<JsonStringEnumConverter>().Any())
            o.Converters.Add(new JsonStringEnumConverter());
    }

    public static string Serialize<T>(T value) => JsonSerializer.Serialize(value, Options);
    public static T? Deserialize<T>(string json) => JsonSerializer.Deserialize<T>(json, Options);
}
