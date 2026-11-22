using Sentinel.Shared.Infrastructure;

namespace Sentinel.Server.Configuration;

/// <summary>
/// Options d'hébergement et de sécurité de <c>Sentinel.Server</c> (section <c>Sentinel</c> de <c>appsettings.json</c>).
/// </summary>
public sealed class SentinelServerOptions
{
    public const string SectionName = "Sentinel";

    /// <summary>Port HTTP (REST + SignalR) écouté sur 127.0.0.1.</summary>
    public int ApiPort { get; set; } = SentinelEndpoints.ServerApiPort;

    /// <summary>Port gRPC HTTP/2 (mTLS par défaut) écouté sur localhost.</summary>
    public int GrpcPort { get; set; } = SentinelEndpoints.ServerGrpcPort;

    /// <summary>Active le mTLS agent ↔ serveur (désactivable en environnement de test).</summary>
    public bool UseMtls { get; set; } = true;

    /// <summary>Durée de validité d'une session administrateur, en minutes (doc §10.2).</summary>
    public int SessionTtlMinutes { get; set; } = 30;

    /// <summary>Origines CORS autorisées (console d'administration Blazor).</summary>
    public string[] CorsOrigins { get; set; } =
    [
        "http://127.0.0.1:5200",
        "http://localhost:5200"
    ];

    /// <summary>Chaîne de connexion SQLite optionnelle (défaut : <see cref="SentinelPaths.ServerDatabase"/>).</summary>
    public string? ConnectionString { get; set; }

    /// <summary>Horodatage UTC de démarrage du processus serveur.</summary>
    public DateTimeOffset StartedAt { get; } = DateTimeOffset.UtcNow;
}
