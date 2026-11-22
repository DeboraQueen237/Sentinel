using Microsoft.AspNetCore.SignalR;

namespace Sentinel.Server.Hubs;

/// <summary>
/// Hub SignalR temps réel exposé sur <c>/hubs/live</c> (contrat <see cref="Sentinel.Shared.Api.LiveHub"/>).
/// Protégé par <see cref="Security.BearerSessionMiddleware"/> (en-tête Bearer ou <c>?access_token=</c>).
/// </summary>
public sealed class SentinelLiveHub : Hub
{
    private readonly ILogger<SentinelLiveHub> _logger;

    public SentinelLiveHub(ILogger<SentinelLiveHub> logger)
    {
        _logger = logger;
    }

    public override Task OnConnectedAsync()
    {
        _logger.LogInformation("Client SignalR connecté : {ConnectionId} (utilisateur={User}).",
            Context.ConnectionId, Context.User?.Identity?.Name ?? "inconnu");
        return base.OnConnectedAsync();
    }

    public override Task OnDisconnectedAsync(Exception? exception)
    {
        _logger.LogInformation("Client SignalR déconnecté : {ConnectionId}.", Context.ConnectionId);
        return base.OnDisconnectedAsync(exception);
    }
}
