using Microsoft.AspNetCore.SignalR;
using Sentinel.Server.Services;
using Sentinel.Shared.Api;
using Sentinel.Shared.Models;

namespace Sentinel.Server.Hubs;

/// <summary>
/// Diffuseur temps réel centralisé sur <see cref="SentinelLiveHub"/>.
/// Limite la diffusion de <see cref="LiveHub.SummaryChanged"/> à au plus 1 fois toutes les 2 secondes.
/// </summary>
public sealed class LiveBroadcaster
{
    private static readonly TimeSpan SummaryMinInterval = TimeSpan.FromSeconds(2);

    private readonly IHubContext<SentinelLiveHub> _hub;
    private readonly IServiceProvider _services;
    private readonly ILogger<LiveBroadcaster> _logger;

    private readonly object _throttleGate = new();
    private DateTimeOffset _lastSummarySent = DateTimeOffset.MinValue;
    private bool _summaryScheduled;

    public LiveBroadcaster(
        IHubContext<SentinelLiveHub> hub,
        IServiceProvider services,
        ILogger<LiveBroadcaster> logger)
    {
        _hub = hub;
        _services = services;
        _logger = logger;
    }

    public Task EventScoredAsync(EventDto dto, CancellationToken ct = default) =>
        SafeSendAsync(LiveHub.EventScored, dto, ct);

    public Task AlertRaisedAsync(AlertDto dto, CancellationToken ct = default) =>
        SafeSendAsync(LiveHub.AlertRaised, dto, ct);

    public Task AlertUpdatedAsync(AlertDto dto, CancellationToken ct = default) =>
        SafeSendAsync(LiveHub.AlertUpdated, dto, ct);

    public Task ClusterUpdatedAsync(ClusterDto dto, CancellationToken ct = default) =>
        SafeSendAsync(LiveHub.ClusterUpdated, dto, ct);

    public Task ActionUpdatedAsync(ActionTicketDto dto, CancellationToken ct = default) =>
        SafeSendAsync(LiveHub.ActionUpdated, dto, ct);

    public Task HostStatusChangedAsync(HostDto dto, CancellationToken ct = default) =>
        SafeSendAsync(LiveHub.HostStatusChanged, dto, ct);

    public Task SettingsChangedAsync(SentinelSettings settings, CancellationToken ct = default) =>
        SafeSendAsync(LiveHub.SettingsChanged, settings, ct);

    public Task NotificationPushedAsync(InAppNotificationDto dto, CancellationToken ct = default) =>
        SafeSendAsync(LiveHub.NotificationPushed, dto, ct);

    /// <summary>
    /// Déclenche une diffusion coalescée et bridée (≤ 1 / 2 s) du résumé du tableau de bord.
    /// </summary>
    public void NotifySummaryChanged()
    {
        TimeSpan delay;
        lock (_throttleGate)
        {
            if (_summaryScheduled)
                return;

            var now = DateTimeOffset.UtcNow;
            var elapsed = now - _lastSummarySent;
            if (elapsed >= SummaryMinInterval)
            {
                _lastSummarySent = now;
                delay = TimeSpan.Zero;
            }
            else
            {
                _summaryScheduled = true;
                delay = SummaryMinInterval - elapsed;
            }
        }

        _ = Task.Run(async () =>
        {
            try
            {
                if (delay > TimeSpan.Zero)
                {
                    await Task.Delay(delay).ConfigureAwait(false);
                    lock (_throttleGate)
                    {
                        _summaryScheduled = false;
                        _lastSummarySent = DateTimeOffset.UtcNow;
                    }
                }

                var dashboard = _services.GetService<DashboardService>();
                if (dashboard is null)
                    return;

                var summary = await dashboard.GetSummaryAsync(CancellationToken.None).ConfigureAwait(false);
                await SafeSendAsync(LiveHub.SummaryChanged, summary, CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                lock (_throttleGate)
                {
                    _summaryScheduled = false;
                }
                _logger.LogDebug(ex, "Échec lors de la diffusion SummaryChanged.");
            }
        });
    }

    private async Task SafeSendAsync(string method, object payload, CancellationToken ct)
    {
        try
        {
            await _hub.Clients.All.SendAsync(method, payload, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Diffusion SignalR '{Method}' ignorée suite à une erreur.", method);
        }
    }
}
