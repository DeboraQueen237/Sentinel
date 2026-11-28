using Microsoft.AspNetCore.SignalR.Client;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Shared.Api;
using Sentinel.Shared.Json;
using Sentinel.Shared.Models;

namespace Sentinel.Admin.Services;

public enum LiveConnectionState
{
    Disconnected,
    Connecting,
    Connected,
    Reconnecting
}

/// <summary>
/// Client SignalR Scoped connecté au hub temps réel <see cref="LiveHub.Path"/> de Sentinel.Server.
/// Diffuse les événements typés vers les composants Blazor abonnés et gère la reconnexion automatique.
/// </summary>
public sealed class LiveHubClient : IAsyncDisposable
{
    private readonly AdminServerOptions _options;
    private readonly AdminSessionState _session;
    private readonly ILogger<LiveHubClient> _logger;
    private readonly SemaphoreSlim _connectLock = new(1, 1);
    private HubConnection? _connection;
    private string? _connectedToken;

    public LiveHubClient(
        AdminServerOptions options,
        AdminSessionState session,
        ILogger<LiveHubClient> logger)
    {
        _options = options;
        _session = session;
        _logger = logger;
    }

    public LiveConnectionState State { get; private set; } = LiveConnectionState.Disconnected;

    public event Action<LiveConnectionState>? StateChanged;
    public event Action<EventDto>? EventScored;
    public event Action<AlertDto>? AlertRaised;
    public event Action<AlertDto>? AlertUpdated;
    public event Action<ClusterDto>? ClusterUpdated;
    public event Action<ActionTicketDto>? ActionUpdated;
    public event Action<HostDto>? HostStatusChanged;
    public event Action<DashboardSummaryDto>? SummaryChanged;
    public event Action<SentinelSettings>? SettingsChanged;
    public event Action<InAppNotificationDto>? NotificationPushed;

    public async Task EnsureConnectedAsync(CancellationToken ct = default)
    {
        if (!_session.IsAuthenticated || string.IsNullOrWhiteSpace(_session.Token))
        {
            await DisconnectAsync();
            return;
        }

        await _connectLock.WaitAsync(ct);
        try
        {
            var token = _session.Token;
            if (_connection is not null &&
                _connectedToken == token &&
                _connection.State is HubConnectionState.Connected or HubConnectionState.Connecting or HubConnectionState.Reconnecting)
            {
                return;
            }

            await DisposeConnectionInternalAsync();

            var hubUrl = $"{_options.ServerUrl}{LiveHub.Path}";
            SetState(LiveConnectionState.Connecting);

            var connection = new HubConnectionBuilder()
                .WithUrl(hubUrl, opts =>
                {
                    opts.AccessTokenProvider = () => Task.FromResult<string?>(_session.Token);
                })
                .AddJsonProtocol(p => SentinelJson.Configure(p.PayloadSerializerOptions))
                .WithAutomaticReconnect(new[]
                {
                    TimeSpan.Zero,
                    TimeSpan.FromSeconds(2),
                    TimeSpan.FromSeconds(5),
                    TimeSpan.FromSeconds(10),
                    TimeSpan.FromSeconds(20)
                })
                .Build();

            connection.On<EventDto>(LiveHub.EventScored, dto => EventScored?.Invoke(dto));
            connection.On<AlertDto>(LiveHub.AlertRaised, dto => AlertRaised?.Invoke(dto));
            connection.On<AlertDto>(LiveHub.AlertUpdated, dto => AlertUpdated?.Invoke(dto));
            connection.On<ClusterDto>(LiveHub.ClusterUpdated, dto => ClusterUpdated?.Invoke(dto));
            connection.On<ActionTicketDto>(LiveHub.ActionUpdated, dto => ActionUpdated?.Invoke(dto));
            connection.On<HostDto>(LiveHub.HostStatusChanged, dto => HostStatusChanged?.Invoke(dto));
            connection.On<DashboardSummaryDto>(LiveHub.SummaryChanged, dto => SummaryChanged?.Invoke(dto));
            connection.On<SentinelSettings>(LiveHub.SettingsChanged, dto => SettingsChanged?.Invoke(dto));
            connection.On<InAppNotificationDto>(LiveHub.NotificationPushed, dto => NotificationPushed?.Invoke(dto));

            connection.Reconnecting += ex =>
            {
                _logger.LogDebug(ex, "SignalR en cours de reconnexion...");
                SetState(LiveConnectionState.Reconnecting);
                return Task.CompletedTask;
            };

            connection.Reconnected += _ =>
            {
                _logger.LogInformation("SignalR reconnecté au serveur SENTINEL.");
                SetState(LiveConnectionState.Connected);
                return Task.CompletedTask;
            };

            connection.Closed += ex =>
            {
                _logger.LogDebug(ex, "Connexion SignalR fermée.");
                SetState(LiveConnectionState.Disconnected);
                return Task.CompletedTask;
            };

            _connection = connection;
            _connectedToken = token;

            try
            {
                await connection.StartAsync(ct);
                SetState(LiveConnectionState.Connected);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Connexion initiale au flux temps réel SignalR échouée ({HubUrl}).", hubUrl);
                SetState(LiveConnectionState.Disconnected);
            }
        }
        finally
        {
            _connectLock.Release();
        }
    }

    public async Task DisconnectAsync()
    {
        await _connectLock.WaitAsync();
        try
        {
            await DisposeConnectionInternalAsync();
            SetState(LiveConnectionState.Disconnected);
        }
        finally
        {
            _connectLock.Release();
        }
    }

    private async Task DisposeConnectionInternalAsync()
    {
        if (_connection is not null)
        {
            var conn = _connection;
            _connection = null;
            _connectedToken = null;
            try
            {
                await conn.DisposeAsync();
            }
            catch
            {
                // Ignoré lors de la fermeture
            }
        }
    }

    private void SetState(LiveConnectionState state)
    {
        if (State == state) return;
        State = state;
        StateChanged?.Invoke(state);
    }

    public async ValueTask DisposeAsync()
    {
        await DisconnectAsync();
        _connectLock.Dispose();
    }
}
