using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Sentinel.Agent.Configuration;
using Sentinel.Agent.Pipeline;
using Sentinel.Agent.Response;
using Sentinel.Shared.Ipc;
using Sentinel.Shared.Json;
using Sentinel.Shared.Models;

namespace Sentinel.Agent.Ipc;

/// <summary>
/// Serveur IPC Named Pipe multi-clients sur <see cref="IpcProtocol.PipeName"/> reliant l'agent
/// (service Windows) aux processus en session utilisateur : <c>Sentinel.Tray</c> et <c>Sentinel.BrowserHost</c>.
/// Protocole JSON Lines UTF-8 (doc §4, contrat <see cref="IpcProtocol"/>).
/// </summary>
public sealed class AgentIpcServer : BackgroundService
{
    private readonly IEventSink _sink;
    private readonly AgentStateStore _stateStore;
    private readonly HostsFileManager _hostsManager;
    private readonly ILogger<AgentIpcServer> _logger;
    private readonly ConcurrentDictionary<Guid, ClientSession> _clients = new();

    public AgentIpcServer(
        IEventSink sink,
        AgentStateStore stateStore,
        HostsFileManager hostsManager,
        ILogger<AgentIpcServer> logger)
    {
        _sink = sink;
        _stateStore = stateStore;
        _hostsManager = hostsManager;
        _logger = logger;

        _stateStore.SettingsChanged += OnSettingsChanged;
    }

    public int ConnectedClientCount => _clients.Count;

    public IReadOnlyList<string> GetConnectedUsers() =>
        _clients.Values
            .Select(c => c.UserName)
            .Where(u => !string.IsNullOrWhiteSpace(u))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

    public Task BroadcastSettingsAsync(SentinelSettings settings, CancellationToken cancellationToken = default)
    {
        var payload = BuildClientSettings(settings);
        return BroadcastAsync(IpcMessage.Create(IpcProtocol.ClientSettings, payload), filter: null, cancellationToken);
    }

    public Task<int> SendNotificationAsync(UserNotification notification, CancellationToken cancellationToken = default) =>
        BroadcastAsync(IpcMessage.Create(IpcProtocol.Notify, notification), c => c.Kind == IpcClientKind.Tray, cancellationToken);

    public Task<int> SendLockSessionAsync(CancellationToken cancellationToken = default) =>
        BroadcastAsync(new IpcMessage(IpcProtocol.LockSession, null), c => c.Kind == IpcClientKind.Tray, cancellationToken);

    public Task<int> SendCloseTabAsync(BrowserCommand command, CancellationToken cancellationToken = default) =>
        BroadcastAsync(IpcMessage.Create(IpcProtocol.CloseTab, command), c => c.Kind == IpcClientKind.BrowserHost, cancellationToken);

    public Task<int> SendBlockDomainsAsync(BrowserCommand command, CancellationToken cancellationToken = default) =>
        BroadcastAsync(IpcMessage.Create(IpcProtocol.BlockDomains, command), c => c.Kind == IpcClientKind.BrowserHost, cancellationToken);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Serveur IPC Named Pipe en écoute sur \\\\.\\pipe\\{PipeName}.", IpcProtocol.PipeName);

        while (!stoppingToken.IsCancellationRequested)
        {
            NamedPipeServerStream? server = null;
            try
            {
                server = CreatePipeServer();
                await server.WaitForConnectionAsync(stoppingToken);

                var connectedPipe = server;
                server = null; // propriété transférée à la tâche client
                _ = Task.Run(() => HandleClientAsync(connectedPipe, stoppingToken), stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                server?.Dispose();
                break;
            }
            catch (Exception ex)
            {
                server?.Dispose();
                _logger.LogWarning(ex, "Erreur lors de l'acceptation d'une connexion IPC ; nouvelle tentative dans 1 s.");
                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }
    }

    private async Task HandleClientAsync(NamedPipeServerStream pipe, CancellationToken stoppingToken)
    {
        var sessionId = Guid.NewGuid();
        using var reader = new StreamReader(pipe, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, bufferSize: 4096, leaveOpen: true);
        using var writer = new StreamWriter(pipe, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false), bufferSize: 4096, leaveOpen: true)
        {
            AutoFlush = true
        };

        var session = new ClientSession(sessionId, pipe, writer);
        _clients[sessionId] = session;

        try
        {
            while (!stoppingToken.IsCancellationRequested && pipe.IsConnected)
            {
                var line = await reader.ReadLineAsync(stoppingToken);
                if (line is null)
                {
                    break;
                }

                if (string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }

                IpcMessage? msg;
                try
                {
                    msg = SentinelJson.Deserialize<IpcMessage>(line);
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Trame IPC JSON invalide ignorée.");
                    continue;
                }

                if (msg is null)
                {
                    continue;
                }

                await ProcessClientMessageAsync(session, msg, stoppingToken);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Arrêt normal.
        }
        catch (IOException)
        {
            // Déconnexion normale du client.
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Fin de session IPC ({Kind}, {User}).", session.Kind, session.UserName);
        }
        finally
        {
            _clients.TryRemove(sessionId, out _);
            session.Dispose();
            pipe.Dispose();
            _logger.LogInformation("Client IPC déconnecté : {Kind} ({User}).", session.Kind, session.UserName);
        }
    }

    private async Task ProcessClientMessageAsync(ClientSession session, IpcMessage message, CancellationToken ct)
    {
        switch (message.Type)
        {
            case IpcProtocol.Hello:
                var hello = message.As<IpcHello>();
                if (hello is not null)
                {
                    session.Kind = hello.Kind;
                    session.UserName = string.IsNullOrWhiteSpace(hello.UserName) ? Environment.UserName : hello.UserName;
                    session.WindowsSessionId = hello.SessionId;
                    _logger.LogInformation("Client IPC connecté : {Kind} (utilisateur {User}, session {SessionId}, v{Version}).",
                        hello.Kind, session.UserName, hello.SessionId, hello.Version);

                    var welcome = IpcMessage.Create(IpcProtocol.Welcome, BuildClientSettings(_stateStore.CurrentSettings));
                    await session.SendAsync(welcome, ct);
                }
                break;

            case IpcProtocol.Event:
                var evt = message.As<SecurityEvent>();
                if (evt is not null)
                {
                    var enriched = evt with
                    {
                        HostId = string.IsNullOrWhiteSpace(evt.HostId) ? _stateStore.HostId : evt.HostId,
                        UserId = string.IsNullOrWhiteSpace(evt.UserId) ? session.UserName : evt.UserId
                    };
                    _sink.Publish(enriched);
                }
                break;

            case IpcProtocol.Ping:
                await session.SendAsync(new IpcMessage(IpcProtocol.Pong, null), ct);
                break;
        }
    }

    private async Task<int> BroadcastAsync(IpcMessage message, Func<ClientSession, bool>? filter, CancellationToken ct)
    {
        var delivered = 0;
        foreach (var (_, client) in _clients)
        {
            if (filter is not null && !filter(client))
            {
                continue;
            }

            if (await client.SendAsync(message, ct))
            {
                delivered++;
            }
        }

        return delivered;
    }

    private IpcClientSettings BuildClientSettings(SentinelSettings settings) =>
        new(
            settings.EnableClipboardMonitoring,
            settings.EnableTypingRhythm,
            settings.EnableBrowserMonitoring,
            settings.Mode,
            _hostsManager.GetBlockedDomains());

    private void OnSettingsChanged(SentinelSettings settings)
    {
        _ = Task.Run(() => BroadcastSettingsAsync(settings));
    }

    private NamedPipeServerStream CreatePipeServer()
    {
        try
        {
            var security = new PipeSecurity();
            security.AddAccessRule(new PipeAccessRule(
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                PipeAccessRights.FullControl,
                AccessControlType.Allow));
            security.AddAccessRule(new PipeAccessRule(
                new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                PipeAccessRights.FullControl,
                AccessControlType.Allow));
            security.AddAccessRule(new PipeAccessRule(
                new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
                PipeAccessRights.ReadWrite,
                AccessControlType.Allow));

            return NamedPipeServerStreamAcl.Create(
                IpcProtocol.PipeName,
                PipeDirection.InOut,
                NamedPipeServerStream.MaxAllowedServerInstances,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous,
                inBufferSize: 8192,
                outBufferSize: 8192,
                pipeSecurity: security);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Création du pipe avec ACL personnalisée impossible ; utilisation des ACL par défaut.");
            return new NamedPipeServerStream(
                IpcProtocol.PipeName,
                PipeDirection.InOut,
                NamedPipeServerStream.MaxAllowedServerInstances,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous,
                inBufferSize: 8192,
                outBufferSize: 8192);
        }
    }

    public override void Dispose()
    {
        _stateStore.SettingsChanged -= OnSettingsChanged;
        base.Dispose();
    }

    private sealed class ClientSession(Guid id, NamedPipeServerStream pipe, StreamWriter writer) : IDisposable
    {
        private readonly SemaphoreSlim _writeLock = new(1, 1);

        public Guid Id { get; } = id;
        public IpcClientKind Kind { get; set; } = IpcClientKind.Tray;
        public string UserName { get; set; } = Environment.UserName;
        public int WindowsSessionId { get; set; }

        public async Task<bool> SendAsync(IpcMessage message, CancellationToken ct)
        {
            if (!pipe.IsConnected)
            {
                return false;
            }

            await _writeLock.WaitAsync(ct);
            try
            {
                if (!pipe.IsConnected)
                {
                    return false;
                }
                var line = SentinelJson.Serialize(message);
                await writer.WriteLineAsync(line.AsMemory(), ct);
                return true;
            }
            catch
            {
                return false;
            }
            finally
            {
                _writeLock.Release();
            }
        }

        public void Dispose() => _writeLock.Dispose();
    }
}
