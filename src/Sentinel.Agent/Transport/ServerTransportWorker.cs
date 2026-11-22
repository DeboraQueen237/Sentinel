using System.Diagnostics;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Grpc.Core;
using Grpc.Net.Client;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Sentinel.Agent.Collectors;
using Sentinel.Agent.Configuration;
using Sentinel.Agent.Ipc;
using Sentinel.Agent.Pipeline;
using Sentinel.Agent.Response;
using Sentinel.Agent.Security;
using Sentinel.Agent.Storage;
using Sentinel.Shared.Grpc;
using Sentinel.Shared.Json;
using Sentinel.Shared.Models;
using Sentinel.Shared.Security;

namespace Sentinel.Agent.Transport;

/// <summary>
/// Client gRPC mTLS vers <c>Sentinel.Server</c> (doc §4, §11) :
/// - Enregistrement au démarrage (<c>Register</c>)
/// - Rejeu fiable par lots depuis <see cref="SqliteEventOutbox"/> (<c>SubmitEvents</c>, jusqu'à 100 événements / 2 s)
/// - Battement de cœur toutes les 15 s (<c>Heartbeat</c> + métriques CPU/RAM/collecteurs + mise à jour à chaud des paramètres)
/// - Flux continu de commandes de réponse (<c>SubscribeCommands</c>) avec reconnexion exponentielle.
/// </summary>
public sealed class ServerTransportWorker : BackgroundService
{
    private readonly AgentOptions _options;
    private readonly AgentStateStore _stateStore;
    private readonly SqliteEventOutbox _outbox;
    private readonly AgentEventPipeline _pipeline;
    private readonly CollectorHostService _collectorHost;
    private readonly AgentIpcServer _ipcServer;
    private readonly ActionExecutor _actionExecutor;
    private readonly SelfIntegrityChecker _integrityChecker;
    private readonly ILogger<ServerTransportWorker> _logger;

    private long _batchSequence;
    private X509Certificate2? _agentCert;
    private X509Certificate2? _caCert;
    private GrpcChannel? _channel;
    private AgentGateway.AgentGatewayClient? _client;
    private volatile bool _registered;

    private TimeSpan _lastCpuTotal = TimeSpan.Zero;
    private DateTimeOffset _lastCpuSampleTime = DateTimeOffset.UtcNow;

    public ServerTransportWorker(
        IOptions<AgentOptions> options,
        AgentStateStore stateStore,
        SqliteEventOutbox outbox,
        AgentEventPipeline pipeline,
        CollectorHostService collectorHost,
        AgentIpcServer ipcServer,
        ActionExecutor actionExecutor,
        SelfIntegrityChecker integrityChecker,
        ILogger<ServerTransportWorker> logger)
    {
        _options = options.Value;
        _stateStore = stateStore;
        _outbox = outbox;
        _pipeline = pipeline;
        _collectorHost = collectorHost;
        _ipcServer = ipcServer;
        _actionExecutor = actionExecutor;
        _integrityChecker = integrityChecker;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _integrityChecker.VerifyAndReportStartup();
        InitializeGrpcClient();

        using (var proc = Process.GetCurrentProcess())
        {
            _lastCpuTotal = proc.TotalProcessorTime;
            _lastCpuSampleTime = DateTimeOffset.UtcNow;
        }

        var heartbeatTask = Task.Run(() => RegistrationAndHeartbeatLoopAsync(stoppingToken), stoppingToken);
        var flushTask = Task.Run(() => EventOutboxFlushLoopAsync(stoppingToken), stoppingToken);
        var commandTask = Task.Run(() => CommandSubscriptionLoopAsync(stoppingToken), stoppingToken);

        await Task.WhenAll(heartbeatTask, flushTask, commandTask);
    }

    private void InitializeGrpcClient()
    {
        var handler = new SocketsHttpHandler
        {
            PooledConnectionIdleTimeout = Timeout.InfiniteTimeSpan,
            KeepAlivePingDelay = TimeSpan.FromSeconds(30),
            KeepAlivePingTimeout = TimeSpan.FromSeconds(15),
            EnableMultipleHttp2Connections = true
        };

        var uri = new Uri(_options.ServerGrpcUrl);
        if (_options.UseMtls && uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                SentinelPki.EnsureCertificates();
                _agentCert = SentinelPki.LoadAgentCertificate();
                _caCert = SentinelPki.LoadCaCertificate();

                handler.SslOptions = new SslClientAuthenticationOptions
                {
                    ClientCertificates = new X509CertificateCollection { _agentCert },
                    RemoteCertificateValidationCallback = (_, cert, _, _) => ValidateServerCertificate(cert, _caCert)
                };
                _logger.LogInformation("Transport gRPC configuré en mode mTLS vers {Url}.", _options.ServerGrpcUrl);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Impossible d'initialiser les certificats mTLS SENTINEL ; tentative de connexion standard.");
            }
        }
        else
        {
            _logger.LogInformation("Transport gRPC configuré sans mTLS vers {Url}.", _options.ServerGrpcUrl);
        }

        _channel = GrpcChannel.ForAddress(_options.ServerGrpcUrl, new GrpcChannelOptions
        {
            HttpHandler = handler,
            MaxReceiveMessageSize = 16 * 1024 * 1024,
            MaxSendMessageSize = 16 * 1024 * 1024
        });
        _client = new AgentGateway.AgentGatewayClient(_channel);
    }

    private static bool ValidateServerCertificate(X509Certificate? cert, X509Certificate2 caCert)
    {
        if (cert is null) return false;
        if (cert is X509Certificate2 c2)
        {
            return SentinelPki.ValidateIssuedBy(c2, caCert);
        }

        using var copy = new X509Certificate2(cert);
        return SentinelPki.ValidateIssuedBy(copy, caCert);
    }

    private async Task RegistrationAndHeartbeatLoopAsync(CancellationToken ct)
    {
        var backoffSeconds = 2;
        var interval = TimeSpan.FromSeconds(Math.Clamp(_options.HeartbeatIntervalSeconds, 5, 120));

        while (!ct.IsCancellationRequested)
        {
            if (_client is null)
            {
                await Task.Delay(TimeSpan.FromSeconds(2), ct);
                continue;
            }

            try
            {
                if (!_registered)
                {
                    var hello = new AgentHello
                    {
                        HostId = _stateStore.HostId,
                        MachineName = Environment.MachineName,
                        OsVersion = Environment.OSVersion.VersionString,
                        AgentVersion = _integrityChecker.AgentVersion,
                        BinarySha256 = _integrityChecker.BinarySha256
                    };
                    var users = _ipcServer.GetConnectedUsers();
                    if (users.Count == 0)
                    {
                        hello.Users.Add(Environment.UserName);
                    }
                    else
                    {
                        hello.Users.AddRange(users);
                    }

                    var reg = await _client.RegisterAsync(hello, deadline: DateTime.UtcNow.AddSeconds(10), cancellationToken: ct);
                    if (reg.Accepted)
                    {
                        _registered = true;
                        backoffSeconds = 2;
                        _logger.LogInformation("Agent enregistré auprès de Sentinel.Server (HostId={HostId}, config v{Version}).",
                            _stateStore.HostId, reg.SettingsVersion);
                        ApplySettingsJson(reg.SettingsJson, reg.SettingsVersion);
                    }
                    else
                    {
                        _logger.LogWarning("Enregistrement refusé par Sentinel.Server : {Message}", reg.Message);
                    }
                }

                if (_registered)
                {
                    var req = BuildHeartbeatRequest();
                    var reply = await _client.HeartbeatAsync(req, deadline: DateTime.UtcNow.AddSeconds(10), cancellationToken: ct);
                    if (reply.Ok && !string.IsNullOrWhiteSpace(reply.SettingsJson))
                    {
                        ApplySettingsJson(reply.SettingsJson, reply.SettingsVersion);
                    }
                    await Task.Delay(interval, ct);
                }
                else
                {
                    await Task.Delay(TimeSpan.FromSeconds(backoffSeconds), ct);
                    backoffSeconds = Math.Min(backoffSeconds * 2, 30);
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _registered = false;
                _logger.LogWarning("Serveur gRPC indisponible ({Error}) ; nouvel essai dans {Delay} s (file locale : {Queue}).",
                    ex.Message, backoffSeconds, _pipeline.PendingCount);
                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(backoffSeconds), ct);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                backoffSeconds = Math.Min(backoffSeconds * 2, 30);
            }
        }
    }

    private async Task EventOutboxFlushLoopAsync(CancellationToken ct)
    {
        var batchSize = Math.Clamp(_options.BatchSize, 10, 500);
        var flushDelay = TimeSpan.FromMilliseconds(Math.Clamp(_options.BatchFlushIntervalMs, 250, 30_000));
        var backoffSeconds = 2;

        while (!ct.IsCancellationRequested)
        {
            try
            {
                await _pipeline.WaitForEventsAsync(flushDelay, ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                break;
            }

            if (_client is null)
            {
                continue;
            }

            while (!ct.IsCancellationRequested)
            {
                var batchEntries = _outbox.PeekBatch(batchSize);
                if (batchEntries.Count == 0)
                {
                    backoffSeconds = 2;
                    break;
                }

                var batch = new EventBatch
                {
                    HostId = _stateStore.HostId,
                    BatchSequence = Interlocked.Increment(ref _batchSequence)
                };
                foreach (var entry in batchEntries)
                {
                    batch.Events.Add(entry.Event.ToProto());
                }

                try
                {
                    var ack = await _client.SubmitEventsAsync(batch, deadline: DateTime.UtcNow.AddSeconds(15), cancellationToken: ct);
                    _outbox.Acknowledge(batchEntries.Select(e => e.Sequence));
                    backoffSeconds = 2;

                    if (ack.Rejected > 0)
                    {
                        _logger.LogWarning("Lot #{Seq} : {Accepted} accepté(s), {Rejected} rejeté(s) ({Msg}).",
                            batch.BatchSequence, ack.Accepted, ack.Rejected, ack.Message);
                    }

                    // Si le lot n'était pas plein, on attend la prochaine fenêtre.
                    if (batchEntries.Count < batchSize)
                    {
                        break;
                    }
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    return;
                }
                catch (Exception ex)
                {
                    _logger.LogDebug("Envoi du lot d'événements différé ({Error}) ; conservation dans l'outbox SQLite ({Count} en attente).",
                        ex.Message, _outbox.Count());
                    try
                    {
                        await Task.Delay(TimeSpan.FromSeconds(backoffSeconds), ct);
                    }
                    catch (OperationCanceledException)
                    {
                        return;
                    }
                    backoffSeconds = Math.Min(backoffSeconds * 2, 30);
                    break;
                }
            }
        }
    }

    private async Task CommandSubscriptionLoopAsync(CancellationToken ct)
    {
        var backoffSeconds = 2;

        while (!ct.IsCancellationRequested)
        {
            if (_client is null)
            {
                await Task.Delay(TimeSpan.FromSeconds(2), ct);
                continue;
            }

            try
            {
                using var call = _client.SubscribeCommands(
                    new CommandSubscription { HostId = _stateStore.HostId },
                    cancellationToken: ct);

                backoffSeconds = 2;
                _logger.LogInformation("Flux de commandes SubscribeCommands connecté.");

                await foreach (var cmd in call.ResponseStream.ReadAllAsync(ct))
                {
                    _logger.LogInformation("Commande reçue : {CommandId} (action={Action}, cible={Target}, revert={Revert}, sim={Sim}).",
                        cmd.CommandId, (ResponseActionType)cmd.ActionType, cmd.Target, cmd.Revert, cmd.Simulate);

                    var report = await _actionExecutor.ExecuteAsync(cmd, ct);

                    try
                    {
                        await _client.ReportActionResultAsync(report, deadline: DateTime.UtcNow.AddSeconds(10), cancellationToken: ct);
                    }
                    catch (Exception reportEx)
                    {
                        _logger.LogWarning(reportEx, "Échec de remontée du résultat pour la commande {CommandId}.", cmd.CommandId);
                    }
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                break;
            }
            catch (RpcException ex) when (ex.StatusCode == StatusCode.Cancelled && ct.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogDebug("Flux SubscribeCommands interrompu ({Error}) ; reconnexion dans {Delay} s.", ex.Message, backoffSeconds);
                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(backoffSeconds), ct);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                backoffSeconds = Math.Min(backoffSeconds * 2, 30);
            }
        }
    }

    private HeartbeatRequest BuildHeartbeatRequest()
    {
        double cpuPercent = 0;
        long workingSet = 0;
        try
        {
            using var proc = Process.GetCurrentProcess();
            workingSet = proc.WorkingSet64;
            var now = DateTimeOffset.UtcNow;
            var elapsedMs = (now - _lastCpuSampleTime).TotalMilliseconds;
            var cpuTotal = proc.TotalProcessorTime;
            if (elapsedMs > 100)
            {
                var cpuDeltaMs = (cpuTotal - _lastCpuTotal).TotalMilliseconds;
                cpuPercent = Math.Clamp(cpuDeltaMs / (elapsedMs * Environment.ProcessorCount) * 100.0, 0.0, 100.0);
                _lastCpuTotal = cpuTotal;
                _lastCpuSampleTime = now;
            }
        }
        catch
        {
            // Ignoré.
        }

        var req = new HeartbeatRequest
        {
            HostId = _stateStore.HostId,
            CpuPercent = Math.Round(cpuPercent, 2),
            WorkingSetBytes = workingSet,
            QueueLength = _pipeline.PendingCount,
            EventsCollected = _pipeline.TotalCollected,
            SettingsVersion = _stateStore.SettingsVersion
        };
        req.Collectors.AddRange(_collectorHost.GetStatuses());
        return req;
    }

    private void ApplySettingsJson(string? settingsJson, long version)
    {
        if (string.IsNullOrWhiteSpace(settingsJson))
        {
            return;
        }

        try
        {
            var settings = SentinelJson.Deserialize<SentinelSettings>(settingsJson);
            if (settings is not null)
            {
                _stateStore.UpdateSettings(settings, version);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Impossible de désérialiser settings_json reçu du serveur.");
        }
    }

    public override void Dispose()
    {
        _channel?.Dispose();
        _agentCert?.Dispose();
        _caCert?.Dispose();
        base.Dispose();
    }
}
