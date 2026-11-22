using System.Threading.Channels;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Sentinel.Agent.Configuration;
using Sentinel.Agent.Storage;
using Sentinel.Shared.Models;

namespace Sentinel.Agent.Pipeline;

/// <summary>Point d'entrée unique des événements produits par les collecteurs et l'IPC.</summary>
public interface IEventSink
{
    bool Publish(SecurityEvent securityEvent);
    long TotalCollected { get; }
    long TotalDropped { get; }
    int PendingCount { get; }
}

/// <summary>
/// Pipeline mémoire borné (<see cref="Channel{T}"/>) déversant les événements par micro-lots dans
/// <see cref="SqliteEventOutbox"/> afin de ne jamais bloquer les collecteurs ni perdre d'événements.
/// </summary>
public sealed class AgentEventPipeline : BackgroundService, IEventSink
{
    private readonly Channel<SecurityEvent> _channel;
    private readonly SqliteEventOutbox _outbox;
    private readonly AgentStateStore _stateStore;
    private readonly ILogger<AgentEventPipeline> _logger;
    private readonly SemaphoreSlim _outboxReadySignal = new(0, int.MaxValue);

    private long _totalCollected;
    private long _totalDropped;

    public AgentEventPipeline(
        SqliteEventOutbox outbox,
        AgentStateStore stateStore,
        IOptions<AgentOptions> options,
        ILogger<AgentEventPipeline> logger)
    {
        _outbox = outbox;
        _stateStore = stateStore;
        _logger = logger;

        var capacity = Math.Clamp(options.Value.ChannelCapacity, 256, 65_536);
        _channel = Channel.CreateBounded<SecurityEvent>(new BoundedChannelOptions(capacity)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
            SingleWriter = false
        });
    }

    public long TotalCollected => Interlocked.Read(ref _totalCollected);
    public long TotalDropped => Interlocked.Read(ref _totalDropped);

    public int PendingCount
    {
        get
        {
            try
            {
                return _outbox.Count() + _channel.Reader.Count;
            }
            catch
            {
                return _channel.Reader.Count;
            }
        }
    }

    /// <summary>Permet au transport gRPC de se réveiller dès que de nouveaux événements sont persistés.</summary>
    public Task WaitForEventsAsync(TimeSpan timeout, CancellationToken cancellationToken) =>
        _outboxReadySignal.WaitAsync(timeout, cancellationToken);

    public bool Publish(SecurityEvent securityEvent)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);

        var normalized = securityEvent;
        if (string.IsNullOrWhiteSpace(normalized.HostId) || string.IsNullOrWhiteSpace(normalized.UserId))
        {
            normalized = normalized with
            {
                HostId = string.IsNullOrWhiteSpace(normalized.HostId) ? _stateStore.HostId : normalized.HostId,
                UserId = string.IsNullOrWhiteSpace(normalized.UserId) ? Environment.UserName : normalized.UserId
            };
        }

        if (_channel.Writer.TryWrite(normalized))
        {
            Interlocked.Increment(ref _totalCollected);
            return true;
        }

        Interlocked.Increment(ref _totalDropped);
        return false;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var buffer = new List<SecurityEvent>(128);
        try
        {
            while (await _channel.Reader.WaitToReadAsync(stoppingToken))
            {
                buffer.Clear();
                while (buffer.Count < 100 && _channel.Reader.TryRead(out var evt))
                {
                    buffer.Add(evt);
                }

                if (buffer.Count == 0)
                {
                    continue;
                }

                try
                {
                    _outbox.EnqueueBatch(buffer);
                    if (_outboxReadySignal.CurrentCount == 0)
                    {
                        _outboxReadySignal.Release();
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Échec de persistance d'un lot de {Count} événements dans l'outbox SQLite.", buffer.Count);
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Flush final des événements restants dans le canal avant arrêt.
            FlushRemaining();
        }
    }

    private void FlushRemaining()
    {
        var remaining = new List<SecurityEvent>();
        while (_channel.Reader.TryRead(out var evt))
        {
            remaining.Add(evt);
        }

        if (remaining.Count > 0)
        {
            try
            {
                _outbox.EnqueueBatch(remaining);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Échec lors du flush final de {Count} événements.", remaining.Count);
            }
        }
    }

    public override void Dispose()
    {
        _channel.Writer.TryComplete();
        _outboxReadySignal.Dispose();
        base.Dispose();
    }
}
