using System.Collections.Concurrent;
using System.Threading.Channels;
using Sentinel.Shared.Grpc;
using Sentinel.Shared.Json;
using Sentinel.Storage.Entities;

namespace Sentinel.Server.Services;

/// <summary>
/// Gestionnaire thread-safe des flux gRPC <c>SubscribeCommands</c> par poste (<c>hostId</c>).
/// Permet la livraison immédiate des commandes temps réel et la détection des agents connectés.
/// </summary>
public sealed class AgentCommandHub
{
    public sealed class AgentSubscription : IDisposable
    {
        private readonly AgentCommandHub _hub;
        private int _disposed;

        internal AgentSubscription(AgentCommandHub hub, string hostId, Guid subscriptionId, Channel<AgentCommand> channel)
        {
            _hub = hub;
            HostId = hostId;
            SubscriptionId = subscriptionId;
            Channel = channel;
        }

        public string HostId { get; }
        public Guid SubscriptionId { get; }
        internal Channel<AgentCommand> Channel { get; }
        public ChannelReader<AgentCommand> Reader => Channel.Reader;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                _hub.Unregister(HostId, SubscriptionId);
                Channel.Writer.TryComplete();
            }
        }
    }

    private readonly ConcurrentDictionary<string, AgentSubscription> _subscriptions = new(StringComparer.OrdinalIgnoreCase);

    public int ConnectedAgentCount => _subscriptions.Count;

    public bool IsConnected(string hostId) =>
        !string.IsNullOrWhiteSpace(hostId) && _subscriptions.ContainsKey(hostId);

    public IReadOnlyCollection<string> GetConnectedHostIds() => _subscriptions.Keys.ToArray();

    /// <summary>
    /// Enregistre un nouveau flux de commandes pour <paramref name="hostId"/>.
    /// Si une ancienne souscription existait, elle est proprement fermée.
    /// </summary>
    public AgentSubscription Register(string hostId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(hostId);

        var channel = Channel.CreateBounded<AgentCommand>(new BoundedChannelOptions(512)
        {
            SingleReader = true,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.Wait
        });

        var sub = new AgentSubscription(this, hostId.Trim(), Guid.NewGuid(), channel);

        _subscriptions.AddOrUpdate(
            sub.HostId,
            sub,
            (_, existing) =>
            {
                existing.Channel.Writer.TryComplete();
                return sub;
            });

        return sub;
    }

    /// <summary>Tente d'envoyer immédiatement une commande à un agent actuellement connecté.</summary>
    public bool TryEnqueue(string hostId, AgentCommand command)
    {
        if (string.IsNullOrWhiteSpace(hostId) || command is null)
            return false;

        if (_subscriptions.TryGetValue(hostId.Trim(), out var sub))
        {
            return sub.Channel.Writer.TryWrite(command);
        }

        return false;
    }

    /// <summary>Construit un message protobuf <see cref="AgentCommand"/> à partir d'un ticket persisté.</summary>
    public static AgentCommand BuildCommand(ActionTicketEntity ticket, bool revert = false, bool simulate = false)
    {
        ArgumentNullException.ThrowIfNull(ticket);

        var cmd = new AgentCommand
        {
            CommandId = ticket.Id.ToString("D"),
            ActionType = ticket.ActionType,
            Target = ticket.Target ?? string.Empty,
            Revert = revert,
            RevertStateJson = ticket.RevertStateJson ?? string.Empty,
            Simulate = simulate
        };

        if (!string.IsNullOrWhiteSpace(ticket.ParametersJson))
        {
            try
            {
                var dict = SentinelJson.Deserialize<Dictionary<string, string>>(ticket.ParametersJson);
                if (dict is not null)
                {
                    foreach (var kv in dict)
                    {
                        if (!string.IsNullOrEmpty(kv.Key) && kv.Value is not null)
                            cmd.Parameters[kv.Key] = kv.Value;
                    }
                }
            }
            catch
            {
                // Ignoré : paramètres JSON malformés
            }
        }

        return cmd;
    }

    private void Unregister(string hostId, Guid subscriptionId)
    {
        if (_subscriptions.TryGetValue(hostId, out var current) && current.SubscriptionId == subscriptionId)
        {
            _subscriptions.TryRemove(new KeyValuePair<string, AgentSubscription>(hostId, current));
        }
    }
}
