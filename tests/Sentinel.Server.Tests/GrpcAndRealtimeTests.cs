using Grpc.Core;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Server.Grpc;
using Sentinel.Server.Hubs;
using Sentinel.Server.Services;
using Sentinel.Shared.Api;
using Sentinel.Shared.Grpc;
using Sentinel.Shared.Json;
using Sentinel.Shared.Models;
using Sentinel.Storage;
using Sentinel.Storage.Services;
using System.Net;
using System.Net.Http.Json;

namespace Sentinel.Server.Tests;

public sealed class GrpcAndRealtimeTests
{
    [Fact]
    public async Task AgentGateway_Register_Heartbeat_SubmitEvents_SubscribeCommands_And_ReportResult_Work_EndToEnd()
    {
        using var factory = new SentinelServerFactory();
        var (client, _, _) = await factory.CreateAuthenticatedClientAsync();

        // Active le mode Active (sans LLM)
        var settings = await client.GetFromJsonAsync<SentinelSettings>(ApiRoutes.Settings, SentinelJson.Options);
        settings!.Mode = OperatingMode.Active;
        settings.Llm.Enabled = false;
        (await client.PutAsJsonAsync(ApiRoutes.Settings, settings, SentinelJson.Options)).EnsureSuccessStatusCode();

        var gateway = new AgentGatewayService(
            factory.Services.GetRequiredService<IDbContextFactory<SentinelDbContext>>(),
            factory.Services.GetRequiredService<EventIngestionService>(),
            factory.Services.GetRequiredService<AgentCommandHub>(),
            factory.Services.GetRequiredService<LiveBroadcaster>(),
            factory.Services.GetRequiredService<HashChainWriter>(),
            NullLogger<AgentGatewayService>.Instance);

        var ctx = new FakeServerCallContext();

        // 1. Register
        var hello = new AgentHello
        {
            HostId = "WS-GRPC-01",
            MachineName = "POSTE-GRPC-01",
            OsVersion = "Windows 11 24H2",
            AgentVersion = "1.0.0",
            BinarySha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        };
        hello.Users.Add("alice");

        var reg = await gateway.Register(hello, ctx);
        reg.Accepted.Should().BeTrue();
        reg.SettingsVersion.Should().BeGreaterThanOrEqualTo(2);
        reg.SettingsJson.Should().NotBeNullOrWhiteSpace();

        // 2. Heartbeat avec même version => settings_json vide
        var hbSame = await gateway.Heartbeat(new HeartbeatRequest
        {
            HostId = "WS-GRPC-01",
            CpuPercent = 1.4,
            WorkingSetBytes = 42 * 1024 * 1024,
            QueueLength = 0,
            SettingsVersion = reg.SettingsVersion
        }, ctx);
        hbSame.Ok.Should().BeTrue();
        hbSame.SettingsJson.Should().BeEmpty();

        // 3. Heartbeat avec ancienne version => renvoie settings_json
        var hbOld = await gateway.Heartbeat(new HeartbeatRequest
        {
            HostId = "WS-GRPC-01",
            CpuPercent = 1.6,
            WorkingSetBytes = 45 * 1024 * 1024,
            QueueLength = 0,
            SettingsVersion = 0
        }, ctx);
        hbOld.Ok.Should().BeTrue();
        hbOld.SettingsJson.Should().NotBeNullOrWhiteSpace();
        hbOld.SettingsVersion.Should().Be(reg.SettingsVersion);

        // 4. SubmitEvents via ProtoMapper
        var evt = SecurityEvent.Create(
            "WS-GRPC-01", "alice", EventCategory.Process, EventTypes.ProcessStart,
            @"C:\Users\alice\Downloads\dropper.exe",
            new Dictionary<string, string>
            {
                [AttributeKeys.ProcessName] = "dropper.exe",
                [AttributeKeys.Signed] = "false"
            });
        var batch = new EventBatch { HostId = "WS-GRPC-01", BatchSequence = 1 };
        batch.Events.Add(evt.ToProto());

        var ack = await gateway.SubmitEvents(batch, ctx);
        ack.Accepted.Should().Be(1);
        ack.Rejected.Should().Be(0);

        // Vérifie que le poste apparaît bien en ligne dans GET /api/hosts
        var hosts = await client.GetFromJsonAsync<HostDto[]>(ApiRoutes.Hosts, SentinelJson.Options);
        hosts.Should().Contain(h => h.HostId == "WS-GRPC-01" && h.Online);

        // 5. Crée une action manuelle PENDANT que l'agent est déconnecté -> doit être dépilée à la connexion SubscribeCommands
        var manualResp = await client.PostAsJsonAsync(
            ApiRoutes.Actions,
            new ManualActionRequest("WS-GRPC-01", ResponseActionType.BlockDomain, "c2.bad.xyz", "Blocage C2"),
            SentinelJson.Options);
        manualResp.StatusCode.Should().Be(HttpStatusCode.Created);
        var ticket = (await manualResp.Content.ReadFromJsonAsync<ActionTicketDto>(SentinelJson.Options))!;

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var streamCtx = new FakeServerCallContext(cts.Token);
        var writer = new CollectingStreamWriter<AgentCommand>(onWrite: _ => cts.Cancel());

        await gateway.SubscribeCommands(new CommandSubscription { HostId = "WS-GRPC-01" }, writer, streamCtx);

        writer.Items.Should().ContainSingle(c => c.CommandId == ticket.Id.ToString("D") && !c.Revert && c.Target == "c2.bad.xyz");

        // 6. ReportActionResult passe le ticket à Executed avec RevertStateJson
        var reportAck = await gateway.ReportActionResult(new ActionResultReport
        {
            CommandId = ticket.Id.ToString("D"),
            HostId = "WS-GRPC-01",
            Success = true,
            Message = "Domaine bloqué dans hosts + pare-feu.",
            RevertStateJson = "{\"ruleName\":\"Sentinel-Block-c2.bad.xyz\"}",
            WasRevert = false
        }, ctx);
        reportAck.Ok.Should().BeTrue();

        var actionsPage = await client.GetFromJsonAsync<PagedResult<ActionTicketDto>>($"{ApiRoutes.Actions}?hostId=WS-GRPC-01", SentinelJson.Options);
        var executed = actionsPage!.Items.Single(a => a.Id == ticket.Id);
        executed.Status.Should().Be(ActionStatus.Executed);
        executed.ExecutedAt.Should().NotBeNull();
    }

    [Fact]
    public async Task SignalR_LiveHub_Requires_Token_And_Accepts_AccessToken_Query_Parameter()
    {
        using var factory = new SentinelServerFactory();
        var (client, _, login) = await factory.CreateAuthenticatedClientAsync();

        // Sans jeton => 401 sur negotiate
        using var anonClient = factory.CreateClient();
        var unauthNegotiate = await anonClient.PostAsync($"{LiveHub.Path}/negotiate?negotiateVersion=1", content: null);
        unauthNegotiate.StatusCode.Should().Be(HttpStatusCode.Unauthorized);

        // Avec ?access_token= => 200 OK sur negotiate
        var authNegotiate = await anonClient.PostAsync(
            $"{LiveHub.Path}/negotiate?negotiateVersion=1&access_token={Uri.EscapeDataString(login.Token)}",
            content: null);
        authNegotiate.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    private sealed class CollectingStreamWriter<T>(Action<T>? onWrite = null) : IServerStreamWriter<T>
    {
        public List<T> Items { get; } = new();
        public WriteOptions? WriteOptions { get; set; }

        public Task WriteAsync(T message)
        {
            Items.Add(message);
            onWrite?.Invoke(message);
            return Task.CompletedTask;
        }
    }

    private sealed class FakeServerCallContext(CancellationToken ct = default) : ServerCallContext
    {
        protected override string MethodCore => "test";
        protected override string HostCore => "localhost";
        protected override string PeerCore => "127.0.0.1";
        protected override DateTime DeadlineCore => DateTime.MaxValue;
        protected override Metadata RequestHeadersCore => new();
        protected override CancellationToken CancellationTokenCore => ct;
        protected override Metadata ResponseTrailersCore => new();
        protected override Status StatusCore { get; set; }
        protected override WriteOptions? WriteOptionsCore { get; set; }
        protected override AuthContext AuthContextCore => new("test", new Dictionary<string, List<AuthProperty>>());
        protected override ContextPropagationToken CreatePropagationTokenCore(ContextPropagationOptions? options) => throw new NotImplementedException();
        protected override Task WriteResponseHeadersAsyncCore(Metadata responseHeaders) => Task.CompletedTask;
    }
}
