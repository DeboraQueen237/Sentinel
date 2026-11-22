using System.Diagnostics;
using System.Reflection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Sentinel.Core.Abstractions;
using Sentinel.Server.Configuration;
using Sentinel.Server.Services;
using Sentinel.Shared.Api;
using Sentinel.Storage;

namespace Sentinel.Server.Endpoints;

internal static class SystemEndpoints
{
    private static readonly string ServerVersion =
        Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "1.0.0";

    public static void MapSystemEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet(ApiRoutes.Ping, () => Results.Text("pong", "text/plain"));

        app.MapGet(ApiRoutes.Health, async (
            IDbContextFactory<SentinelDbContext> dbFactory,
            IThreatPipeline pipeline,
            AgentCommandHub commandHub,
            IOptions<SentinelServerOptions> options,
            CancellationToken ct) =>
        {
            bool dbOk;
            try
            {
                await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
                dbOk = await db.Database.CanConnectAsync(ct).ConfigureAwait(false);
            }
            catch
            {
                dbOk = false;
            }

            var stats = pipeline.Stats;
            var settings = pipeline.Settings;
            var llmRatio = stats.EventsProcessed > 0
                ? Math.Round((double)stats.LlmCalls / stats.EventsProcessed, 4)
                : 0.0;

            var workingSetMb = Process.GetCurrentProcess().WorkingSet64 / (1024 * 1024);

            var health = new SystemHealthDto(
                Version: ServerVersion,
                StartedAt: options.Value.StartedAt,
                DatabaseOk: dbOk,
                LlmAvailable: stats.LlmAvailable,
                LlmModel: settings.Llm.Model,
                LlmAvgLatencyMs: stats.AvgLlmLatencyMs,
                EventsProcessed: stats.EventsProcessed,
                AvgPipelineLatencyMs: stats.AvgPipelineLatencyMs,
                LlmUsageRatio: llmRatio,
                AgentsConnected: commandHub.ConnectedAgentCount,
                Mode: settings.Mode,
                ProcessWorkingSetMb: workingSetMb);

            return Results.Ok(health);
        });
    }
}
