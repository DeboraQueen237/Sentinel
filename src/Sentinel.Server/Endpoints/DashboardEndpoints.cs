using Sentinel.Server.Services;
using Sentinel.Shared.Api;

namespace Sentinel.Server.Endpoints;

internal static class DashboardEndpoints
{
    public static void MapDashboardEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet(ApiRoutes.DashboardSummary, async (DashboardService dashboard, CancellationToken ct) =>
        {
            var summary = await dashboard.GetSummaryAsync(ct).ConfigureAwait(false);
            return Results.Ok(summary);
        });

        app.MapGet(ApiRoutes.DashboardTimeline, async (string? range, DashboardService dashboard, CancellationToken ct) =>
        {
            var series = await dashboard.GetTimelineAsync(range, ct).ConfigureAwait(false);
            return Results.Ok(series);
        });
    }
}
