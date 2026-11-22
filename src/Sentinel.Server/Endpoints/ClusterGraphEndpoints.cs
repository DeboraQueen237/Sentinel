using Microsoft.EntityFrameworkCore;
using Sentinel.Server.Services;
using Sentinel.Shared.Api;
using Sentinel.Storage;
using Sentinel.Storage.Mapping;

namespace Sentinel.Server.Endpoints;

internal static class ClusterGraphEndpoints
{
    public static void MapClusterGraphEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet(ApiRoutes.Clusters, async (
            int? minScore,
            string? hostId,
            DateTimeOffset? from,
            DateTimeOffset? to,
            int? page,
            int? pageSize,
            IDbContextFactory<SentinelDbContext> dbFactory,
            CancellationToken ct) =>
        {
            var (p, ps) = EndpointHelpers.NormalizePaging(page, pageSize);

            await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
            var query = db.Clusters.AsNoTracking().AsQueryable();

            if (minScore.HasValue) query = query.Where(c => c.Score >= minScore.Value);
            if (!string.IsNullOrWhiteSpace(hostId)) query = query.Where(c => c.HostId == hostId.Trim());
            if (from.HasValue) query = query.Where(c => c.LastSeenUnixMs >= from.Value.ToUnixTimeMilliseconds());
            if (to.HasValue) query = query.Where(c => c.LastSeenUnixMs <= to.Value.ToUnixTimeMilliseconds());

            var total = await query.CountAsync(ct).ConfigureAwait(false);
            var items = await query
                .OrderByDescending(c => c.LastSeenUnixMs)
                .Skip((p - 1) * ps)
                .Take(ps)
                .ToListAsync(ct)
                .ConfigureAwait(false);

            return Results.Ok(new PagedResult<ClusterDto>(items.Select(c => c.ToDto()).ToArray(), total, p, ps));
        });

        app.MapGet(ApiRoutes.ClusterById, async (
            Guid id,
            IDbContextFactory<SentinelDbContext> dbFactory,
            CancellationToken ct) =>
        {
            await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
            var cluster = await db.Clusters.AsNoTracking().FirstOrDefaultAsync(c => c.Id == id, ct).ConfigureAwait(false);
            if (cluster is null)
                return EndpointHelpers.Error(StatusCodes.Status404NotFound, "CLUSTER_NOT_FOUND", "Cluster introuvable.");

            return Results.Ok(cluster.ToDto());
        });

        app.MapGet(ApiRoutes.Graph, async (
            DateTimeOffset? from,
            DateTimeOffset? to,
            string? hostId,
            int? minScore,
            Guid? clusterId,
            int? limit,
            GraphBuilderService graphBuilder,
            CancellationToken ct) =>
        {
            var graph = await graphBuilder.BuildGraphAsync(
                from, to, hostId, minScore, clusterId, limit ?? 150, ct).ConfigureAwait(false);
            return Results.Ok(graph);
        });
    }
}
