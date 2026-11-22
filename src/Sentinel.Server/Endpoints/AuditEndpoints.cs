using Microsoft.EntityFrameworkCore;
using Sentinel.Shared.Api;
using Sentinel.Storage;
using Sentinel.Storage.Mapping;
using Sentinel.Storage.Services;

namespace Sentinel.Server.Endpoints;

internal static class AuditEndpoints
{
    public static void MapAuditEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet(ApiRoutes.Audit, async (
            string? actor,
            string? action,
            DateTimeOffset? from,
            DateTimeOffset? to,
            int? page,
            int? pageSize,
            IDbContextFactory<SentinelDbContext> dbFactory,
            CancellationToken ct) =>
        {
            var (p, ps) = EndpointHelpers.NormalizePaging(page, pageSize, defaultSize: 50, maxSize: 200);

            await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
            var query = db.AuditEntries.AsNoTracking().AsQueryable();

            if (!string.IsNullOrWhiteSpace(actor))
                query = query.Where(a => a.Actor == actor.Trim());
            if (!string.IsNullOrWhiteSpace(action))
                query = query.Where(a => a.Action == action.Trim());
            if (from.HasValue)
                query = query.Where(a => a.TimestampUnixMs >= from.Value.ToUnixTimeMilliseconds());
            if (to.HasValue)
                query = query.Where(a => a.TimestampUnixMs <= to.Value.ToUnixTimeMilliseconds());

            var total = await query.CountAsync(ct).ConfigureAwait(false);
            var items = await query
                .OrderByDescending(a => a.Id)
                .Skip((p - 1) * ps)
                .Take(ps)
                .ToListAsync(ct)
                .ConfigureAwait(false);

            return Results.Ok(new PagedResult<AuditEntryDto>(items.Select(a => a.ToDto()).ToArray(), total, p, ps));
        });

        app.MapGet(ApiRoutes.AuditVerify, async (
            IntegrityVerifier verifier,
            CancellationToken ct) =>
        {
            var reports = await verifier.VerifyAllAsync(ct).ConfigureAwait(false);
            return Results.Ok(reports);
        });
    }
}
