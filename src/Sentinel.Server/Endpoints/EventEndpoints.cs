using Microsoft.EntityFrameworkCore;
using Sentinel.Shared.Api;
using Sentinel.Shared.Models;
using Sentinel.Storage;
using Sentinel.Storage.Mapping;

namespace Sentinel.Server.Endpoints;

internal static class EventEndpoints
{
    public static void MapEventEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet(ApiRoutes.Events, async (
            string? category,
            int? minScore,
            string? hostId,
            string? search,
            DateTimeOffset? from,
            DateTimeOffset? to,
            int? page,
            int? pageSize,
            IDbContextFactory<SentinelDbContext> dbFactory,
            CancellationToken ct) =>
        {
            var (p, ps) = EndpointHelpers.NormalizePaging(page, pageSize, defaultSize: 50, maxSize: 200);
            var parsedCat = EndpointHelpers.TryParseEnum<EventCategory>(category);

            await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
            var query = db.Events.AsNoTracking().AsQueryable();

            if (parsedCat.HasValue) query = query.Where(e => e.Category == (int)parsedCat.Value);
            if (minScore.HasValue) query = query.Where(e => e.Score >= minScore.Value);
            if (!string.IsNullOrWhiteSpace(hostId)) query = query.Where(e => e.HostId == hostId.Trim());
            if (from.HasValue) query = query.Where(e => e.TimestampUnixMs >= from.Value.ToUnixTimeMilliseconds());
            if (to.HasValue) query = query.Where(e => e.TimestampUnixMs <= to.Value.ToUnixTimeMilliseconds());

            if (!string.IsNullOrWhiteSpace(search))
            {
                var term = $"%{search.Trim()}%";
                query = query.Where(e =>
                    EF.Functions.Like(e.Subject, term) ||
                    EF.Functions.Like(e.EventType, term) ||
                    EF.Functions.Like(e.HostId, term) ||
                    EF.Functions.Like(e.UserId, term) ||
                    EF.Functions.Like(e.Justification, term) ||
                    EF.Functions.Like(e.AttributesJson, term));
            }

            var total = await query.CountAsync(ct).ConfigureAwait(false);
            var items = await query
                .OrderByDescending(e => e.TimestampUnixMs)
                .Skip((p - 1) * ps)
                .Take(ps)
                .ToListAsync(ct)
                .ConfigureAwait(false);

            return Results.Ok(new PagedResult<EventDto>(items.Select(e => e.ToDto()).ToArray(), total, p, ps));
        });

        app.MapGet(ApiRoutes.EventById, async (
            Guid id,
            IDbContextFactory<SentinelDbContext> dbFactory,
            CancellationToken ct) =>
        {
            await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
            var evt = await db.Events.AsNoTracking().FirstOrDefaultAsync(e => e.Id == id, ct).ConfigureAwait(false);
            if (evt is null)
                return EndpointHelpers.Error(StatusCodes.Status404NotFound, "EVENT_NOT_FOUND", "Événement introuvable.");

            return Results.Ok(evt.ToDto());
        });
    }
}
