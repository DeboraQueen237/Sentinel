using Sentinel.Server.Services;
using Sentinel.Shared.Api;
using Sentinel.Storage.Services;

namespace Sentinel.Server.Endpoints;

internal static class HostEntityEndpoints
{
    public static void MapHostEntityEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet(ApiRoutes.Hosts, async (EntityProfileService profiles, CancellationToken ct) =>
        {
            var hosts = await profiles.GetHostsAsync(ct).ConfigureAwait(false);
            return Results.Ok(hosts);
        });

        app.MapGet(ApiRoutes.Entities, async (
            string? kind,
            string? search,
            int? limit,
            EntityProfileService profiles,
            CancellationToken ct) =>
        {
            var parsedKind = EndpointHelpers.TryParseEnum<EntityKind>(kind);
            var list = await profiles.ListEntitiesAsync(parsedKind, search, limit ?? 100, ct).ConfigureAwait(false);
            return Results.Ok(list);
        });

        // Route catch-all {*key} pour supporter les chemins Windows (\) et URLs encodées par Uri.EscapeDataString
        app.MapGet("/api/entities/{kind}/{*key}", async (
            string kind,
            string key,
            HttpContext ctx,
            EntityProfileService profiles,
            HashChainWriter auditWriter,
            CancellationToken ct) =>
        {
            var parsedKind = EndpointHelpers.TryParseEnum<EntityKind>(kind);
            if (!parsedKind.HasValue)
                return EndpointHelpers.Error(StatusCodes.Status400BadRequest, "INVALID_ENTITY_KIND", $"Type d'entité inconnu : '{kind}'.");

            var decodedKey = Uri.UnescapeDataString(key ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(decodedKey))
                return EndpointHelpers.Error(StatusCodes.Status400BadRequest, "INVALID_ENTITY_KEY", "Clé d'entité requise.");

            // Exigence transparence / éthique (doc §2.3, §10.2) : toute consultation de fiche est journalisée dans l'audit
            await auditWriter.WriteAuditAsync(
                EndpointHelpers.GetActor(ctx),
                "EntityProfileViewed",
                $"{parsedKind.Value}:{decodedKey}",
                $"Consultation de la fiche {parsedKind.Value} « {decodedKey} ».",
                EndpointHelpers.GetClientIp(ctx),
                ct).ConfigureAwait(false);

            var profile = await profiles.GetProfileAsync(parsedKind.Value, decodedKey, ct).ConfigureAwait(false);
            if (profile is null)
                return EndpointHelpers.Error(StatusCodes.Status404NotFound, "ENTITY_NOT_FOUND", $"Entité {parsedKind.Value} '{decodedKey}' introuvable.");

            return Results.Ok(profile);
        });
    }
}
