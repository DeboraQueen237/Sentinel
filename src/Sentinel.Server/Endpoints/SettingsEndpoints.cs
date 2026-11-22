using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Sentinel.Core.Abstractions;
using Sentinel.Server.Hubs;
using Sentinel.Shared.Api;
using Sentinel.Shared.Json;
using Sentinel.Shared.Models;
using Sentinel.Storage;
using Sentinel.Storage.Entities;
using Sentinel.Storage.Services;

namespace Sentinel.Server.Endpoints;

internal static class SettingsEndpoints
{
    public static void MapSettingsEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet(ApiRoutes.Settings, async (
            IDbContextFactory<SentinelDbContext> dbFactory,
            IThreatPipeline pipeline,
            CancellationToken ct) =>
        {
            await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
            var entity = await db.Settings.AsNoTracking()
                .FirstOrDefaultAsync(s => s.Id == SettingsEntity.SingletonId, ct)
                .ConfigureAwait(false);

            var settings = entity is not null
                ? SentinelJson.Deserialize<SentinelSettings>(entity.SettingsJson) ?? pipeline.Settings
                : pipeline.Settings;

            return Results.Ok(settings);
        });

        app.MapPut(ApiRoutes.Settings, async (
            [FromBody] SentinelSettings settings,
            HttpContext ctx,
            IDbContextFactory<SentinelDbContext> dbFactory,
            IThreatPipeline pipeline,
            HashChainWriter auditWriter,
            LiveBroadcaster broadcaster,
            CancellationToken ct) =>
        {
            if (settings is null)
                return EndpointHelpers.Error(StatusCodes.Status400BadRequest, "INVALID_SETTINGS", "Objet de paramètres requis.");

            var validationError = ValidateSettings(settings);
            if (validationError is not null)
                return EndpointHelpers.Error(StatusCodes.Status400BadRequest, "INVALID_SETTINGS", validationError);

            var now = DateTimeOffset.UtcNow;
            var serialized = SentinelJson.Serialize(settings);
            long newVersion;

            await using (var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false))
            {
                var entity = await db.Settings
                    .FirstOrDefaultAsync(s => s.Id == SettingsEntity.SingletonId, ct)
                    .ConfigureAwait(false);

                if (entity is null)
                {
                    entity = new SettingsEntity
                    {
                        Id = SettingsEntity.SingletonId,
                        Version = 1,
                        SettingsJson = serialized,
                        UpdatedAt = now
                    };
                    db.Settings.Add(entity);
                }
                else
                {
                    entity.Version++;
                    entity.SettingsJson = serialized;
                    entity.UpdatedAt = now;
                }

                newVersion = entity.Version;
                await db.SaveChangesAsync(ct).ConfigureAwait(false);
            }

            pipeline.UpdateSettings(settings);

            await auditWriter.WriteAuditAsync(
                EndpointHelpers.GetActor(ctx),
                "SettingsUpdated",
                "settings:global",
                $"Version={newVersion}, Mode={settings.Mode}, Seuils=[{settings.Thresholds.Low}/{settings.Thresholds.Moderate}/{settings.Thresholds.High}/{settings.Thresholds.Critical}], LLM={settings.Llm.Enabled} ({settings.Llm.Model}), Corrélation={settings.Correlation.Enabled}.",
                EndpointHelpers.GetClientIp(ctx),
                ct).ConfigureAwait(false);

            await broadcaster.SettingsChangedAsync(settings, ct).ConfigureAwait(false);
            broadcaster.NotifySummaryChanged();

            return Results.Ok(settings);
        });
    }

    private static string? ValidateSettings(SentinelSettings s)
    {
        if (s.Thresholds is null)
            return "Les seuils de menace sont requis.";

        var t = s.Thresholds;
        if (t.Low <= 0 || t.Low >= t.Moderate || t.Moderate >= t.High || t.High >= t.Critical || t.Critical > 100)
        {
            return "Les seuils doivent vérifier strictement 0 < Low < Moderate < High < Critical <= 100.";
        }

        if (s.EventRetentionDays < 1 || s.AlertRetentionDays < 1)
            return "Les durées de rétention doivent être supérieures ou égales à 1 jour.";

        if (s.Llm is null)
            return "La configuration LLM est requise.";

        if (s.Llm.TimeoutSeconds < 1)
            return "Le délai d'expiration LLM doit être d'au moins 1 seconde.";

        if (s.Correlation is null)
            return "La configuration de corrélation est requise.";

        if (s.Correlation.ShortWindowMinutes < 1 ||
            s.Correlation.MediumWindowMinutes < s.Correlation.ShortWindowMinutes ||
            s.Correlation.LongWindowHours < 1)
        {
            return "Les fenêtres de corrélation doivent être strictement positives et ordonnées (Short <= Medium).";
        }

        return null;
    }
}
