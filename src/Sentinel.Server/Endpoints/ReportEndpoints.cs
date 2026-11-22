using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Sentinel.Server.Services;
using Sentinel.Shared.Api;
using Sentinel.Storage;
using Sentinel.Storage.Entities;
using Sentinel.Storage.Mapping;
using Sentinel.Storage.Services;

namespace Sentinel.Server.Endpoints;

internal static class ReportEndpoints
{
    public static void MapReportEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet(ApiRoutes.ReportGenerate, async (
            DateTimeOffset? from,
            DateTimeOffset? to,
            string? format,
            string? hostId,
            HttpContext ctx,
            ReportGeneratorService generator,
            HashChainWriter auditWriter,
            CancellationToken ct) =>
        {
            var effectiveTo = to ?? DateTimeOffset.UtcNow;
            var effectiveFrom = from ?? effectiveTo.AddDays(-7);
            if (effectiveFrom > effectiveTo)
                return EndpointHelpers.Error(StatusCodes.Status400BadRequest, "INVALID_RANGE", "La date de début doit être antérieure à la date de fin.");

            var parsedFormat = EndpointHelpers.TryParseEnum<ReportFormat>(format) ?? ReportFormat.Pdf;

            var report = await generator.GenerateGlobalReportAsync(effectiveFrom, effectiveTo, parsedFormat, hostId, ct)
                .ConfigureAwait(false);

            await auditWriter.WriteAuditAsync(
                EndpointHelpers.GetActor(ctx),
                "ReportGenerated",
                string.IsNullOrWhiteSpace(hostId) ? "report:global" : $"report:host:{hostId.Trim()}",
                $"Format={parsedFormat}, From={effectiveFrom:O}, To={effectiveTo:O}, Taille={report.Content.Length} octets.",
                EndpointHelpers.GetClientIp(ctx),
                ct).ConfigureAwait(false);

            return Results.File(report.Content, report.ContentType, report.FileName);
        });

        app.MapGet(ApiRoutes.ReportAlert, async (
            Guid id,
            string? format,
            HttpContext ctx,
            ReportGeneratorService generator,
            HashChainWriter auditWriter,
            CancellationToken ct) =>
        {
            var parsedFormat = EndpointHelpers.TryParseEnum<ReportFormat>(format) ?? ReportFormat.Pdf;
            var report = await generator.GenerateAlertReportAsync(id, parsedFormat, ct).ConfigureAwait(false);
            if (report is null)
                return EndpointHelpers.Error(StatusCodes.Status404NotFound, "ALERT_NOT_FOUND", "Alerte introuvable.");

            await auditWriter.WriteAuditAsync(
                EndpointHelpers.GetActor(ctx),
                "AlertReportGenerated",
                $"alert:{id:D}",
                $"Format={parsedFormat}, Taille={report.Content.Length} octets.",
                EndpointHelpers.GetClientIp(ctx),
                ct).ConfigureAwait(false);

            return Results.File(report.Content, report.ContentType, report.FileName);
        });

        app.MapGet(ApiRoutes.Evaluation, async (
            IDbContextFactory<SentinelDbContext> dbFactory,
            CancellationToken ct) =>
        {
            await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
            var all = await db.EvaluationMetrics
                .AsNoTracking()
                .OrderByDescending(m => m.Id)
                .ToListAsync(ct)
                .ConfigureAwait(false);

            if (all.Count == 0)
                return Results.Ok(Array.Empty<ScenarioMetricDto>());

            var latestRun = all.Max(m => m.RunAt);
            var latest = all
                .Where(m => m.RunAt == latestRun)
                .OrderBy(m => m.Scenario, StringComparer.OrdinalIgnoreCase)
                .ThenBy(m => m.Configuration, StringComparer.OrdinalIgnoreCase)
                .Select(m => m.ToDto())
                .ToArray();

            return Results.Ok(latest);
        });

        app.MapPost(ApiRoutes.Evaluation, async (
            [FromBody] ScenarioMetricDto[] metrics,
            HttpContext ctx,
            IDbContextFactory<SentinelDbContext> dbFactory,
            HashChainWriter auditWriter,
            CancellationToken ct) =>
        {
            if (metrics is null || metrics.Length == 0)
                return EndpointHelpers.Error(StatusCodes.Status400BadRequest, "EMPTY_METRICS", "Au moins une métrique d'évaluation est requise.");

            var runAt = DateTimeOffset.UtcNow;
            await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);

            foreach (var m in metrics)
            {
                db.EvaluationMetrics.Add(new EvaluationMetricEntity
                {
                    RunAt = runAt,
                    Scenario = m.Scenario ?? string.Empty,
                    Configuration = m.Configuration ?? string.Empty,
                    Detected = m.Detected,
                    EventsBeforeAlert = m.EventsBeforeAlert,
                    SecondsToDetect = m.SecondsToDetect,
                    PeakScore = m.PeakScore,
                    FalsePositives = m.FalsePositives
                });
            }

            await db.SaveChangesAsync(ct).ConfigureAwait(false);

            await auditWriter.WriteAuditAsync(
                EndpointHelpers.GetActor(ctx),
                "EvaluationMetricsRecorded",
                "evaluation:latest",
                $"{metrics.Length} métrique(s) de simulation enregistrée(s) (RunAt={runAt:O}).",
                EndpointHelpers.GetClientIp(ctx),
                ct).ConfigureAwait(false);

            return Results.Ok(metrics);
        });
    }
}
