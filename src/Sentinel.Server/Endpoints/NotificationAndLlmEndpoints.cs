using Microsoft.AspNetCore.Mvc;
using Sentinel.AI;
using Sentinel.Core.Abstractions;
using Sentinel.Server.Services;
using Sentinel.Shared.Api;
using Sentinel.Storage.Services;

namespace Sentinel.Server.Endpoints;

internal static class NotificationAndLlmEndpoints
{
    public static void MapNotificationAndLlmEndpoints(this IEndpointRouteBuilder app)
    {
        // --------------------------------------------------------------------- LLM local (Qwen auto-sélection & métriques)
        app.MapGet(ApiRoutes.LlmStatus, async (
            ILlmAssessor llm,
            IThreatPipeline pipeline,
            CancellationToken ct) =>
        {
            if (llm.LastSelection is null && pipeline.Settings.Llm.Enabled)
            {
                await llm.CheckHealthAsync(ct).ConfigureAwait(false);
            }

            return Results.Ok(BuildLlmStatusDto(llm, pipeline));
        });

        app.MapPost(ApiRoutes.LlmSelectBest, async (
            HttpContext ctx,
            ILlmAssessor llm,
            IThreatPipeline pipeline,
            HashChainWriter auditWriter,
            CancellationToken ct) =>
        {
            var selection = await llm.RefreshModelSelectionAsync(ct).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(selection.SelectedModel) && pipeline.Settings.Llm.WarmUpOnStartup)
            {
                _ = Task.Run(() => llm.WarmUpAsync(CancellationToken.None), CancellationToken.None);
            }

            await auditWriter.WriteAuditAsync(
                EndpointHelpers.GetActor(ctx),
                "LlmModelAutoSelected",
                "system:llm",
                $"Actif={selection.SelectedModel ?? "aucun"}, Auto={selection.AutoSelected}, Qwen={selection.IsQwen}, RAM={selection.HostRamGb:F1}Go, Raison={selection.Reason}",
                EndpointHelpers.GetClientIp(ctx),
                ct).ConfigureAwait(false);

            return Results.Ok(BuildLlmStatusDto(llm, pipeline));
        });

        // --------------------------------------------------------------------- Scan système général, Audit sécurité & Démo
        app.MapPost(ApiRoutes.SystemScan, async (
            HttpContext ctx,
            SystemScanAndAuditService scanner,
            CancellationToken ct) =>
        {
            var req = await EndpointHelpers.ReadOptionalJsonAsync<SystemScanRequest>(ctx.Request, ct).ConfigureAwait(false)
                      ?? new SystemScanRequest();
            var report = await scanner.RunGeneralSystemScanAsync(
                req.IngestAnomalies,
                req.IncludeAiSummary,
                EndpointHelpers.GetActor(ctx),
                ct).ConfigureAwait(false);
            return Results.Ok(report);
        });

        app.MapGet(ApiRoutes.SystemScanLast, (SystemScanAndAuditService scanner) =>
            Results.Ok(scanner.LastScanReport));

        app.MapPost(ApiRoutes.SystemSecurityAudit, async (
            HttpContext ctx,
            SystemScanAndAuditService scanner,
            CancellationToken ct) =>
        {
            var report = await scanner.RunSystemSecurityAuditAsync(
                includeAiPlan: true,
                actor: EndpointHelpers.GetActor(ctx),
                ct: ct).ConfigureAwait(false);
            return Results.Ok(report);
        });

        app.MapGet(ApiRoutes.SystemSecurityAuditLast, (SystemScanAndAuditService scanner) =>
            Results.Ok(scanner.LastAuditReport));

        app.MapPost(ApiRoutes.DemoRun, async (
            [FromBody] DemoRunRequest request,
            HttpContext ctx,
            SystemScanAndAuditService scanner,
            CancellationToken ct) =>
        {
            if (request is null || string.IsNullOrWhiteSpace(request.ScenarioId))
            {
                return EndpointHelpers.Error(StatusCodes.Status400BadRequest, "INVALID_SCENARIO", "Spécifiez un identifiant de scénario.");
            }

            var result = await scanner.RunDemoScenarioAsync(request.ScenarioId, EndpointHelpers.GetActor(ctx), ct).ConfigureAwait(false);
            return Results.Ok(result);
        });

        // --------------------------------------------------------------------- Notifications administrateur multi-canaux + Inbox In-App
        app.MapGet(ApiRoutes.NotificationStatus, (IAlertNotificationDispatcher notifications) =>
            Results.Ok(notifications.GetStatus()));

        app.MapGet(ApiRoutes.NotificationInbox, (IAlertNotificationDispatcher notifications) =>
            Results.Ok(notifications.GetInbox()));

        app.MapPost(ApiRoutes.NotificationInboxReadAll, (IAlertNotificationDispatcher notifications) =>
            Results.Ok(new { markedRead = notifications.MarkAllRead() }));

        app.MapPost(ApiRoutes.NotificationTest, async (
            [FromBody] NotificationTestRequest request,
            HttpContext ctx,
            IAlertNotificationDispatcher notifications,
            HashChainWriter auditWriter,
            CancellationToken ct) =>
        {
            if (request is null || string.IsNullOrWhiteSpace(request.Channel))
            {
                return EndpointHelpers.Error(StatusCodes.Status400BadRequest, "INVALID_CHANNEL", "Spécifiez un canal : inapp, email, sms, whatsapp ou webhook.");
            }

            var delivery = await notifications.SendTestAsync(request.Channel, ct).ConfigureAwait(false);

            await auditWriter.WriteAuditAsync(
                EndpointHelpers.GetActor(ctx),
                "NotificationTestTriggered",
                $"notification:{delivery.Channel}",
                $"Succès={delivery.Success}, Latence={delivery.ElapsedMs}ms" + (string.IsNullOrWhiteSpace(delivery.Error) ? string.Empty : $", Erreur={delivery.Error}"),
                EndpointHelpers.GetClientIp(ctx),
                ct).ConfigureAwait(false);

            return Results.Ok(delivery);
        });

        app.MapPut(ApiRoutes.NotificationSecrets, async (
            [FromBody] NotificationSecretsRequest request,
            HttpContext ctx,
            NotificationSecretStore secretStore,
            HashChainWriter auditWriter,
            CancellationToken ct) =>
        {
            if (request is null)
            {
                return EndpointHelpers.Error(StatusCodes.Status400BadRequest, "INVALID_REQUEST", "Requête de secrets requise.");
            }

            var status = secretStore.Update(request);

            var changed = new List<string>(4);
            if (!string.IsNullOrWhiteSpace(request.SmtpPassword) || request.ClearSmtpPassword) changed.Add("smtp");
            if (!string.IsNullOrWhiteSpace(request.SmsApiToken) || request.ClearSmsToken) changed.Add("sms");
            if (!string.IsNullOrWhiteSpace(request.WhatsAppAccessToken) || request.ClearWhatsAppToken) changed.Add("whatsapp");
            if (!string.IsNullOrWhiteSpace(request.WebhookSecret) || request.ClearWebhookSecret) changed.Add("webhook");

            await auditWriter.WriteAuditAsync(
                EndpointHelpers.GetActor(ctx),
                "NotificationSecretsUpdated",
                "settings:notifications:secrets",
                $"Secrets mis à jour (chiffrés {status.StorageMode}) : [{string.Join(", ", changed)}].",
                EndpointHelpers.GetClientIp(ctx),
                ct).ConfigureAwait(false);

            return Results.Ok(status);
        });
    }

    internal static LlmStatusDto BuildLlmStatusDto(ILlmAssessor llm, IThreatPipeline pipeline)
    {
        var cfg = pipeline.Settings.Llm;
        var metrics = llm.Metrics;
        var selection = llm.LastSelection;
        var activeModel = !string.IsNullOrWhiteSpace(llm.ActiveModel) ? llm.ActiveModel : cfg.Model;

        var models = selection?.Candidates
            .Select(m => new OllamaModelInfoDto(
                Name: m.Name,
                SizeBytes: m.SizeBytes,
                Family: m.Family,
                ParameterSize: m.ParameterSize,
                QuantizationLevel: m.QuantizationLevel,
                IsQwen: OllamaModelSelector.IsQwenModel(m),
                Selected: string.Equals(m.Name, activeModel, StringComparison.OrdinalIgnoreCase)))
            .ToArray() ?? Array.Empty<OllamaModelInfoDto>();

        var reason = selection?.Reason ?? (cfg.Enabled
            ? (metrics.IsAvailable
                ? $"Modèle local actif : {activeModel}."
                : "Ollama local non détecté pour le moment (repli déterministe sur règles actif).")
            : "Scoring LLM local désactivé.");

        return new LlmStatusDto(
            Enabled: cfg.Enabled,
            Available: metrics.IsAvailable,
            Endpoint: cfg.Endpoint,
            ConfiguredModel: cfg.Model,
            ActiveModel: activeModel,
            AutoSelectBestQwen: cfg.AutoSelectBestQwen,
            AutoSelected: selection?.AutoSelected ?? false,
            SelectionReason: reason,
            HostRamGb: selection?.HostRamGb ?? OllamaModelSelector.GetHostRamGb(),
            Calls: metrics.Calls,
            Successes: metrics.Successes,
            Failures: metrics.Failures,
            CacheHits: metrics.CacheHits,
            AvgLatencyMs: metrics.AvgLatencyMs,
            ContextWindow: cfg.ContextWindow,
            MaxOutputTokens: cfg.MaxOutputTokens,
            KeepAlive: cfg.KeepAlive,
            WarmedUp: metrics.WarmedUp,
            InstalledModels: models);
    }
}
