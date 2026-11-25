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

        // --------------------------------------------------------------------- Notifications administrateur multi-canaux
        app.MapGet(ApiRoutes.NotificationStatus, (IAlertNotificationDispatcher notifications) =>
            Results.Ok(notifications.GetStatus()));

        app.MapPost(ApiRoutes.NotificationTest, async (
            [FromBody] NotificationTestRequest request,
            HttpContext ctx,
            IAlertNotificationDispatcher notifications,
            HashChainWriter auditWriter,
            CancellationToken ct) =>
        {
            if (request is null || string.IsNullOrWhiteSpace(request.Channel))
            {
                return EndpointHelpers.Error(StatusCodes.Status400BadRequest, "INVALID_CHANNEL", "Spécifiez un canal : email, whatsapp ou webhook.");
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

            // Journaliser uniquement quels types de secrets ont été modifiés (JAMAIS leurs valeurs)
            var changed = new List<string>(3);
            if (!string.IsNullOrWhiteSpace(request.SmtpPassword) || request.ClearSmtpPassword) changed.Add("smtp");
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
