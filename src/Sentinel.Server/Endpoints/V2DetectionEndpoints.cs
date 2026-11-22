using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Sentinel.Core.Abstractions;
using Sentinel.Detection.Sigma;
using Sentinel.Detection.Static;
using Sentinel.ML;
using Sentinel.Server.Services;
using Sentinel.Shared.Api;
using Sentinel.Shared.Infrastructure;
using Sentinel.Shared.Json;
using Sentinel.Shared.Models;
using Sentinel.Storage;
using Sentinel.Storage.Services;
using Sentinel.ThreatIntel;

namespace Sentinel.Server.Endpoints;

/// <summary>
/// Routes REST v2 (Missions 1 à 11) : Santé agents (Defender/Sysmon/CPU/RAM), Threat Intelligence,
/// Règles Sigma &amp; YARA (activation/rechargement), Scan statique à la demande, Modèle ML, Canaris,
/// Historique réversible des retours analyste et récit chronologique des clusters.
/// </summary>
internal static class V2DetectionEndpoints
{
    public static void MapV2DetectionEndpoints(this IEndpointRouteBuilder app)
    {
        // 1. Santé détaillée des agents (CPU, RAM, Defender, Sysmon, collecteurs)
        app.MapGet(ApiRoutes.AgentsHealth, async (
            IDbContextFactory<SentinelDbContext> dbFactory,
            AgentCommandHub commandHub,
            CancellationToken ct) =>
        {
            await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
            var hosts = await db.Hosts.AsNoTracking().OrderByDescending(h => h.LastSeenUnixMs).ToListAsync(ct).ConfigureAwait(false);
            var now = DateTimeOffset.UtcNow;

            var list = new List<AgentHealthDto>(hosts.Count);
            foreach (var h in hosts)
            {
                var collectors = ParseCollectors(h.CollectorsJson);
                var defCol = collectors.FirstOrDefault(c => c.Name.Equals("Defender", StringComparison.OrdinalIgnoreCase));
                var sysmonCol = collectors.FirstOrDefault(c => c.Name.Equals("Sysmon", StringComparison.OrdinalIgnoreCase));

                var defActive = defCol?.Running ?? false;
                var defRealtime = defActive && !(defCol?.Error?.Contains("désactivée", StringComparison.OrdinalIgnoreCase) ?? false);
                var sysmonInstalled = sysmonCol is not null &&
                                      (sysmonCol.Running || !(sysmonCol.Error?.Contains("non installé", StringComparison.OrdinalIgnoreCase) ?? true));

                var online = commandHub.IsConnected(h.HostId) || (now - h.LastSeen) <= TimeSpan.FromMinutes(2);
                var totalCollected = collectors.Sum(c => c.EventsProduced);

                list.Add(new AgentHealthDto(
                    h.HostId,
                    h.MachineName,
                    h.OsVersion,
                    string.IsNullOrWhiteSpace(h.AgentVersion) ? "2.0.0" : h.AgentVersion,
                    online,
                    h.LastSeen,
                    Math.Round(h.CpuPercent, 1),
                    h.WorkingSetBytes / (1024 * 1024),
                    h.QueueLength,
                    totalCollected,
                    defActive,
                    defRealtime,
                    sysmonInstalled,
                    collectors));
            }

            return Results.Ok(list);
        });

        // 2. Threat Intelligence (M4)
        app.MapGet(ApiRoutes.ThreatIntelStatus, (IReputationService ti) => Results.Ok(ti.GetStatus()));

        app.MapGet(ApiRoutes.ThreatIntelLookup, (string type, string value, IReputationService ti) =>
        {
            if (string.IsNullOrWhiteSpace(value))
                return EndpointHelpers.Error(StatusCodes.Status400BadRequest, "INVALID_INDICATOR", "Indicateur requis.");
            return Results.Ok(ti.Lookup(type ?? "domain", value.Trim()));
        });

        app.MapPost(ApiRoutes.ThreatIntelRefresh, async (
            HttpContext ctx,
            IReputationService ti,
            HashChainWriter auditWriter,
            CancellationToken ct) =>
        {
            var status = await ti.RefreshNowAsync(ct).ConfigureAwait(false);
            await auditWriter.WriteAuditAsync(
                EndpointHelpers.GetActor(ctx),
                "ThreatIntelRefreshed",
                "threat-intel",
                $"Synchronisation manuelle : {status.TotalIndicators} indicateur(s).",
                EndpointHelpers.GetClientIp(ctx),
                ct).ConfigureAwait(false);
            return Results.Ok(status);
        });

        // 3. Règles Sigma & YARA (M2, M3)
        app.MapGet(ApiRoutes.Rules, (ISigmaEngine sigma, IYaraScanner yara) =>
        {
            var all = new List<RuleSummaryDto>();
            all.AddRange(sigma.GetRuleSummaries());
            all.AddRange(yara.GetRuleSummaries());
            return Results.Ok(all.OrderBy(r => r.Engine).ThenBy(r => r.Title).ToArray());
        });

        app.MapPost(ApiRoutes.RuleToggle, async (
            string id,
            [FromBody] RuleToggleRequest req,
            HttpContext ctx,
            ISigmaEngine sigma,
            IYaraScanner yara,
            HashChainWriter auditWriter,
            CancellationToken ct) =>
        {
            var ok = sigma.SetRuleEnabled(id, req.Enabled) || yara.SetRuleEnabled(id, req.Enabled);
            if (!ok)
                return EndpointHelpers.Error(StatusCodes.Status404NotFound, "RULE_NOT_FOUND", $"Règle '{id}' introuvable.");

            var updated = sigma.GetRuleSummaries().Concat(yara.GetRuleSummaries())
                .FirstOrDefault(r => r.Id.Equals(id, StringComparison.OrdinalIgnoreCase));

            await auditWriter.WriteAuditAsync(
                EndpointHelpers.GetActor(ctx),
                "RuleToggled",
                $"rule:{id}",
                $"Règle {(req.Enabled ? "activée" : "désactivée")}.",
                EndpointHelpers.GetClientIp(ctx),
                ct).ConfigureAwait(false);

            return updated is not null ? Results.Ok(updated) : Results.NoContent();
        });

        app.MapPost(ApiRoutes.RulesReload, async (
            HttpContext ctx,
            ISigmaEngine sigma,
            IYaraScanner yara,
            HashChainWriter auditWriter,
            CancellationToken ct) =>
        {
            var sRes = sigma.Reload();
            var yRes = yara.Reload();
            var errors = sRes.Errors.Select(e => $"[Sigma] {e.FilePath}: {e.Message}")
                .Concat(yRes.Errors.Select(e => $"[YARA] {e.FilePath}: {e.Message}"))
                .ToArray();

            await auditWriter.WriteAuditAsync(
                EndpointHelpers.GetActor(ctx),
                "RulesReloaded",
                "rules",
                $"Rechargement à chaud : {sigma.RuleCount} Sigma, {yara.RuleCount} YARA ({errors.Length} erreur(s)).",
                EndpointHelpers.GetClientIp(ctx),
                ct).ConfigureAwait(false);

            return Results.Ok(new RulesReloadResultDto(sigma.RuleCount, yara.RuleCount, errors, DateTimeOffset.UtcNow));
        });

        // 4. Scan statique PE + YARA + ML à la demande (M3, M5)
        app.MapPost(ApiRoutes.StaticScan, async (
            [FromBody] StaticScanRequest req,
            HttpContext ctx,
            IStaticFileScanner scanner,
            IPeMlClassifier ml,
            HashChainWriter auditWriter,
            CancellationToken ct) =>
        {
            if (req is null || string.IsNullOrWhiteSpace(req.FilePath))
                return EndpointHelpers.Error(StatusCodes.Status400BadRequest, "INVALID_PATH", "Chemin de fichier requis.");

            var outcome = await scanner.ScanFileDetailedAsync(req.FilePath.Trim(), ct).ConfigureAwait(false);
            var dto = outcome.Result;

            if (string.IsNullOrWhiteSpace(dto.Error) && dto.IsPe && File.Exists(req.FilePath.Trim()))
            {
                var mlPred = ml.PredictFile(req.FilePath.Trim());
                if (mlPred.ModelLoaded)
                {
                    var combined = Math.Clamp(dto.CombinedScore + (int)Math.Round(mlPred.BoundedScoreContribution * 0.5), 0, 100);
                    dto = dto with
                    {
                        MlMaliciousProbability = Math.Round(mlPred.MaliciousProbability, 4),
                        MlTopFeatures = mlPred.TopContributingFeatures,
                        CombinedScore = combined
                    };
                }
            }

            await auditWriter.WriteAuditAsync(
                EndpointHelpers.GetActor(ctx),
                "StaticScanExecuted",
                $"file:{req.FilePath}",
                $"Scan statique terminé : score={dto.CombinedScore}/100, YARA={dto.YaraMatches.Count}, PE={dto.IsPe}.",
                EndpointHelpers.GetClientIp(ctx),
                ct).ConfigureAwait(false);

            return Results.Ok(dto);
        });

        // 5. Statut du modèle ML PE (M5)
        app.MapGet(ApiRoutes.MlStatus, (IPeMlClassifier ml) => Results.Ok(ml.GetStatus()));

        // 6. Fichiers canari anti-ransomware (M6)
        app.MapGet(ApiRoutes.Canaries, () => Results.Ok(LoadCanaryStatuses()));

        app.MapPost(ApiRoutes.CanariesRedeploy, async (
            HttpContext ctx,
            HashChainWriter auditWriter,
            CancellationToken ct) =>
        {
            var statuses = LoadCanaryStatuses();
            await auditWriter.WriteAuditAsync(
                EndpointHelpers.GetActor(ctx),
                "CanariesChecked",
                "canaries",
                $"Vérification des canaris demandée ({statuses.Count} fichier(s) suivi(s)).",
                EndpointHelpers.GetClientIp(ctx),
                ct).ConfigureAwait(false);
            return Results.Ok(statuses);
        });

        // 7. Historique réversible des retours analyste & récit de cluster (M8)
        app.MapGet(ApiRoutes.FeedbackHistory, (IThreatPipeline pipeline) =>
            Results.Ok(pipeline.GetFeedbackHistory()));

        app.MapPost(ApiRoutes.FeedbackRevert, async (
            Guid id,
            HttpContext ctx,
            IThreatPipeline pipeline,
            HashChainWriter auditWriter,
            CancellationToken ct) =>
        {
            if (!pipeline.RevertFeedback(id))
                return EndpointHelpers.Error(StatusCodes.Status404NotFound, "FEEDBACK_NOT_FOUND", "Retour analyste introuvable ou déjà annulé.");

            await auditWriter.WriteAuditAsync(
                EndpointHelpers.GetActor(ctx),
                "FeedbackReverted",
                $"feedback:{id:D}",
                "Retour analyste annulé sur le modèle de corrélation.",
                EndpointHelpers.GetClientIp(ctx),
                ct).ConfigureAwait(false);

            var updated = pipeline.GetFeedbackHistory().FirstOrDefault(f => f.Id == id);
            return updated is not null ? Results.Ok(updated) : Results.NoContent();
        });

        app.MapGet("/api/clusters/{id:guid}/narrative", async (
            Guid id,
            IThreatPipeline pipeline,
            IDbContextFactory<SentinelDbContext> dbFactory,
            CancellationToken ct) =>
        {
            var liveCluster = pipeline.GetCluster(id);
            if (liveCluster is not null)
            {
                return Results.Ok(new ClusterNarrativeDto(
                    liveCluster.Id,
                    liveCluster.Narrative,
                    liveCluster.ChainProbability,
                    liveCluster.MitreTactics,
                    liveCluster.ScoreContributions));
            }

            await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
            var entity = await db.Clusters.AsNoTracking().FirstOrDefaultAsync(c => c.Id == id, ct).ConfigureAwait(false);
            if (entity is null)
                return EndpointHelpers.Error(StatusCodes.Status404NotFound, "CLUSTER_NOT_FOUND", "Cluster introuvable.");

            var techniques = SentinelJson.Deserialize<List<string>>(entity.MitreTechniquesJson) ?? new List<string>();
            var tactics = techniques
                .Select(t => MitreCatalog.TryGet(t)?.Tactic)
                .Where(t => !string.IsNullOrWhiteSpace(t))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Cast<string>()
                .ToArray();

            return Results.Ok(new ClusterNarrativeDto(
                entity.Id,
                entity.Justification,
                0.0,
                tactics,
                Array.Empty<ScoreContribution>()));
        });
    }

    private static IReadOnlyList<CollectorHealthDto> ParseCollectors(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return Array.Empty<CollectorHealthDto>();
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Array) return Array.Empty<CollectorHealthDto>();
            var list = new List<CollectorHealthDto>();
            foreach (var el in doc.RootElement.EnumerateArray())
            {
                var name = el.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
                var running = el.TryGetProperty("running", out var r) && r.ValueKind == JsonValueKind.True;
                var error = el.TryGetProperty("error", out var e) ? e.GetString() : null;
                var count = el.TryGetProperty("eventsProduced", out var ep) && ep.TryGetInt64(out var c) ? c : 0;
                if (!string.IsNullOrWhiteSpace(name))
                    list.Add(new CollectorHealthDto(name, running, string.IsNullOrWhiteSpace(error) ? null : error, count));
            }
            return list;
        }
        catch
        {
            return Array.Empty<CollectorHealthDto>();
        }
    }

    private static IReadOnlyList<CanaryStatusDto> LoadCanaryStatuses()
    {
        try
        {
            var path = SentinelPaths.CanariesRegistryFile;
            if (!File.Exists(path)) return Array.Empty<CanaryStatusDto>();

            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            if (doc.RootElement.ValueKind != JsonValueKind.Array) return Array.Empty<CanaryStatusDto>();

            var hostId = Environment.MachineName.ToLowerInvariant();
            var now = DateTimeOffset.UtcNow;
            var list = new List<CanaryStatusDto>();
            foreach (var el in doc.RootElement.EnumerateArray())
            {
                var id = el.TryGetProperty("id", out var idEl) ? idEl.GetString() ?? "" : "";
                var filePath = el.TryGetProperty("filePath", out var fpEl) ? fpEl.GetString() ?? "" : "";
                var folder = el.TryGetProperty("folder", out var fEl) ? fEl.GetString() ?? "" : "";
                var sha = el.TryGetProperty("expectedSha256", out var sEl) ? sEl.GetString() ?? "" : "";
                var size = el.TryGetProperty("sizeBytes", out var szEl) && szEl.TryGetInt64(out var sz) ? sz : 0;
                var deployed = el.TryGetProperty("deployedAt", out var dEl) && dEl.TryGetDateTimeOffset(out var dt) ? dt : now;
                var exists = !string.IsNullOrWhiteSpace(filePath) && File.Exists(filePath);
                var intact = exists;
                if (exists && !string.IsNullOrWhiteSpace(sha))
                {
                    try
                    {
                        var actual = Sentinel.Shared.Security.HashChain.Sha256File(filePath);
                        intact = actual.Equals(sha, StringComparison.OrdinalIgnoreCase);
                    }
                    catch { intact = false; }
                }

                list.Add(new CanaryStatusDto(
                    id, hostId, filePath, folder, sha, size, intact, deployed, now,
                    intact ? "Intact" : (exists ? "Modified" : "Deleted")));
            }
            return list;
        }
        catch
        {
            return Array.Empty<CanaryStatusDto>();
        }
    }
}
