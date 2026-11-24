using System.Diagnostics;
using Sentinel.Core;
using Sentinel.Detection.Sigma;
using Sentinel.Shared.Models;
using Sentinel.Simulation.Ai;
using Sentinel.Simulation.Scenarios;

namespace Sentinel.Simulation.Benchmark;

/// <summary>
/// Exécute le protocole expérimental A vs B vs C (doc §14.3, v2) sur les 11 scénarios d'attaque
/// et le corpus de trafic bénin sur 24 heures (480+ événements) avec moteur Sigma natif actif.
/// </summary>
public sealed class BenchmarkRunner
{
    public static readonly IReadOnlyList<EvaluationConfigSpec> Configurations =
    [
        new("A", "A - Règles + Sigma seules", EnableLlm: false, EnableCorrelation: false, EarlyEscalation: false),
        new("B", "B - Règles + Sigma + IA", EnableLlm: true, EnableCorrelation: false, EarlyEscalation: false),
        new("C", "C - SENTINEL v2 Complet", EnableLlm: true, EnableCorrelation: true, EarlyEscalation: true)
    ];

    private static ISigmaEngine? TryLoadSigmaEngine()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        for (var i = 0; i < 8 && dir is not null; i++, dir = dir.Parent)
        {
            var candidate = Path.Combine(dir.FullName, "rules", "sigma");
            if (Directory.Exists(candidate))
            {
                var engine = new SigmaEngine();
                engine.LoadFromDirectory(candidate);
                return engine;
            }
        }

        var cwdCandidate = Path.Combine(Directory.GetCurrentDirectory(), "rules", "sigma");
        if (Directory.Exists(cwdCandidate))
        {
            var engine = new SigmaEngine();
            engine.LoadFromDirectory(cwdCandidate);
            return engine;
        }

        return null;
    }

    public async Task<EvaluationReport> RunAsync(
        CliOptions options,
        LlmAssessorResolver.ResolvedAssessor resolvedLlm,
        CancellationToken ct = default)
    {
        var hostId = string.IsNullOrWhiteSpace(options.HostId) ? ScenarioCatalog.DefaultEvalHostId : options.HostId.Trim();
        const string userId = ScenarioCatalog.DefaultEvalUserId;

        var benignEvents = ScenarioCatalog.BuildBenignCorpus(hostId, userId);
        var scenarios = ScenarioCatalog.BuildAttackScenarios(hostId, userId);
        var sigmaEngine = TryLoadSigmaEngine();

        // Préchauffage JIT hors mesure pour que les latences reflètent le régime établi du pipeline
        await WarmUpJitAsync(options, resolvedLlm, ct).ConfigureAwait(false);

        var details = new List<ScenarioRunDetail>(scenarios.Count * Configurations.Count);
        var summaries = new List<ConfigurationSummary>(Configurations.Count);

        foreach (var cfg in Configurations)
        {
            ct.ThrowIfCancellationRequested();

            // 1. Évaluation du corpus bénin sur 24 heures (480+ événements) pour mesurer le FPR et établir la baseline comportementale
            var benignSettings = BuildSettings(cfg, options, resolvedLlm.UsingRealOllama);
            var benignLlm = resolvedLlm.Factory(benignSettings.Llm);
            var benignPipeline = ThreatPipelineFactory.Create(benignSettings, benignLlm, sigma: sigmaEngine);

            var falsePositives = 0;
            var totalLatencyMs = 0.0;
            var totalEventsMeasured = 0L;
            var totalLlmCalls = 0L;

            foreach (var evt in benignEvents)
            {
                ct.ThrowIfCancellationRequested();
                var res = await benignPipeline.ProcessAsync(evt, ct).ConfigureAwait(false);
                totalLatencyMs += res.ElapsedMs;
                totalEventsMeasured++;
                if (res.LlmUsed) totalLlmCalls++;

                if (IsAlertTriggered(res))
                {
                    falsePositives++;
                }
            }

            // Exporte la baseline apprise sur la journée de travail normale pour les scénarios d'attaque
            var learnedBaselineJson = benignPipeline.ExportBaseline();
            DisposeIfDisposable(benignLlm);

            // 2. Exécution isolée de chacun des 8 scénarios d'attaque avec la baseline comportementale chargée
            var cfgDetails = new List<ScenarioRunDetail>(scenarios.Count);

            foreach (var scenario in scenarios)
            {
                ct.ThrowIfCancellationRequested();

                var runSettings = BuildSettings(cfg, options, resolvedLlm.UsingRealOllama);
                var runLlm = resolvedLlm.Factory(runSettings.Llm);
                var pipeline = ThreatPipelineFactory.Create(runSettings, runLlm, sigma: sigmaEngine);
                pipeline.ImportBaseline(learnedBaselineJson);

                var detected = false;
                var eventsBeforeAlert = 0;
                var secondsToDetect = 0.0;
                var peakScore = 0;
                var firstAlertScore = 0;
                var firstAlertLevel = ThreatLevel.Info;
                var firstAlertType = ThreatType.None;
                string? firstAlertTrigger = null;
                string? detectedChain = null;
                var earlyEscalated = false;
                var scenarioLatencySum = 0.0;
                var scenarioLlmCalls = 0L;

                var firstTimestamp = scenario.Events[0].Timestamp;

                for (var idx = 0; idx < scenario.Events.Count; idx++)
                {
                    var evt = scenario.Events[idx];
                    var result = await pipeline.ProcessAsync(evt, ct).ConfigureAwait(false);

                    scenarioLatencySum += result.ElapsedMs;
                    totalLatencyMs += result.ElapsedMs;
                    totalEventsMeasured++;

                    if (result.LlmUsed)
                    {
                        scenarioLlmCalls++;
                        totalLlmCalls++;
                    }

                    var effectiveScore = result.Decision?.Score
                        ?? Math.Max(result.Scored.Assessment.Score, result.Cluster?.Score ?? 0);
                    if (effectiveScore > peakScore) peakScore = effectiveScore;

                    if (scenario.IsMultiStageChain && result.Cluster?.Chain is { } chain)
                    {
                        detectedChain = $"{chain.Name} ({chain.StepsMatched}/{chain.TotalSteps})";
                    }

                    if (!detected && IsAlertTriggered(result))
                    {
                        detected = true;
                        eventsBeforeAlert = idx + 1;
                        secondsToDetect = Math.Max(0.0, (evt.Timestamp - firstTimestamp).TotalSeconds);
                        firstAlertScore = effectiveScore;
                        firstAlertLevel = result.Decision?.Level ?? ThreatLevels.FromScore(effectiveScore);
                        firstAlertType = result.Decision?.Type ?? result.Scored.Assessment.Type;
                        firstAlertTrigger = $"{evt.Category}/{evt.EventType}";
                        earlyEscalated = result.Cluster?.Escalated ?? false;
                    }

                    if (options.DelayMs > 0)
                    {
                        await Task.Delay(options.DelayMs, ct).ConfigureAwait(false);
                    }
                }

                DisposeIfDisposable(runLlm);

                var detail = new ScenarioRunDetail(
                    scenario.Id,
                    scenario.Name,
                    scenario.MitreTechniques,
                    cfg.Key,
                    cfg.DisplayName,
                    scenario.Events.Count,
                    scenario.IsMultiStageChain,
                    detected,
                    eventsBeforeAlert,
                    Math.Round(secondsToDetect, 2),
                    peakScore,
                    firstAlertScore,
                    firstAlertLevel,
                    firstAlertType,
                    firstAlertTrigger,
                    detectedChain,
                    earlyEscalated,
                    falsePositives,
                    scenarioLlmCalls,
                    scenario.Events.Count > 0 ? Math.Round(scenarioLatencySum / scenario.Events.Count, 3) : 0.0);

                cfgDetails.Add(detail);
                details.Add(detail);
            }

            // 3. Agrégation des métriques scientifiques pour cette configuration
            var detectedRuns = cfgDetails.Where(d => d.Detected).ToList();
            var detectedMultiStage = detectedRuns.Where(d => d.IsMultiStageChain).ToList();

            var tp = detectedRuns.Count;
            var recall = scenarios.Count > 0 ? (double)tp / scenarios.Count : 0.0;
            var precision = (tp + falsePositives) > 0 ? (double)tp / (tp + falsePositives) : 1.0;
            var fpr = benignEvents.Count > 0 ? (double)falsePositives / benignEvents.Count : 0.0;
            var avgEventsAll = detectedRuns.Count > 0 ? detectedRuns.Average(d => d.EventsBeforeAlert) : 0.0;
            var avgEventsMulti = detectedMultiStage.Count > 0 ? detectedMultiStage.Average(d => d.EventsBeforeAlert) : 0.0;
            var avgTtd = detectedRuns.Count > 0 ? detectedRuns.Average(d => d.SecondsToDetect) : 0.0;
            var avgLatency = totalEventsMeasured > 0 ? totalLatencyMs / totalEventsMeasured : 0.0;
            var llmRatio = totalEventsMeasured > 0 ? (double)totalLlmCalls / totalEventsMeasured : 0.0;
            var workingSetMb = Math.Round(Process.GetCurrentProcess().WorkingSet64 / (1024.0 * 1024.0), 1);

            summaries.Add(new ConfigurationSummary(
                cfg.Key,
                cfg.DisplayName,
                tp,
                scenarios.Count,
                Math.Round(recall, 4),
                Math.Round(precision, 4),
                benignEvents.Count,
                falsePositives,
                Math.Round(fpr, 6),
                Math.Round(avgEventsAll, 2),
                Math.Round(avgEventsMulti, 2),
                Math.Round(avgTtd, 2),
                Math.Round(avgLatency, 3),
                workingSetMb,
                totalLlmCalls,
                Math.Round(llmRatio, 4)));
        }

        // 4. Comparaison appariée (sur les scénarios détectés par les deux configurations pour éviter tout biais)
        var byScenario = details.GroupBy(d => d.ScenarioId).ToList();
        var pairedAC = byScenario
            .Select(g => (A: g.First(x => x.ConfigKey == "A"), C: g.First(x => x.ConfigKey == "C")))
            .Where(p => p.A.Detected && p.C.Detected)
            .ToList();

        var pairedBC = byScenario
            .Select(g => (B: g.First(x => x.ConfigKey == "B"), C: g.First(x => x.ConfigKey == "C")))
            .Where(p => p.B.Detected && p.C.Detected)
            .ToList();

        var pairedAvgTtdA = pairedAC.Count > 0 ? pairedAC.Average(p => p.A.SecondsToDetect) : 0.0;
        var pairedAvgTtdCvsA = pairedAC.Count > 0 ? pairedAC.Average(p => p.C.SecondsToDetect) : 0.0;
        var gainTtdCvsA = pairedAvgTtdA > 0 ? ((pairedAvgTtdA - pairedAvgTtdCvsA) / pairedAvgTtdA) * 100.0 : 0.0;

        var pairedAvgTtdB = pairedBC.Count > 0 ? pairedBC.Average(p => p.B.SecondsToDetect) : 0.0;
        var pairedAvgTtdCvsB = pairedBC.Count > 0 ? pairedBC.Average(p => p.C.SecondsToDetect) : 0.0;
        var gainTtdCvsB = pairedAvgTtdB > 0 ? ((pairedAvgTtdB - pairedAvgTtdCvsB) / pairedAvgTtdB) * 100.0 : 0.0;

        var gainEventsCvsA = pairedAC.Count > 0 ? pairedAC.Average(p => p.A.EventsBeforeAlert - p.C.EventsBeforeAlert) : 0.0;
        var gainEventsCvsB = pairedBC.Count > 0 ? pairedBC.Average(p => p.B.EventsBeforeAlert - p.C.EventsBeforeAlert) : 0.0;

        var cMultiStage = details.Where(d => d.ConfigKey == "C" && d.IsMultiStageChain).ToList();
        var secondEventVerified = cMultiStage.Count > 0 && cMultiStage.All(d => d.Detected && d.EventsBeforeAlert <= 2);

        return new EvaluationReport(
            DateTimeOffset.UtcNow,
            hostId,
            resolvedLlm.ModeLabel,
            resolvedLlm.UsingRealOllama,
            benignEvents.Count,
            summaries,
            details,
            Math.Round(pairedAvgTtdA, 2),
            Math.Round(pairedAvgTtdCvsA, 2),
            Math.Round(gainTtdCvsA, 1),
            Math.Round(pairedAvgTtdB, 2),
            Math.Round(pairedAvgTtdCvsB, 2),
            Math.Round(gainTtdCvsB, 1),
            Math.Round(gainEventsCvsA, 2),
            Math.Round(gainEventsCvsB, 2),
            secondEventVerified);
    }

    private static async Task WarmUpJitAsync(
        CliOptions options,
        LlmAssessorResolver.ResolvedAssessor resolvedLlm,
        CancellationToken ct)
    {
        // Évite tout appel réseau Ollama inutile pendant le préchauffage JIT
        var warmupCfg = Configurations[^1];
        var settings = BuildSettings(warmupCfg, options, usingRealOllama: false);
        settings.Llm.Enabled = !resolvedLlm.UsingRealOllama;
        var llm = new DeterministicSimulatedLlmAssessor();
        var pipe = ThreatPipelineFactory.Create(settings, llm);
        var t0 = DateTimeOffset.UtcNow;

        await pipe.ProcessAsync(
            SecurityEvent.Create("WARMUP", "warmup", EventCategory.Clipboard, EventTypes.ClipboardUrl, "https://bit.ly/warmup",
                new Dictionary<string, string> { [AttributeKeys.Domain] = "bit.ly", [AttributeKeys.IsShortener] = "true" },
                timestamp: t0),
            ct).ConfigureAwait(false);
        await pipe.ProcessAsync(
            SecurityEvent.Create("WARMUP", "warmup", EventCategory.Browser, EventTypes.UrlVisited, "https://bit.ly/warmup",
                new Dictionary<string, string> { [AttributeKeys.Domain] = "bit.ly", [AttributeKeys.IsShortener] = "true" },
                timestamp: t0.AddSeconds(2)),
            ct).ConfigureAwait(false);
    }

    private static bool IsAlertTriggered(PipelineResult result) =>
        result.Decision is { } d && (d.AlertAdmin || d.Level >= ThreatLevel.High);

    private static SentinelSettings BuildSettings(EvaluationConfigSpec cfg, CliOptions options, bool usingRealOllama = false) => new()
    {
        Mode = OperatingMode.Active,
        Llm = new LlmSettings
        {
            Enabled = cfg.EnableLlm,
            Endpoint = options.OllamaUrl,
            Model = options.OllamaModel,
            TimeoutSeconds = usingRealOllama ? 30 : 10,
            AmbiguityLow = 25,
            AmbiguityHigh = 80,
            MinConfidence = 0.5,
            MaxConcurrency = 1
        },
        Correlation = new CorrelationSettings
        {
            Enabled = cfg.EnableCorrelation,
            EarlyEscalation = cfg.EarlyEscalation,
            ShortWindowMinutes = 5,
            MediumWindowMinutes = 30,
            LongWindowHours = 24,
            MinEventScore = 30,
            DecayHalfLifeMinutes = 15,
            SameEntityWeight = 0.8,
            SameTypeWeight = 0.3
        }
    };

    private static void DisposeIfDisposable(object obj)
    {
        if (obj is IDisposable d) d.Dispose();
    }
}
