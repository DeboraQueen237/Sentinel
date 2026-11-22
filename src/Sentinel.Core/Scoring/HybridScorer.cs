using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.AI;
using Sentinel.Core.Baseline;
using Sentinel.Core.Enrichment;
using Sentinel.Detection.Sigma;
using Sentinel.ML;
using Sentinel.Shared.Models;
using Sentinel.ThreatIntel;

namespace Sentinel.Core.Scoring;

/// <summary>Résultat interne complet de l'étape de scoring hybride.</summary>
public sealed record HybridScoringOutput(
    ThreatAssessment Assessment,
    EnrichedEvent Enriched,
    bool LlmUsed);

/// <summary>
/// Orchestre le scoring hybride multi-moteurs (v1 + v2) :
/// 1) Pré-filtre déterministe &amp; exclusions ;
/// 2) Threat Intelligence locale (Bloom + SQLite), Règles déterministes, Moteur Sigma natif, Baseline et signal auxiliaire ML PE ;
/// 3) Appel sélectif au LLM local (Ollama) uniquement dans la bande ambiguë <c>[AmbiguityLow, AmbiguityHigh]</c> ;
/// 4) Fusion pondérée par confiance et explication par source (<see cref="ScoreContribution"/>).
/// </summary>
public sealed class HybridScorer
{
    private readonly EventPreFilter _preFilter;
    private readonly RuleEngine _rules;
    private readonly BehavioralBaseline _baseline;
    private readonly ILlmAssessor _llm;
    private readonly ISigmaEngine? _sigma;
    private readonly IReputationService? _threatIntel;
    private readonly IPeMlClassifier? _mlClassifier;
    private readonly ILogger<HybridScorer> _logger;

    public HybridScorer(
        EventPreFilter preFilter,
        RuleEngine rules,
        BehavioralBaseline baseline,
        ILlmAssessor llm,
        ILogger<HybridScorer>? logger = null,
        ISigmaEngine? sigma = null,
        IReputationService? threatIntel = null,
        IPeMlClassifier? mlClassifier = null)
    {
        _preFilter = preFilter ?? throw new ArgumentNullException(nameof(preFilter));
        _rules = rules ?? throw new ArgumentNullException(nameof(rules));
        _baseline = baseline ?? throw new ArgumentNullException(nameof(baseline));
        _llm = llm ?? throw new ArgumentNullException(nameof(llm));
        _sigma = sigma;
        _threatIntel = threatIntel;
        _mlClassifier = mlClassifier;
        _logger = logger ?? NullLogger<HybridScorer>.Instance;
    }

    public async ValueTask<HybridScoringOutput> ScoreAsync(
        SecurityEvent evt,
        SentinelSettings settings,
        IReadOnlyList<RecentEventSummary> recentContext,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(evt);
        ArgumentNullException.ThrowIfNull(settings);

        // 1. Pré-filtre & enrichissement déterministe
        var enriched = _preFilter.Evaluate(evt, settings);

        if (enriched.IsExcluded)
        {
            _baseline.Observe(enriched);
            return new HybridScoringOutput(
                new ThreatAssessment(
                    evt.Id,
                    0,
                    ThreatType.None,
                    enriched.ExclusionReason ?? "Exclu par politique de filtrage.",
                    AssessmentSource.Rules,
                    1.0),
                enriched,
                LlmUsed: false);
        }

        if (_baseline.IsLearnedBenign(enriched))
        {
            _baseline.Observe(enriched);
            return new HybridScoringOutput(
                new ThreatAssessment(
                    evt.Id,
                    0,
                    ThreatType.None,
                    "Événement reconnu comme bénin via le retour analyste (faux positif appris).",
                    AssessmentSource.Rules,
                    0.95),
                enriched,
                LlmUsed: false);
        }

        if (enriched.IsTrustedSignedBypass)
        {
            _baseline.Observe(enriched);
            return new HybridScoringOutput(
                new ThreatAssessment(
                    evt.Id,
                    0,
                    ThreatType.None,
                    $"Processus signé par un éditeur de confiance ({enriched.Publisher}).",
                    AssessmentSource.Rules,
                    0.95),
                enriched,
                LlmUsed: false);
        }

        // 2. Règles déterministes + écart comportemental baseline + moteurs v2 (ThreatIntel, Sigma, ML)
        var ruleResult = _rules.Evaluate(enriched);
        var deviation = _baseline.Evaluate(enriched);

        var combinedScore = ruleResult.Score;
        var threatType = ruleResult.ThreatType;
        var matchedRuleIds = ruleResult.Matches.Select(m => m.RuleId).ToList();
        var mitreSet = new HashSet<string>(ruleResult.MitreTechniques, StringComparer.OrdinalIgnoreCase);
        var justificationParts = new List<string>(4);
        if (ruleResult.Score > 0 && !string.IsNullOrWhiteSpace(ruleResult.Justification))
            justificationParts.Add(ruleResult.Justification);
        var contributions = new List<ScoreContribution>(6);
        var activeEngines = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (ruleResult.Score > 0)
        {
            activeEngines.Add("Rules");
            contributions.Add(new ScoreContribution(
                "Rules",
                ruleResult.Score,
                1.0,
                ruleResult.Justification,
                ruleResult.Matches.Select(m => m.RuleId).ToArray()));
        }

        // 2b. Renseignement sur les menaces local (Bloom + SQLite — < quelques ms)
        if (_threatIntel is not null && settings.ThreatIntel.Enabled)
        {
            var tiMatch = LookupThreatIntel(enriched);
            if (tiMatch is not null)
            {
                activeEngines.Add("ThreatIntel");
                var tiScore = Math.Clamp(tiMatch.SuggestedScore, 85, 98);
                combinedScore = Math.Max(combinedScore, tiScore);
                if (threatType == ThreatType.None || threatType == ThreatType.Anomaly)
                {
                    threatType = tiMatch.ThreatType.Contains("phish", StringComparison.OrdinalIgnoreCase)
                        ? ThreatType.Phishing
                        : ThreatType.Malware;
                }
                var tiRuleId = $"TI-{tiMatch.Source.ToUpperInvariant()}";
                matchedRuleIds.Add(tiRuleId);
                mitreSet.Add("T1071");
                mitreSet.Add("T1105");
                justificationParts.Add(tiMatch.Justification);
                contributions.Add(new ScoreContribution(
                    "ThreatIntel",
                    tiScore,
                    1.0,
                    tiMatch.Justification,
                    [tiRuleId]));
            }
        }

        // 2c. Moteur Sigma natif C#
        if (_sigma is not null && settings.Rules.EnableSigma && _sigma.EnabledRuleCount > 0)
        {
            var sigmaAssessment = _sigma.EvaluateAsAssessment(evt);
            if (sigmaAssessment is not null && sigmaAssessment.Score > 0)
            {
                activeEngines.Add("Sigma");
                combinedScore = combinedScore == 0
                    ? sigmaAssessment.Score
                    : Math.Clamp((int)Math.Round(100.0 * (1.0 - (1.0 - combinedScore / 100.0) * (1.0 - sigmaAssessment.Score / 100.0))), combinedScore, 100);
                if (threatType == ThreatType.None || threatType == ThreatType.Anomaly)
                {
                    threatType = sigmaAssessment.Type;
                }
                matchedRuleIds.AddRange(sigmaAssessment.MatchedRules);
                foreach (var t in sigmaAssessment.MitreTechniques) mitreSet.Add(t);
                justificationParts.Add(sigmaAssessment.Justification);
                contributions.Add(new ScoreContribution(
                    "Sigma",
                    sigmaAssessment.Score,
                    0.9,
                    sigmaAssessment.Justification,
                    sigmaAssessment.MatchedRules));
            }
        }

        // 2d. Signal auxiliaire ML PE (strictement borné, jamais seul décisif)
        if (settings.MachineLearning.Enabled)
        {
            var mlContribution = EvaluateBoundedMlSignal(evt, enriched, settings.MachineLearning);
            if (mlContribution is not null)
            {
                activeEngines.Add("MachineLearning");
                var cap = Math.Clamp(settings.MachineLearning.MaxScoreContribution, 5, 45);
                var bounded = Math.Min(cap, mlContribution.Score);
                // Ne dépasse jamais le seuil Modéré (54) si le ML est seul
                combinedScore = combinedScore == 0
                    ? Math.Min(bounded, Math.Max(0, settings.Thresholds.Moderate - 1))
                    : Math.Min(100, combinedScore + (int)Math.Round(bounded * 0.6));
                if (threatType == ThreatType.None) threatType = ThreatType.Anomaly;
                matchedRuleIds.Add("ML-PE-CLASSIFIER");
                justificationParts.Add(mlContribution.Summary);
                contributions.Add(mlContribution with { Score = bounded });
            }
        }

        if (deviation.Bonus > 0)
        {
            contributions.Add(new ScoreContribution(
                "Baseline",
                deviation.Bonus,
                0.5,
                string.Join(" ; ", deviation.Reasons),
                deviation.RuleIds));

            if (combinedScore == 0)
            {
                combinedScore = Math.Min(50, deviation.Bonus);
                threatType = ThreatType.Anomaly;
                justificationParts.Add(string.Join(" ; ", deviation.Reasons));
            }
            else
            {
                combinedScore = Math.Min(100, combinedScore + deviation.Bonus);
                justificationParts.Add(string.Join(" ; ", deviation.Reasons));
            }
            matchedRuleIds.AddRange(deviation.RuleIds);
        }

        var justification = justificationParts.Count > 0
            ? string.Join(" ; ", justificationParts)
            : ruleResult.Justification;

        var finalScore = combinedScore;
        var finalType = threatType;
        var finalJustification = justification;
        var source = activeEngines.Count > 1
            ? AssessmentSource.MultiEngine
            : activeEngines.Contains("ThreatIntel") ? AssessmentSource.ThreatIntel
            : activeEngines.Contains("Sigma") ? AssessmentSource.Sigma
            : activeEngines.Contains("MachineLearning") ? AssessmentSource.MachineLearning
            : AssessmentSource.Rules;
        var confidence = combinedScore == 0 ? 0.95 : (activeEngines.Count > 1 ? 0.90 : 0.80);
        var llmUsed = false;

        // 3. Scoring IA local sélectif dans la bande ambiguë [AmbiguityLow, AmbiguityHigh]
        var llmCfg = settings.Llm;
        if (llmCfg.Enabled &&
            _llm.IsAvailable &&
            combinedScore >= llmCfg.AmbiguityLow &&
            combinedScore <= llmCfg.AmbiguityHigh)
        {
            var llmResult = await TryEvaluateWithLlmAsync(
                evt, combinedScore, threatType, justification, matchedRuleIds, recentContext, ct)
                .ConfigureAwait(false);

            if (llmResult is not null && llmResult.Confidence >= llmCfg.MinConfidence)
            {
                // Fusion pondérée par la confiance (confiance 0.5 -> 50 % IA ; confiance 1.0 -> 75 % IA)
                var clampedConf = Math.Clamp(llmResult.Confidence, 0.0, 1.0);
                var llmWeight = 0.25 + (0.50 * clampedConf);
                finalScore = Math.Clamp(
                    (int)Math.Round(combinedScore * (1.0 - llmWeight) + llmResult.Score * llmWeight),
                    0,
                    100);

                finalType = llmResult.Type != ThreatType.None ? llmResult.Type : threatType;
                finalJustification =
                    $"{llmResult.Justification} [Hybride — règles : {combinedScore}/100, IA : {llmResult.Score}/100, confiance : {clampedConf:P0}]";
                source = AssessmentSource.Hybrid;
                confidence = Math.Round(clampedConf, 2);
                llmUsed = true;
                contributions.Add(new ScoreContribution(
                    "LLM",
                    llmResult.Score,
                    Math.Round(llmWeight, 2),
                    llmResult.Justification));
            }
        }

        // 4. Apprentissage baseline uniquement sur les événements bénins (score < seuil Faible)
        //    pour éviter tout empoisonnement de la baseline par des signaux suspects
        if (finalScore < settings.Thresholds.Low)
        {
            _baseline.Observe(enriched);
        }

        var assessment = new ThreatAssessment(
            evt.Id,
            finalScore,
            finalType,
            finalJustification,
            source,
            confidence)
        {
            MatchedRules = matchedRuleIds.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
            MitreTechniques = mitreSet.ToArray(),
            ScoreContributions = contributions
        };

        return new HybridScoringOutput(assessment, enriched, llmUsed);
    }

    private ThreatIntelMatch? LookupThreatIntel(EnrichedEvent e)
    {
        if (_threatIntel is null) return null;
        if (!string.IsNullOrWhiteSpace(e.Sha256))
        {
            var m = _threatIntel.LookupHash(e.Sha256);
            if (m is not null) return m;
        }
        if (!string.IsNullOrWhiteSpace(e.Url))
        {
            var m = _threatIntel.LookupUrl(e.Url);
            if (m is not null) return m;
        }
        if (!string.IsNullOrWhiteSpace(e.Domain))
        {
            var m = _threatIntel.LookupDomain(e.Domain);
            if (m is not null) return m;
        }
        if (!string.IsNullOrWhiteSpace(e.RemoteIp))
        {
            var m = _threatIntel.LookupIp(e.RemoteIp);
            if (m is not null) return m;
        }
        return null;
    }

    private ScoreContribution? EvaluateBoundedMlSignal(SecurityEvent evt, EnrichedEvent enriched, MlSettings cfg)
    {
        // 1. Score ML déjà calculé par l'agent sur le poste
        if (evt.AttrDouble(AttributeKeys.MlScore) is { } precomputed && precomputed >= cfg.SuspiciousProbabilityThreshold)
        {
            var scaled = (int)Math.Round(precomputed * cfg.MaxScoreContribution);
            var top = evt.Attr(AttributeKeys.MlTopFeatures);
            var summary = $"Classifieur ML PE : probabilité {precomputed:P1}" + (string.IsNullOrWhiteSpace(top) ? string.Empty : $" ({top})");
            return new ScoreContribution("MachineLearning", scaled, 0.35, summary,
                string.IsNullOrWhiteSpace(top) ? null : top.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        }

        // 2. Inférence locale optionnelle si le fichier PE existe sur cette machine
        if (_mlClassifier is not null &&
            evt.Category is EventCategory.File or EventCategory.Process or EventCategory.StaticAnalysis)
        {
            var candidatePath = enriched.FilePath ?? enriched.ProcessPath;
            if (!string.IsNullOrWhiteSpace(candidatePath) &&
                (candidatePath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                 candidatePath.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) &&
                File.Exists(candidatePath))
            {
                var pred = _mlClassifier.PredictFile(candidatePath);
                if (pred.ModelLoaded && pred.BoundedScoreContribution > 0 && pred.MaliciousProbability >= cfg.SuspiciousProbabilityThreshold)
                {
                    var summary = $"Classifieur ML PE (v{pred.ModelVersion}) : probabilité {pred.MaliciousProbability:P1} ({string.Join(", ", pred.TopContributingFeatures.Take(3))})";
                    return new ScoreContribution("MachineLearning", pred.BoundedScoreContribution, 0.35, summary, pred.TopContributingFeatures);
                }
            }
        }

        return null;
    }

    private async Task<LlmAssessmentResult?> TryEvaluateWithLlmAsync(
        SecurityEvent evt,
        int ruleScore,
        ThreatType ruleType,
        string ruleJustification,
        IReadOnlyList<string> matchedRules,
        IReadOnlyList<RecentEventSummary> recentContext,
        CancellationToken ct)
    {
        try
        {
            var baselineText = _baseline.FormatForPrompt(evt.HostId, evt.UserId);
            var ctx = new LlmScoringContext(
                evt,
                ruleScore,
                ruleType,
                ruleJustification,
                matchedRules,
                recentContext,
                baselineText);

            return await _llm.AssessAsync(ctx, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Échec du scoring IA pour l'événement {EventId}, repli intégral sur les règles.", evt.Id);
            return null;
        }
    }
}
