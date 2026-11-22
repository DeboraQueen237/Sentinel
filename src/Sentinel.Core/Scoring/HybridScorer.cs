using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.AI;
using Sentinel.Core.Baseline;
using Sentinel.Core.Enrichment;
using Sentinel.Shared.Models;

namespace Sentinel.Core.Scoring;

/// <summary>Résultat interne complet de l'étape de scoring hybride.</summary>
public sealed record HybridScoringOutput(
    ThreatAssessment Assessment,
    EnrichedEvent Enriched,
    bool LlmUsed);

/// <summary>
/// Orchestre le scoring hybride en 4 étages (doc §7.1) :
/// 1) Pré-filtre déterministe &amp; exclusions ;
/// 2) Moteur de règles déterministes + écart baseline comportementale ;
/// 3) Appel sélectif au LLM local uniquement dans la bande ambiguë <c>[AmbiguityLow, AmbiguityHigh]</c> ;
/// 4) Fusion pondérée par confiance ou repli intégral sur les règles.
/// </summary>
public sealed class HybridScorer
{
    private readonly EventPreFilter _preFilter;
    private readonly RuleEngine _rules;
    private readonly BehavioralBaseline _baseline;
    private readonly ILlmAssessor _llm;
    private readonly ILogger<HybridScorer> _logger;

    public HybridScorer(
        EventPreFilter preFilter,
        RuleEngine rules,
        BehavioralBaseline baseline,
        ILlmAssessor llm,
        ILogger<HybridScorer>? logger = null)
    {
        _preFilter = preFilter ?? throw new ArgumentNullException(nameof(preFilter));
        _rules = rules ?? throw new ArgumentNullException(nameof(rules));
        _baseline = baseline ?? throw new ArgumentNullException(nameof(baseline));
        _llm = llm ?? throw new ArgumentNullException(nameof(llm));
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

        // 2. Règles déterministes + écart comportemental baseline
        var ruleResult = _rules.Evaluate(enriched);
        var deviation = _baseline.Evaluate(enriched);

        var combinedScore = ruleResult.Score;
        var threatType = ruleResult.ThreatType;
        var matchedRuleIds = ruleResult.Matches.Select(m => m.RuleId).ToList();
        var justification = ruleResult.Justification;

        if (deviation.Bonus > 0)
        {
            if (combinedScore == 0)
            {
                combinedScore = Math.Min(50, deviation.Bonus);
                threatType = ThreatType.Anomaly;
                justification = string.Join(" ; ", deviation.Reasons);
            }
            else
            {
                combinedScore = Math.Min(100, combinedScore + deviation.Bonus);
                justification = $"{justification} ; {string.Join(" ; ", deviation.Reasons)}";
            }
            matchedRuleIds.AddRange(deviation.RuleIds);
        }

        var finalScore = combinedScore;
        var finalType = threatType;
        var finalJustification = justification;
        var source = AssessmentSource.Rules;
        var confidence = combinedScore == 0 ? 0.95 : 0.80;
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
            MatchedRules = matchedRuleIds,
            MitreTechniques = ruleResult.MitreTechniques
        };

        return new HybridScoringOutput(assessment, enriched, llmUsed);
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
