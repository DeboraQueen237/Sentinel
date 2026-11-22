using Sentinel.AI;
using Sentinel.Core.Baseline;
using Sentinel.Core.Enrichment;
using Sentinel.Shared.Models;

namespace Sentinel.Core.Tests;

public sealed class HybridScorerAndBaselineTests
{
    [Fact]
    public async Task HybridScorer_CallsLlmOnlyInAmbiguityBand_AndFusesByConfidence()
    {
        var fakeLlm = new FakeLlmAssessor((_, _) =>
            Task.FromResult<LlmAssessmentResult?>(
                new LlmAssessmentResult(82, ThreatType.Phishing, "Lien suspect confirmé par l'IA.", 0.90)));

        var settings = TestEvents.ActiveSettings(llmEnabled: true, correlationEnabled: false);
        settings.Llm.AmbiguityLow = 25;
        settings.Llm.AmbiguityHigh = 80;
        settings.Llm.MinConfidence = 0.5;

        var pipeline = ThreatPipelineFactory.Create(settings, llm: fakeLlm);

        // 1. Score 0 (< AmbiguityLow) : LLM NON appelé
        var benign = await pipeline.ProcessAsync(TestEvents.Make(
            EventCategory.Process, EventTypes.ProcessStart, @"C:\Program Files\App\notepad.exe",
            new() { [AttributeKeys.Signed] = "true", [AttributeKeys.Publisher] = "Microsoft Corporation" }));
        benign.LlmUsed.Should().BeFalse();
        fakeLlm.CallCount.Should().Be(0);

        // 2. Score 95 (> AmbiguityHigh, EICAR) : LLM NON appelé
        var critical = await pipeline.ProcessAsync(TestEvents.Make(
            EventCategory.File, EventTypes.FileCreated, @"C:\Users\alice\Downloads\eicar.com",
            new() { [AttributeKeys.Sha256] = ThreatIndicators.EicarSha256 }));
        critical.LlmUsed.Should().BeFalse();
        critical.Scored.Assessment.Source.Should().Be(AssessmentSource.Rules);
        fakeLlm.CallCount.Should().Be(0);

        // 3. Score 38 (dans [25, 80]) : LLM appelé et fusionné
        var ambiguous = await pipeline.ProcessAsync(TestEvents.Make(
            EventCategory.Clipboard, EventTypes.ClipboardUrl, "https://bit.ly/facture",
            new() { [AttributeKeys.Url] = "https://bit.ly/facture", [AttributeKeys.IsShortener] = "true" }));

        fakeLlm.CallCount.Should().Be(1);
        ambiguous.LlmUsed.Should().BeTrue();
        ambiguous.Scored.Assessment.Source.Should().Be(AssessmentSource.Hybrid);
        // Fusion : rule=38, llm=82, conf=0.90 -> w = 0.25 + 0.5*0.9 = 0.70 -> round(38*0.3 + 82*0.7) = 69
        ambiguous.Scored.Assessment.Score.Should().Be(69);
        ambiguous.Scored.Assessment.Justification.Should().Contain("Lien suspect confirmé");
    }

    [Fact]
    public async Task HybridScorer_FallsBackToRules_OnLowConfidence_Null_OrException()
    {
        var settings = TestEvents.ActiveSettings(llmEnabled: true, correlationEnabled: false);
        var evt = TestEvents.Make(
            EventCategory.Clipboard, EventTypes.ClipboardUrl, "https://bit.ly/test",
            new() { [AttributeKeys.Url] = "https://bit.ly/test", [AttributeKeys.IsShortener] = "true" });

        // Confiance trop faible (< MinConfidence = 0.5)
        var lowConfLlm = new FakeLlmAssessor((_, _) =>
            Task.FromResult<LlmAssessmentResult?>(new LlmAssessmentResult(95, ThreatType.Phishing, "Incertain", 0.2)));
        var res1 = await ThreatPipelineFactory.Create(settings, lowConfLlm).ProcessAsync(evt);
        res1.LlmUsed.Should().BeFalse();
        res1.Scored.Assessment.Source.Should().Be(AssessmentSource.Rules);
        res1.Scored.Assessment.Score.Should().Be(38);

        // Exception / timeout
        var throwingLlm = new FakeLlmAssessor((_, _) => throw new TimeoutException("Ollama timeout"));
        var res2 = await ThreatPipelineFactory.Create(settings, throwingLlm).ProcessAsync(evt);
        res2.LlmUsed.Should().BeFalse();
        res2.Scored.Assessment.Source.Should().Be(AssessmentSource.Rules);
        res2.Scored.Assessment.Score.Should().Be(38);

        // Indisponible (IsAvailable == false) -> même pas appelé
        var unavailableLlm = new FakeLlmAssessor((_, _) =>
            Task.FromResult<LlmAssessmentResult?>(new LlmAssessmentResult(90, ThreatType.Phishing, "ok", 0.9)),
            available: false);
        var res3 = await ThreatPipelineFactory.Create(settings, unavailableLlm).ProcessAsync(evt);
        unavailableLlm.CallCount.Should().Be(0);
        res3.LlmUsed.Should().BeFalse();
    }

    [Fact]
    public async Task BehavioralBaseline_DetectsUnusualHour_ReinjectsFalsePositives_AndExportsImportsJson()
    {
        var settings = TestEvents.ActiveSettings(llmEnabled: false, correlationEnabled: false);
        var pipeline = ThreatPipelineFactory.Create(settings);

        // 1. Construction d'une baseline d'heures de bureau (09h..17h) + rythme de frappe normal (~5 t/s)
        for (var i = 0; i < 30; i++)
        {
            var hour = 9 + (i % 8);
            var ts = new DateTimeOffset(2026, 3, 1 + (i / 8), hour, 15, 0, TimeSpan.Zero);
            await pipeline.ProcessAsync(TestEvents.Make(
                EventCategory.Process, EventTypes.ProcessStart, @"C:\Program Files\Office\app.exe",
                new() { [AttributeKeys.ProcessName] = "app.exe", [AttributeKeys.Signed] = "true", [AttributeKeys.Publisher] = "Microsoft Corporation" },
                ts: ts));

            if (i < 15)
            {
                await pipeline.ProcessAsync(TestEvents.Make(
                    EventCategory.Typing, EventTypes.TypingStats, "typing",
                    new()
                    {
                        [AttributeKeys.KeysPerSecond] = (4.8 + (i % 3) * 0.4).ToString(System.Globalization.CultureInfo.InvariantCulture),
                        [AttributeKeys.MeanIntervalMs] = "195",
                        [AttributeKeys.IntervalStdDevMs] = "35",
                        [AttributeKeys.SampleSize] = "40"
                    },
                    ts: ts));
            }
        }

        var summary = pipeline.GetBaseline("HOST-01", "alice");
        summary.Should().NotBeNull();
        summary!.UsualHours.Should().Contain(9).And.NotContain(3);
        summary.TypingKpsMean.Should().BeInRange(4.5, 6.0);

        // 2. Activité à 03h du matin -> écart horaire détecté
        var nightTs = new DateTimeOffset(2026, 3, 12, 3, 10, 0, TimeSpan.Zero);
        var nightEvt = await pipeline.ProcessAsync(TestEvents.Make(
            EventCategory.Process, EventTypes.ProcessStart, @"C:\Custom\mystery.exe",
            new() { [AttributeKeys.ProcessName] = "mystery.exe", [AttributeKeys.Signed] = "false" },
            ts: nightTs));
        nightEvt.Scored.Assessment.MatchedRules.Should().Contain("BASE-UNUSUAL-HOUR");

        // 3. Export / Import JSON dans un nouveau pipeline
        var exported = pipeline.ExportBaseline();
        var pipeline2 = ThreatPipelineFactory.Create(settings);
        pipeline2.ImportBaseline(exported);
        var restored = pipeline2.GetBaseline("HOST-01", "alice");
        restored.Should().NotBeNull();
        restored!.UsualHours.Should().BeEquivalentTo(summary.UsualHours);
        restored.TypingKpsMean.Should().BeApproximately(summary.TypingKpsMean, 0.05);

        // 4. Retour faux positif (doc §9.4) -> prochain événement identique devient score 0
        var fpEvt = TestEvents.Make(
            EventCategory.Process, EventTypes.ProcessStart, @"C:\Users\alice\Downloads\internal-tool.exe",
            new()
            {
                [AttributeKeys.ProcessName] = "internal-tool.exe",
                [AttributeKeys.Signed] = "false",
                [AttributeKeys.Sha256] = "11223344556677889900"
            });

        var first = await pipeline.ProcessAsync(fpEvt);
        first.Scored.Assessment.Score.Should().BeGreaterThan(0);

        pipeline.ApplyFeedback(new AnalystFeedback(null, null, [fpEvt.Id], IsFalsePositive: true, Comment: "Outil interne autorisé"));

        var second = await pipeline.ProcessAsync(TestEvents.Make(
            EventCategory.Process, EventTypes.ProcessStart, @"C:\Users\alice\Downloads\internal-tool.exe",
            new()
            {
                [AttributeKeys.ProcessName] = "internal-tool.exe",
                [AttributeKeys.Signed] = "false",
                [AttributeKeys.Sha256] = "11223344556677889900"
            }));
        second.Scored.Assessment.Score.Should().Be(0);
    }
}
