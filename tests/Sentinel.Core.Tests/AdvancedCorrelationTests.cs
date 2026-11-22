using FluentAssertions;
using Sentinel.AI;
using Sentinel.Core;
using Sentinel.Core.Correlation;
using Sentinel.Shared.Models;
using Xunit;

namespace Sentinel.Core.Tests;

public sealed class AdvancedCorrelationTests
{
    [Fact]
    public void MarkovModel_AssignsHigherProbabilityToAttackSequenceAndSupportsReversibleFeedback()
    {
        var markov = new AttackChainMarkovModel();

        var phishingSeq = new[] { EventCategory.Clipboard, EventCategory.Browser, EventCategory.File, EventCategory.Process, EventCategory.Network };
        var benignSeq = new[] { EventCategory.Session, EventCategory.Typing, EventCategory.Clipboard };

        var pAttack = markov.EstimateChainProbability(phishingSeq);
        var pBenign = markov.EstimateChainProbability(benignSeq);

        pAttack.Should().BeGreaterThan(0.70);
        pAttack.Should().BeGreaterThan(pBenign);

        // Retour faux positif -> diminue la probabilité
        var fbId = Guid.NewGuid();
        markov.ApplyFeedback(fbId, phishingSeq, isFalsePositive: true);
        var pAfterFp = markov.EstimateChainProbability(phishingSeq);
        pAfterFp.Should().BeLessThan(pAttack);

        // Annulation du retour -> restaure exactement la probabilité initiale
        markov.RevertFeedback(fbId).Should().BeTrue();
        var pAfterRevert = markov.EstimateChainProbability(phishingSeq);
        pAfterRevert.Should().BeApproximately(pAttack, 0.002);
    }

    [Fact]
    public async Task Pipeline_ProducesMitreTacticsNarrativeContributionsAndTimestampedEdges()
    {
        var settings = new SentinelSettings { Mode = OperatingMode.Active };
        settings.Llm.Enabled = false;
        var pipeline = ThreatPipelineFactory.Create(settings);

        var t0 = new DateTimeOffset(2026, 11, 22, 10, 0, 0, TimeSpan.Zero);
        var e1 = SecurityEvent.Create("HOST-M8", "alice", EventCategory.Clipboard, EventTypes.ClipboardUrl,
            "https://bit.ly/facture2026",
            new Dictionary<string, string> { [AttributeKeys.Domain] = "bit.ly", [AttributeKeys.IsShortener] = "true" },
            timestamp: t0);
        var e2 = SecurityEvent.Create("HOST-M8", "alice", EventCategory.Browser, EventTypes.UrlVisited,
            "https://bit.ly/facture2026",
            new Dictionary<string, string>
            {
                [AttributeKeys.Domain] = "bit.ly",
                [AttributeKeys.Url] = "https://bit.ly/facture2026",
                [AttributeKeys.IsShortener] = "true"
            },
            timestamp: t0.AddSeconds(15));
        var e3 = SecurityEvent.Create("HOST-M8", "alice", EventCategory.Process, EventTypes.ProcessStart,
            @"C:\Users\alice\Downloads\facture.pdf.exe",
            new Dictionary<string, string>
            {
                [AttributeKeys.ProcessName] = "powershell.exe",
                [AttributeKeys.CommandLine] = "powershell -enc SQBFAFgA",
                [AttributeKeys.FileName] = "facture.pdf.exe"
            },
            timestamp: t0.AddSeconds(25));

        var r1 = await pipeline.ProcessAsync(e1);
        var r2 = await pipeline.ProcessAsync(e2);
        var r3 = await pipeline.ProcessAsync(e3);

        // Escalade précoce dès le 2e événement préservée
        r2.Cluster.Should().NotBeNull();
        r2.Cluster!.Escalated.Should().BeTrue();

        // Cluster final enrichi v2
        r3.Cluster.Should().NotBeNull();
        var cluster = r3.Cluster!;
        cluster.MitreTactics.Should().Contain("Initial Access");
        cluster.Narrative.Should().Contain("HOST-M8").And.Contain("→");
        cluster.ChainProbability.Should().BeGreaterThan(0.6);
        cluster.ScoreContributions.Should().Contain(c => c.Engine == "Rules");
        cluster.ScoreContributions.Should().Contain(c => c.Engine == "MarkovModel");
        cluster.Links.Should().AllSatisfy(l => l.ObservedAt.Should().NotBeNull());

        // Feedback réversible + historique
        var fb = new AnalystFeedback(null, cluster.Id, cluster.EventIds, IsFalsePositive: false, "Confirmé TP");
        pipeline.ApplyFeedback(fb);
        pipeline.GetFeedbackHistory().Should().ContainSingle(h => h.Id == fb.FeedbackId && !h.Reverted);
        pipeline.RevertFeedback(fb.FeedbackId).Should().BeTrue();
        pipeline.GetFeedbackHistory().Should().ContainSingle(h => h.Id == fb.FeedbackId && h.Reverted);
    }

    [Fact]
    public async Task RuleEngine_ScoresV2CategoriesDefenderCanaryScriptAtHighOrCritical()
    {
        var settings = new SentinelSettings { Mode = OperatingMode.Active };
        settings.Llm.Enabled = false;
        var pipeline = ThreatPipelineFactory.Create(settings);

        var defWeak = SecurityEvent.Create("HOST-V2", "bob", EventCategory.Defender, EventTypes.DefenderRealtimeDisabled, "RealTimeProtection");
        var canaryHit = SecurityEvent.Create("HOST-V2", "bob", EventCategory.Canary, EventTypes.CanaryEncrypted,
            @"C:\Users\bob\Documents\Budget_Previsionnel_2026.csv",
            new Dictionary<string, string> { [AttributeKeys.Entropy] = "7.91" });
        var psBypass = SecurityEvent.Create("HOST-V2", "bob", EventCategory.Script, EventTypes.ScriptLoggingBypass,
            "ScriptBlock:1234",
            new Dictionary<string, string> { [AttributeKeys.ScriptIndicators] = "LoggingOrDefenseBypass,DownloadAndExecute" });

        var rDef = await pipeline.ProcessAsync(defWeak);
        var rCan = await pipeline.ProcessAsync(canaryHit);
        var rPs = await pipeline.ProcessAsync(psBypass);

        rDef.Scored.Assessment.Score.Should().BeGreaterThanOrEqualTo(90);
        rDef.Scored.Assessment.MitreTechniques.Should().Contain("T1562.001");

        rCan.Scored.Assessment.Score.Should().BeGreaterThanOrEqualTo(95);
        rCan.Scored.Assessment.Type.Should().Be(ThreatType.Ransomware);
        rCan.Decision!.Actions.Should().Contain(a => a.Type == ResponseActionType.KillProcess || a.Type == ResponseActionType.IsolateNetwork);

        rPs.Scored.Assessment.Score.Should().BeGreaterThanOrEqualTo(85);
        rPs.Scored.Assessment.MitreTechniques.Should().Contain("T1562.006");
    }
}
