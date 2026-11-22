using System.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.AI;
using Sentinel.Core.Abstractions;
using Sentinel.Core.Correlation;
using Sentinel.Core.Decision;
using Sentinel.Shared.Api;
using Sentinel.Shared.Models;

namespace Sentinel.Core.Tests;

public sealed class DecisionAndEvaluationTests
{
    [Fact]
    public void DecisionEngine_ImplementsFullMatrix_Levels0To4_AndModes()
    {
        var engine = new DecisionEngine();
        var now = TestEvents.BaseTime;

        var evt = TestEvents.Make(
            EventCategory.Browser, EventTypes.UrlVisited, "https://evil-phish.xyz",
            new()
            {
                [AttributeKeys.Domain] = "evil-phish.xyz",
                [AttributeKeys.Url] = "https://evil-phish.xyz/login",
                [AttributeKeys.TabId] = "tab-42",
                [AttributeKeys.ProcessId] = "999",
                [AttributeKeys.FilePath] = @"C:\Users\alice\Downloads\drop.exe",
                [AttributeKeys.DeviceId] = "USB-HID-99",
                [AttributeKeys.RemoteIp] = "198.51.100.7"
            });

        var active = TestEvents.ActiveSettings();

        // Niveau 0 : Info -> LogOnly
        var d0 = engine.Decide(evt, new ThreatAssessment(evt.Id, 10, ThreatType.None, "bénin", AssessmentSource.Rules, 0.9), null, null, active, now);
        d0.Level.Should().Be(ThreatLevel.Info);
        d0.AlertAdmin.Should().BeFalse();
        d0.Actions.Select(a => a.Type).Should().Contain(ResponseActionType.LogOnly);

        // Niveau 1 : Faible -> MarkForCorrelation
        var d1 = engine.Decide(evt, new ThreatAssessment(evt.Id, 40, ThreatType.Phishing, "faible", AssessmentSource.Rules, 0.8), null, null, active, now);
        d1.Level.Should().Be(ThreatLevel.Low);
        d1.Actions.Select(a => a.Type).Should().Contain(ResponseActionType.MarkForCorrelation);

        // Niveau 2 : Modéré -> NotifyUser + EnhancedMonitoring
        var d2 = engine.Decide(evt, new ThreatAssessment(evt.Id, 60, ThreatType.Phishing, "modéré", AssessmentSource.Rules, 0.8), null, null, active, now);
        d2.Level.Should().Be(ThreatLevel.Moderate);
        d2.NotifyUser.Should().BeTrue();
        d2.AlertAdmin.Should().BeFalse();
        d2.Actions.Select(a => a.Type).Should().Contain(ResponseActionType.NotifyUser).And.Contain(ResponseActionType.EnhancedMonitoring);

        // Niveau 3 : Élevé -> AlertAdmin + RequiresHumanApproval + actions proposées (Automatic = false)
        var d3 = engine.Decide(evt, new ThreatAssessment(evt.Id, 82, ThreatType.Phishing, "élevé", AssessmentSource.Rules, 0.85), null, null, active, now);
        d3.Level.Should().Be(ThreatLevel.High);
        d3.AlertAdmin.Should().BeTrue();
        d3.RequiresHumanApproval.Should().BeTrue();
        d3.Actions.Should().OnlyContain(a => !a.Automatic);
        d3.Actions.Should().Contain(a => a.Type == ResponseActionType.BlockDomain && a.Target == "evil-phish.xyz");

        // Niveau 4 (Active) : Critique -> actions automatiques réversibles pour chaque ThreatType
        var expectedCritical = new Dictionary<ThreatType, ResponseActionType[]>
        {
            [ThreatType.Phishing] = [ResponseActionType.BlockDomain, ResponseActionType.CloseBrowserTab],
            [ThreatType.Malware] = [ResponseActionType.KillProcess, ResponseActionType.QuarantineFile],
            [ThreatType.Ransomware] = [ResponseActionType.KillProcess, ResponseActionType.IsolateNetwork, ResponseActionType.ProtectFolders],
            [ThreatType.BadUsb] = [ResponseActionType.DisableDevice],
            [ThreatType.Exfiltration] = [ResponseActionType.BlockProcessConnections],
            [ThreatType.Intrusion] = [ResponseActionType.LockAccount, ResponseActionType.BlockIp],
            [ThreatType.SocialEngineering] = [ResponseActionType.BlockDomain],
            [ThreatType.Persistence] = [ResponseActionType.QuarantineFile],
            [ThreatType.Anomaly] = [ResponseActionType.LockSession],
            [ThreatType.Tampering] = [ResponseActionType.IsolateNetwork, ResponseActionType.LockSession]
        };

        foreach (var (threatType, expectedActions) in expectedCritical)
        {
            var dc = engine.Decide(evt, new ThreatAssessment(evt.Id, 95, threatType, "critique", AssessmentSource.Rules, 0.95), null, null, active, now);
            dc.Level.Should().Be(ThreatLevel.Critical);
            dc.AlertAdmin.Should().BeTrue();
            dc.Mode.Should().Be(OperatingMode.Active);

            foreach (var expectedAction in expectedActions)
            {
                dc.Actions.Should().Contain(a => a.Type == expectedAction && a.Automatic && a.Parameters["reversible"] == "true",
                    $"action critique automatique réversible {expectedAction} attendue pour {threatType}");
            }
        }

        // Mode Simulation : niveau 4 -> AUCUNE action automatique
        var simSettings = TestEvents.ActiveSettings();
        simSettings.Mode = OperatingMode.Simulation;
        var dSim = engine.Decide(evt, new ThreatAssessment(evt.Id, 95, ThreatType.Malware, "critique", AssessmentSource.Rules, 0.95), null, null, simSettings, now);
        dSim.Mode.Should().Be(OperatingMode.Simulation);
        dSim.Actions.Should().OnlyContain(a => !a.Automatic);

        // Mode Learning < 7 jours -> Learning (Automatic = false) ; >= 7 jours avec AutoLeaveLearning -> Active
        var learnSettings = TestEvents.ActiveSettings();
        learnSettings.Mode = OperatingMode.Learning;
        learnSettings.LearningStartedAt = now.AddDays(-2);
        learnSettings.LearningPeriodDays = 7;
        learnSettings.AutoLeaveLearning = true;

        var dLearn = engine.Decide(evt, new ThreatAssessment(evt.Id, 95, ThreatType.Malware, "critique", AssessmentSource.Rules, 0.95), null, null, learnSettings, now);
        dLearn.Mode.Should().Be(OperatingMode.Learning);
        dLearn.Actions.Should().OnlyContain(a => !a.Automatic);

        var dAfterLearn = engine.Decide(evt, new ThreatAssessment(evt.Id, 95, ThreatType.Malware, "critique", AssessmentSource.Rules, 0.95), null, null, learnSettings, now.AddDays(6));
        dAfterLearn.Mode.Should().Be(OperatingMode.Active);
        dAfterLearn.Actions.Should().Contain(a => a.Type == ResponseActionType.KillProcess && a.Automatic);
    }

    [Fact]
    public async Task ScientificEvaluation_ABC_PhishingScenario_ConfigC_DetectsStrictlyEarlierThanAAndB()
    {
        // Scénario Phishing -> exécution étalé sur 180 secondes (signaux faibles successifs puis compromission)
        var t0 = TestEvents.BaseTime;
        var scenario = new[]
        {
            // Étape 1 (t=0s) : URL raccourcie copiée (signal faible individuel = 38)
            TestEvents.Make(EventCategory.Clipboard, EventTypes.ClipboardUrl, "https://bit.ly/rh-bonus",
                new() { [AttributeKeys.Url] = "https://bit.ly/rh-bonus", [AttributeKeys.Domain] = "bit.ly", [AttributeKeys.IsShortener] = "true" },
                ts: t0, hints: "camp-phish"),

            // Étape 2 (t=25s) : Ouverture vers domaine récent (signal faible individuel = 48)
            TestEvents.Make(EventCategory.Browser, EventTypes.UrlVisited, "https://portail-rh-info.com/bonus",
                new() { [AttributeKeys.Url] = "https://portail-rh-info.com/bonus", [AttributeKeys.Domain] = "portail-rh-info.com", [AttributeKeys.DomainAgeDays] = "3" },
                ts: t0.AddSeconds(25), hints: "camp-phish"),

            // Étape 3 (t=60s) : Téléchargement d'un exécutable (signal faible individuel = 46)
            TestEvents.Make(EventCategory.Browser, EventTypes.DownloadStarted, "bonus_viewer.exe",
                new() { [AttributeKeys.FileName] = "bonus_viewer.exe", [AttributeKeys.Domain] = "portail-rh-info.com", [AttributeKeys.IsExecutable] = "true" },
                ts: t0.AddSeconds(60), hints: "camp-phish"),

            // Étape 4 (t=110s) : Exécution non signée depuis Téléchargements (signal faible individuel = 48)
            TestEvents.Make(EventCategory.Process, EventTypes.ProcessStart, @"C:\Users\alice\Downloads\bonus_viewer.exe",
                new() { [AttributeKeys.ProcessPath] = @"C:\Users\alice\Downloads\bonus_viewer.exe", [AttributeKeys.Signed] = "false", [AttributeKeys.ProcessId] = "6120" },
                ts: t0.AddSeconds(110), hints: "camp-phish"),

            // Étape 5 (t=180s) : PowerShell encodé + obfusqué lancé par le payload (score individuel élevé >= 80)
            TestEvents.Make(EventCategory.Process, EventTypes.ProcessStart, @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                new()
                {
                    [AttributeKeys.ProcessName] = "powershell.exe",
                    [AttributeKeys.ParentProcessId] = "6120",
                    [AttributeKeys.CommandLine] = "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"
                },
                ts: t0.AddSeconds(180), hints: "camp-phish")
        };

        // Faux LLM réaliste : évalue chaque événement ambigu de manière nuancée (légèrement plus sévère que les règles, mais ne crée pas de faux critique sur un simple clic isolé)
        ILlmAssessor CreateRealisticLlm() => new FakeLlmAssessor((ctx, _) =>
        {
            var boosted = Math.Min(70, ctx.RuleScore + 12);
            return Task.FromResult<LlmAssessmentResult?>(
                new LlmAssessmentResult(boosted, ctx.RuleType, "Contexte suspect évalué par IA locale.", 0.75));
        });

        // Config A : Règles seules
        var pipeA = ThreatPipelineFactory.Create(TestEvents.ActiveSettings(llmEnabled: false, correlationEnabled: false));
        // Config B : Règles + IA (sans corrélation)
        var pipeB = ThreatPipelineFactory.Create(TestEvents.ActiveSettings(llmEnabled: true, correlationEnabled: false), CreateRealisticLlm());
        // Config C : Règles + IA + Corrélation
        var pipeC = ThreatPipelineFactory.Create(TestEvents.ActiveSettings(llmEnabled: true, correlationEnabled: true), CreateRealisticLlm());

        var metricA = await RunScenario(pipeA, "A-RulesOnly", scenario);
        var metricB = await RunScenario(pipeB, "B-RulesPlusLlm", scenario);
        var metricC = await RunScenario(pipeC, "C-FullCorrelation", scenario);

        metricA.Detected.Should().BeTrue();
        metricB.Detected.Should().BeTrue();
        metricC.Detected.Should().BeTrue();

        // Hypothèse scientifique (§1.2, §8.4, §14.3) : C détecte STRICTEMENT plus tôt en événements ET en secondes que A et B
        metricC.EventsBeforeAlert.Should().BeLessThan(metricA.EventsBeforeAlert);
        metricC.EventsBeforeAlert.Should().BeLessThan(metricB.EventsBeforeAlert);
        metricC.SecondsToDetect.Should().BeLessThan(metricA.SecondsToDetect);
        metricC.SecondsToDetect.Should().BeLessThan(metricB.SecondsToDetect);
        metricC.EventsBeforeAlert.Should().BeLessThanOrEqualTo(2);
    }

    [Fact]
    public async Task Performance_Processes5000EventsUnder3Seconds_WithBoundedClusters()
    {
        var settings = TestEvents.ActiveSettings(llmEnabled: false, correlationEnabled: true);
        var pipeline = ThreatPipelineFactory.Create(settings);

        // Préchauffage JIT sur un événement bénin hors mesure
        await pipeline.ProcessAsync(TestEvents.Make(
            EventCategory.Process,
            EventTypes.ProcessStart,
            @"C:\Program Files\App\warmup.exe",
            new() { [AttributeKeys.ProcessName] = "warmup.exe", [AttributeKeys.Signed] = "true", [AttributeKeys.Publisher] = "Microsoft Corporation" },
            ts: TestEvents.BaseTime.AddSeconds(-10),
            hostId: "WARMUP",
            userId: "warmup"));

        var sw = Stopwatch.StartNew();
        var t0 = TestEvents.BaseTime;

        for (var i = 0; i < 5000; i++)
        {
            SecurityEvent evt;
            if (i % 5 == 0)
            {
                // Événement suspect corrélable réparti sur plusieurs hôtes/domaines
                var host = $"HOST-{i % 40}";
                var domain = $"suspect-{i % 250}.xyz";
                evt = TestEvents.Make(
                    EventCategory.Browser,
                    EventTypes.UrlVisited,
                    $"https://{domain}/p/{i}",
                    new() { [AttributeKeys.Domain] = domain, [AttributeKeys.DomainAgeDays] = "5" },
                    ts: t0.AddSeconds(i),
                    hostId: host,
                    userId: $"user-{i % 20}");
            }
            else
            {
                // Événement bénin
                evt = TestEvents.Make(
                    EventCategory.Process,
                    EventTypes.ProcessStart,
                    @"C:\Program Files\App\word.exe",
                    new() { [AttributeKeys.ProcessName] = "word.exe", [AttributeKeys.Signed] = "true", [AttributeKeys.Publisher] = "Microsoft Corporation" },
                    ts: t0.AddSeconds(i),
                    hostId: $"HOST-{i % 40}",
                    userId: $"user-{i % 20}");
            }

            var res = await pipeline.ProcessAsync(evt);
            res.Decision.Should().NotBeNull();
        }

        sw.Stop();

        sw.Elapsed.Should().BeLessThan(TimeSpan.FromSeconds(3));
        pipeline.Stats.EventsProcessed.Should().Be(5001);
        pipeline.Stats.ActiveClusters.Should().BeGreaterThan(0);
        pipeline.Stats.ActiveClusters.Should().BeLessThanOrEqualTo(CorrelationEngine.MaxActiveClusters);
    }

    [Fact]
    public void ServiceCollectionExtensions_RegistersCoreServicesCleanly()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSentinelCore(TestEvents.ActiveSettings(llmEnabled: true, correlationEnabled: true));

        using var provider = services.BuildServiceProvider();
        var llm = provider.GetRequiredService<ILlmAssessor>();
        var pipeline = provider.GetRequiredService<IThreatPipeline>();

        llm.Should().BeOfType<OllamaAssessor>();
        pipeline.Should().BeOfType<ThreatPipeline>();
        pipeline.Settings.Mode.Should().Be(OperatingMode.Active);

        // Mise à jour à chaud des paramètres (UpdateSettings)
        var updated = pipeline.Settings;
        updated.Mode = OperatingMode.Simulation;
        updated.ExcludedDomains.Add("mon-domaine-interne.local");
        pipeline.UpdateSettings(updated);
        pipeline.Settings.Mode.Should().Be(OperatingMode.Simulation);
        pipeline.Settings.ExcludedDomains.Should().Contain("mon-domaine-interne.local");
    }

    private static async Task<ScenarioMetricDto> RunScenario(IThreatPipeline pipeline, string configName, SecurityEvent[] events)
    {
        var detected = false;
        var eventsBeforeAlert = events.Length;
        var secondsToDetect = (events[^1].Timestamp - events[0].Timestamp).TotalSeconds;
        var peakScore = 0;

        for (var i = 0; i < events.Length; i++)
        {
            var res = await pipeline.ProcessAsync(events[i]);
            var score = Math.Max(res.Scored.Assessment.Score, res.Cluster?.Score ?? 0);
            if (score > peakScore) peakScore = score;

            if (!detected && res.Decision is { AlertAdmin: true })
            {
                detected = true;
                eventsBeforeAlert = i + 1;
                secondsToDetect = (events[i].Timestamp - events[0].Timestamp).TotalSeconds;
            }
        }

        return new ScenarioMetricDto("PhishingToExecution", configName, detected, eventsBeforeAlert, secondsToDetect, peakScore, 0);
    }
}
