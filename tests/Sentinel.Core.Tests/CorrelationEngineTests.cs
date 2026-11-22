using Sentinel.Core.Correlation;
using Sentinel.Core.Enrichment;
using Sentinel.Shared.Models;

namespace Sentinel.Core.Tests;

public sealed class CorrelationEngineTests
{
    [Fact]
    public void CorrelationEngine_AppliesExactFormula_AndExponentialTimeDecay()
    {
        var preFilter = new EventPreFilter(new LocalReputationStore());
        var settings = TestEvents.ActiveSettings();
        settings.Correlation.EarlyEscalation = false; // Isoler la formule pure §8.2
        settings.Correlation.DecayHalfLifeMinutes = 15;
        settings.Correlation.SameEntityWeight = 0.8;

        // Cas 1 : Δt = 0 min (facteur_temps = 1.0), même domaine (poids = 0.8)
        var engine0 = new CorrelationEngine();
        var e1 = TestEvents.Make(EventCategory.Network, EventTypes.DnsQuery, "drop.xyz",
            new() { [AttributeKeys.Domain] = "drop.xyz" }, ts: TestEvents.BaseTime);
        var e2 = TestEvents.Make(EventCategory.Network, EventTypes.NetworkConnection, "drop.xyz",
            new() { [AttributeKeys.Domain] = "drop.xyz" }, ts: TestEvents.BaseTime);

        var a1 = new ThreatAssessment(e1.Id, 40, ThreatType.Exfiltration, "dns", AssessmentSource.Rules, 0.8);
        var a2 = new ThreatAssessment(e2.Id, 50, ThreatType.Exfiltration, "net", AssessmentSource.Rules, 0.8);

        engine0.Correlate(preFilter.Evaluate(e1, settings), a1, settings).Should().BeNull();
        var out0 = engine0.Correlate(preFilter.Evaluate(e2, settings), a2, settings);

        out0.Should().NotBeNull();
        // Formule §8.2 : round(50 + 40 * 0.8 * 2^(0)) = 50 + 32 = 82
        out0!.Cluster.Score.Should().Be(82);
        out0.Cluster.MaxEventScore.Should().Be(50);

        // Cas 2 : Δt = 15 min (exactement 1 demi-vie -> facteur_temps = 0.5)
        var engine15 = new CorrelationEngine();
        var e2Later = e2 with { Id = Guid.NewGuid(), Timestamp = TestEvents.BaseTime.AddMinutes(15) };
        var a2Later = a2 with { EventId = e2Later.Id };

        engine15.Correlate(preFilter.Evaluate(e1, settings), a1, settings);
        var out15 = engine15.Correlate(preFilter.Evaluate(e2Later, settings), a2Later, settings);

        out15.Should().NotBeNull();
        // Formule §8.2 : round(50 + 40 * 0.8 * 0.5) = 50 + 16 = 66
        out15!.Cluster.Score.Should().Be(66);
        out15.Cluster.Score.Should().BeLessThan(out0.Cluster.Score);
    }

    [Fact]
    public void CorrelationEngine_EarlyEscalation_RaisesLevelAtSecondSimilarEvent()
    {
        var preFilter = new EventPreFilter(new LocalReputationStore());
        var e1 = TestEvents.Make(EventCategory.Session, EventTypes.LogonFailure, "alice",
            new() { [AttributeKeys.TargetUser] = "alice" }, ts: TestEvents.BaseTime);
        var e2 = TestEvents.Make(EventCategory.Session, EventTypes.LogonFailure, "alice",
            new() { [AttributeKeys.TargetUser] = "alice" }, ts: TestEvents.BaseTime.AddMinutes(10));

        var a1 = new ThreatAssessment(e1.Id, 34, ThreatType.Intrusion, "échec 1", AssessmentSource.Rules, 0.8);
        var a2 = new ThreatAssessment(e2.Id, 34, ThreatType.Intrusion, "échec 2", AssessmentSource.Rules, 0.8);

        // Sans escalade précoce
        var sOff = TestEvents.ActiveSettings();
        sOff.Correlation.EarlyEscalation = false;
        var engOff = new CorrelationEngine();
        engOff.Correlate(preFilter.Evaluate(e1, sOff), a1, sOff);
        var cOff = engOff.Correlate(preFilter.Evaluate(e2, sOff), a2, sOff)!.Cluster;

        // Avec escalade précoce
        var sOn = TestEvents.ActiveSettings();
        sOn.Correlation.EarlyEscalation = true;
        var engOn = new CorrelationEngine();
        engOn.Correlate(preFilter.Evaluate(e1, sOn), a1, sOn);
        var cOn = engOn.Correlate(preFilter.Evaluate(e2, sOn), a2, sOn)!.Cluster;

        cOff.Escalated.Should().BeFalse();
        cOff.Level.Should().Be(ThreatLevel.Low);

        cOn.Escalated.Should().BeTrue();
        cOn.Level.Should().Be(ThreatLevels.Raise(cOff.Level));
        cOn.Score.Should().BeGreaterThanOrEqualTo(sOn.Thresholds.Moderate);
    }

    [Fact]
    public async Task AttackChain1_PhishingToExecution_DetectedEndToEnd()
    {
        var pipeline = ThreatPipelineFactory.Create(TestEvents.ActiveSettings());
        var t = TestEvents.BaseTime;

        await pipeline.ProcessAsync(TestEvents.Make(EventCategory.Clipboard, EventTypes.ClipboardUrl, "https://bit.ly/f2026",
            new() { [AttributeKeys.Url] = "https://bit.ly/f2026", [AttributeKeys.Domain] = "bit.ly", [AttributeKeys.IsShortener] = "true" },
            ts: t, hints: "phish-camp-1"));

        await pipeline.ProcessAsync(TestEvents.Make(EventCategory.Browser, EventTypes.UrlVisited, "https://pay-rh.xyz/facture",
            new() { [AttributeKeys.Url] = "https://pay-rh.xyz/facture", [AttributeKeys.Domain] = "pay-rh.xyz", [AttributeKeys.DomainAgeDays] = "2" },
            ts: t.AddSeconds(15), hints: "phish-camp-1"));

        await pipeline.ProcessAsync(TestEvents.Make(EventCategory.Browser, EventTypes.DownloadStarted, "facture_2026.exe",
            new() { [AttributeKeys.FileName] = "facture_2026.exe", [AttributeKeys.Domain] = "pay-rh.xyz", [AttributeKeys.IsExecutable] = "true" },
            ts: t.AddSeconds(30), hints: "phish-camp-1"));

        await pipeline.ProcessAsync(TestEvents.Make(EventCategory.Process, EventTypes.ProcessStart, @"C:\Users\alice\Downloads\facture_2026.exe",
            new() { [AttributeKeys.ProcessPath] = @"C:\Users\alice\Downloads\facture_2026.exe", [AttributeKeys.Signed] = "false", [AttributeKeys.ProcessId] = "4200" },
            ts: t.AddSeconds(50), hints: "phish-camp-1"));

        var finalRes = await pipeline.ProcessAsync(TestEvents.Make(EventCategory.Network, EventTypes.NetworkConnection, "pay-rh.xyz",
            new() { [AttributeKeys.Domain] = "pay-rh.xyz", [AttributeKeys.RemoteIp] = "185.220.101.4", [AttributeKeys.RemotePort] = "4444", [AttributeKeys.ProcessId] = "4200" },
            ts: t.AddSeconds(65), hints: "phish-camp-1"));

        finalRes.Cluster.Should().NotBeNull();
        finalRes.Cluster!.Chain.Should().NotBeNull();
        finalRes.Cluster.Chain!.ChainId.Should().Be("CHAIN-PHISHING");
        finalRes.Cluster.Chain.IsComplete.Should().BeTrue();
        finalRes.Cluster.Chain.StepsMatched.Should().Be(5);
        finalRes.Cluster.Score.Should().BeGreaterThanOrEqualTo(90);
        finalRes.Cluster.MitreTechniques.Should().Contain("T1566");
    }

    [Fact]
    public async Task AttackChain2_BadUsb_DetectedEndToEnd()
    {
        var pipeline = ThreatPipelineFactory.Create(TestEvents.ActiveSettings());
        var t = TestEvents.BaseTime;

        await pipeline.ProcessAsync(TestEvents.Make(EventCategory.Device, EventTypes.UsbInserted, @"USB\VID_2E8A&PID_0005\1",
            new() { [AttributeKeys.DeviceId] = "USB-HID-01", [AttributeKeys.DeviceClass] = "HID", [AttributeKeys.IsKeyboard] = "true", [AttributeKeys.VendorId] = "2E8A" },
            ts: t));

        await pipeline.ProcessAsync(TestEvents.Make(EventCategory.Typing, EventTypes.TypingStats, "typing",
            new() { [AttributeKeys.KeysPerSecond] = "48.5", [AttributeKeys.MeanIntervalMs] = "20", [AttributeKeys.IntervalStdDevMs] = "2.1", [AttributeKeys.SampleSize] = "60", [AttributeKeys.Injected] = "true" },
            ts: t.AddSeconds(2)));

        var finalRes = await pipeline.ProcessAsync(TestEvents.Make(EventCategory.Process, EventTypes.ProcessStart, @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            new() { [AttributeKeys.ProcessName] = "powershell.exe", [AttributeKeys.CommandLine] = "powershell -nop -w hidden -enc SQBFAFgA" },
            ts: t.AddSeconds(4)));

        finalRes.Cluster.Should().NotBeNull();
        finalRes.Cluster!.Chain.Should().NotBeNull();
        finalRes.Cluster.Chain!.ChainId.Should().Be("CHAIN-BADUSB");
        finalRes.Cluster.Chain.IsComplete.Should().BeTrue();
        finalRes.Cluster.DominantType.Should().Be(ThreatType.BadUsb);
    }

    [Fact]
    public async Task AttackChain3_Ransomware_DetectedEndToEnd()
    {
        var pipeline = ThreatPipelineFactory.Create(TestEvents.ActiveSettings());
        var t = TestEvents.BaseTime;

        await pipeline.ProcessAsync(TestEvents.Make(EventCategory.File, EventTypes.FileBurst, @"C:\Users\alice\Documents",
            new() { [AttributeKeys.BurstCount] = "45", [AttributeKeys.BurstWindowSeconds] = "8", [AttributeKeys.BurstAvgEntropy] = "7.85", [AttributeKeys.BurstDistinctExtensions] = "3", [AttributeKeys.ProcessId] = "7777" },
            ts: t));

        var finalRes = await pipeline.ProcessAsync(TestEvents.Make(EventCategory.File, EventTypes.FileRenamed, @"C:\Users\alice\Documents\budget.xlsx.locked",
            new() { [AttributeKeys.FilePath] = @"C:\Users\alice\Documents\budget.xlsx.locked", [AttributeKeys.OldExtension] = ".xlsx", [AttributeKeys.Extension] = ".locked", [AttributeKeys.Entropy] = "7.92", [AttributeKeys.ProcessId] = "7777" },
            ts: t.AddSeconds(3)));

        finalRes.Cluster.Should().NotBeNull();
        finalRes.Cluster!.Chain.Should().NotBeNull();
        finalRes.Cluster.Chain!.ChainId.Should().Be("CHAIN-RANSOMWARE");
        finalRes.Cluster.Chain.IsComplete.Should().BeTrue();
        finalRes.Cluster.DominantType.Should().Be(ThreatType.Ransomware);
        finalRes.Cluster.Score.Should().BeGreaterThanOrEqualTo(90);
    }

    [Fact]
    public async Task AttackChain4_Exfiltration_DetectedEndToEnd()
    {
        var pipeline = ThreatPipelineFactory.Create(TestEvents.ActiveSettings());
        var t = TestEvents.BaseTime;

        await pipeline.ProcessAsync(TestEvents.Make(EventCategory.File, EventTypes.FileCreated, @"C:\Users\alice\Temp\export_rh.7z",
            new() { [AttributeKeys.FilePath] = @"C:\Users\alice\Temp\export_rh.7z", [AttributeKeys.IsArchive] = "true", [AttributeKeys.FileSize] = "25000000" },
            ts: t));

        await pipeline.ProcessAsync(TestEvents.Make(EventCategory.Network, EventTypes.DnsQuery, "upload-drop.xyz",
            new() { [AttributeKeys.Domain] = "upload-drop.xyz", [AttributeKeys.DomainAgeDays] = "4" },
            ts: t.AddSeconds(20)));

        var finalRes = await pipeline.ProcessAsync(TestEvents.Make(EventCategory.Network, EventTypes.NetworkVolume, "upload-drop.xyz",
            new() { [AttributeKeys.Domain] = "upload-drop.xyz", [AttributeKeys.BytesSent] = "26000000", [AttributeKeys.Direction] = "outbound" },
            ts: t.AddSeconds(45)));

        finalRes.Cluster.Should().NotBeNull();
        finalRes.Cluster!.Chain.Should().NotBeNull();
        finalRes.Cluster.Chain!.ChainId.Should().Be("CHAIN-EXFILTRATION");
        finalRes.Cluster.Chain.IsComplete.Should().BeTrue();
        finalRes.Cluster.DominantType.Should().Be(ThreatType.Exfiltration);
    }

    [Fact]
    public async Task AttackChain5_BruteForceIntrusion_DetectedEndToEnd()
    {
        var pipeline = ThreatPipelineFactory.Create(TestEvents.ActiveSettings());
        var t = TestEvents.BaseTime;

        await pipeline.ProcessAsync(TestEvents.Make(EventCategory.Session, EventTypes.LogonFailure, "alice",
            new() { [AttributeKeys.TargetUser] = "alice", [AttributeKeys.SourceIp] = "198.51.100.42", [AttributeKeys.FailureCount] = "1" },
            ts: t));

        await pipeline.ProcessAsync(TestEvents.Make(EventCategory.Session, EventTypes.LogonFailure, "alice",
            new() { [AttributeKeys.TargetUser] = "alice", [AttributeKeys.SourceIp] = "198.51.100.42", [AttributeKeys.FailureCount] = "5" },
            ts: t.AddSeconds(15)));

        await pipeline.ProcessAsync(TestEvents.Make(EventCategory.Session, EventTypes.LogonSuccess, "alice",
            new() { [AttributeKeys.TargetUser] = "alice", [AttributeKeys.SourceIp] = "198.51.100.42" },
            ts: t.AddSeconds(30)));

        var finalRes = await pipeline.ProcessAsync(TestEvents.Make(EventCategory.Process, EventTypes.ProcessStart, @"C:\Temp\recon.exe",
            new() { [AttributeKeys.ProcessPath] = @"C:\Temp\recon.exe", [AttributeKeys.Signed] = "false", [AttributeKeys.Elevated] = "true" },
            ts: t.AddSeconds(45)));

        finalRes.Cluster.Should().NotBeNull();
        finalRes.Cluster!.Chain.Should().NotBeNull();
        finalRes.Cluster.Chain!.ChainId.Should().Be("CHAIN-BRUTEFORCE");
        finalRes.Cluster.Chain.IsComplete.Should().BeTrue();
        finalRes.Cluster.DominantType.Should().Be(ThreatType.Intrusion);
    }

    [Fact]
    public async Task AttackChain6_Persistence_DetectedEndToEnd()
    {
        var pipeline = ThreatPipelineFactory.Create(TestEvents.ActiveSettings());
        var t = TestEvents.BaseTime;

        await pipeline.ProcessAsync(TestEvents.Make(EventCategory.Installation, EventTypes.AppInstalled, "FreePdfHelper",
            new() { [AttributeKeys.AppName] = "FreePdfHelper", [AttributeKeys.Signed] = "false" },
            ts: t));

        await pipeline.ProcessAsync(TestEvents.Make(EventCategory.Installation, EventTypes.StartupEntryAdded, @"HKCU\...\Run\FreePdfHelper",
            new() { [AttributeKeys.RegistryKey] = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", [AttributeKeys.RegistryValue] = @"C:\Users\alice\AppData\Roaming\helper.exe" },
            ts: t.AddSeconds(10)));

        var finalRes = await pipeline.ProcessAsync(TestEvents.Make(EventCategory.Installation, EventTypes.ScheduledTaskCreated, "FreePdfSyncTask",
            new() { [AttributeKeys.TaskName] = "FreePdfSyncTask", [AttributeKeys.CommandLine] = @"C:\Users\alice\AppData\Roaming\helper.exe --silent" },
            ts: t.AddSeconds(20)));

        finalRes.Cluster.Should().NotBeNull();
        finalRes.Cluster!.Chain.Should().NotBeNull();
        finalRes.Cluster.Chain!.ChainId.Should().Be("CHAIN-PERSISTENCE");
        finalRes.Cluster.Chain.IsComplete.Should().BeTrue();
        finalRes.Cluster.DominantType.Should().Be(ThreatType.Persistence);
    }

    [Fact]
    public async Task AttackChain7_SocialEngineering_DetectedEndToEnd()
    {
        var pipeline = ThreatPipelineFactory.Create(TestEvents.ActiveSettings());
        var t = TestEvents.BaseTime;

        await pipeline.ProcessAsync(TestEvents.Make(EventCategory.Browser, EventTypes.LinkClicked, "https://bit.ly/prime-rh",
            new() { [AttributeKeys.Url] = "https://bit.ly/prime-rh", [AttributeKeys.Domain] = "bit.ly", [AttributeKeys.IsShortener] = "true", [AttributeKeys.TabId] = "tab-7" },
            ts: t));

        await pipeline.ProcessAsync(TestEvents.Make(EventCategory.Browser, EventTypes.UrlVisited, "https://prime-rh-2026.click",
            new() { [AttributeKeys.Url] = "https://prime-rh-2026.click", [AttributeKeys.Domain] = "prime-rh-2026.click", [AttributeKeys.DomainAgeDays] = "2", [AttributeKeys.TabId] = "tab-7" },
            ts: t.AddSeconds(5)));

        var finalRes = await pipeline.ProcessAsync(TestEvents.Make(EventCategory.Browser, EventTypes.DownloadStarted, "prime_rh.pdf.exe",
            new() { [AttributeKeys.FileName] = "prime_rh.pdf.exe", [AttributeKeys.Domain] = "prime-rh-2026.click", [AttributeKeys.IsExecutable] = "true", [AttributeKeys.TabId] = "tab-7" },
            ts: t.AddSeconds(12)));

        finalRes.Cluster.Should().NotBeNull();
        finalRes.Cluster!.Chain.Should().NotBeNull();
        finalRes.Cluster.Chain!.ChainId.Should().Be("CHAIN-SOCIAL-ENG");
        finalRes.Cluster.Chain.IsComplete.Should().BeTrue();
        finalRes.Cluster.DominantType.Should().Be(ThreatType.SocialEngineering);
    }

    [Fact]
    public async Task CorrelationEngine_MergesTwoClusters_AndSupportsWarmUp()
    {
        var settings = TestEvents.ActiveSettings();
        var t = TestEvents.BaseTime;

        // Deux clusters distincts sur le même poste (utilisateurs différents pour ne pas se relier immédiatement)
        var eA1 = TestEvents.Make(EventCategory.Browser, EventTypes.UrlVisited, "https://c2-a.xyz",
            new() { [AttributeKeys.Domain] = "c2-a.xyz", [AttributeKeys.DomainAgeDays] = "2" }, ts: t, userId: "u1");
        var eA2 = TestEvents.Make(EventCategory.Network, EventTypes.DnsQuery, "c2-a.xyz",
            new() { [AttributeKeys.Domain] = "c2-a.xyz", [AttributeKeys.DomainAgeDays] = "2" }, ts: t.AddSeconds(10), userId: "u1");

        var eB1 = TestEvents.Make(EventCategory.File, EventTypes.FileCreated, @"C:\Users\u2\Downloads\drop.exe",
            new() { [AttributeKeys.FilePath] = @"C:\Users\u2\Downloads\drop.exe", [AttributeKeys.Sha256] = "deadbeef1234", [AttributeKeys.IsExecutable] = "true" }, ts: t.AddSeconds(15), userId: "u2");
        var eB2 = TestEvents.Make(EventCategory.Process, EventTypes.ProcessStart, @"C:\Users\u2\Downloads\drop.exe",
            new() { [AttributeKeys.ProcessPath] = @"C:\Users\u2\Downloads\drop.exe", [AttributeKeys.Sha256] = "deadbeef1234", [AttributeKeys.Signed] = "false" }, ts: t.AddSeconds(20), userId: "u2");

        // Événement pont partageant à la fois le domaine c2-a.xyz et le hash deadbeef1234
        var bridge = TestEvents.Make(EventCategory.Network, EventTypes.NetworkConnection, "c2-a.xyz",
            new() { [AttributeKeys.Domain] = "c2-a.xyz", [AttributeKeys.Sha256] = "deadbeef1234", [AttributeKeys.RemotePort] = "4444" }, ts: t.AddSeconds(25), userId: "u3");

        var pipeline = ThreatPipelineFactory.Create(settings);
        await pipeline.ProcessAsync(eA1);
        var rA = await pipeline.ProcessAsync(eA2);
        await pipeline.ProcessAsync(eB1);
        var rB = await pipeline.ProcessAsync(eB2);

        rA.Cluster.Should().NotBeNull();
        rB.Cluster.Should().NotBeNull();
        rA.Cluster!.Id.Should().NotBe(rB.Cluster!.Id);
        pipeline.GetActiveClusters("HOST-01").Should().HaveCount(2);

        var merged = await pipeline.ProcessAsync(bridge);
        merged.Cluster.Should().NotBeNull();
        merged.Cluster!.EventIds.Should().HaveCount(5);
        pipeline.GetActiveClusters("HOST-01").Should().HaveCount(1);

        // Vérification WarmUpAsync sur un nouveau pipeline
        var warmed = ThreatPipelineFactory.Create(settings);
        await warmed.WarmUpAsync(
        [
            new ScoredEvent(eA1, new ThreatAssessment(eA1.Id, 48, ThreatType.Phishing, "r", AssessmentSource.Rules, 0.8)),
            new ScoredEvent(eA2, new ThreatAssessment(eA2.Id, 46, ThreatType.Phishing, "r", AssessmentSource.Rules, 0.8))
        ]);
        warmed.GetActiveClusters("HOST-01").Should().HaveCount(1);
    }
}
