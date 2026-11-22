using Sentinel.Core.Enrichment;
using Sentinel.Core.Scoring;
using Sentinel.Shared.Models;

namespace Sentinel.Core.Tests;

public sealed class PreFilterAndRulesTests
{
    [Fact]
    public async Task PreFilter_ExcludesConfiguredProcesses_Domains_Hashes_Paths_AndTrustedPublishers()
    {
        var settings = TestEvents.ActiveSettings();
        settings.ExcludedHashes.Add("abcdef0123456789");
        settings.ExcludedPaths.Add(@"C:\DevTools\TrustedApp\");

        var pipeline = ThreatPipelineFactory.Create(settings);

        // 1. Processus exclu
        var procExcluded = await pipeline.ProcessAsync(TestEvents.Make(
            EventCategory.Process, EventTypes.ProcessStart, @"C:\Temp\MsMpEng.exe",
            new Dictionary<string, string>
            {
                [AttributeKeys.ProcessName] = "MsMpEng.exe",
                [AttributeKeys.Signed] = "false"
            }));
        procExcluded.Scored.Assessment.Score.Should().Be(0);
        procExcluded.Scored.Assessment.Type.Should().Be(ThreatType.None);

        // 2. Domaine exclu (sous-domaine inclus)
        var domainExcluded = await pipeline.ProcessAsync(TestEvents.Make(
            EventCategory.Network, EventTypes.NetworkConnection, "download.microsoft.com",
            new Dictionary<string, string>
            {
                [AttributeKeys.Domain] = "download.microsoft.com",
                [AttributeKeys.BytesSent] = "50000000"
            }));
        domainExcluded.Scored.Assessment.Score.Should().Be(0);

        // 3. Hash exclu
        var hashExcluded = await pipeline.ProcessAsync(TestEvents.Make(
            EventCategory.File, EventTypes.FileCreated, @"C:\Users\alice\Downloads\tool.exe",
            new Dictionary<string, string>
            {
                [AttributeKeys.Sha256] = "ABCDEF0123456789",
                [AttributeKeys.IsExecutable] = "true"
            }));
        hashExcluded.Scored.Assessment.Score.Should().Be(0);

        // 4. Chemin exclu
        var pathExcluded = await pipeline.ProcessAsync(TestEvents.Make(
            EventCategory.Process, EventTypes.ProcessStart, @"C:\DevTools\TrustedApp\runner.exe",
            new Dictionary<string, string>
            {
                [AttributeKeys.ProcessPath] = @"C:\DevTools\TrustedApp\runner.exe",
                [AttributeKeys.Signed] = "false"
            }));
        pathExcluded.Scored.Assessment.Score.Should().Be(0);

        // 5. Éditeur de confiance signé (non LOLBin, dossier normal) -> score 0
        var trustedSigned = await pipeline.ProcessAsync(TestEvents.Make(
            EventCategory.Process, EventTypes.ProcessStart, @"C:\Program Files\Google\Chrome\chrome.exe",
            new Dictionary<string, string>
            {
                [AttributeKeys.ProcessName] = "chrome.exe",
                [AttributeKeys.Signed] = "true",
                [AttributeKeys.Publisher] = "Google LLC"
            }));
        trustedSigned.Scored.Assessment.Score.Should().Be(0);

        // 6. Contre-exemple CRITIQUE : PowerShell signé Microsoft avec -enc NE DOIT PAS être blanchi !
        var signedLolbin = await pipeline.ProcessAsync(TestEvents.Make(
            EventCategory.Process, EventTypes.ProcessStart, @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            new Dictionary<string, string>
            {
                [AttributeKeys.ProcessName] = "powershell.exe",
                [AttributeKeys.Signed] = "true",
                [AttributeKeys.Publisher] = "Microsoft Corporation",
                [AttributeKeys.CommandLine] = "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="
            }));
        signedLolbin.Scored.Assessment.Score.Should().BeGreaterThanOrEqualTo(60);
        signedLolbin.Scored.Assessment.MatchedRules.Should().Contain("PROC-LOLBIN-ENCODED");
    }

    [Fact]
    public async Task SystemSelfProtection_IsNeverBypassedByExclusions()
    {
        var settings = TestEvents.ActiveSettings();
        var pipeline = ThreatPipelineFactory.Create(settings);

        var tampering = await pipeline.ProcessAsync(TestEvents.Make(
            EventCategory.System, EventTypes.AgentTampering, "Sentinel.Agent.exe",
            new Dictionary<string, string>
            {
                [AttributeKeys.ProcessName] = "Sentinel.Agent.exe",
                [AttributeKeys.Reason] = "Tentative d'arrêt forcé du service"
            }));

        tampering.Scored.Assessment.Score.Should().BeGreaterThanOrEqualTo(90);
        tampering.Scored.Assessment.Type.Should().Be(ThreatType.Tampering);
        tampering.Scored.Assessment.MitreTechniques.Should().Contain("T1562");
    }

    [Fact]
    public void RuleEngine_CoversEveryCategory_AndMapsValidMitreTechniques()
    {
        var preFilter = new EventPreFilter(new LocalReputationStore());
        var engine = new RuleEngine();
        var settings = TestEvents.ActiveSettings();

        var samples = new (SecurityEvent Evt, string ExpectedRule, ThreatType ExpectedType, string ExpectedMitre)[]
        {
            (TestEvents.Make(EventCategory.Process, EventTypes.ProcessStart, @"C:\Users\alice\AppData\Local\Temp\drop.exe",
                new() { [AttributeKeys.Signed] = "false", [AttributeKeys.ProcessPath] = @"C:\Users\alice\AppData\Local\Temp\drop.exe" }),
                "PROC-UNSIGNED-TEMP", ThreatType.Malware, "T1204.002"),

            (TestEvents.Make(EventCategory.Process, EventTypes.ProcessStart, @"C:\Windows\System32\cmd.exe",
                new() { [AttributeKeys.ProcessName] = "cmd.exe", [AttributeKeys.ParentProcessName] = "WINWORD.EXE" }),
                "PROC-OFFICE-SPAWN-SHELL", ThreatType.Malware, "T1566"),

            (TestEvents.Make(EventCategory.Network, EventTypes.NetworkConnection, "185.10.20.30",
                new() { [AttributeKeys.RemoteIp] = "185.10.20.30", [AttributeKeys.RemotePort] = "4444", [AttributeKeys.IsPrivateIp] = "false" }),
                "NET-UNUSUAL-PORT", ThreatType.Intrusion, "T1071"),

            (TestEvents.Make(EventCategory.Clipboard, EventTypes.ClipboardUrl, "https://bit.ly/facture",
                new() { [AttributeKeys.Url] = "https://bit.ly/facture", [AttributeKeys.IsShortener] = "true" }),
                "CLIP-SHORTENER-URL", ThreatType.Phishing, "T1566.002"),

            (TestEvents.Make(EventCategory.File, EventTypes.FileCreated, @"C:\Users\alice\Downloads\facture.pdf.exe",
                new() { [AttributeKeys.FilePath] = @"C:\Users\alice\Downloads\facture.pdf.exe", [AttributeKeys.DoubleExtension] = "true" }),
                "FILE-DOUBLE-EXT", ThreatType.Malware, "T1036.007"),

            (TestEvents.Make(EventCategory.File, EventTypes.FileCreated, @"C:\Users\alice\Downloads\eicar.com",
                new() { [AttributeKeys.Sha256] = ThreatIndicators.EicarSha256 }),
                "FILE-EICAR-HASH", ThreatType.Malware, "T1204.002"),

            (TestEvents.Make(EventCategory.Session, EventTypes.LogonFailure, "alice",
                new() { [AttributeKeys.TargetUser] = "alice", [AttributeKeys.FailureCount] = "6" }),
                "SESS-BRUTEFORCE-BURST", ThreatType.Intrusion, "T1110"),

            (TestEvents.Make(EventCategory.Typing, EventTypes.TypingStats, "typing",
                new() { [AttributeKeys.Injected] = "true", [AttributeKeys.KeysPerSecond] = "42", [AttributeKeys.SampleSize] = "25" }),
                "TYPING-INJECTED", ThreatType.BadUsb, "T1056"),

            (TestEvents.Make(EventCategory.Device, EventTypes.UsbInserted, @"USB\VID_2E8A&PID_0005",
                new() { [AttributeKeys.DeviceClass] = "HID", [AttributeKeys.IsKeyboard] = "true", [AttributeKeys.VendorId] = "2E8A" }),
                "USB-NEW-HID-KEYBOARD", ThreatType.BadUsb, "T1200"),

            (TestEvents.Make(EventCategory.Browser, EventTypes.UrlVisited, "https://pay-rh.xyz/login",
                new() { [AttributeKeys.Domain] = "pay-rh.xyz", [AttributeKeys.DomainAgeDays] = "3" }),
                "BROW-RECENT-DOMAIN", ThreatType.Phishing, "T1566.002"),

            (TestEvents.Make(EventCategory.Installation, EventTypes.StartupEntryAdded, @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater",
                new() { [AttributeKeys.RegistryKey] = @"HKCU\...\Run", [AttributeKeys.RegistryValue] = @"C:\Temp\updater.exe" }),
                "PERS-STARTUP-KEY", ThreatType.Persistence, "T1547.001"),

            (TestEvents.Make(EventCategory.System, EventTypes.IntegrityViolation, "Sentinel.Agent.dll",
                new() { [AttributeKeys.Component] = "Sentinel.Agent.dll" }),
                "SYS-INTEGRITY-VIOLATION", ThreatType.Tampering, "T1562")
        };

        foreach (var (evt, expectedRule, expectedType, expectedMitre) in samples)
        {
            var enriched = preFilter.Evaluate(evt, settings);
            var res = engine.Evaluate(enriched);

            res.Score.Should().BeInRange(1, 100, $"règle attendue {expectedRule}");
            res.Matches.Select(m => m.RuleId).Should().Contain(expectedRule);
            res.ThreatType.Should().Be(expectedType, $"règle attendue {expectedRule}");
            res.MitreTechniques.Should().Contain(expectedMitre);
            res.Justification.Should().NotBeNullOrWhiteSpace();

            foreach (var tech in res.MitreTechniques)
            {
                MitreCatalog.TryGet(tech).Should().NotBeNull($"technique MITRE {tech} absente du catalogue");
            }
        }
    }

    [Fact]
    public void RuleEngine_WeakSignalsStayInCalibrationRange_AndCombineNonLinearly()
    {
        var combined1 = RuleEngine.CombineWeights([new RuleMatch("R1", 40, ThreatType.Phishing, ["T1566"], "a")]);
        var combined2 = RuleEngine.CombineWeights([
            new RuleMatch("R1", 40, ThreatType.Phishing, ["T1566"], "a"),
            new RuleMatch("R2", 40, ThreatType.Phishing, ["T1566"], "b")
        ]);

        combined1.Should().Be(40);
        combined2.Should().Be(64); // 100 * (1 - 0.6 * 0.6) = 64
        combined2.Should().BeGreaterThan(combined1).And.BeLessThan(80);
    }
}
