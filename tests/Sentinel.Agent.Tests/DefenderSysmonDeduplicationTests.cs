using FluentAssertions;
using Sentinel.Agent.Collectors;
using Sentinel.Agent.Pipeline;
using Sentinel.Shared.Models;
using Xunit;

namespace Sentinel.Agent.Tests;

public sealed class DefenderSysmonDeduplicationTests
{
    private const string Defender1116Xml = """
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <EventID>1116</EventID>
            <TimeCreated SystemTime="2026-11-22T12:00:00.000Z" />
          </System>
          <EventData>
            <Data Name="Threat ID">2147519003</Data>
            <Data Name="Threat Name">Virus:DOS/EICAR_Test_File</Data>
            <Data Name="Severity Name">Severe</Data>
            <Data Name="Category Name">Virus</Data>
            <Data Name="Path">file:_C:\Users\Alice\Downloads\eicar.com</Data>
            <Data Name="Process Name">C:\Windows\explorer.exe</Data>
            <Data Name="Detection User">DESKTOP\Alice</Data>
          </EventData>
        </Event>
        """;

    private const string Defender5001Xml = """
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <EventID>5001</EventID>
            <TimeCreated SystemTime="2026-11-22T12:05:00.000Z" />
          </System>
          <EventData>
            <Data Name="Product Name">Microsoft Defender Antivirus</Data>
          </EventData>
        </Event>
        """;

    private const string Defender5007ExclusionXml = """
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <EventID>5007</EventID>
            <TimeCreated SystemTime="2026-11-22T12:06:00.000Z" />
          </System>
          <EventData>
            <Data Name="New Value">HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\Temp\payload = 0x0</Data>
            <Data Name="Old Value"></Data>
          </EventData>
        </Event>
        """;

    private const string DefenderWmiJson = """
        {
          "detectionId": "det-001",
          "threatId": "2147519003",
          "threatName": "Virus:DOS/EICAR_Test_File",
          "severity": "Severe",
          "category": "Virus",
          "processName": "C:\\Windows\\explorer.exe",
          "filePath": "C:\\Users\\Alice\\Downloads\\eicar.com",
          "domainUser": "DESKTOP\\Alice",
          "action": "Quarantine",
          "actionSuccess": true,
          "detectedAt": "2026-11-22T12:00:01Z"
        }
        """;

    private const string SysmonProcessCreateXml = """
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <EventID>1</EventID>
            <TimeCreated SystemTime="2026-11-22T12:10:00.500Z" />
          </System>
          <EventData>
            <Data Name="RuleName">T1059.001</Data>
            <Data Name="ProcessId">4242</Data>
            <Data Name="Image">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
            <Data Name="CommandLine">powershell.exe -NoP -enc SQBFAFgA</Data>
            <Data Name="User">DESKTOP\Alice</Data>
            <Data Name="Hashes">MD5=AAA,SHA256=ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789</Data>
            <Data Name="ParentProcessId">1200</Data>
            <Data Name="ParentImage">C:\Program Files\Microsoft Office\WINWORD.EXE</Data>
          </EventData>
        </Event>
        """;

    private const string SysmonRegistryRunXml = """
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <EventID>13</EventID>
            <TimeCreated SystemTime="2026-11-22T12:11:00.000Z" />
          </System>
          <EventData>
            <Data Name="ProcessId">4242</Data>
            <Data Name="Image">C:\Users\Alice\AppData\Local\Temp\updater.exe</Data>
            <Data Name="TargetObject">HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater</Data>
            <Data Name="Details">C:\Users\Alice\AppData\Local\Temp\updater.exe</Data>
            <Data Name="User">DESKTOP\Alice</Data>
          </EventData>
        </Event>
        """;

    [Fact]
    public void DefenderOperationalXml_1116_ParsesThreatDetection()
    {
        var evt = DefenderCollector.ParseOperationalEventXml(Defender1116Xml, "HOST-01");
        evt.Should().NotBeNull();
        evt!.Category.Should().Be(EventCategory.Defender);
        evt.EventType.Should().Be(EventTypes.DefenderThreatDetected);
        evt.Attr(AttributeKeys.DefenderThreatName).Should().Be("Virus:DOS/EICAR_Test_File");
        evt.Attr(AttributeKeys.FilePath).Should().Be(@"C:\Users\Alice\Downloads\eicar.com");
        evt.Attr(AttributeKeys.DefenderSeverity).Should().Be("Severe");
    }

    [Fact]
    public void DefenderOperationalXml_5001And5007_DetectWeakening()
    {
        var rtEvt = DefenderCollector.ParseOperationalEventXml(Defender5001Xml, "HOST-01");
        rtEvt.Should().NotBeNull();
        rtEvt!.EventType.Should().Be(EventTypes.DefenderRealtimeDisabled);

        var exclEvt = DefenderCollector.ParseOperationalEventXml(Defender5007ExclusionXml, "HOST-01");
        exclEvt.Should().NotBeNull();
        exclEvt!.EventType.Should().Be(EventTypes.DefenderExclusionAdded);
        exclEvt.Attr(AttributeKeys.DefenderExclusion).Should().Contain(@"C:\Temp\payload");
    }

    [Fact]
    public void DefenderWmiJson_ParsesThreatDetection()
    {
        var evt = DefenderCollector.ParseWmiThreatDetectionJson(DefenderWmiJson, "HOST-01");
        evt.Should().NotBeNull();
        evt!.Category.Should().Be(EventCategory.Defender);
        evt.Attr(AttributeKeys.DefenderAction).Should().Be("Quarantine");
        evt.Attr(AttributeKeys.EventSources).Should().Be("DefenderWMI");
    }

    [Fact]
    public void SysmonXml_ParsesProcessCreateAndRegistryStartup()
    {
        var procEvt = SysmonCollector.ParseSysmonEventXml(SysmonProcessCreateXml, "HOST-01");
        procEvt.Should().NotBeNull();
        procEvt!.Category.Should().Be(EventCategory.Process);
        procEvt.EventType.Should().Be(EventTypes.ProcessStart);
        procEvt.Attr(AttributeKeys.ProcessId).Should().Be("4242");
        procEvt.Attr(AttributeKeys.Sha256).Should().Be("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
        procEvt.Attr(AttributeKeys.ParentProcessName).Should().Be("WINWORD.EXE");
        procEvt.Attr(AttributeKeys.EventSources).Should().Be("Sysmon");

        var regEvt = SysmonCollector.ParseSysmonEventXml(SysmonRegistryRunXml, "HOST-01");
        regEvt.Should().NotBeNull();
        regEvt!.Category.Should().Be(EventCategory.Installation);
        regEvt.EventType.Should().Be(EventTypes.StartupEntryAdded);
        regEvt.Attr(AttributeKeys.RegistryKey).Should().Contain(@"CurrentVersion\Run\Updater");
    }

    [Fact]
    public void Deduplicator_MergesSameFactFromMultipleSourcesAndListsBothSources()
    {
        var dedup = new EventDeduplicator(TimeSpan.FromSeconds(5));

        var fromWmi = DefenderCollector.ParseWmiThreatDetectionJson(DefenderWmiJson, "HOST-01")!;
        var fromLog = DefenderCollector.ParseOperationalEventXml(Defender1116Xml, "HOST-01")!;

        var mergedBatch = dedup.DeduplicateBatch([fromLog, fromWmi]);
        mergedBatch.Should().HaveCount(1);
        mergedBatch[0].Attr(AttributeKeys.EventSources).Should().Contain("DefenderEventLog").And.Contain("DefenderWMI");
        mergedBatch[0].Attr(AttributeKeys.DefenderAction).Should().Be("Quarantine");
        mergedBatch[0].Attr(AttributeKeys.DeduplicatedCount).Should().Be("2");

        // Test processus vu par ProcessCollector ET par Sysmon
        var sysmonProc = SysmonCollector.ParseSysmonEventXml(SysmonProcessCreateXml, "HOST-01")!;
        var etwProc = SecurityEvent.Create(
            "HOST-01",
            "Alice",
            EventCategory.Process,
            EventTypes.ProcessStart,
            @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            new Dictionary<string, string>
            {
                [AttributeKeys.ProcessId] = "4242",
                [AttributeKeys.ProcessPath] = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                [AttributeKeys.ProcessName] = "powershell.exe",
                [AttributeKeys.Signed] = "true",
                [AttributeKeys.CollectorSource] = "ProcessCollector"
            },
            timestamp: sysmonProc.Timestamp.AddMilliseconds(-200));

        var mergedProcs = dedup.DeduplicateBatch([etwProc, sysmonProc]);
        mergedProcs.Should().HaveCount(1);
        mergedProcs[0].Attr(AttributeKeys.EventSources).Should().Be("ProcessCollector,Sysmon");
        mergedProcs[0].Attr(AttributeKeys.Signed).Should().Be("true");
        mergedProcs[0].Attr(AttributeKeys.CommandLine).Should().Contain("-enc");
        mergedProcs[0].Attr(AttributeKeys.Sha256).Should().NotBeNullOrWhiteSpace();
    }
}
