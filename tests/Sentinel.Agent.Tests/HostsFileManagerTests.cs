using System.Text;
using Sentinel.Agent.Response;

namespace Sentinel.Agent.Tests;

public sealed class HostsFileManagerTests : IDisposable
{
    private readonly string _tempDir;

    public HostsFileManagerTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"sentinel-hosts-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    [Theory]
    [InlineData("# Fichier hosts Windows\r\n127.0.0.1 localhost\r\n")]
    [InlineData("# Sans saut de ligne final\r\n127.0.0.1 localhost")]
    public void BlockAndUnblockDomains_ShouldRestoreOriginalHostsFileExactly(string originalContent)
    {
        var hostsPath = Path.Combine(_tempDir, $"hosts-{Guid.NewGuid():N}");
        File.WriteAllText(hostsPath, originalContent, new UTF8Encoding(false));

        var manager = new HostsFileManager(hostsPath);

        manager.BlockDomain("phishing.example.com").Should().BeTrue();
        manager.BlockDomain("phishing.example.com").Should().BeFalse("blocage idempotent");
        manager.BlockDomain("https://malware.example.org/payload").Should().BeTrue();

        var modified = File.ReadAllText(hostsPath, Encoding.UTF8);
        modified.Should().Contain(HostsFileManager.StartMarker);
        modified.Should().Contain("0.0.0.0 phishing.example.com");
        modified.Should().Contain("0.0.0.0 malware.example.org");
        modified.Should().Contain("127.0.0.1 localhost");

        manager.GetBlockedDomains().Should().BeEquivalentTo(["phishing.example.com", "malware.example.org"]);

        manager.UnblockDomain("phishing.example.com").Should().BeTrue();
        manager.GetBlockedDomains().Should().Equal("malware.example.org");

        manager.UnblockDomain("malware.example.org").Should().BeTrue();
        manager.GetBlockedDomains().Should().BeEmpty();

        var restored = File.ReadAllText(hostsPath, Encoding.UTF8);
        restored.Should().Be(originalContent, "l'annulation de tous les blocages doit restaurer le fichier hosts à l'identique");
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempDir))
            {
                Directory.Delete(_tempDir, recursive: true);
            }
        }
        catch
        {
            // Ignoré.
        }
    }
}
