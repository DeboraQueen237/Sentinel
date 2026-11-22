using System.Text;
using Sentinel.Agent.Response;
using Sentinel.Shared.Security;

namespace Sentinel.Agent.Tests;

public sealed class QuarantineManagerTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _quarantineDir;

    public QuarantineManagerTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"sentinel-quarantine-test-{Guid.NewGuid():N}");
        _quarantineDir = Path.Combine(_tempDir, "Quarantine");
        Directory.CreateDirectory(_tempDir);
    }

    [Fact]
    public void QuarantineAndRestore_ShouldEncryptAtRestAndRestoreExactSha256()
    {
        const string marker = "SENTINEL_CLEAR_TEXT_PAYLOAD_MUST_NOT_APPEAR_IN_QUARANTINE";
        var content = string.Concat(Enumerable.Repeat(marker + "\r\n", 400));
        var sourceFile = Path.Combine(_tempDir, "suspect.bin");
        File.WriteAllText(sourceFile, content, Encoding.UTF8);
        var originalSha = HashChain.Sha256File(sourceFile);

        var manager = new QuarantineManager(_quarantineDir);

        // 1. Mise en quarantaine chiffrée
        var record = manager.Quarantine(sourceFile);

        File.Exists(sourceFile).Should().BeFalse("le fichier source doit disparaître de son emplacement d'origine");
        File.Exists(record.QuarantinedFilePath).Should().BeTrue();
        File.Exists(record.MetadataPath).Should().BeTrue();
        record.OriginalSha256.Should().Be(originalSha);

        // Le fichier en quarantaine ne doit JAMAIS contenir le texte clair.
        var encryptedBytes = File.ReadAllBytes(record.QuarantinedFilePath);
        var markerBytes = Encoding.UTF8.GetBytes(marker);
        encryptedBytes.AsSpan().IndexOf(markerBytes).Should().Be(-1, "le fichier en quarantaine doit être chiffré en AES-256-GCM");

        // 2. Restauration à l'identique
        var restoredPath = manager.Restore(record.QuarantineId);

        restoredPath.Should().Be(sourceFile);
        File.Exists(sourceFile).Should().BeTrue();
        HashChain.Sha256File(sourceFile).Should().Be(originalSha);
        File.ReadAllText(sourceFile, Encoding.UTF8).Should().Be(content);
        File.Exists(record.QuarantinedFilePath).Should().BeFalse();
        File.Exists(record.MetadataPath).Should().BeFalse();
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
