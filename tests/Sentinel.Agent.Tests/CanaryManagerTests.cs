using System.Security.Cryptography;
using FluentAssertions;
using Sentinel.Agent.Collectors;
using Sentinel.Shared.Models;
using Xunit;

namespace Sentinel.Agent.Tests;

public sealed class CanaryManagerTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _registryPath;

    public CanaryManagerTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sentinel-canary-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
        _registryPath = Path.Combine(_tempDir, "canaries.json");
    }

    [Fact]
    public void EnsureDeployed_CreatesDiscreetCanariesAndVerifiesIntact()
    {
        var manager = new CanaryManager(registryPath: _registryPath);
        var settings = new CanarySettings
        {
            Enabled = true,
            FilesPerFolder = 2,
            Folders = [_tempDir]
        };

        var records = manager.EnsureDeployed(settings);
        records.Should().HaveCount(2);
        records.All(r => File.Exists(r.FilePath)).Should().BeTrue();
        records.All(r => r.SizeBytes >= 16_000).Should().BeTrue();
        records.All(r => !Path.GetFileName(r.FilePath).Contains("canary", StringComparison.OrdinalIgnoreCase)).Should().BeTrue();

        manager.VerifyAll().Should().BeEmpty();
    }

    [Fact]
    public void BenignRansomwareSimulation_DetectsEncryptionModificationAndDeletion()
    {
        var manager = new CanaryManager(registryPath: _registryPath);
        var settings = new CanarySettings
        {
            Enabled = true,
            FilesPerFolder = 2,
            Folders = [_tempDir]
        };

        var records = manager.EnsureDeployed(settings);
        var first = records[0];
        var second = records[1];

        // 1. Simulation benigne de chiffrement (octets aleatoires haute entropie > 7.2)
        var randomBytes = RandomNumberGenerator.GetBytes(32_768);
        File.WriteAllBytes(first.FilePath, randomBytes);

        // 2. Simulation de suppression
        File.Delete(second.FilePath);

        var findings = manager.VerifyAll();
        findings.Should().HaveCount(2);
        findings.Should().Contain(f => f.Record.Id == first.Id && f.EventType == EventTypes.CanaryEncrypted && f.ObservedEntropy >= 7.2);
        findings.Should().Contain(f => f.Record.Id == second.Id && f.EventType == EventTypes.CanaryDeleted);

        // Nettoyage propre
        manager.RemoveAll();
        File.Exists(first.FilePath).Should().BeFalse();
    }

    public void Dispose()
    {
        try { if (Directory.Exists(_tempDir)) Directory.Delete(_tempDir, recursive: true); } catch { /* ignoré */ }
    }
}
