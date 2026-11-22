using System.Security.Cryptography;
using System.Text;
using Sentinel.Agent.Collectors;
using Sentinel.Shared.Models;

namespace Sentinel.Agent.Tests;

public sealed class FileAnalyzerTests
{
    [Fact]
    public void ComputeShannonEntropy_ShouldDistinguishPlainTextFromRandomData()
    {
        var plainText = Encoding.UTF8.GetBytes(
            string.Concat(Enumerable.Repeat("Bonjour ceci est un rapport administratif standard pour SENTINEL. ", 80)));
        var randomData = RandomNumberGenerator.GetBytes(32 * 1024);
        var zeroData = new byte[1024];

        var textEntropy = FileAnalyzer.ComputeShannonEntropy(plainText);
        var randomEntropy = FileAnalyzer.ComputeShannonEntropy(randomData);
        var zeroEntropy = FileAnalyzer.ComputeShannonEntropy(zeroData);
        var emptyEntropy = FileAnalyzer.ComputeShannonEntropy(ReadOnlySpan<byte>.Empty);

        zeroEntropy.Should().Be(0.0);
        emptyEntropy.Should().Be(0.0);
        textEntropy.Should().BeInRange(3.0, 5.0);
        randomEntropy.Should().BeGreaterThan(7.85);
        randomEntropy.Should().BeLessThanOrEqualTo(8.0);
    }

    [Fact]
    public void ComputeFileEntropy_ShouldComputeOnTempFileStreaming()
    {
        var path = Path.Combine(Path.GetTempPath(), $"sentinel-entropy-{Guid.NewGuid():N}.bin");
        try
        {
            File.WriteAllBytes(path, RandomNumberGenerator.GetBytes(128 * 1024));
            var entropy = FileAnalyzer.ComputeFileEntropy(path);
            entropy.Should().BeGreaterThan(7.85);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Theory]
    [InlineData("facture.pdf.exe", true)]
    [InlineData(@"C:\Users\Alice\Downloads\devis_2026.docx.scr", true)]
    [InlineData("photo.jpg.bat", true)]
    [InlineData("archive.zip.vbs", true)]
    [InlineData("comptabilite.xlsx.ps1", true)]
    [InlineData("document.txt.hta", true)]
    [InlineData("rapport.v2.pdf", false)]
    [InlineData("sauvegarde.2026.zip", false)]
    [InlineData("notes.final.docx", false)]
    [InlineData("setup.exe", false)]
    [InlineData("readme.txt", false)]
    public void HasDoubleExtension_ShouldDetectMasqueradingWithoutFalsePositives(string fileName, bool expected)
    {
        FileAnalyzer.HasDoubleExtension(fileName).Should().Be(expected);
    }

    [Fact]
    public void ClassificationHelpers_ShouldIdentifyExecutablesArchivesAndFolders()
    {
        FileAnalyzer.IsExecutableExtension("payload.exe").Should().BeTrue();
        FileAnalyzer.IsExecutableExtension("script.ps1").Should().BeTrue();
        FileAnalyzer.IsExecutableExtension("rapport.pdf").Should().BeFalse();

        FileAnalyzer.IsArchiveExtension("exfil.7z").Should().BeTrue();
        FileAnalyzer.IsArchiveExtension("backup.zip").Should().BeTrue();
        FileAnalyzer.IsArchiveExtension("notes.txt").Should().BeFalse();

        FileAnalyzer.ClassifyWatchedFolder(@"C:\Users\Alice\Downloads\test.exe").Should().Be(WatchedFolders.Downloads);
        FileAnalyzer.ClassifyWatchedFolder(@"C:\Users\Alice\Desktop\note.txt").Should().Be(WatchedFolders.Desktop);
        FileAnalyzer.ClassifyWatchedFolder(@"C:\Users\Alice\Documents\doc.pdf").Should().Be(WatchedFolders.Documents);
    }
}
