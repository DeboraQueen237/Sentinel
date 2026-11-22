using System.Globalization;
using Sentinel.Shared.Models;

namespace Sentinel.Agent.Collectors;

/// <summary>Résultat agrégé d'une rafale suspecte de modifications de fichiers (ransomware).</summary>
public sealed record BurstDetectionResult(
    int Count,
    double WindowSeconds,
    int DistinctExtensions,
    double AverageEntropy,
    string SampleFolder,
    string SamplePath,
    DateTimeOffset DetectedAtUtc);

/// <summary>
/// Détecteur de rafale de chiffrement / renommage massif caractéristique d'un ransomware (doc §6.4, §8.3).
/// Analyse une fenêtre glissante bornée et produit un événement <see cref="EventTypes.FileBurst"/>.
/// </summary>
public sealed class RansomwareBurstDetector
{
    private readonly TimeSpan _window;
    private readonly int _minFileCount;
    private readonly double _highEntropyThreshold;
    private readonly TimeSpan _cooldown;
    private readonly object _gate = new();
    private readonly Queue<FileActivitySample> _samples = new();
    private DateTimeOffset _lastBurstEmittedAt = DateTimeOffset.MinValue;

    public RansomwareBurstDetector(
        TimeSpan? window = null,
        int minFileCount = 15,
        double highEntropyThreshold = 6.8,
        TimeSpan? cooldown = null)
    {
        _window = window ?? TimeSpan.FromSeconds(10);
        _minFileCount = Math.Max(3, minFileCount);
        _highEntropyThreshold = highEntropyThreshold;
        _cooldown = cooldown ?? TimeSpan.FromSeconds(15);
    }

    public BurstDetectionResult? RecordActivity(
        string filePath,
        string extension,
        double entropy,
        bool isRename = false,
        DateTimeOffset? timestamp = null)
    {
        var now = timestamp ?? DateTimeOffset.UtcNow;
        var normExt = string.IsNullOrWhiteSpace(extension) ? string.Empty : extension.ToLowerInvariant();
        var normPath = filePath ?? string.Empty;

        lock (_gate)
        {
            var cutoff = now - _window;
            while (_samples.Count > 0 && _samples.Peek().Timestamp < cutoff)
            {
                _samples.Dequeue();
            }

            _samples.Enqueue(new FileActivitySample(now, normPath, normExt, entropy, isRename));

            // Garde-fou mémoire sur les rafales extrêmes.
            while (_samples.Count > 2000)
            {
                _samples.Dequeue();
            }

            if (_samples.Count < _minFileCount)
            {
                return null;
            }

            if (now - _lastBurstEmittedAt < _cooldown)
            {
                return null;
            }

            var distinctFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var distinctExts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            double entropySum = 0;
            int entropyCount = 0;
            int renameCount = 0;
            DateTimeOffset firstTs = now;

            foreach (var sample in _samples)
            {
                if (sample.Timestamp < firstTs)
                {
                    firstTs = sample.Timestamp;
                }

                distinctFiles.Add(sample.FilePath);
                if (!string.IsNullOrEmpty(sample.Extension))
                {
                    distinctExts.Add(sample.Extension);
                }

                if (sample.Entropy > 0)
                {
                    entropySum += sample.Entropy;
                    entropyCount++;
                }

                if (sample.IsRename)
                {
                    renameCount++;
                }
            }

            if (distinctFiles.Count < _minFileCount)
            {
                return null;
            }

            var avgEntropy = entropyCount > 0 ? entropySum / entropyCount : 0.0;
            var highEntropyBurst = avgEntropy >= _highEntropyThreshold;
            var massRenameBurst = renameCount >= _minFileCount && avgEntropy >= 5.5;

            if (!highEntropyBurst && !massRenameBurst)
            {
                return null;
            }

            var observedWindow = Math.Max(0.1, (now - firstTs).TotalSeconds);
            _lastBurstEmittedAt = now;

            return new BurstDetectionResult(
                distinctFiles.Count,
                Math.Round(observedWindow, 2),
                distinctExts.Count,
                Math.Round(avgEntropy, 3),
                FileAnalyzer.ClassifyWatchedFolder(normPath),
                normPath,
                now);
        }
    }

    public static SecurityEvent ToSecurityEvent(string hostId, string userId, BurstDetectionResult burst)
    {
        ArgumentNullException.ThrowIfNull(burst);
        var folder = Path.GetDirectoryName(burst.SamplePath) ?? burst.SamplePath;

        return SecurityEvent.Create(
            hostId,
            userId,
            EventCategory.File,
            EventTypes.FileBurst,
            folder,
            new Dictionary<string, string>
            {
                [AttributeKeys.BurstCount] = burst.Count.ToString(CultureInfo.InvariantCulture),
                [AttributeKeys.BurstWindowSeconds] = burst.WindowSeconds.ToString("0.##", CultureInfo.InvariantCulture),
                [AttributeKeys.BurstDistinctExtensions] = burst.DistinctExtensions.ToString(CultureInfo.InvariantCulture),
                [AttributeKeys.BurstAvgEntropy] = burst.AverageEntropy.ToString("0.###", CultureInfo.InvariantCulture),
                [AttributeKeys.WatchedFolder] = burst.SampleFolder,
                [AttributeKeys.FilePath] = burst.SamplePath
            },
            $"folder:{burst.SampleFolder};burst:{burst.Count}",
            burst.DetectedAtUtc);
    }

    private readonly record struct FileActivitySample(
        DateTimeOffset Timestamp,
        string FilePath,
        string Extension,
        double Entropy,
        bool IsRename);
}
