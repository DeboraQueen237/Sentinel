using System.Globalization;
using Sentinel.Shared.Models;

namespace Sentinel.Tray.Collectors;

/// <summary>Statistiques agrégées de rythme de frappe (doc §2.1, §6.6 : JAMAIS les touches frappées).</summary>
public sealed record TypingStatsResult(
    double KeysPerSecond,
    double MeanIntervalMs,
    double StdDevMs,
    int SampleSize,
    bool Injected,
    bool IsAnomalous);

/// <summary>
/// Analyseur de dynamique de saisie respectant strictement la vie privée (doc §2.1, §2.2, §6.6) :
/// ne reçoit QUE des horodatages haute précision (en millisecondes) et le drapeau <c>LLKHF_INJECTED</c>.
/// Aucun code de touche (<c>vkCode</c>) ni caractère n'est accepté, stocké ou transmis.
/// </summary>
public sealed class TypingRhythmAnalyzer
{
    private readonly int _windowSamples;
    private readonly double _windowDurationMs;
    private readonly double _pauseSplitMs;
    private readonly int _minSamplesForFlush;
    private readonly object _gate = new();

    private readonly List<double> _intervalsMs = new(32);
    private double _windowStartMs;
    private double _lastKeystrokeMs;
    private int _sampleCount;
    private bool _anyInjected;

    public TypingRhythmAnalyzer(
        int windowSamples = 20,
        double windowDurationMs = 5000.0,
        double pauseSplitMs = 2000.0,
        int minSamplesForFlush = 5)
    {
        _windowSamples = Math.Max(4, windowSamples);
        _windowDurationMs = Math.Max(500.0, windowDurationMs);
        _pauseSplitMs = Math.Max(500.0, pauseSplitMs);
        _minSamplesForFlush = Math.Clamp(minSamplesForFlush, 3, _windowSamples);
    }

    /// <summary>
    /// Enregistre uniquement l'instant d'une frappe (ms) et si l'entrée provenait d'une injection synthétique.
    /// Retourne des statistiques agrégées lorsqu'une fenêtre (20 frappes ou 5 s) est complète.
    /// </summary>
    public TypingStatsResult? RecordKeystroke(double timestampMs, bool isInjected)
    {
        lock (_gate)
        {
            if (_sampleCount == 0)
            {
                StartWindowLocked(timestampMs, isInjected);
                return null;
            }

            var deltaMs = timestampMs - _lastKeystrokeMs;
            if (deltaMs < 0)
            {
                // Protection contre un éventuel saut d'horloge.
                deltaMs = 0.1;
            }

            // Une longue pause sépare deux rafales distinctes.
            if (deltaMs > _pauseSplitMs)
            {
                var flushed = _sampleCount >= _minSamplesForFlush ? FlushLocked() : null;
                StartWindowLocked(timestampMs, isInjected);
                return flushed;
            }

            _intervalsMs.Add(Math.Max(0.1, deltaMs));
            _lastKeystrokeMs = timestampMs;
            _sampleCount++;
            _anyInjected |= isInjected;

            var windowElapsed = _lastKeystrokeMs - _windowStartMs;
            if (_sampleCount >= _windowSamples ||
                (windowElapsed >= _windowDurationMs && _sampleCount >= _minSamplesForFlush))
            {
                return FlushLocked();
            }

            return null;
        }
    }

    public TypingStatsResult? FlushIfReady()
    {
        lock (_gate)
        {
            return _sampleCount >= _minSamplesForFlush ? FlushLocked() : null;
        }
    }

    private void StartWindowLocked(double timestampMs, bool isInjected)
    {
        _intervalsMs.Clear();
        _windowStartMs = timestampMs;
        _lastKeystrokeMs = timestampMs;
        _sampleCount = 1;
        _anyInjected = isInjected;
    }

    private TypingStatsResult FlushLocked()
    {
        var samples = _sampleCount;
        var injected = _anyInjected;
        var elapsedMs = Math.Max(1.0, _lastKeystrokeMs - _windowStartMs);

        double mean = 0;
        double stdDev = 0;
        if (_intervalsMs.Count > 0)
        {
            double sum = 0;
            foreach (var dt in _intervalsMs) sum += dt;
            mean = sum / _intervalsMs.Count;

            double varianceSum = 0;
            foreach (var dt in _intervalsMs)
            {
                var diff = dt - mean;
                varianceSum += diff * diff;
            }
            stdDev = Math.Sqrt(varianceSum / _intervalsMs.Count);
        }

        // Vitesse moyenne en touches/seconde sur la fenêtre mesurée.
        var kps = (samples - 1) / (elapsedMs / 1000.0);

        // Heuristique d'anomalie BadUSB / saisie automatisée :
        // - frappe injectée (LLKHF_INJECTED), OU
        // - cadence inhumaine (>= 25 frappes/s), OU
        // - cadence rapide (>= 15 frappes/s) combinée à une régularité mécanique (écart-type < 8 ms).
        var isAnomalous = injected
                          || kps >= 25.0
                          || (kps >= 15.0 && stdDev < 8.0);

        _intervalsMs.Clear();
        _sampleCount = 0;
        _anyInjected = false;

        return new TypingStatsResult(
            Math.Round(kps, 2),
            Math.Round(mean, 2),
            Math.Round(stdDev, 2),
            samples,
            injected,
            isAnomalous);
    }

    public static SecurityEvent ToSecurityEvent(
        TypingStatsResult stats,
        string hostId,
        string userId,
        DateTimeOffset? timestamp = null)
    {
        ArgumentNullException.ThrowIfNull(stats);

        var subject = stats.Injected
            ? "injected-input"
            : (stats.IsAnomalous ? "automated-rhythm" : "keyboard-rhythm");

        return SecurityEvent.Create(
            hostId,
            userId,
            EventCategory.Typing,
            EventTypes.TypingStats,
            subject,
            new Dictionary<string, string>
            {
                [AttributeKeys.KeysPerSecond] = stats.KeysPerSecond.ToString("0.##", CultureInfo.InvariantCulture),
                [AttributeKeys.MeanIntervalMs] = stats.MeanIntervalMs.ToString("0.##", CultureInfo.InvariantCulture),
                [AttributeKeys.IntervalStdDevMs] = stats.StdDevMs.ToString("0.##", CultureInfo.InvariantCulture),
                [AttributeKeys.SampleSize] = stats.SampleSize.ToString(CultureInfo.InvariantCulture),
                [AttributeKeys.Injected] = stats.Injected ? "true" : "false"
            },
            $"user:{userId};typing:{subject}",
            timestamp);
    }
}
