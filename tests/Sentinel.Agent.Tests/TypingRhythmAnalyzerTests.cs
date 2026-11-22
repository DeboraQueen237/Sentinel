using Sentinel.Shared.Models;
using Sentinel.Tray.Collectors;

namespace Sentinel.Agent.Tests;

public sealed class TypingRhythmAnalyzerTests
{
    [Fact]
    public void NormalHumanTyping_ShouldNotBeFlaggedAsAnomalous()
    {
        var analyzer = new TypingRhythmAnalyzer(windowSamples: 20);
        int[] humanIntervals = [165, 210, 145, 280, 190, 155, 240, 175, 220, 130, 260, 195, 160, 230, 185, 150, 250, 170, 205];

        double ts = 1000.0;
        TypingStatsResult? result = analyzer.RecordKeystroke(ts, isInjected: false);
        result.Should().BeNull();

        foreach (var dt in humanIntervals)
        {
            ts += dt;
            var maybe = analyzer.RecordKeystroke(ts, isInjected: false);
            if (maybe is not null)
            {
                result = maybe;
            }
        }

        result.Should().NotBeNull();
        result!.IsAnomalous.Should().BeFalse();
        result.Injected.Should().BeFalse();
        result.SampleSize.Should().Be(20);
        result.KeysPerSecond.Should().BeInRange(3.5, 8.0);
        result.StdDevMs.Should().BeGreaterThan(20.0);
    }

    [Fact]
    public void BadUsbBurst_HighSpeedLowVarianceAndInjected_ShouldBeDetectedAsAnomalous()
    {
        var analyzer = new TypingRhythmAnalyzer(windowSamples: 20);
        double ts = 5000.0;
        TypingStatsResult? result = null;

        // 20 frappes à 12 ms d'intervalle (~83 touches/sec, écart-type < 1 ms) avec flag LLKHF_INJECTED
        for (int i = 0; i < 20; i++)
        {
            var maybe = analyzer.RecordKeystroke(ts, isInjected: true);
            if (maybe is not null)
            {
                result = maybe;
            }
            ts += 12.0 + (i % 2 == 0 ? 0.5 : -0.5);
        }

        result.Should().NotBeNull();
        result!.IsAnomalous.Should().BeTrue();
        result.Injected.Should().BeTrue();
        result.KeysPerSecond.Should().BeGreaterThan(60.0);
        result.StdDevMs.Should().BeLessThan(5.0);

        var evt = TypingRhythmAnalyzer.ToSecurityEvent(result, "host-01", "alice");
        evt.Category.Should().Be(EventCategory.Typing);
        evt.EventType.Should().Be(EventTypes.TypingStats);
        evt.AttrDouble(AttributeKeys.KeysPerSecond).Should().BeGreaterThan(60.0);
        evt.AttrDouble(AttributeKeys.IntervalStdDevMs).Should().BeLessThan(5.0);
        evt.AttrIsTrue(AttributeKeys.Injected).Should().BeTrue();

        // Vérifie qu'aucune clé de caractère ou vkCode n'existe dans les attributs.
        evt.Attributes.Keys.Should().BeEquivalentTo(
            [
                AttributeKeys.KeysPerSecond,
                AttributeKeys.MeanIntervalMs,
                AttributeKeys.IntervalStdDevMs,
                AttributeKeys.SampleSize,
                AttributeKeys.Injected
            ]);
    }
}
