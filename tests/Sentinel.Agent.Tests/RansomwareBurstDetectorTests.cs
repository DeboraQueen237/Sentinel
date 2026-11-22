using Sentinel.Agent.Collectors;
using Sentinel.Shared.Models;

namespace Sentinel.Agent.Tests;

public sealed class RansomwareBurstDetectorTests
{
    [Fact]
    public void RapidHighEntropyWrites_ShouldEmitFileBurstEvent()
    {
        var detector = new RansomwareBurstDetector(
            window: TimeSpan.FromSeconds(10),
            minFileCount: 15,
            highEntropyThreshold: 6.8,
            cooldown: TimeSpan.FromSeconds(15));

        var t0 = new DateTimeOffset(2026, 11, 22, 10, 0, 0, TimeSpan.Zero);
        BurstDetectionResult? burst = null;

        for (int i = 0; i < 18; i++)
        {
            var ext = i % 2 == 0 ? ".locked" : ".enc";
            var res = detector.RecordActivity(
                $@"C:\Users\Alice\Documents\file_{i}{ext}",
                ext,
                entropy: 7.85,
                isRename: true,
                timestamp: t0.AddMilliseconds(i * 120));

            if (res is not null)
            {
                burst = res;
                break;
            }
        }

        burst.Should().NotBeNull();
        burst!.Count.Should().BeGreaterThanOrEqualTo(15);
        burst.DistinctExtensions.Should().Be(2);
        burst.AverageEntropy.Should().BeGreaterThan(7.5);
        burst.WindowSeconds.Should().BeLessThan(10.0);

        var evt = RansomwareBurstDetector.ToSecurityEvent("host-01", "alice", burst);
        evt.Category.Should().Be(EventCategory.File);
        evt.EventType.Should().Be(EventTypes.FileBurst);
        evt.AttrLong(AttributeKeys.BurstCount).Should().Be(burst.Count);
        evt.AttrDouble(AttributeKeys.BurstAvgEntropy).Should().BeGreaterThan(7.5);
        evt.AttrLong(AttributeKeys.BurstDistinctExtensions).Should().Be(2);
    }

    [Fact]
    public void NormalLowEntropyOrSlowActivity_ShouldNotEmitBurst()
    {
        var detector = new RansomwareBurstDetector(
            window: TimeSpan.FromSeconds(10),
            minFileCount: 15,
            highEntropyThreshold: 6.8);

        var t0 = new DateTimeOffset(2026, 11, 22, 10, 0, 0, TimeSpan.Zero);

        // 1. Écritures rapides mais texte clair faible entropie
        for (int i = 0; i < 20; i++)
        {
            var res = detector.RecordActivity(
                $@"C:\Users\Alice\Documents\notes_{i}.txt",
                ".txt",
                entropy: 3.9,
                isRename: false,
                timestamp: t0.AddMilliseconds(i * 150));
            res.Should().BeNull();
        }

        // 2. Fichiers haute entropie mais très espacés dans le temps (1 toutes les 5 s)
        var slowDetector = new RansomwareBurstDetector(
            window: TimeSpan.FromSeconds(10),
            minFileCount: 15,
            highEntropyThreshold: 6.8);

        for (int i = 0; i < 20; i++)
        {
            var res = slowDetector.RecordActivity(
                $@"C:\Users\Alice\Downloads\archive_{i}.zip",
                ".zip",
                entropy: 7.9,
                isRename: false,
                timestamp: t0.AddSeconds(i * 5));
            res.Should().BeNull();
        }
    }
}
