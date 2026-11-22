using Sentinel.Agent.Storage;
using Sentinel.Shared.Models;

namespace Sentinel.Agent.Tests;

public sealed class SqliteEventOutboxTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _dbPath;

    public SqliteEventOutboxTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"sentinel-outbox-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
        _dbPath = Path.Combine(_tempDir, "outbox.db");
    }

    [Fact]
    public void EnqueuePeekAcknowledgeAndPersistAcrossReopen_ShouldWorkReliably()
    {
        var e1 = SecurityEvent.Create("host-1", "alice", EventCategory.Process, EventTypes.ProcessStart, "notepad.exe");
        var e2 = SecurityEvent.Create("host-1", "alice", EventCategory.Network, EventTypes.NetworkConnection, "example.com");
        var e3 = SecurityEvent.Create("host-1", "alice", EventCategory.File, EventTypes.FileCreated, @"C:\Temp\a.txt");

        using (var outbox = new SqliteEventOutbox(_dbPath, maxCapacity: 100))
        {
            outbox.Enqueue(e1);
            outbox.EnqueueBatch([e2, e3]);
            outbox.Count().Should().Be(3);

            var firstBatch = outbox.PeekBatch(2);
            firstBatch.Should().HaveCount(2);
            firstBatch[0].Event.Id.Should().Be(e1.Id);
            firstBatch[1].Event.Id.Should().Be(e2.Id);

            outbox.Acknowledge([firstBatch[0].Sequence]).Should().Be(1);
            outbox.Count().Should().Be(2);
        }

        // Réouverture sur le même fichier SQLite : les 2 événements non acquittés doivent être toujours présents.
        using (var reopened = new SqliteEventOutbox(_dbPath, maxCapacity: 100))
        {
            reopened.Count().Should().Be(2);
            var remaining = reopened.PeekBatch(10);
            remaining.Should().HaveCount(2);
            remaining[0].Event.Id.Should().Be(e2.Id);
            remaining[1].Event.Id.Should().Be(e3.Id);

            reopened.Acknowledge(remaining.Select(r => r.Sequence)).Should().Be(2);
            reopened.Count().Should().Be(0);
        }
    }

    [Fact]
    public void CapacityCap_ShouldPurgeOldestEventsFifo()
    {
        using var outbox = new SqliteEventOutbox(_dbPath, maxCapacity: 5);
        var events = Enumerable.Range(1, 8)
            .Select(i => SecurityEvent.Create("host-1", "alice", EventCategory.System, EventTypes.Heartbeat, $"evt-{i}"))
            .ToList();

        outbox.EnqueueBatch(events);

        outbox.Count().Should().Be(5);
        var kept = outbox.PeekBatch(10);
        kept.Select(k => k.Event.Subject).Should().Equal("evt-4", "evt-5", "evt-6", "evt-7", "evt-8");
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
