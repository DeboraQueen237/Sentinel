using Microsoft.Data.Sqlite;
using Sentinel.Shared.Infrastructure;
using Sentinel.Shared.Json;
using Sentinel.Shared.Models;

namespace Sentinel.Agent.Storage;

/// <summary>Entrée stockée dans la file locale persistante de l'agent.</summary>
public sealed record OutboxEntry(long Sequence, SecurityEvent Event);

/// <summary>
/// File locale persistante SQLite (mode WAL) garantissant la tolérance aux pannes lorsque
/// <c>Sentinel.Server</c> est indisponible : les événements sont conservés sur disque (cap FIFO borné)
/// puis rejoués automatiquement dès la reconnexion (doc §3.2, §4).
/// </summary>
public sealed class SqliteEventOutbox : IDisposable
{
    private readonly string _connectionString;
    private readonly int _maxCapacity;
    private readonly object _gate = new();
    private bool _disposed;

    public string DatabasePath { get; }

    public SqliteEventOutbox(string? databasePath = null, int maxCapacity = 50_000)
    {
        if (maxCapacity <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxCapacity), "La capacité maximale doit être strictement positive.");
        }

        DatabasePath = databasePath ?? SentinelPaths.AgentOutboxDatabase;
        _maxCapacity = maxCapacity;

        var dir = Path.GetDirectoryName(DatabasePath);
        if (!string.IsNullOrWhiteSpace(dir))
        {
            Directory.CreateDirectory(dir);
        }

        var builder = new SqliteConnectionStringBuilder
        {
            DataSource = DatabasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared,
            Pooling = true
        };
        _connectionString = builder.ToString();

        InitializeSchema();
    }

    private void InitializeSchema()
    {
        lock (_gate)
        {
            using var conn = OpenConnection();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = NORMAL;
                PRAGMA busy_timeout = 5000;
                CREATE TABLE IF NOT EXISTS event_outbox (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL,
                    created_utc INTEGER NOT NULL,
                    payload_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_event_outbox_created ON event_outbox(created_utc);
                """;
            cmd.ExecuteNonQuery();
        }
    }

    public void Enqueue(SecurityEvent evt)
    {
        ArgumentNullException.ThrowIfNull(evt);
        EnqueueBatch([evt]);
    }

    public void EnqueueBatch(IReadOnlyList<SecurityEvent> events)
    {
        ArgumentNullException.ThrowIfNull(events);
        if (events.Count == 0)
        {
            return;
        }

        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            using var conn = OpenConnection();
            using var tx = conn.BeginTransaction();

            using (var insert = conn.CreateCommand())
            {
                insert.Transaction = tx;
                insert.CommandText = """
                    INSERT INTO event_outbox (event_id, created_utc, payload_json)
                    VALUES ($id, $created, $payload);
                    """;

                var pId = insert.Parameters.Add("$id", SqliteType.Text);
                var pCreated = insert.Parameters.Add("$created", SqliteType.Integer);
                var pPayload = insert.Parameters.Add("$payload", SqliteType.Text);

                foreach (var evt in events)
                {
                    pId.Value = evt.Id.ToString("D");
                    pCreated.Value = evt.Timestamp.ToUnixTimeMilliseconds();
                    pPayload.Value = SentinelJson.Serialize(evt);
                    insert.ExecuteNonQuery();
                }
            }

            EnforceCapacityLocked(conn, tx);
            tx.Commit();
        }
    }

    public IReadOnlyList<OutboxEntry> PeekBatch(int maxCount)
    {
        if (maxCount <= 0)
        {
            return Array.Empty<OutboxEntry>();
        }

        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            using var conn = OpenConnection();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT seq, payload_json
                FROM event_outbox
                ORDER BY seq ASC
                LIMIT $limit;
                """;
            cmd.Parameters.AddWithValue("$limit", maxCount);

            var results = new List<OutboxEntry>(Math.Min(maxCount, 256));
            var corruptSeqs = new List<long>();

            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                var seq = reader.GetInt64(0);
                var json = reader.GetString(1);
                try
                {
                    var evt = SentinelJson.Deserialize<SecurityEvent>(json);
                    if (evt is not null)
                    {
                        results.Add(new OutboxEntry(seq, evt));
                    }
                    else
                    {
                        corruptSeqs.Add(seq);
                    }
                }
                catch
                {
                    corruptSeqs.Add(seq);
                }
            }

            if (corruptSeqs.Count > 0)
            {
                AcknowledgeLocked(conn, corruptSeqs);
            }

            return results;
        }
    }

    public int Acknowledge(IEnumerable<long> sequences)
    {
        ArgumentNullException.ThrowIfNull(sequences);
        var list = sequences as IList<long> ?? sequences.ToList();
        if (list.Count == 0)
        {
            return 0;
        }

        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            using var conn = OpenConnection();
            return AcknowledgeLocked(conn, list);
        }
    }

    public int Count()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            using var conn = OpenConnection();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT COUNT(*) FROM event_outbox;";
            return Convert.ToInt32(cmd.ExecuteScalar());
        }
    }

    private void EnforceCapacityLocked(SqliteConnection conn, SqliteTransaction tx)
    {
        using var countCmd = conn.CreateCommand();
        countCmd.Transaction = tx;
        countCmd.CommandText = "SELECT COUNT(*) FROM event_outbox;";
        var total = Convert.ToInt64(countCmd.ExecuteScalar());

        var excess = total - _maxCapacity;
        if (excess <= 0)
        {
            return;
        }

        using var purgeCmd = conn.CreateCommand();
        purgeCmd.Transaction = tx;
        purgeCmd.CommandText = """
            DELETE FROM event_outbox
            WHERE seq IN (
                SELECT seq FROM event_outbox ORDER BY seq ASC LIMIT $excess
            );
            """;
        purgeCmd.Parameters.AddWithValue("$excess", excess);
        purgeCmd.ExecuteNonQuery();
    }

    private static int AcknowledgeLocked(SqliteConnection conn, IList<long> sequences)
    {
        using var tx = conn.BeginTransaction();
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = "DELETE FROM event_outbox WHERE seq = $seq;";
        var pSeq = cmd.Parameters.Add("$seq", SqliteType.Integer);

        var deleted = 0;
        foreach (var seq in sequences)
        {
            pSeq.Value = seq;
            deleted += cmd.ExecuteNonQuery();
        }

        tx.Commit();
        return deleted;
    }

    private SqliteConnection OpenConnection()
    {
        var conn = new SqliteConnection(_connectionString);
        conn.Open();
        return conn;
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }
            _disposed = true;
            try
            {
                using var conn = new SqliteConnection(_connectionString);
                SqliteConnection.ClearPool(conn);
            }
            catch
            {
                // Ignoré à la fermeture.
            }
        }
    }
}
