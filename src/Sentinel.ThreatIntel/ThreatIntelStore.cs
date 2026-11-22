using System.Globalization;
using Microsoft.Data.Sqlite;
using Sentinel.Shared.Infrastructure;

namespace Sentinel.ThreatIntel;

/// <summary>
/// Magasin SQLite local de renseignement sur les menaces (mode WAL, requêtes indexées)
/// couplé à un filtre de Bloom reconstruit atomiquement en mémoire.
/// Garantit un fonctionnement 100 % hors ligne sur la dernière base connue.
/// </summary>
public sealed class ThreatIntelStore : IDisposable
{
    private const string IsoUtcFormat = "yyyy-MM-ddTHH:mm:ss.fffZ";

    private readonly string _connectionString;
    private readonly bool _isInMemory;
    private readonly int _bloomExpectedCapacity;
    private readonly double _bloomFalsePositiveRate;
    private readonly object _writeGate = new();
    private readonly object _readGate = new();

    private SqliteConnection _readConnection;
    private SqliteCommand _lookupCommand;
    private volatile BloomFilter _bloomFilter;
    private bool _disposed;

    public string DatabasePath { get; }

    /// <summary>Instance active du filtre de Bloom en mémoire (échangée atomiquement lors des reconstructions).</summary>
    public BloomFilter CurrentBloomFilter => _bloomFilter;

    public ThreatIntelStore(
        string? databasePath = null,
        int bloomExpectedCapacity = 500_000,
        double bloomFalsePositiveRate = 0.0005,
        DateTimeOffset? initialNowUtc = null)
    {
        DatabasePath = string.IsNullOrWhiteSpace(databasePath)
            ? SentinelPaths.ThreatIntelDatabase
            : databasePath;

        _isInMemory = DatabasePath.Equals(":memory:", StringComparison.OrdinalIgnoreCase);
        _bloomExpectedCapacity = Math.Max(bloomExpectedCapacity, 1_024);
        _bloomFalsePositiveRate = Math.Clamp(bloomFalsePositiveRate, 1e-6, 0.25);

        if (!_isInMemory)
        {
            var dir = Path.GetDirectoryName(DatabasePath);
            if (!string.IsNullOrWhiteSpace(dir))
            {
                Directory.CreateDirectory(dir);
            }
        }

        var builder = new SqliteConnectionStringBuilder
        {
            DataSource = DatabasePath,
            Mode = _isInMemory ? SqliteOpenMode.Memory : SqliteOpenMode.ReadWriteCreate,
            Cache = _isInMemory ? SqliteCacheMode.Shared : SqliteCacheMode.Default,
            Pooling = !_isInMemory
        };
        _connectionString = builder.ToString();

        _readConnection = new SqliteConnection(_connectionString);
        _readConnection.Open();

        InitializeSchema(_readConnection);
        _lookupCommand = CreatePreparedLookupCommand(_readConnection);
        _bloomFilter = new BloomFilter(_bloomExpectedCapacity, _bloomFalsePositiveRate);

        // Chargement initial hors ligne depuis la base SQLite existante
        RebuildBloomFilter(initialNowUtc ?? DateTimeOffset.UtcNow);
    }

    private static void InitializeSchema(SqliteConnection conn)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA temp_store = MEMORY;
            PRAGMA cache_size = -8000;
            PRAGMA busy_timeout = 5000;

            CREATE TABLE IF NOT EXISTS Indicators (
                Type TEXT NOT NULL,
                Value TEXT NOT NULL,
                Source TEXT NOT NULL,
                ThreatType TEXT NOT NULL,
                FirstSeenUtc TEXT NOT NULL,
                LastSeenUtc TEXT NOT NULL,
                ExpiresAtUtc TEXT NOT NULL,
                Confidence INTEGER NOT NULL,
                PRIMARY KEY (Type, Value, Source)
            );

            CREATE INDEX IF NOT EXISTS IX_Indicators_Type_Value ON Indicators (Type, Value);
            CREATE INDEX IF NOT EXISTS IX_Indicators_ExpiresAtUtc ON Indicators (ExpiresAtUtc);

            CREATE TABLE IF NOT EXISTS FeedState (
                Name TEXT PRIMARY KEY,
                License TEXT NOT NULL,
                LastUpdatedUtc TEXT NULL,
                IndicatorCount INTEGER NOT NULL DEFAULT 0,
                LastError TEXT NULL
            );
            """;
        cmd.ExecuteNonQuery();
    }

    private static SqliteCommand CreatePreparedLookupCommand(SqliteConnection conn)
    {
        var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT Type, Value, Source, ThreatType, FirstSeenUtc, LastSeenUtc, ExpiresAtUtc, Confidence
            FROM Indicators
            WHERE Type = $type AND Value = $value AND ExpiresAtUtc > $nowUtc
            ORDER BY Confidence DESC, LastSeenUtc DESC
            LIMIT 1;
            """;
        cmd.Parameters.Add("$type", SqliteType.Text);
        cmd.Parameters.Add("$value", SqliteType.Text);
        cmd.Parameters.Add("$nowUtc", SqliteType.Text);
        cmd.Prepare();
        return cmd;
    }

    /// <summary>
    /// Recherche un indicateur normalisé non expiré.
    /// Rejette les absents en &lt; 0,05 ms via le filtre de Bloom, puis interroge l'index SQLite en &lt; 2 ms.
    /// </summary>
    public ThreatIntelIndicator? FindIndicator(string normalizedType, string normalizedValue, DateTimeOffset nowUtc)
    {
        if (string.IsNullOrEmpty(normalizedType) || string.IsNullOrEmpty(normalizedValue))
        {
            return null;
        }

        ObjectDisposedException.ThrowIf(_disposed, this);

        // Pré-filtrage ultra-rapide en mémoire (aucune requête SQLite sur rejet négatif)
        if (!_bloomFilter.MightContain(normalizedType.AsSpan(), normalizedValue.AsSpan()))
        {
            return null;
        }

        var nowIso = FormatUtc(nowUtc);

        lock (_readGate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            _lookupCommand.Parameters["$type"].Value = normalizedType;
            _lookupCommand.Parameters["$value"].Value = normalizedValue;
            _lookupCommand.Parameters["$nowUtc"].Value = nowIso;

            using var reader = _lookupCommand.ExecuteReader();
            if (!reader.Read())
            {
                return null;
            }

            return new ThreatIntelIndicator(
                Type: reader.GetString(0),
                Value: reader.GetString(1),
                Source: reader.GetString(2),
                ThreatType: reader.GetString(3),
                FirstSeenUtc: ParseUtc(reader.GetString(4)),
                LastSeenUtc: ParseUtc(reader.GetString(5)),
                ExpiresAtUtc: ParseUtc(reader.GetString(6)),
                Confidence: reader.GetInt32(7));
        }
    }

    /// <summary>
    /// Mise à jour différentielle par lot dans une transaction SQLite unique (upsert).
    /// Préserve la date <c>FirstSeenUtc</c> la plus ancienne et étend <c>ExpiresAtUtc</c> / <c>LastSeenUtc</c>.
    /// </summary>
    public int UpsertIndicators(IEnumerable<ThreatIntelIndicator> indicators, bool rebuildBloom = false, DateTimeOffset? nowUtc = null)
    {
        ArgumentNullException.ThrowIfNull(indicators);

        var batch = indicators as IReadOnlyList<ThreatIntelIndicator> ?? indicators.ToList();
        if (batch.Count == 0)
        {
            if (rebuildBloom)
            {
                RebuildBloomFilter(nowUtc ?? DateTimeOffset.UtcNow);
            }
            return 0;
        }

        var upserted = 0;

        lock (_writeGate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            if (_isInMemory)
            {
                lock (_readGate)
                {
                    upserted = ExecuteUpsertBatch(_readConnection, batch);
                }
            }
            else
            {
                using var writeConn = OpenWriteConnection();
                upserted = ExecuteUpsertBatch(writeConn, batch);
            }
        }

        var activeBloom = _bloomFilter;
        if (rebuildBloom || activeBloom.AddedCount + upserted > activeBloom.ExpectedCapacity)
        {
            RebuildBloomFilter(nowUtc ?? DateTimeOffset.UtcNow);
        }
        else
        {
            // Mise à jour lock-free immédiate du filtre actif entre deux reconstructions complètes
            for (var i = 0; i < batch.Count; i++)
            {
                var item = batch[i];
                if (!string.IsNullOrEmpty(item.Type) && !string.IsNullOrEmpty(item.Value))
                {
                    activeBloom.Add(item.Type.AsSpan(), item.Value.AsSpan());
                }
            }
        }

        return upserted;
    }

    private static int ExecuteUpsertBatch(SqliteConnection conn, IReadOnlyList<ThreatIntelIndicator> batch)
    {
        using var tx = conn.BeginTransaction();
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            INSERT INTO Indicators (Type, Value, Source, ThreatType, FirstSeenUtc, LastSeenUtc, ExpiresAtUtc, Confidence)
            VALUES ($type, $value, $source, $threatType, $firstSeen, $lastSeen, $expiresAt, $confidence)
            ON CONFLICT(Type, Value, Source) DO UPDATE SET
                ThreatType = CASE WHEN excluded.ThreatType <> '' THEN excluded.ThreatType ELSE Indicators.ThreatType END,
                FirstSeenUtc = CASE WHEN excluded.FirstSeenUtc < Indicators.FirstSeenUtc THEN excluded.FirstSeenUtc ELSE Indicators.FirstSeenUtc END,
                LastSeenUtc = CASE WHEN excluded.LastSeenUtc > Indicators.LastSeenUtc THEN excluded.LastSeenUtc ELSE Indicators.LastSeenUtc END,
                ExpiresAtUtc = CASE WHEN excluded.ExpiresAtUtc > Indicators.ExpiresAtUtc THEN excluded.ExpiresAtUtc ELSE Indicators.ExpiresAtUtc END,
                Confidence = CASE WHEN excluded.Confidence > Indicators.Confidence THEN excluded.Confidence ELSE Indicators.Confidence END;
            """;

        var pType = cmd.Parameters.Add("$type", SqliteType.Text);
        var pValue = cmd.Parameters.Add("$value", SqliteType.Text);
        var pSource = cmd.Parameters.Add("$source", SqliteType.Text);
        var pThreat = cmd.Parameters.Add("$threatType", SqliteType.Text);
        var pFirst = cmd.Parameters.Add("$firstSeen", SqliteType.Text);
        var pLast = cmd.Parameters.Add("$lastSeen", SqliteType.Text);
        var pExpires = cmd.Parameters.Add("$expiresAt", SqliteType.Text);
        var pConf = cmd.Parameters.Add("$confidence", SqliteType.Integer);
        cmd.Prepare();

        var count = 0;
        for (var i = 0; i < batch.Count; i++)
        {
            var item = batch[i];
            if (string.IsNullOrWhiteSpace(item.Type) ||
                string.IsNullOrWhiteSpace(item.Value) ||
                string.IsNullOrWhiteSpace(item.Source))
            {
                continue;
            }

            pType.Value = item.Type;
            pValue.Value = item.Value;
            pSource.Value = item.Source;
            pThreat.Value = item.ThreatType ?? string.Empty;
            pFirst.Value = FormatUtc(item.FirstSeenUtc);
            pLast.Value = FormatUtc(item.LastSeenUtc);
            pExpires.Value = FormatUtc(item.ExpiresAtUtc);
            pConf.Value = Math.Clamp(item.Confidence, 0, 100);
            cmd.ExecuteNonQuery();
            count++;
        }

        tx.Commit();
        return count;
    }

    /// <summary>Supprime les indicateurs expirés et reconstruit atomiquement le filtre de Bloom si demandé.</summary>
    public int PurgeExpired(DateTimeOffset? nowUtc = null, bool rebuildBloom = true)
    {
        var effectiveNow = nowUtc ?? DateTimeOffset.UtcNow;
        var nowIso = FormatUtc(effectiveNow);
        int deleted;

        lock (_writeGate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            if (_isInMemory)
            {
                lock (_readGate)
                {
                    deleted = ExecutePurge(_readConnection, nowIso);
                }
            }
            else
            {
                using var writeConn = OpenWriteConnection();
                deleted = ExecutePurge(writeConn, nowIso);
            }
        }

        if (rebuildBloom && deleted > 0)
        {
            RebuildBloomFilter(effectiveNow);
        }

        return deleted;
    }

    private static int ExecutePurge(SqliteConnection conn, string nowIso)
    {
        using var tx = conn.BeginTransaction();
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = "DELETE FROM Indicators WHERE ExpiresAtUtc <= $nowUtc;";
        cmd.Parameters.AddWithValue("$nowUtc", nowIso);
        var deleted = cmd.ExecuteNonQuery();
        tx.Commit();
        return deleted;
    }

    /// <summary>
    /// Reconstruit intégralement un nouveau <see cref="BloomFilter"/> à partir des indicateurs actifs
    /// dans SQLite puis remplace la référence active de manière atomique (aucune interruption des lectures).
    /// </summary>
    public BloomFilter RebuildBloomFilter(DateTimeOffset? nowUtc = null)
    {
        var nowIso = FormatUtc(nowUtc ?? DateTimeOffset.UtcNow);
        BloomFilter rebuilt;

        lock (_readGate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            using var countCmd = _readConnection.CreateCommand();
            countCmd.CommandText = "SELECT COUNT(*) FROM Indicators WHERE ExpiresAtUtc > $nowUtc;";
            countCmd.Parameters.AddWithValue("$nowUtc", nowIso);
            var activeCount = Convert.ToInt64(countCmd.ExecuteScalar());

            var capacity = activeCount > _bloomExpectedCapacity
                ? (int)Math.Min(int.MaxValue, Math.Ceiling(activeCount * 1.5))
                : _bloomExpectedCapacity;

            rebuilt = new BloomFilter(capacity, _bloomFalsePositiveRate);

            using var selectCmd = _readConnection.CreateCommand();
            selectCmd.CommandText = "SELECT Type, Value FROM Indicators WHERE ExpiresAtUtc > $nowUtc;";
            selectCmd.Parameters.AddWithValue("$nowUtc", nowIso);

            using var reader = selectCmd.ExecuteReader();
            while (reader.Read())
            {
                var type = reader.GetString(0);
                var value = reader.GetString(1);
                rebuilt.Add(type.AsSpan(), value.AsSpan());
            }
        }

        Interlocked.Exchange(ref _bloomFilter, rebuilt);
        return rebuilt;
    }

    /// <summary>Enregistre l'état complet d'un flux après mise à jour réussie.</summary>
    public void UpsertFeedState(ThreatIntelFeedState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        lock (_writeGate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            if (_isInMemory)
            {
                lock (_readGate)
                {
                    ExecuteUpsertFeedState(_readConnection, state);
                }
            }
            else
            {
                using var writeConn = OpenWriteConnection();
                ExecuteUpsertFeedState(writeConn, state);
            }
        }
    }

    private static void ExecuteUpsertFeedState(SqliteConnection conn, ThreatIntelFeedState state)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO FeedState (Name, License, LastUpdatedUtc, IndicatorCount, LastError)
            VALUES ($name, $license, $lastUpdated, $count, $lastError)
            ON CONFLICT(Name) DO UPDATE SET
                License = excluded.License,
                LastUpdatedUtc = excluded.LastUpdatedUtc,
                IndicatorCount = excluded.IndicatorCount,
                LastError = excluded.LastError;
            """;
        cmd.Parameters.AddWithValue("$name", state.Name);
        cmd.Parameters.AddWithValue("$license", state.License);
        cmd.Parameters.AddWithValue("$lastUpdated", state.LastUpdatedUtc.HasValue ? FormatUtc(state.LastUpdatedUtc.Value) : DBNull.Value);
        cmd.Parameters.AddWithValue("$count", state.IndicatorCount);
        cmd.Parameters.AddWithValue("$lastError", (object?)state.LastError ?? DBNull.Value);
        cmd.ExecuteNonQuery();
    }

    /// <summary>
    /// Consigne une erreur sur un flux tout en préservant <c>LastUpdatedUtc</c> et <c>IndicatorCount</c>
    /// de la dernière synchronisation réussie (continuité 100 % hors ligne).
    /// </summary>
    public void RecordFeedError(string feedName, string license, string errorMessage)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(feedName);

        lock (_writeGate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            if (_isInMemory)
            {
                lock (_readGate)
                {
                    ExecuteRecordFeedError(_readConnection, feedName, license, errorMessage);
                }
            }
            else
            {
                using var writeConn = OpenWriteConnection();
                ExecuteRecordFeedError(writeConn, feedName, license, errorMessage);
            }
        }
    }

    private static void ExecuteRecordFeedError(SqliteConnection conn, string feedName, string license, string errorMessage)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO FeedState (Name, License, LastUpdatedUtc, IndicatorCount, LastError)
            VALUES ($name, $license, NULL, 0, $lastError)
            ON CONFLICT(Name) DO UPDATE SET
                License = excluded.License,
                LastError = excluded.LastError;
            """;
        cmd.Parameters.AddWithValue("$name", feedName);
        cmd.Parameters.AddWithValue("$license", license);
        cmd.Parameters.AddWithValue("$lastError", errorMessage);
        cmd.ExecuteNonQuery();
    }

    /// <summary>Retourne tous les états de flux persistés dans la table <c>FeedState</c>.</summary>
    public IReadOnlyList<ThreatIntelFeedState> GetFeedStates()
    {
        lock (_readGate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            using var cmd = _readConnection.CreateCommand();
            cmd.CommandText = "SELECT Name, License, LastUpdatedUtc, IndicatorCount, LastError FROM FeedState ORDER BY Name;";

            var results = new List<ThreatIntelFeedState>();
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                results.Add(new ThreatIntelFeedState(
                    Name: reader.GetString(0),
                    License: reader.GetString(1),
                    LastUpdatedUtc: reader.IsDBNull(2) ? null : ParseUtc(reader.GetString(2)),
                    IndicatorCount: reader.GetInt32(3),
                    LastError: reader.IsDBNull(4) ? null : reader.GetString(4)));
            }

            return results;
        }
    }

    /// <summary>Compte les indicateurs actifs (non expirés) par type.</summary>
    public (int Total, int HashCount, int DomainCount, int UrlCount, int IpCount) GetIndicatorCounts(DateTimeOffset? nowUtc = null)
    {
        var nowIso = FormatUtc(nowUtc ?? DateTimeOffset.UtcNow);

        lock (_readGate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            using var cmd = _readConnection.CreateCommand();
            cmd.CommandText = """
                SELECT Type, COUNT(DISTINCT Value)
                FROM Indicators
                WHERE ExpiresAtUtc > $nowUtc
                GROUP BY Type;
                """;
            cmd.Parameters.AddWithValue("$nowUtc", nowIso);

            int hashes = 0, domains = 0, urls = 0, ips = 0;
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                var type = reader.GetString(0);
                var count = reader.GetInt32(1);
                switch (type)
                {
                    case IndicatorTypes.Hash:
                        hashes = count;
                        break;
                    case IndicatorTypes.Domain:
                        domains = count;
                        break;
                    case IndicatorTypes.Url:
                        urls = count;
                        break;
                    case IndicatorTypes.Ip:
                        ips = count;
                        break;
                }
            }

            return (hashes + domains + urls + ips, hashes, domains, urls, ips);
        }
    }

    private SqliteConnection OpenWriteConnection()
    {
        var conn = new SqliteConnection(_connectionString);
        conn.Open();
        using var pragma = conn.CreateCommand();
        pragma.CommandText = "PRAGMA busy_timeout = 5000;";
        pragma.ExecuteNonQuery();
        return conn;
    }

    private static string FormatUtc(DateTimeOffset value) =>
        value.ToUniversalTime().ToString(IsoUtcFormat, CultureInfo.InvariantCulture);

    private static DateTimeOffset ParseUtc(string value) =>
        DateTimeOffset.TryParse(
            value,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out var parsed)
            ? parsed
            : DateTimeOffset.MinValue;

    public void Dispose()
    {
        lock (_writeGate)
        {
            lock (_readGate)
            {
                if (_disposed)
                {
                    return;
                }

                _disposed = true;
                try
                {
                    _lookupCommand.Dispose();
                    _readConnection.Close();
                    _readConnection.Dispose();

                    if (!_isInMemory)
                    {
                        using var conn = new SqliteConnection(_connectionString);
                        SqliteConnection.ClearPool(conn);
                    }
                }
                catch
                {
                    // Ignoré lors de la libération.
                }
            }
        }
    }
}
