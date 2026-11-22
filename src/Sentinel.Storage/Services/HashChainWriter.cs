using System.Globalization;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Sentinel.Shared.Security;
using Sentinel.Storage.Entities;

namespace Sentinel.Storage.Services;

/// <summary>
/// Écrivain thread-safe des journaux chaînés cryptographiquement (événements et audit).
/// Sérialise strictement l'accès par <see cref="SemaphoreSlim"/> afin que la chaîne SHA-256
/// reste contiguë et inviolée même sous forte concurrence (doc §3.2, §11).
/// </summary>
public sealed class HashChainWriter : IDisposable
{
    private readonly IDbContextFactory<SentinelDbContext> _dbFactory;
    private readonly SemaphoreSlim _eventLock = new(1, 1);
    private readonly SemaphoreSlim _auditLock = new(1, 1);
    private bool _disposed;

    public HashChainWriter(IDbContextFactory<SentinelDbContext> dbFactory)
    {
        _dbFactory = dbFactory;
    }

    /// <summary>
    /// Construit la charge utile canonique, déterministe et indépendante de la culture d'un événement.
    /// Note : <see cref="EventEntity.ClusterId"/> est volontairement exclu afin qu'une fusion ultérieure
    /// de clusters ne casse pas la chaîne d'intégrité des faits bruts ingérés.
    /// </summary>
    public static string ComputeEventPayload(EventEntity e)
    {
        ArgumentNullException.ThrowIfNull(e);

        var sb = new StringBuilder(512);
        sb.Append("evt:v1|")
          .Append(e.ChainSeq.ToString(CultureInfo.InvariantCulture)).Append('|')
          .Append(e.Id.ToString("D")).Append('|')
          .Append(e.TimestampUnixMs.ToString(CultureInfo.InvariantCulture)).Append('|')
          .Append(Escape(e.HostId)).Append('|')
          .Append(Escape(e.UserId)).Append('|')
          .Append(e.Category.ToString(CultureInfo.InvariantCulture)).Append('|')
          .Append(Escape(e.EventType)).Append('|')
          .Append(Escape(e.Subject)).Append('|')
          .Append(Escape(e.AttributesJson)).Append('|')
          .Append(Escape(e.CorrelationHints)).Append('|')
          .Append(e.Score.ToString(CultureInfo.InvariantCulture)).Append('|')
          .Append(e.Level.ToString(CultureInfo.InvariantCulture)).Append('|')
          .Append(e.ThreatType.ToString(CultureInfo.InvariantCulture)).Append('|')
          .Append(Escape(e.Justification)).Append('|')
          .Append(e.Source.ToString(CultureInfo.InvariantCulture)).Append('|')
          .Append(e.Confidence.ToString("F6", CultureInfo.InvariantCulture)).Append('|')
          .Append(Escape(e.MatchedRulesJson)).Append('|')
          .Append(Escape(e.MitreTechniquesJson));
        return sb.ToString();
    }

    /// <summary>
    /// Construit la charge utile canonique, déterministe et indépendante de la culture d'une entrée d'audit.
    /// </summary>
    public static string ComputeAuditPayload(AuditEntryEntity a)
    {
        ArgumentNullException.ThrowIfNull(a);

        var sb = new StringBuilder(256);
        sb.Append("audit:v1|")
          .Append(a.TimestampUnixMs.ToString(CultureInfo.InvariantCulture)).Append('|')
          .Append(Escape(a.Actor)).Append('|')
          .Append(Escape(a.Action)).Append('|')
          .Append(Escape(a.Target)).Append('|')
          .Append(Escape(a.Details)).Append('|')
          .Append(Escape(a.IpAddress));
        return sb.ToString();
    }

    /// <summary>Ajoute une entrée d'audit chaînée de manière atomique et thread-safe.</summary>
    public async Task<AuditEntryEntity> AppendAuditAsync(AuditEntryEntity entry, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(entry);
        await using var db = await _dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        return await AppendAuditAsync(db, entry, ct).ConfigureAwait(false);
    }

    /// <summary>Ajoute une entrée d'audit chaînée sur un contexte fourni et enregistre immédiatement.</summary>
    public async Task<AuditEntryEntity> AppendAuditAsync(
        SentinelDbContext db,
        AuditEntryEntity entry,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(db);
        ArgumentNullException.ThrowIfNull(entry);

        await _auditLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            NormalizeAuditTimestamp(entry);

            var previousHash = await db.AuditEntries
                .AsNoTracking()
                .OrderByDescending(a => a.Id)
                .Select(a => a.Hash)
                .FirstOrDefaultAsync(ct)
                .ConfigureAwait(false) ?? HashChain.Genesis;

            entry.PreviousHash = previousHash;
            entry.Hash = HashChain.Compute(previousHash, ComputeAuditPayload(entry));

            db.AuditEntries.Add(entry);
            await db.SaveChangesAsync(ct).ConfigureAwait(false);
            return entry;
        }
        finally
        {
            _auditLock.Release();
        }
    }

    /// <summary>Méthode utilitaire créant et persistant directement une entrée d'audit horodatée UTC.</summary>
    public Task<AuditEntryEntity> WriteAuditAsync(
        string actor,
        string action,
        string target,
        string? details = null,
        string? ipAddress = null,
        CancellationToken ct = default)
    {
        var now = DateTimeOffset.UtcNow;
        var entry = new AuditEntryEntity
        {
            Timestamp = now,
            TimestampUnixMs = now.ToUnixTimeMilliseconds(),
            Actor = actor,
            Action = action,
            Target = target,
            Details = details,
            IpAddress = ipAddress
        };
        return AppendAuditAsync(entry, ct);
    }

    /// <summary>
    /// Attribue <see cref="EventEntity.ChainSeq"/>, calcule le hash chaîné et persiste l'événement atomiquement.
    /// </summary>
    public async Task<EventEntity> AppendEventAsync(EventEntity entity, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(entity);
        await using var db = await _dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        return await AppendEventAsync(db, entity, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Chaîne un événement et enregistre le contexte <paramref name="db"/> sous verrou séquentiel
    /// (permet de persister dans la même transaction SQLite l'événement et les clusters/alertes associés).
    /// </summary>
    public async Task<EventEntity> AppendEventAsync(
        SentinelDbContext db,
        EventEntity entity,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(db);
        ArgumentNullException.ThrowIfNull(entity);

        await _eventLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            NormalizeEventTimestamp(entity);

            var tail = await db.Events
                .AsNoTracking()
                .OrderByDescending(e => e.ChainSeq)
                .Select(e => new { e.ChainSeq, e.Hash })
                .FirstOrDefaultAsync(ct)
                .ConfigureAwait(false);

            var nextSeq = (tail?.ChainSeq ?? 0L) + 1L;
            var previousHash = tail?.Hash ?? HashChain.Genesis;

            entity.ChainSeq = nextSeq;
            entity.PreviousHash = previousHash;
            entity.Hash = HashChain.Compute(previousHash, ComputeEventPayload(entity));

            db.Events.Add(entity);
            await db.SaveChangesAsync(ct).ConfigureAwait(false);
            return entity;
        }
        finally
        {
            _eventLock.Release();
        }
    }

    /// <summary>
    /// Chaîne et persiste un lot d'événements en une seule transaction séquentielle (optimisé pour <c>SubmitEvents</c>).
    /// </summary>
    public async Task<IReadOnlyList<EventEntity>> AppendEventsAsync(
        IEnumerable<EventEntity> entities,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(entities);
        var list = entities as IReadOnlyList<EventEntity> ?? entities.ToList();
        if (list.Count == 0)
            return list;

        await using var db = await _dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        return await AppendEventsAsync(db, list, ct).ConfigureAwait(false);
    }

    /// <summary>Chaîne et persiste un lot d'événements sur un contexte fourni, en une transaction atomique.</summary>
    public async Task<IReadOnlyList<EventEntity>> AppendEventsAsync(
        SentinelDbContext db,
        IEnumerable<EventEntity> entities,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(db);
        ArgumentNullException.ThrowIfNull(entities);

        var list = entities as IReadOnlyList<EventEntity> ?? entities.ToList();
        if (list.Count == 0)
            return list;

        await _eventLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var ownsTransaction = db.Database.CurrentTransaction is null;
            await using var tx = ownsTransaction
                ? await db.Database.BeginTransactionAsync(ct).ConfigureAwait(false)
                : null;

            var tail = await db.Events
                .AsNoTracking()
                .OrderByDescending(e => e.ChainSeq)
                .Select(e => new { e.ChainSeq, e.Hash })
                .FirstOrDefaultAsync(ct)
                .ConfigureAwait(false);

            var nextSeq = (tail?.ChainSeq ?? 0L) + 1L;
            var previousHash = tail?.Hash ?? HashChain.Genesis;

            foreach (var entity in list)
            {
                NormalizeEventTimestamp(entity);
                entity.ChainSeq = nextSeq++;
                entity.PreviousHash = previousHash;
                entity.Hash = HashChain.Compute(previousHash, ComputeEventPayload(entity));
                previousHash = entity.Hash;
                db.Events.Add(entity);
            }

            await db.SaveChangesAsync(ct).ConfigureAwait(false);

            if (tx is not null)
            {
                await tx.CommitAsync(ct).ConfigureAwait(false);
            }

            return list;
        }
        finally
        {
            _eventLock.Release();
        }
    }

    private static void NormalizeEventTimestamp(EventEntity e)
    {
        if (e.Id == Guid.Empty)
        {
            e.Id = Guid.NewGuid();
        }

        if (e.Timestamp == default && e.TimestampUnixMs != 0)
        {
            e.Timestamp = DateTimeOffset.FromUnixTimeMilliseconds(e.TimestampUnixMs);
        }
        else if (e.Timestamp == default)
        {
            e.Timestamp = DateTimeOffset.UtcNow;
            e.TimestampUnixMs = e.Timestamp.ToUnixTimeMilliseconds();
        }
        else
        {
            e.TimestampUnixMs = e.Timestamp.ToUnixTimeMilliseconds();
        }
    }

    private static void NormalizeAuditTimestamp(AuditEntryEntity a)
    {
        if (a.Timestamp == default && a.TimestampUnixMs != 0)
        {
            a.Timestamp = DateTimeOffset.FromUnixTimeMilliseconds(a.TimestampUnixMs);
        }
        else if (a.Timestamp == default)
        {
            a.Timestamp = DateTimeOffset.UtcNow;
            a.TimestampUnixMs = a.Timestamp.ToUnixTimeMilliseconds();
        }
        else
        {
            a.TimestampUnixMs = a.Timestamp.ToUnixTimeMilliseconds();
        }
    }

    private static string Escape(string? value)
    {
        if (string.IsNullOrEmpty(value))
            return string.Empty;

        return value.Replace("\\", "\\\\", StringComparison.Ordinal)
                    .Replace("|", "\\|", StringComparison.Ordinal);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _eventLock.Dispose();
        _auditLock.Dispose();
    }
}
