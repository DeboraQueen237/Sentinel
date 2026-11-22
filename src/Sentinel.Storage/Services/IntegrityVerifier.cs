using Microsoft.EntityFrameworkCore;
using Sentinel.Shared.Api;
using Sentinel.Shared.Security;

namespace Sentinel.Storage.Services;

/// <summary>
/// Vérifie l'intégrité cryptographique complète des chaînes SHA-256 d'audit et d'événements
/// (contrat de <c>GET /api/audit/verify</c>, doc §3.2, §11).
/// </summary>
public sealed class IntegrityVerifier
{
    public const string AuditScope = "audit";
    public const string EventsScope = "events";

    private readonly IDbContextFactory<SentinelDbContext> _dbFactory;

    public IntegrityVerifier(IDbContextFactory<SentinelDbContext> dbFactory)
    {
        _dbFactory = dbFactory;
    }

    /// <summary>Vérifie successivement la chaîne d'audit et la chaîne d'événements.</summary>
    public async Task<IReadOnlyList<IntegrityReportDto>> VerifyAllAsync(CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        return await VerifyAllAsync(db, ct).ConfigureAwait(false);
    }

    /// <summary>Vérifie les deux chaînes sur un contexte donné.</summary>
    public async Task<IReadOnlyList<IntegrityReportDto>> VerifyAllAsync(
        SentinelDbContext db,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(db);
        var auditReport = await VerifyAuditChainAsync(db, ct).ConfigureAwait(false);
        var eventsReport = await VerifyEventChainAsync(db, ct).ConfigureAwait(false);
        return new[] { auditReport, eventsReport };
    }

    /// <summary>Vérifie l'intégralité de la chaîne d'audit depuis <see cref="HashChain.Genesis"/>.</summary>
    public async Task<IntegrityReportDto> VerifyAuditChainAsync(CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        return await VerifyAuditChainAsync(db, ct).ConfigureAwait(false);
    }

    /// <summary>Vérifie l'intégralité de la chaîne d'audit sur un contexte donné (streaming mémoire constante).</summary>
    public async Task<IntegrityReportDto> VerifyAuditChainAsync(
        SentinelDbContext db,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(db);

        var expectedPrevious = HashChain.Genesis;
        long checkedCount = 0;

        var query = db.AuditEntries
            .AsNoTracking()
            .OrderBy(a => a.Id)
            .AsAsyncEnumerable();

        await foreach (var entry in query.WithCancellation(ct).ConfigureAwait(false))
        {
            checkedCount++;

            if (!string.Equals(entry.PreviousHash, expectedPrevious, StringComparison.Ordinal))
            {
                return new IntegrityReportDto(false, checkedCount, entry.Id, AuditScope);
            }

            var payload = HashChainWriter.ComputeAuditPayload(entry);
            if (!HashChain.Verify(expectedPrevious, payload, entry.Hash))
            {
                return new IntegrityReportDto(false, checkedCount, entry.Id, AuditScope);
            }

            expectedPrevious = entry.Hash;
        }

        return new IntegrityReportDto(true, checkedCount, null, AuditScope);
    }

    /// <summary>
    /// Vérifie l'intégralité de la chaîne d'événements par ordre de <c>ChainSeq</c>.
    /// Gère proprement la purge de rétention (si <c>ChainSeq &gt; 1</c> au premier enregistrement retenu,
    /// l'ancre initiale est vérifiée sur son propre hash puis la contiguïté stricte <c>ChainSeq + 1</c>
    /// et le chaînage SHA-256 sont contrôlés jusqu'à la fin).
    /// </summary>
    public async Task<IntegrityReportDto> VerifyEventChainAsync(CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        return await VerifyEventChainAsync(db, ct).ConfigureAwait(false);
    }

    /// <summary>Vérifie la chaîne d'événements sur un contexte donné (streaming mémoire constante).</summary>
    public async Task<IntegrityReportDto> VerifyEventChainAsync(
        SentinelDbContext db,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(db);

        string? expectedPrevious = null;
        long expectedSeq = 1;
        long checkedCount = 0;

        var query = db.Events
            .AsNoTracking()
            .OrderBy(e => e.ChainSeq)
            .AsAsyncEnumerable();

        await foreach (var entry in query.WithCancellation(ct).ConfigureAwait(false))
        {
            checkedCount++;

            if (checkedCount == 1)
            {
                if (entry.ChainSeq <= 0)
                {
                    return new IntegrityReportDto(false, checkedCount, entry.ChainSeq, EventsScope);
                }

                if (entry.ChainSeq == 1)
                {
                    expectedPrevious = HashChain.Genesis;
                }
                else
                {
                    // Préfixe purgé par la politique de rétention : l'ancre doit porter un hash précédent valide (64 hex).
                    if (!IsValidSha256Hex(entry.PreviousHash))
                    {
                        return new IntegrityReportDto(false, checkedCount, entry.ChainSeq, EventsScope);
                    }

                    expectedPrevious = entry.PreviousHash;
                }

                expectedSeq = entry.ChainSeq;
            }
            else if (entry.ChainSeq != expectedSeq)
            {
                return new IntegrityReportDto(false, checkedCount, entry.ChainSeq, EventsScope);
            }

            if (!string.Equals(entry.PreviousHash, expectedPrevious, StringComparison.Ordinal))
            {
                return new IntegrityReportDto(false, checkedCount, entry.ChainSeq, EventsScope);
            }

            var payload = HashChainWriter.ComputeEventPayload(entry);
            if (!HashChain.Verify(expectedPrevious!, payload, entry.Hash))
            {
                return new IntegrityReportDto(false, checkedCount, entry.ChainSeq, EventsScope);
            }

            expectedPrevious = entry.Hash;
            expectedSeq = entry.ChainSeq + 1;
        }

        return new IntegrityReportDto(true, checkedCount, null, EventsScope);
    }

    private static bool IsValidSha256Hex(string? value)
    {
        if (string.IsNullOrEmpty(value) || value.Length != 64)
            return false;

        foreach (var c in value)
        {
            var isHex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
            if (!isHex) return false;
        }

        return true;
    }
}
