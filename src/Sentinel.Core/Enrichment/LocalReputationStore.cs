namespace Sentinel.Core.Enrichment;

/// <summary>
/// Réputation locale en mémoire (hashes, domaines et IP suspects observés ou appris,
/// ainsi que les éléments marqués bénins par retour faux positif — doc §7.1-1 &amp; §9.4).
/// Strictement bornée en mémoire et thread-safe.
/// </summary>
public sealed class LocalReputationStore
{
    private const int MaxEntriesPerSet = 10_000;

    private readonly object _gate = new();
    private readonly HashSet<string> _badHashes = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _badDomains = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _badIps = new(StringComparer.OrdinalIgnoreCase);

    private readonly HashSet<string> _benignHashes = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _benignDomains = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _benignProcesses = new(StringComparer.OrdinalIgnoreCase);

    public LocalReputationStore()
    {
        _badHashes.Add(ThreatIndicators.EicarSha256);
    }

    public void MarkBadHash(string? sha256)
    {
        if (string.IsNullOrWhiteSpace(sha256)) return;
        lock (_gate)
        {
            var key = sha256.Trim();
            _benignHashes.Remove(key);
            AddBounded(_badHashes, key);
        }
    }

    public void MarkBadDomain(string? domain)
    {
        if (string.IsNullOrWhiteSpace(domain)) return;
        lock (_gate)
        {
            var key = domain.Trim().TrimEnd('.').ToLowerInvariant();
            _benignDomains.Remove(key);
            AddBounded(_badDomains, key);
        }
    }

    public void MarkBadIp(string? ip)
    {
        if (string.IsNullOrWhiteSpace(ip)) return;
        lock (_gate)
        {
            AddBounded(_badIps, ip.Trim());
        }
    }

    public void MarkBenign(string? processName = null, string? domain = null, string? sha256 = null)
    {
        lock (_gate)
        {
            if (!string.IsNullOrWhiteSpace(processName))
            {
                AddBounded(_benignProcesses, ThreatIndicators.NormalizeProcessName(processName));
            }
            if (!string.IsNullOrWhiteSpace(domain))
            {
                var d = domain.Trim().TrimEnd('.').ToLowerInvariant();
                _badDomains.Remove(d);
                AddBounded(_benignDomains, d);
            }
            if (!string.IsNullOrWhiteSpace(sha256))
            {
                var h = sha256.Trim();
                if (!h.Equals(ThreatIndicators.EicarSha256, StringComparison.OrdinalIgnoreCase))
                {
                    _badHashes.Remove(h);
                    AddBounded(_benignHashes, h);
                }
            }
        }
    }

    public bool IsBadHash(string? sha256)
    {
        if (string.IsNullOrWhiteSpace(sha256)) return false;
        lock (_gate) return _badHashes.Contains(sha256.Trim());
    }

    public bool IsBadDomain(string? domain)
    {
        if (string.IsNullOrWhiteSpace(domain)) return false;
        var key = domain.Trim().TrimEnd('.').ToLowerInvariant();
        lock (_gate)
        {
            if (_badDomains.Contains(key)) return true;
            foreach (var bad in _badDomains)
            {
                if (key.EndsWith("." + bad, StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }
    }

    public bool IsBadIp(string? ip)
    {
        if (string.IsNullOrWhiteSpace(ip)) return false;
        lock (_gate) return _badIps.Contains(ip.Trim());
    }

    public bool IsBenignHash(string? sha256)
    {
        if (string.IsNullOrWhiteSpace(sha256)) return false;
        lock (_gate) return _benignHashes.Contains(sha256.Trim());
    }

    public bool IsBenignDomain(string? domain)
    {
        if (string.IsNullOrWhiteSpace(domain)) return false;
        var key = domain.Trim().TrimEnd('.').ToLowerInvariant();
        lock (_gate) return _benignDomains.Contains(key);
    }

    public bool IsBenignProcess(string? processName)
    {
        if (string.IsNullOrWhiteSpace(processName)) return false;
        var key = ThreatIndicators.NormalizeProcessName(processName);
        lock (_gate) return _benignProcesses.Contains(key);
    }

    private static void AddBounded(HashSet<string> set, string value)
    {
        if (set.Count >= MaxEntriesPerSet)
        {
            // Éviction simple du premier élément si la borne maximale est atteinte
            using var e = set.GetEnumerator();
            if (e.MoveNext()) set.Remove(e.Current);
        }
        set.Add(value);
    }
}
