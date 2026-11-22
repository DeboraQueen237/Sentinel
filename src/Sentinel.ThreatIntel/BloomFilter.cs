using System.Numerics;

namespace Sentinel.ThreatIntel;

/// <summary>
/// Filtre de Bloom thread-safe sans dépendance externe (opérations atomiques lock-free sur tableau de mots 64 bits).
/// Utilise un double hachage amélioré (FNV-1a + fmix64 et mélange type xxHash64 + fmix64) offrant
/// un taux de faux positifs &lt; 0,1 % pour 500 000 indicateurs (~1 Mo en mémoire) et un rejet négatif &lt; 0,05 ms.
/// </summary>
public sealed class BloomFilter
{
    private readonly ulong[] _bits;
    private readonly ulong _bitCount;
    private readonly int _hashCount;
    private long _addedCount;

    /// <summary>
    /// Crée un filtre de Bloom dimensionné automatiquement pour <paramref name="expectedCapacity"/> éléments
    /// et un taux de faux positifs cible <paramref name="falsePositiveRate"/>.
    /// </summary>
    public BloomFilter(int expectedCapacity = 500_000, double falsePositiveRate = 0.0005)
    {
        if (expectedCapacity <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(expectedCapacity), "La capacité attendue doit être strictement positive.");
        }

        if (falsePositiveRate <= 0.0 || falsePositiveRate >= 1.0)
        {
            throw new ArgumentOutOfRangeException(nameof(falsePositiveRate), "Le taux de faux positifs doit être compris entre 0 et 1.");
        }

        ExpectedCapacity = Math.Max(expectedCapacity, 1_024);
        TargetFalsePositiveRate = Math.Clamp(falsePositiveRate, 1e-6, 0.25);

        // m = -n * ln(p) / (ln(2)^2)
        var ln2 = Math.Log(2.0);
        var exactBits = -ExpectedCapacity * Math.Log(TargetFalsePositiveRate) / (ln2 * ln2);
        var wordCount = (int)Math.Ceiling(exactBits / 64.0);
        wordCount = Math.Max(wordCount, 16);

        _bits = new ulong[wordCount];
        _bitCount = (ulong)wordCount * 64UL;

        // k = round((m / n) * ln(2))
        _hashCount = Math.Clamp((int)Math.Round(((double)_bitCount / ExpectedCapacity) * ln2), 1, 24);
    }

    public int ExpectedCapacity { get; }
    public double TargetFalsePositiveRate { get; }
    public long BitCount => (long)_bitCount;
    public int HashFunctionCount => _hashCount;
    public long AddedCount => Interlocked.Read(ref _addedCount);
    public long MemoryBytes => (long)_bits.Length * sizeof(ulong);

    /// <summary>Estimation théorique du taux de faux positifs au remplissage courant.</summary>
    public double EstimatedFalsePositiveRate
    {
        get
        {
            var n = (double)AddedCount;
            if (n <= 0.0)
            {
                return 0.0;
            }

            var exponent = -_hashCount * n / _bitCount;
            return Math.Pow(1.0 - Math.Exp(exponent), _hashCount);
        }
    }

    /// <summary>Insère une chaîne dans le filtre de manière thread-safe et lock-free.</summary>
    public void Add(string item)
    {
        ArgumentNullException.ThrowIfNull(item);
        Add(item.AsSpan());
    }

    /// <summary>Insère un span de caractères dans le filtre sans allocation tas.</summary>
    public void Add(ReadOnlySpan<char> item)
    {
        var (h1, h2) = ComputeHashes(item);
        SetBits(h1, h2);
        Interlocked.Increment(ref _addedCount);
    }

    /// <summary>Insère une paire (type, valeur) sans allocation de chaîne intermédiaire.</summary>
    public void Add(ReadOnlySpan<char> indicatorType, ReadOnlySpan<char> value)
    {
        var (h1, h2) = ComputePairHashes(indicatorType, value);
        SetBits(h1, h2);
        Interlocked.Increment(ref _addedCount);
    }

    /// <summary>Teste l'appartenance probable d'une chaîne (faux négatifs impossibles).</summary>
    public bool MightContain(string item)
    {
        ArgumentNullException.ThrowIfNull(item);
        return MightContain(item.AsSpan());
    }

    /// <summary>Teste l'appartenance probable d'un span sans allocation tas.</summary>
    public bool MightContain(ReadOnlySpan<char> item)
    {
        var (h1, h2) = ComputeHashes(item);
        return TestBits(h1, h2);
    }

    /// <summary>Teste l'appartenance probable d'une paire (type, valeur) sans allocation tas.</summary>
    public bool MightContain(ReadOnlySpan<char> indicatorType, ReadOnlySpan<char> value)
    {
        var (h1, h2) = ComputePairHashes(indicatorType, value);
        return TestBits(h1, h2);
    }

    private void SetBits(ulong h1, ulong h2)
    {
        var bitCount = _bitCount;
        var hashCount = _hashCount;
        var bits = _bits;

        for (ulong i = 0; i < (ulong)hashCount; i++)
        {
            var combined = unchecked(h1 + (i * h2) + (i * i));
            var bitIndex = combined % bitCount;
            var wordIndex = (int)(bitIndex >> 6);
            var mask = 1UL << (int)(bitIndex & 63UL);

            if ((Volatile.Read(ref bits[wordIndex]) & mask) == 0)
            {
                Interlocked.Or(ref bits[wordIndex], mask);
            }
        }
    }

    private bool TestBits(ulong h1, ulong h2)
    {
        var bitCount = _bitCount;
        var hashCount = _hashCount;
        var bits = _bits;

        for (ulong i = 0; i < (ulong)hashCount; i++)
        {
            var combined = unchecked(h1 + (i * h2) + (i * i));
            var bitIndex = combined % bitCount;
            var wordIndex = (int)(bitIndex >> 6);
            var mask = 1UL << (int)(bitIndex & 63UL);

            if ((Volatile.Read(ref bits[wordIndex]) & mask) == 0)
            {
                return false;
            }
        }

        return true;
    }

    private static (ulong H1, ulong H2) ComputeHashes(ReadOnlySpan<char> span)
    {
        unchecked
        {
            const ulong fnvOffset = 14695981039346656037UL;
            const ulong fnvPrime = 1099511628211UL;
            const ulong prime1 = 11400714785074694791UL;
            const ulong prime2 = 14029467366897019727UL;
            const ulong prime3 = 1609587929392839161UL;

            var h1 = fnvOffset;
            var h2 = prime1 ^ ((ulong)span.Length * prime3);

            for (var i = 0; i < span.Length; i++)
            {
                ulong c = span[i];
                h1 ^= c;
                h1 *= fnvPrime;

                h2 ^= c * prime2;
                h2 = (BitOperations.RotateLeft(h2, 27) * prime1) + prime3;
            }

            h1 = Mix64(h1 ^ (ulong)span.Length);
            h2 = Mix64(h2 ^ (h1 >> 32)) | 1UL;
            return (h1, h2);
        }
    }

    private static (ulong H1, ulong H2) ComputePairHashes(ReadOnlySpan<char> prefix, ReadOnlySpan<char> value)
    {
        unchecked
        {
            const ulong fnvOffset = 14695981039346656037UL;
            const ulong fnvPrime = 1099511628211UL;
            const ulong prime1 = 11400714785074694791UL;
            const ulong prime2 = 14029467366897019727UL;
            const ulong prime3 = 1609587929392839161UL;

            var totalLength = (ulong)(prefix.Length + 1 + value.Length);
            var h1 = fnvOffset;
            var h2 = prime1 ^ (totalLength * prime3);

            for (var i = 0; i < prefix.Length; i++)
            {
                ulong c = prefix[i];
                h1 ^= c;
                h1 *= fnvPrime;

                h2 ^= c * prime2;
                h2 = (BitOperations.RotateLeft(h2, 27) * prime1) + prime3;
            }

            // Séparateur ':'
            const ulong sep = ':';
            h1 ^= sep;
            h1 *= fnvPrime;
            h2 ^= sep * prime2;
            h2 = (BitOperations.RotateLeft(h2, 27) * prime1) + prime3;

            for (var i = 0; i < value.Length; i++)
            {
                ulong c = value[i];
                h1 ^= c;
                h1 *= fnvPrime;

                h2 ^= c * prime2;
                h2 = (BitOperations.RotateLeft(h2, 27) * prime1) + prime3;
            }

            h1 = Mix64(h1 ^ totalLength);
            h2 = Mix64(h2 ^ (h1 >> 32)) | 1UL;
            return (h1, h2);
        }
    }

    /// <summary>Finaliseur avalanche MurmurHash3 (fmix64).</summary>
    private static ulong Mix64(ulong k)
    {
        unchecked
        {
            k ^= k >> 33;
            k *= 0xff51afd7ed558ccdUL;
            k ^= k >> 33;
            k *= 0xc4ceb9fe1a85ec53UL;
            k ^= k >> 33;
            return k;
        }
    }
}
