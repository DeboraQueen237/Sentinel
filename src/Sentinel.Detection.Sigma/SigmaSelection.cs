using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using Sentinel.Shared.Models;

namespace Sentinel.Detection.Sigma;

/// <summary>Modificateurs Sigma appliques a un champ de selection.</summary>
[Flags]
public enum SigmaFieldModifiers
{
    None = 0,
    Contains = 1 << 0,
    StartsWith = 1 << 1,
    EndsWith = 1 << 2,
    Regex = 1 << 3,
    All = 1 << 4,
    WinDash = 1 << 5,
    Base64 = 1 << 6,
    Base64Offset = 1 << 7,
    Cased = 1 << 8,
    Cidr = 1 << 9,
    Wide = 1 << 10,
    Utf16Be = 1 << 11,
    Exists = 1 << 12,
    GreaterThan = 1 << 13,
    GreaterOrEqual = 1 << 14,
    LessThan = 1 << 15,
    LessOrEqual = 1 << 16
}

/// <summary>Reseau CIDR IPv4 ou IPv6 pre-compile pour comparaison sans allocation.</summary>
public readonly struct CidrNetwork
{
    private readonly AddressFamily _family;
    private readonly uint _v4Network;
    private readonly uint _v4Mask;
    private readonly UInt128 _v6Network;
    private readonly UInt128 _v6Mask;

    private CidrNetwork(uint v4Network, uint v4Mask)
    {
        _family = AddressFamily.InterNetwork;
        _v4Network = v4Network;
        _v4Mask = v4Mask;
        _v6Network = default;
        _v6Mask = default;
    }

    private CidrNetwork(UInt128 v6Network, UInt128 v6Mask)
    {
        _family = AddressFamily.InterNetworkV6;
        _v4Network = 0;
        _v4Mask = 0;
        _v6Network = v6Network;
        _v6Mask = v6Mask;
    }

    public static bool TryParse(string cidr, out CidrNetwork network)
    {
        network = default;
        if (string.IsNullOrWhiteSpace(cidr))
            return false;

        var slashIdx = cidr.IndexOf('/');
        if (slashIdx <= 0 || slashIdx >= cidr.Length - 1)
            return false;

        var ipSpan = cidr.AsSpan(0, slashIdx).Trim();
        var prefixSpan = cidr.AsSpan(slashIdx + 1).Trim();

        if (!IPAddress.TryParse(ipSpan, out var ip) ||
            !int.TryParse(prefixSpan, NumberStyles.None, CultureInfo.InvariantCulture, out var prefix))
            return false;

        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            if (prefix < 0 || prefix > 32)
                return false;

            Span<byte> bytes = stackalloc byte[4];
            if (!ip.TryWriteBytes(bytes, out _))
                return false;

            var addr = BinaryPrimitives.ReadUInt32BigEndian(bytes);
            var mask = prefix == 0 ? 0u : ~0u << (32 - prefix);
            network = new CidrNetwork(addr & mask, mask);
            return true;
        }

        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (prefix < 0 || prefix > 128)
                return false;

            Span<byte> bytes = stackalloc byte[16];
            if (!ip.TryWriteBytes(bytes, out _))
                return false;

            var addr = BinaryPrimitives.ReadUInt128BigEndian(bytes);
            var mask = prefix == 0 ? UInt128.Zero : ~UInt128.Zero << (128 - prefix);
            network = new CidrNetwork(addr & mask, mask);
            return true;
        }

        return false;
    }

    public bool Contains(string? ipText)
    {
        if (string.IsNullOrWhiteSpace(ipText) || !IPAddress.TryParse(ipText.Trim(), out var ip))
            return false;

        if (_family == AddressFamily.InterNetwork)
        {
            if (ip.IsIPv4MappedToIPv6)
                ip = ip.MapToIPv4();

            if (ip.AddressFamily != AddressFamily.InterNetwork)
                return false;

            Span<byte> bytes = stackalloc byte[4];
            if (!ip.TryWriteBytes(bytes, out _))
                return false;

            var addr = BinaryPrimitives.ReadUInt32BigEndian(bytes);
            return (addr & _v4Mask) == _v4Network;
        }

        if (_family == AddressFamily.InterNetworkV6)
        {
            if (ip.AddressFamily != AddressFamily.InterNetworkV6)
                return false;

            Span<byte> bytes = stackalloc byte[16];
            if (!ip.TryWriteBytes(bytes, out _))
                return false;

            var addr = BinaryPrimitives.ReadUInt128BigEndian(bytes);
            return (addr & _v6Mask) == _v6Network;
        }

        return false;
    }
}

/// <summary>
/// Evaluateur pre-compile d'une valeur unitaire dans un matcher Sigma (litteraux, wildcards,
/// variantes <c>windash</c>, variantes <c>base64</c>/<c>base64offset</c>, regex 100 ms, CIDR, numerique ou null).
/// </summary>
public sealed class SigmaValueMatcher
{
    public static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(100);
    private static readonly char[] WinDashChars = ['-', '/', '\u2013', '\u2014'];

    private enum MatchKind
    {
        Null,
        LiteralExact,
        LiteralContains,
        LiteralStartsWith,
        LiteralEndsWith,
        Regex,
        Cidr,
        Exists,
        NumericCompare
    }

    private readonly MatchKind _kind;
    private readonly StringComparison _comparison;
    private readonly string[] _literals;
    private readonly Regex[] _regexes;
    private readonly CidrNetwork _cidr;
    private readonly bool _expectedExists;
    private readonly double _numericTarget;
    private readonly SigmaFieldModifiers _numericOp;

    /// <summary>Ancres litterales necessaires (en minuscules) pour le pre-filtrage Aho-Corasick, ou vide si non indexable.</summary>
    internal IReadOnlyList<string> PreFilterAnchors { get; }

    private SigmaValueMatcher(
        MatchKind kind,
        StringComparison comparison,
        string[]? literals = null,
        Regex[]? regexes = null,
        CidrNetwork cidr = default,
        bool expectedExists = false,
        double numericTarget = 0,
        SigmaFieldModifiers numericOp = SigmaFieldModifiers.None,
        IReadOnlyList<string>? preFilterAnchors = null)
    {
        _kind = kind;
        _comparison = comparison;
        _literals = literals ?? Array.Empty<string>();
        _regexes = regexes ?? Array.Empty<Regex>();
        _cidr = cidr;
        _expectedExists = expectedExists;
        _numericTarget = numericTarget;
        _numericOp = numericOp;
        PreFilterAnchors = preFilterAnchors ?? Array.Empty<string>();
    }

    public static SigmaValueMatcher Compile(string? rawValue, SigmaFieldModifiers modifiers)
    {
        // Correspondance null explicite (champ absent ou vide)
        if (rawValue is null)
            return new SigmaValueMatcher(MatchKind.Null, StringComparison.OrdinalIgnoreCase);

        // Modificateur |exists
        if ((modifiers & SigmaFieldModifiers.Exists) != 0)
        {
            var expected = rawValue.Equals("true", StringComparison.OrdinalIgnoreCase) || rawValue == "1";
            return new SigmaValueMatcher(MatchKind.Exists, StringComparison.OrdinalIgnoreCase, expectedExists: expected);
        }

        // Modificateur |cidr
        if ((modifiers & SigmaFieldModifiers.Cidr) != 0)
        {
            if (!CidrNetwork.TryParse(rawValue, out var net))
                throw new SigmaParseException($"Plage CIDR invalide : '{rawValue}'.");
            return new SigmaValueMatcher(MatchKind.Cidr, StringComparison.Ordinal, cidr: net);
        }

        // Modificateurs numeriques |gt, |gte, |lt, |lte
        var numMask = SigmaFieldModifiers.GreaterThan | SigmaFieldModifiers.GreaterOrEqual |
                      SigmaFieldModifiers.LessThan | SigmaFieldModifiers.LessOrEqual;
        if ((modifiers & numMask) != 0)
        {
            if (!double.TryParse(rawValue, NumberStyles.Float, CultureInfo.InvariantCulture, out var num))
                throw new SigmaParseException($"Valeur numerique invalide pour comparateur : '{rawValue}'.");
            return new SigmaValueMatcher(
                MatchKind.NumericCompare,
                StringComparison.Ordinal,
                numericTarget: num,
                numericOp: modifiers & numMask);
        }

        var isCased = (modifiers & SigmaFieldModifiers.Cased) != 0;
        var isBase64 = (modifiers & (SigmaFieldModifiers.Base64 | SigmaFieldModifiers.Base64Offset)) != 0;

        // Modificateur |re (pre-compilation avec timeout anti-ReDoS 100 ms)
        if ((modifiers & SigmaFieldModifiers.Regex) != 0)
        {
            var rxOpts = RegexOptions.Compiled | RegexOptions.Singleline |
                         (isCased ? RegexOptions.None : RegexOptions.IgnoreCase);
            try
            {
                var rx = new Regex(rawValue, rxOpts, RegexTimeout);
                return new SigmaValueMatcher(MatchKind.Regex, isCased ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase, regexes: [rx]);
            }
            catch (ArgumentException ex)
            {
                throw new SigmaParseException($"Expression reguliere Sigma invalide '{rawValue}' : {ex.Message}", ex);
            }
        }

        // Expansion |windash et |base64 / |base64offset au chargement
        var expanded = new List<string>(4) { rawValue };
        var windashRegexFallback = false;

        if ((modifiers & SigmaFieldModifiers.WinDash) != 0)
        {
            var wdVariants = ExpandWinDash(rawValue, out windashRegexFallback);
            if (!windashRegexFallback)
            {
                expanded = wdVariants;
            }
        }

        if (windashRegexFallback && !isBase64)
        {
            var rx = BuildWinDashRegex(rawValue, modifiers, isCased);
            var anchor = ExtractLongestSafeSegment(rawValue);
            return new SigmaValueMatcher(
                MatchKind.Regex,
                isCased ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase,
                regexes: [rx],
                preFilterAnchors: anchor is not null ? [anchor] : Array.Empty<string>());
        }

        if (isBase64)
        {
            var isOffset = (modifiers & SigmaFieldModifiers.Base64Offset) != 0;
            var hasContains = (modifiers & SigmaFieldModifiers.Contains) != 0;
            var hasStartsWith = (modifiers & SigmaFieldModifiers.StartsWith) != 0;
            var hasEndsWith = (modifiers & SigmaFieldModifiers.EndsWith) != 0;
            var wideOnly = (modifiers & SigmaFieldModifiers.Wide) != 0;
            var utf16BeOnly = (modifiers & SigmaFieldModifiers.Utf16Be) != 0;

            var b64Variants = new HashSet<string>(StringComparer.Ordinal);
            foreach (var item in expanded)
            {
                foreach (var encoded in ExpandBase64Variants(item, isOffset, hasContains, wideOnly, utf16BeOnly))
                    b64Variants.Add(encoded);
            }

            var literals = b64Variants.ToArray();
            var matchKind = hasStartsWith ? MatchKind.LiteralStartsWith
                          : hasEndsWith ? MatchKind.LiteralEndsWith
                          : (hasContains || isOffset) ? MatchKind.LiteralContains
                          : MatchKind.LiteralExact;

            var anchors = BuildLiteralAnchors(literals);
            // Base64 est sensible a la casse (A != a dans l'alphabet Base64)
            return new SigmaValueMatcher(matchKind, StringComparison.Ordinal, literals: literals, preFilterAnchors: anchors);
        }

        // Mode texte standard (exact, contains, startswith, endswith) avec support wildcards * et ?
        var comparison = isCased ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase;
        var hasWildcards = false;
        for (var i = 0; i < expanded.Count; i++)
        {
            if (expanded[i].IndexOfAny(['*', '?']) >= 0)
            {
                hasWildcards = true;
                break;
            }
        }

        if (hasWildcards)
        {
            var rxOpts = RegexOptions.Compiled | RegexOptions.Singleline |
                         (isCased ? RegexOptions.None : RegexOptions.IgnoreCase);
            var regexList = new Regex[expanded.Count];
            var anchors = new List<string>(expanded.Count);
            var allHaveAnchor = true;

            for (var i = 0; i < expanded.Count; i++)
            {
                var rxPattern = WildcardToRegex(expanded[i], modifiers);
                regexList[i] = new Regex(rxPattern, rxOpts, RegexTimeout);
                var seg = ExtractLongestWildcardSegment(expanded[i]);
                if (seg is not null)
                    anchors.Add(seg);
                else
                    allHaveAnchor = false;
            }

            return new SigmaValueMatcher(
                MatchKind.Regex,
                comparison,
                regexes: regexList,
                preFilterAnchors: allHaveAnchor ? DeduplicateAnchors(anchors) : Array.Empty<string>());
        }

        var kind = (modifiers & SigmaFieldModifiers.Contains) != 0 ? MatchKind.LiteralContains
                 : (modifiers & SigmaFieldModifiers.StartsWith) != 0 ? MatchKind.LiteralStartsWith
                 : (modifiers & SigmaFieldModifiers.EndsWith) != 0 ? MatchKind.LiteralEndsWith
                 : MatchKind.LiteralExact;

        var literalArray = expanded.Distinct(comparison == StringComparison.Ordinal
            ? StringComparer.Ordinal
            : StringComparer.OrdinalIgnoreCase).ToArray();

        return new SigmaValueMatcher(kind, comparison, literals: literalArray, preFilterAnchors: BuildLiteralAnchors(literalArray));
    }

    public bool IsMatch(string? candidate)
    {
        switch (_kind)
        {
            case MatchKind.Null:
                return string.IsNullOrEmpty(candidate);

            case MatchKind.Exists:
                return _expectedExists == !string.IsNullOrEmpty(candidate);

            case MatchKind.Cidr:
                return _cidr.Contains(candidate);

            case MatchKind.NumericCompare:
                if (candidate is null ||
                    !double.TryParse(candidate, NumberStyles.Float, CultureInfo.InvariantCulture, out var num))
                    return false;
                return _numericOp switch
                {
                    SigmaFieldModifiers.GreaterThan => num > _numericTarget,
                    SigmaFieldModifiers.GreaterOrEqual => num >= _numericTarget,
                    SigmaFieldModifiers.LessThan => num < _numericTarget,
                    SigmaFieldModifiers.LessOrEqual => num <= _numericTarget,
                    _ => false
                };

            case MatchKind.LiteralExact:
                if (candidate is null) return false;
                for (var i = 0; i < _literals.Length; i++)
                    if (candidate.Equals(_literals[i], _comparison)) return true;
                return false;

            case MatchKind.LiteralContains:
                if (candidate is null) return false;
                for (var i = 0; i < _literals.Length; i++)
                    if (candidate.Contains(_literals[i], _comparison)) return true;
                return false;

            case MatchKind.LiteralStartsWith:
                if (candidate is null) return false;
                for (var i = 0; i < _literals.Length; i++)
                    if (candidate.StartsWith(_literals[i], _comparison)) return true;
                return false;

            case MatchKind.LiteralEndsWith:
                if (candidate is null) return false;
                for (var i = 0; i < _literals.Length; i++)
                    if (candidate.EndsWith(_literals[i], _comparison)) return true;
                return false;

            case MatchKind.Regex:
                if (candidate is null) return false;
                for (var i = 0; i < _regexes.Length; i++)
                {
                    try
                    {
                        if (_regexes[i].IsMatch(candidate))
                            return true;
                    }
                    catch (RegexMatchTimeoutException)
                    {
                        // Protection anti-ReDoS : ne jamais bloquer le pipeline
                    }
                }
                return false;

            default:
                return false;
        }
    }

    /// <summary>
    /// Pre-genere les variantes <c>windash</c> (<c>-</c>, <c>/</c>, <c>–</c>, <c>—</c>) pour les commutateurs CLI Windows.
    /// Si plus de 3 positions de commutateur sont presentes, bascule sur une regex pre-compilee pour eviter l'explosion combinatoire.
    /// </summary>
    public static List<string> ExpandWinDash(string value, out bool useRegexFallback)
    {
        useRegexFallback = false;
        var positions = FindWinDashPositions(value);
        if (positions.Count == 0)
            return [value];

        if (positions.Count > 3)
        {
            useRegexFallback = true;
            return [value];
        }

        var total = 1 << (positions.Count * 2); // 4^k
        var results = new List<string>(total);
        var buffer = value.ToCharArray();

        void Recurse(int depth)
        {
            if (depth == positions.Count)
            {
                results.Add(new string(buffer));
                return;
            }
            var idx = positions[depth];
            for (var d = 0; d < WinDashChars.Length; d++)
            {
                buffer[idx] = WinDashChars[d];
                Recurse(depth + 1);
            }
        }

        Recurse(0);
        return results;
    }

    private static List<int> FindWinDashPositions(string value)
    {
        var switchPositions = new List<int>(4);
        for (var i = 0; i < value.Length; i++)
        {
            var c = value[i];
            if (c != '-' && c != '/' && c != '\u2013' && c != '\u2014')
                continue;

            var validPrev = i == 0 || char.IsWhiteSpace(value[i - 1]) || value[i - 1] is '"' or '\'';
            var validNext = i + 1 < value.Length && char.IsLetterOrDigit(value[i + 1]);
            if (validPrev && validNext)
                switchPositions.Add(i);
        }

        if (switchPositions.Count > 0)
            return switchPositions;

        // Repli : si le motif est simplement "-" ou "/" ou contient des tirets simples
        for (var i = 0; i < value.Length; i++)
        {
            if (value[i] is '-' or '/' or '\u2013' or '\u2014')
                switchPositions.Add(i);
        }
        return switchPositions;
    }

    private static Regex BuildWinDashRegex(string rawValue, SigmaFieldModifiers modifiers, bool isCased)
    {
        var positions = new HashSet<int>(FindWinDashPositions(rawValue));
        var sb = new StringBuilder(rawValue.Length * 2);
        var isContains = (modifiers & SigmaFieldModifiers.Contains) != 0;
        var isStartsWith = (modifiers & SigmaFieldModifiers.StartsWith) != 0;
        var isEndsWith = (modifiers & SigmaFieldModifiers.EndsWith) != 0;

        if (!isContains && !isEndsWith) sb.Append('^');
        for (var i = 0; i < rawValue.Length; i++)
        {
            if (positions.Contains(i))
                sb.Append(@"[-/\u2013\u2014]");
            else if (rawValue[i] == '*')
                sb.Append(".*");
            else if (rawValue[i] == '?')
                sb.Append('.');
            else
                sb.Append(Regex.Escape(rawValue[i].ToString()));
        }
        if (!isContains && !isStartsWith) sb.Append('$');

        var opts = RegexOptions.Compiled | RegexOptions.Singleline |
                   (isCased ? RegexOptions.None : RegexOptions.IgnoreCase);
        return new Regex(sb.ToString(), opts, RegexTimeout);
    }

    /// <summary>
    /// Genere les variantes Base64 en UTF-8 et UTF-16LE (plus les decalages d'octets 0/1/2 pour <c>base64offset</c>).
    /// </summary>
    public static IReadOnlyList<string> ExpandBase64Variants(
        string value,
        bool includeOffsets,
        bool isContains,
        bool wideOnly = false,
        bool utf16BeOnly = false)
    {
        var results = new List<string>(6);
        var seen = new HashSet<string>(StringComparer.Ordinal);

        void AddEncoding(Encoding encoding)
        {
            var rawBytes = encoding.GetBytes(value);
            if (rawBytes.Length == 0)
                return;

            if (!includeOffsets)
            {
                var exact = Convert.ToBase64String(rawBytes);
                if (seen.Add(exact))
                    results.Add(exact);

                // Pour |base64|contains, inclure egalement le prefixe invariant a offset 0 sans padding '='
                if (isContains && rawBytes.Length >= 3)
                {
                    var offset0 = EncodeBase64AtOffset(rawBytes, 0);
                    if (offset0.Length >= 3 && seen.Add(offset0))
                        results.Add(offset0);
                }
                return;
            }

            // |base64offset : 3 decalages possibles (0, 1, 2 octets) garantissant la correspondance
            // quelle que soit la position dans un flux Base64 plus large
            for (var offset = 0; offset < 3; offset++)
            {
                var slice = EncodeBase64AtOffset(rawBytes, offset);
                if (slice.Length > 0 && seen.Add(slice))
                    results.Add(slice);
            }

            // Si la chaine est tres courte (ex. 1 octet), conserver l'encodage exact comme filet de securite
            if (results.Count == 0)
            {
                var exact = Convert.ToBase64String(rawBytes);
                if (seen.Add(exact))
                    results.Add(exact);
            }
        }

        if (utf16BeOnly)
        {
            AddEncoding(Encoding.BigEndianUnicode);
        }
        else if (wideOnly)
        {
            AddEncoding(Encoding.Unicode);
        }
        else
        {
            AddEncoding(Encoding.UTF8);
            AddEncoding(Encoding.Unicode); // UTF-16LE (PowerShell -EncodedCommand)
        }

        return results;
    }

    private static string EncodeBase64AtOffset(byte[] rawBytes, int offset)
    {
        var padded = new byte[offset + rawBytes.Length];
        Buffer.BlockCopy(rawBytes, 0, padded, offset, rawBytes.Length);
        var b64 = Convert.ToBase64String(padded);

        var startTrim = offset switch
        {
            0 => 0,
            1 => 2,
            2 => 3,
            _ => 0
        };

        var endTrim = (padded.Length % 3) switch
        {
            0 => 0,
            1 => 3,
            2 => 2,
            _ => 0
        };

        var sliceLen = b64.Length - startTrim - endTrim;
        return sliceLen > 0 ? b64.Substring(startTrim, sliceLen) : string.Empty;
    }

    private static string WildcardToRegex(string wildcard, SigmaFieldModifiers modifiers)
    {
        var escaped = Regex.Escape(wildcard).Replace(@"\*", ".*").Replace(@"\?", ".");
        if ((modifiers & SigmaFieldModifiers.Contains) != 0)
            return escaped;
        if ((modifiers & SigmaFieldModifiers.StartsWith) != 0)
            return "^" + escaped;
        if ((modifiers & SigmaFieldModifiers.EndsWith) != 0)
            return escaped + "$";
        return "^" + escaped + "$";
    }

    private static IReadOnlyList<string> BuildLiteralAnchors(string[] literals)
    {
        if (literals.Length == 0)
            return Array.Empty<string>();

        var anchors = new List<string>(literals.Length);
        for (var i = 0; i < literals.Length; i++)
        {
            if (literals[i].Length < 2)
                return Array.Empty<string>();
            anchors.Add(literals[i].ToLowerInvariant());
        }

        return DeduplicateAnchors(anchors);
    }

    private static string? ExtractLongestWildcardSegment(string wildcard)
    {
        var segments = wildcard.Split(['*', '?'], StringSplitOptions.RemoveEmptyEntries);
        string? best = null;
        for (var i = 0; i < segments.Length; i++)
        {
            if (segments[i].Length >= 3 && (best is null || segments[i].Length > best.Length))
                best = segments[i];
        }
        return best?.ToLowerInvariant();
    }

    private static string? ExtractLongestSafeSegment(string value)
    {
        var segments = value.Split(['-', '/', '\u2013', '\u2014', '*', '?'], StringSplitOptions.RemoveEmptyEntries);
        string? best = null;
        for (var i = 0; i < segments.Length; i++)
        {
            if (segments[i].Length >= 3 && (best is null || segments[i].Length > best.Length))
                best = segments[i];
        }
        return best?.ToLowerInvariant();
    }

    private static string[] DeduplicateAnchors(List<string> anchors)
    {
        var set = new HashSet<string>(anchors, StringComparer.Ordinal);
        return set.ToArray();
    }
}

/// <summary>Critere sur un champ Sigma donne (avec modificateurs et liste de valeurs).</summary>
public sealed class SigmaFieldMatcher
{
    public string FieldName { get; }
    public SigmaFieldModifiers Modifiers { get; }
    public bool MatchAll => (Modifiers & SigmaFieldModifiers.All) != 0;
    public IReadOnlyList<SigmaValueMatcher> ValueMatchers { get; }

    public SigmaFieldMatcher(
        string fieldName,
        SigmaFieldModifiers modifiers,
        IReadOnlyList<SigmaValueMatcher> valueMatchers)
    {
        FieldName = fieldName;
        Modifiers = modifiers;
        ValueMatchers = valueMatchers;
    }

    public bool IsMatch(SecurityEvent evt)
    {
        var fieldValue = SigmaFieldMapper.GetFieldValue(evt, FieldName);

        if (MatchAll)
        {
            for (var i = 0; i < ValueMatchers.Count; i++)
            {
                if (!ValueMatchers[i].IsMatch(fieldValue))
                    return false;
            }
            return ValueMatchers.Count > 0;
        }

        for (var i = 0; i < ValueMatchers.Count; i++)
        {
            if (ValueMatchers[i].IsMatch(fieldValue))
                return true;
        }
        return false;
    }

    /// <summary>
    /// Extrait un ensemble d'ancres necessaires (disjonction) pour le pre-filtrage Aho-Corasick,
    /// ou <c>null</c> si ce champ n'est pas elegible au pre-filtrage (ex. champ virtuel, regex, CIDR, null).
    /// </summary>
    internal string[]? ExtractNecessaryAnchors()
    {
        if (SigmaFieldMapper.IsVirtualOnlyField(FieldName) || ValueMatchers.Count == 0)
            return null;

        if (MatchAll)
        {
            // En mode AND (|all), n'importe quel ValueMatcher fournit une condition necessaire :
            // choisir le plus selectif (moins d'alternatives, plus longue ancre minimale).
            string[]? best = null;
            var bestMinLen = -1;

            for (var i = 0; i < ValueMatchers.Count; i++)
            {
                var anchors = ValueMatchers[i].PreFilterAnchors;
                if (anchors.Count == 0)
                    continue;

                var minLen = MinLength(anchors);
                if (best is null ||
                    anchors.Count < best.Length ||
                    (anchors.Count == best.Length && minLen > bestMinLen))
                {
                    best = anchors is string[] arr ? arr : anchors.ToArray();
                    bestMinLen = minLen;
                }
            }

            return best;
        }

        // En mode OR, chaque ValueMatcher doit posseder des ancres pour garantir 0 faux negatif
        var union = new HashSet<string>(StringComparer.Ordinal);
        for (var i = 0; i < ValueMatchers.Count; i++)
        {
            var anchors = ValueMatchers[i].PreFilterAnchors;
            if (anchors.Count == 0)
                return null;

            for (var j = 0; j < anchors.Count; j++)
            {
                union.Add(anchors[j]);
                if (union.Count > 64)
                    return null;
            }
        }

        return union.Count == 0 ? null : union.ToArray();
    }

    private static int MinLength(IReadOnlyList<string> anchors)
    {
        var min = int.MaxValue;
        for (var i = 0; i < anchors.Count; i++)
        {
            if (anchors[i].Length < min)
                min = anchors[i].Length;
        }
        return min;
    }
}

/// <summary>Groupe conjonctif (AND) de <see cref="SigmaFieldMatcher"/> correspondant a un dictionnaire YAML Sigma.</summary>
public sealed class SigmaFieldGroup
{
    public IReadOnlyList<SigmaFieldMatcher> FieldMatchers { get; }

    public SigmaFieldGroup(IReadOnlyList<SigmaFieldMatcher> fieldMatchers)
    {
        FieldMatchers = fieldMatchers;
    }

    public bool IsMatch(SecurityEvent evt)
    {
        for (var i = 0; i < FieldMatchers.Count; i++)
        {
            if (!FieldMatchers[i].IsMatch(evt))
                return false;
        }
        return FieldMatchers.Count > 0;
    }

    internal string[]? ExtractNecessaryAnchors()
    {
        // Conjonction AND : selectionner le matcher le plus selectif
        string[]? best = null;
        var bestMinLen = -1;

        for (var i = 0; i < FieldMatchers.Count; i++)
        {
            var anchors = FieldMatchers[i].ExtractNecessaryAnchors();
            if (anchors is null || anchors.Length == 0)
                continue;

            var minLen = int.MaxValue;
            for (var j = 0; j < anchors.Length; j++)
            {
                if (anchors[j].Length < minLen)
                    minLen = anchors[j].Length;
            }

            if (best is null ||
                anchors.Length < best.Length ||
                (anchors.Length == best.Length && minLen > bestMinLen))
            {
                best = anchors;
                bestMinLen = minLen;
            }
        }

        return best;
    }
}

/// <summary>
/// Selection nommee d'une regle Sigma : soit une disjonction (OR) de dictionnaires de champs (AND),
/// soit une liste de mots-cles recherches dans tous les champs textuels de l'evenement.
/// </summary>
public sealed class SigmaSelection
{
    public string Name { get; }
    public IReadOnlyList<SigmaFieldGroup> FieldGroups { get; }
    public IReadOnlyList<SigmaValueMatcher> KeywordMatchers { get; }

    public bool IsKeywordSelection => KeywordMatchers.Count > 0 && FieldGroups.Count == 0;

    public SigmaSelection(
        string name,
        IReadOnlyList<SigmaFieldGroup>? fieldGroups = null,
        IReadOnlyList<SigmaValueMatcher>? keywordMatchers = null)
    {
        Name = name;
        FieldGroups = fieldGroups ?? Array.Empty<SigmaFieldGroup>();
        KeywordMatchers = keywordMatchers ?? Array.Empty<SigmaValueMatcher>();
    }

    public bool IsMatch(SecurityEvent evt)
    {
        if (KeywordMatchers.Count > 0)
        {
            for (var i = 0; i < KeywordMatchers.Count; i++)
            {
                if (MatchesAnyEventText(evt, KeywordMatchers[i]))
                    return true;
            }
        }

        for (var i = 0; i < FieldGroups.Count; i++)
        {
            if (FieldGroups[i].IsMatch(evt))
                return true;
        }

        return false;
    }

    private static bool MatchesAnyEventText(SecurityEvent evt, SigmaValueMatcher matcher)
    {
        if (!string.IsNullOrEmpty(evt.Subject) && matcher.IsMatch(evt.Subject))
            return true;
        if (!string.IsNullOrEmpty(evt.UserId) && matcher.IsMatch(evt.UserId))
            return true;
        if (!string.IsNullOrEmpty(evt.EventType) && matcher.IsMatch(evt.EventType))
            return true;

        foreach (var kv in evt.Attributes)
        {
            if (!string.IsNullOrEmpty(kv.Value) && matcher.IsMatch(kv.Value))
                return true;
        }

        return false;
    }

    internal string[]? ExtractNecessaryAnchors()
    {
        var union = new HashSet<string>(StringComparer.Ordinal);

        if (KeywordMatchers.Count > 0)
        {
            for (var i = 0; i < KeywordMatchers.Count; i++)
            {
                var anchors = KeywordMatchers[i].PreFilterAnchors;
                if (anchors.Count == 0)
                    return null;
                for (var j = 0; j < anchors.Count; j++)
                {
                    union.Add(anchors[j]);
                    if (union.Count > 64)
                        return null;
                }
            }
        }

        for (var i = 0; i < FieldGroups.Count; i++)
        {
            var anchors = FieldGroups[i].ExtractNecessaryAnchors();
            if (anchors is null || anchors.Length == 0)
                return null;
            for (var j = 0; j < anchors.Length; j++)
            {
                union.Add(anchors[j]);
                if (union.Count > 64)
                    return null;
            }
        }

        return union.Count == 0 ? null : union.ToArray();
    }
}

/// <summary>Contexte sur pile pour l'evaluation memoisee des selections d'une regle sur un evenement.</summary>
internal ref struct SelectionEvalContext
{
    private readonly SigmaSelection[] _selections;
    private readonly SecurityEvent _evt;
    // Etat par selection : 0 = non evalue, 1 = faux, 2 = vrai
    private readonly Span<byte> _states;

    public SelectionEvalContext(SigmaSelection[] selections, SecurityEvent evt, Span<byte> states)
    {
        _selections = selections;
        _evt = evt;
        _states = states;
    }

    public bool EvaluateSelection(int index)
    {
        var state = _states[index];
        if (state != 0)
            return state == 2;

        var matched = _selections[index].IsMatch(_evt);
        _states[index] = matched ? (byte)2 : (byte)1;
        return matched;
    }

    public IReadOnlyList<string> GetMatchedSelectionNames()
    {
        var count = 0;
        for (var i = 0; i < _states.Length; i++)
        {
            if (_states[i] == 2) count++;
        }
        if (count == 0)
            return Array.Empty<string>();

        var names = new string[count];
        var pos = 0;
        for (var i = 0; i < _states.Length; i++)
        {
            if (_states[i] == 2)
                names[pos++] = _selections[i].Name;
        }
        return names;
    }
}
