using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace Sentinel.Detection.Static;

/// <summary>Type de motif declare dans la section <c>strings:</c> d'une regle YARA.</summary>
public enum YaraStringKind
{
    Text = 0,
    Hex = 1,
    Regex = 2
}

/// <summary>Definition compilee d'une chaine YARA (<c>$id = ...</c>).</summary>
public sealed class YaraStringDefinition
{
    public string Identifier { get; }
    public YaraStringKind Kind { get; }
    public bool Ascii { get; }
    public bool Wide { get; }
    public bool NoCase { get; }
    public bool FullWord { get; }
    public byte[]? AsciiPattern { get; }
    public byte[]? WidePattern { get; }
    public ManagedYaraFallbackEngine.HexPattern? Hex { get; }
    public Regex? CompiledRegex { get; }
    public string RawDefinition { get; }

    public YaraStringDefinition(
        string identifier,
        YaraStringKind kind,
        bool ascii,
        bool wide,
        bool noCase,
        bool fullWord,
        byte[]? asciiPattern,
        byte[]? widePattern,
        ManagedYaraFallbackEngine.HexPattern? hex,
        Regex? compiledRegex,
        string rawDefinition)
    {
        Identifier = identifier;
        Kind = kind;
        Ascii = ascii;
        Wide = wide;
        NoCase = noCase;
        FullWord = fullWord;
        AsciiPattern = asciiPattern;
        WidePattern = widePattern;
        Hex = hex;
        CompiledRegex = compiledRegex;
        RawDefinition = rawDefinition;
    }
}

/// <summary>Regle YARA parsee et prete a etre evaluee par <see cref="ManagedYaraFallbackEngine"/>.</summary>
public sealed class ParsedYaraRule
{
    public string Identifier { get; }
    public string Namespace { get; }
    public string SourceFile { get; }
    public bool IsPrivate { get; }
    public bool IsGlobal { get; }
    public IReadOnlyList<string> Tags { get; }
    public IReadOnlyDictionary<string, string> Metadata { get; }
    public IReadOnlyList<YaraStringDefinition> Strings { get; }
    public string ConditionSource { get; }
    internal ManagedYaraFallbackEngine.YaraExpr ConditionAst { get; }
    public string RawRuleText { get; }
    public string? Description { get; }
    public string Level { get; }
    public int Score { get; }
    public IReadOnlyList<string> MitreTechniques { get; }

    internal ParsedYaraRule(
        string identifier,
        string @namespace,
        string sourceFile,
        bool isPrivate,
        bool isGlobal,
        IReadOnlyList<string> tags,
        IReadOnlyDictionary<string, string> metadata,
        IReadOnlyList<YaraStringDefinition> strings,
        string conditionSource,
        ManagedYaraFallbackEngine.YaraExpr conditionAst,
        string rawRuleText)
    {
        Identifier = identifier;
        Namespace = @namespace;
        SourceFile = sourceFile;
        IsPrivate = isPrivate;
        IsGlobal = isGlobal;
        Tags = tags;
        Metadata = metadata;
        Strings = strings;
        ConditionSource = conditionSource;
        ConditionAst = conditionAst;
        RawRuleText = rawRuleText;

        metadata.TryGetValue("description", out var desc);
        Description = desc;

        metadata.TryGetValue("severity", out var sev);
        if (string.IsNullOrWhiteSpace(sev))
            metadata.TryGetValue("level", out sev);
        Level = YaraSeverityLevels.Normalize(sev);

        if (metadata.TryGetValue("score", out var rawScore) &&
            int.TryParse(rawScore, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsedScore))
        {
            Score = Math.Clamp(parsedScore, 0, 100);
        }
        else
        {
            Score = YaraSeverityLevels.ToScore(Level);
        }

        MitreTechniques = ExtractMitreTechniques(metadata, tags);
    }

    internal static IReadOnlyList<string> ExtractMitreTechniques(
        IReadOnlyDictionary<string, string> metadata,
        IReadOnlyList<string> tags)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var key in new[] { "mitre", "mitre_attack", "mitre_technique", "attack", "technique" })
        {
            if (metadata.TryGetValue(key, out var val) && !string.IsNullOrWhiteSpace(val))
            {
                foreach (Match m in MitreRegex.Matches(val))
                    set.Add(m.Value.ToUpperInvariant());
            }
        }

        foreach (var tag in tags)
        {
            foreach (Match m in MitreRegex.Matches(tag))
                set.Add(m.Value.ToUpperInvariant());
        }

        return set.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static readonly Regex MitreRegex = new(
        @"\bT\d{4}(?:\.\d{3})?\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant);
}

/// <summary>Exception levee lors d'une erreur de syntaxe dans une regle YARA.</summary>
public sealed class YaraParseException : Exception
{
    public YaraParseException(string message) : base(message) { }
    public YaraParseException(string message, Exception innerException) : base(message, innerException) { }
}

/// <summary>
/// Moteur de repli 100% manage (C#) explicitement documente pour l'evaluation de regles YARA standard
/// lorsque la bibliotheque native <c>libyara</c> (<c>dnYara</c>) n'est pas disponible sur le poste.
/// Supporte :
/// <list type="bullet">
///   <item>Metadonnees (<c>meta:</c>) et tags de regle</item>
///   <item>Chaines texte (<c>ascii</c>, <c>wide</c>, <c>nocase</c>, <c>fullword</c>)</item>
///   <item>Motifs hexadecimaux (<c>{ 4D 5A ?? [2-4] ( 90 | CC ) ?A }</c>)</item>
///   <item>Expressions regulieres (<c>/regex/i</c>, <c>ascii</c>, <c>wide</c>, <c>nocase</c>)</item>
///   <item>Conditions booleennes (<c>and</c>, <c>or</c>, <c>not</c>, parentheses, <c>any/all/none/N of them</c>,
///   <c>N of ($a*)</c>, <c>$a at offset</c>, <c>$a in (a..b)</c>, <c>#a</c>, <c>@a</c>, <c>filesize</c>,
///   <c>uint8/uint16/uint32/uint16be/uint32be</c>)</item>
/// </list>
/// </summary>
public sealed class ManagedYaraFallbackEngine
{
    public const string EngineDisplayName = YaraEngineNames.ManagedFallback;

    private static readonly TimeSpan RegexMatchTimeout = TimeSpan.FromMilliseconds(500);

    /// <summary>Parse un fichier ou texte source YARA contenant une ou plusieurs regles.</summary>
    public static IReadOnlyList<ParsedYaraRule> ParseSource(
        string source,
        string sourceFile = "<memory>",
        string? @namespace = null)
    {
        ArgumentNullException.ThrowIfNull(source);

        var ns = string.IsNullOrWhiteSpace(@namespace)
            ? DeriveNamespace(sourceFile)
            : @namespace.Trim();

        var parser = new YaraSourceParser(source, sourceFile, ns);
        return parser.ParseAllRules();
    }

    /// <summary>Evalue une collection de regles parsees sur un tampon d'octets.</summary>
    public IReadOnlyList<YaraMatchResult> ScanBytes(
        ReadOnlySpan<byte> data,
        IReadOnlyList<ParsedYaraRule> rules,
        IReadOnlySet<string>? disabledRuleIds = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(rules);
        if (rules.Count == 0)
            return Array.Empty<YaraMatchResult>();

        var context = new ScanBufferContext(data);
        var matchedRuleLookup = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var results = new List<YaraMatchResult>();

        foreach (var rule in rules)
        {
            ct.ThrowIfCancellationRequested();

            if (disabledRuleIds is not null && disabledRuleIds.Contains(rule.Identifier))
                continue;

            var ruleState = new RuleEvalContext(rule, context, matchedRuleLookup, ct);
            bool matched;
            try
            {
                matched = rule.ConditionAst.EvalBool(ruleState);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (RegexMatchTimeoutException)
            {
                matched = false;
            }

            if (!matched)
                continue;

            matchedRuleLookup.Add(rule.Identifier);

            if (rule.IsPrivate)
                continue;

            var matchedStrings = ruleState.GetMatchedStringIdentifiers();
            results.Add(new YaraMatchResult(
                RuleId: rule.Identifier,
                Namespace: rule.Namespace,
                SourceFile: rule.SourceFile,
                Level: rule.Level,
                Score: rule.Score,
                Description: rule.Description,
                Tags: rule.Tags,
                MitreTechniques: rule.MitreTechniques,
                MatchedStrings: matchedStrings,
                Metadata: rule.Metadata,
                EngineName: EngineDisplayName));
        }

        return results;
    }

    private static string DeriveNamespace(string sourceFile)
    {
        if (string.IsNullOrWhiteSpace(sourceFile) || sourceFile == "<memory>")
            return "default";

        var name = Path.GetFileNameWithoutExtension(sourceFile);
        return string.IsNullOrWhiteSpace(name) ? "default" : name;
    }

    // =========================================================================
    //  Contexte de scan (decodage paresseux Latin1 / UTF-16LE pour regex)
    // =========================================================================

    internal sealed class ScanBufferContext
    {
        private readonly byte[] _bytes;
        private string? _latin1;
        private string? _utf16Le;

        public ScanBufferContext(ReadOnlySpan<byte> data)
        {
            _bytes = data.ToArray();
        }

        public ReadOnlySpan<byte> Span => _bytes;
        public long Length => _bytes.Length;

        public string GetLatin1() => _latin1 ??= Encoding.Latin1.GetString(_bytes);

        public string GetUtf16Le() => _utf16Le ??= Encoding.Unicode.GetString(_bytes);
    }

    internal sealed class RuleEvalContext
    {
        private readonly ParsedYaraRule _rule;
        private readonly ScanBufferContext _buffer;
        private readonly HashSet<string> _matchedRules;
        private readonly CancellationToken _ct;
        private readonly Dictionary<string, List<(int Offset, int Length)>> _matchCache = new(StringComparer.Ordinal);

        public RuleEvalContext(
            ParsedYaraRule rule,
            ScanBufferContext buffer,
            HashSet<string> matchedRules,
            CancellationToken ct)
        {
            _rule = rule;
            _buffer = buffer;
            _matchedRules = matchedRules;
            _ct = ct;
        }

        public ReadOnlySpan<byte> Bytes => _buffer.Span;
        public long FileSize => _buffer.Length;
        public IReadOnlyList<YaraStringDefinition> AllStrings => _rule.Strings;
        public bool IsRuleMatched(string ruleId) => _matchedRules.Contains(ruleId);

        public List<(int Offset, int Length)> GetMatches(string stringId)
        {
            _ct.ThrowIfCancellationRequested();
            if (_matchCache.TryGetValue(stringId, out var cached))
                return cached;

            var def = _rule.Strings.FirstOrDefault(s => s.Identifier.Equals(stringId, StringComparison.Ordinal));
            if (def is null)
                return new List<(int, int)>();

            var matches = FindMatches(def, _buffer, _ct);
            _matchCache[stringId] = matches;
            return matches;
        }

        public IReadOnlyList<string> GetMatchedStringIdentifiers()
        {
            var matched = new List<string>();
            foreach (var def in _rule.Strings)
            {
                if (_matchCache.TryGetValue(def.Identifier, out var list) && list.Count > 0)
                    matched.Add(def.Identifier);
            }
            return matched;
        }

        private static List<(int Offset, int Length)> FindMatches(
            YaraStringDefinition def,
            ScanBufferContext buffer,
            CancellationToken ct)
        {
            const int maxMatchesPerString = 4096;
            var results = new List<(int Offset, int Length)>();
            var span = buffer.Span;

            switch (def.Kind)
            {
                case YaraStringKind.Text:
                    if (def.Ascii && def.AsciiPattern is { Length: > 0 } asciiPat)
                    {
                        SearchTextBytes(span, asciiPat, def.NoCase, def.FullWord, isWide: false, results, maxMatchesPerString, ct);
                    }
                    if (def.Wide && def.WidePattern is { Length: > 0 } widePat)
                    {
                        SearchTextBytes(span, widePat, def.NoCase, def.FullWord, isWide: true, results, maxMatchesPerString, ct);
                    }
                    break;

                case YaraStringKind.Hex:
                    if (def.Hex is not null)
                    {
                        def.Hex.FindAll(span, results, maxMatchesPerString, ct);
                    }
                    break;

                case YaraStringKind.Regex:
                    if (def.CompiledRegex is not null)
                    {
                        if (def.Ascii || !def.Wide)
                        {
                            var latin1 = buffer.GetLatin1();
                            foreach (Match m in def.CompiledRegex.Matches(latin1))
                            {
                                ct.ThrowIfCancellationRequested();
                                if (def.FullWord && !CheckFullWordAscii(span, m.Index, m.Length))
                                    continue;
                                results.Add((m.Index, m.Length));
                                if (results.Count >= maxMatchesPerString)
                                    break;
                            }
                        }
                        if (def.Wide && results.Count < maxMatchesPerString)
                        {
                            var utf16 = buffer.GetUtf16Le();
                            foreach (Match m in def.CompiledRegex.Matches(utf16))
                            {
                                ct.ThrowIfCancellationRequested();
                                var byteOffset = m.Index * 2;
                                var byteLen = m.Length * 2;
                                if (def.FullWord && !CheckFullWordWide(span, byteOffset, byteLen))
                                    continue;
                                results.Add((byteOffset, byteLen));
                                if (results.Count >= maxMatchesPerString)
                                    break;
                            }
                        }
                    }
                    break;
            }

            if (results.Count > 1)
                results.Sort((a, b) => a.Offset.CompareTo(b.Offset));

            return results;
        }

        private static void SearchTextBytes(
            ReadOnlySpan<byte> haystack,
            byte[] needle,
            bool noCase,
            bool fullWord,
            bool isWide,
            List<(int Offset, int Length)> results,
            int maxMatches,
            CancellationToken ct)
        {
            if (needle.Length == 0 || needle.Length > haystack.Length)
                return;

            if (!noCase)
            {
                var pos = 0;
                var needleSpan = needle.AsSpan();
                while (pos <= haystack.Length - needle.Length)
                {
                    ct.ThrowIfCancellationRequested();
                    var rel = haystack.Slice(pos).IndexOf(needleSpan);
                    if (rel < 0)
                        break;

                    var found = pos + rel;
                    if (!fullWord || (isWide ? CheckFullWordWide(haystack, found, needle.Length) : CheckFullWordAscii(haystack, found, needle.Length)))
                    {
                        results.Add((found, needle.Length));
                        if (results.Count >= maxMatches)
                            return;
                    }
                    pos = found + 1;
                }
            }
            else
            {
                // Recherche insensible a la casse avec filtrage rapide sur le premier octet
                var firstLower = ToAsciiLower(needle[0]);
                var firstUpper = ToAsciiUpper(needle[0]);
                var limit = haystack.Length - needle.Length;

                for (var i = 0; i <= limit; i++)
                {
                    if ((i & 0x3FFF) == 0)
                        ct.ThrowIfCancellationRequested();

                    var b = haystack[i];
                    if (b != firstLower && b != firstUpper)
                        continue;

                    var ok = true;
                    for (var j = 1; j < needle.Length; j++)
                    {
                        if (ToAsciiLower(haystack[i + j]) != ToAsciiLower(needle[j]))
                        {
                            ok = false;
                            break;
                        }
                    }

                    if (ok)
                    {
                        if (!fullWord || (isWide ? CheckFullWordWide(haystack, i, needle.Length) : CheckFullWordAscii(haystack, i, needle.Length)))
                        {
                            results.Add((i, needle.Length));
                            if (results.Count >= maxMatches)
                                return;
                        }
                    }
                }
            }
        }

        private static byte ToAsciiLower(byte b) => (b >= (byte)'A' && b <= (byte)'Z') ? (byte)(b + 32) : b;
        private static byte ToAsciiUpper(byte b) => (b >= (byte)'a' && b <= (byte)'z') ? (byte)(b - 32) : b;

        private static bool IsAsciiAlphaNum(byte b) =>
            (b >= (byte)'0' && b <= (byte)'9') ||
            (b >= (byte)'A' && b <= (byte)'Z') ||
            (b >= (byte)'a' && b <= (byte)'z');

        private static bool CheckFullWordAscii(ReadOnlySpan<byte> data, int offset, int length)
        {
            if (offset > 0 && IsAsciiAlphaNum(data[offset - 1]))
                return false;
            var after = offset + length;
            if (after < data.Length && IsAsciiAlphaNum(data[after]))
                return false;
            return true;
        }

        private static bool CheckFullWordWide(ReadOnlySpan<byte> data, int offset, int length)
        {
            if (offset >= 2 && data[offset - 1] == 0 && IsAsciiAlphaNum(data[offset - 2]))
                return false;
            var after = offset + length;
            if (after + 1 < data.Length && data[after + 1] == 0 && IsAsciiAlphaNum(data[after]))
                return false;
            return true;
        }
    }

    // =========================================================================
    //  Motifs hexadecimaux YARA ({ 4D 5A ?? [1-4] ( 90 | CC ) ?A })
    // =========================================================================

    public sealed class HexPattern
    {
        private readonly HexNode[] _nodes;
        private readonly byte? _anchorByte;

        internal HexPattern(HexNode[] nodes)
        {
            _nodes = nodes;
            if (nodes.Length > 0 && nodes[0] is HexByteNode bn && bn.Mask == 0xFF)
                _anchorByte = bn.Value;
        }

        public void FindAll(
            ReadOnlySpan<byte> data,
            List<(int Offset, int Length)> results,
            int maxMatches,
            CancellationToken ct)
        {
            if (_nodes.Length == 0 || data.Length == 0)
                return;

            var pos = 0;
            while (pos < data.Length)
            {
                ct.ThrowIfCancellationRequested();

                if (_anchorByte.HasValue)
                {
                    var rel = data.Slice(pos).IndexOf(_anchorByte.Value);
                    if (rel < 0)
                        break;
                    pos += rel;
                }

                if (TryMatchAt(data, pos, 0, out var endPos))
                {
                    results.Add((pos, endPos - pos));
                    if (results.Count >= maxMatches)
                        return;
                }

                pos++;
            }
        }

        private bool TryMatchAt(ReadOnlySpan<byte> data, int dataPos, int nodeIdx, out int endPos)
        {
            if (nodeIdx == _nodes.Length)
            {
                endPos = dataPos;
                return true;
            }

            var node = _nodes[nodeIdx];
            switch (node)
            {
                case HexByteNode bn:
                    if (dataPos < data.Length && (data[dataPos] & bn.Mask) == (bn.Value & bn.Mask))
                        return TryMatchAt(data, dataPos + 1, nodeIdx + 1, out endPos);
                    endPos = dataPos;
                    return false;

                case HexJumpNode jn:
                    var maxJump = Math.Min(jn.Max, data.Length - dataPos);
                    for (var skip = jn.Min; skip <= maxJump; skip++)
                    {
                        if (TryMatchAt(data, dataPos + skip, nodeIdx + 1, out endPos))
                            return true;
                    }
                    endPos = dataPos;
                    return false;

                case HexAltNode an:
                    foreach (var branch in an.Branches)
                    {
                        if (MatchBranch(data, dataPos, branch, 0, nodeIdx + 1, out endPos))
                            return true;
                    }
                    endPos = dataPos;
                    return false;

                default:
                    endPos = dataPos;
                    return false;
            }
        }

        private bool MatchBranch(
            ReadOnlySpan<byte> data,
            int dataPos,
            HexNode[] branch,
            int branchIdx,
            int nextMainNodeIdx,
            out int endPos)
        {
            if (branchIdx == branch.Length)
                return TryMatchAt(data, dataPos, nextMainNodeIdx, out endPos);

            switch (branch[branchIdx])
            {
                case HexByteNode bn:
                    if (dataPos < data.Length && (data[dataPos] & bn.Mask) == (bn.Value & bn.Mask))
                        return MatchBranch(data, dataPos + 1, branch, branchIdx + 1, nextMainNodeIdx, out endPos);
                    endPos = dataPos;
                    return false;

                case HexJumpNode jn:
                    var maxJump = Math.Min(jn.Max, data.Length - dataPos);
                    for (var skip = jn.Min; skip <= maxJump; skip++)
                    {
                        if (MatchBranch(data, dataPos + skip, branch, branchIdx + 1, nextMainNodeIdx, out endPos))
                            return true;
                    }
                    endPos = dataPos;
                    return false;

                default:
                    endPos = dataPos;
                    return false;
            }
        }

        internal static HexPattern Parse(string hexBody)
        {
            var idx = 0;
            var nodes = ParseSequence(hexBody, ref idx, stopAtPipeOrParen: false);
            if (nodes.Length == 0)
                throw new YaraParseException("Motif hexadecimal YARA vide.");
            return new HexPattern(nodes);
        }

        private static HexNode[] ParseSequence(string s, ref int idx, bool stopAtPipeOrParen)
        {
            var list = new List<HexNode>();
            while (idx < s.Length)
            {
                SkipHexTrivia(s, ref idx);
                if (idx >= s.Length)
                    break;

                var c = s[idx];
                if (stopAtPipeOrParen && (c == '|' || c == ')'))
                    break;

                if (c == '[')
                {
                    idx++;
                    var start = idx;
                    while (idx < s.Length && s[idx] != ']') idx++;
                    if (idx >= s.Length)
                        throw new YaraParseException("Saut hexadecimal '[' non ferme.");
                    var rangeText = s.Substring(start, idx - start).Trim();
                    idx++; // consume ']'

                    int min = 0;
                    int max = 256;
                    var dash = rangeText.IndexOf('-');
                    if (dash < 0)
                    {
                        min = max = int.Parse(rangeText, CultureInfo.InvariantCulture);
                    }
                    else
                    {
                        var left = rangeText.Substring(0, dash).Trim();
                        var right = rangeText.Substring(dash + 1).Trim();
                        min = string.IsNullOrEmpty(left) ? 0 : int.Parse(left, CultureInfo.InvariantCulture);
                        max = string.IsNullOrEmpty(right) ? Math.Max(min + 256, 512) : int.Parse(right, CultureInfo.InvariantCulture);
                    }
                    list.Add(new HexJumpNode(Math.Max(0, min), Math.Max(min, max)));
                }
                else if (c == '(')
                {
                    idx++; // '('
                    var branches = new List<HexNode[]>();
                    while (idx < s.Length)
                    {
                        branches.Add(ParseSequence(s, ref idx, stopAtPipeOrParen: true));
                        SkipHexTrivia(s, ref idx);
                        if (idx < s.Length && s[idx] == '|')
                        {
                            idx++;
                            continue;
                        }
                        if (idx < s.Length && s[idx] == ')')
                        {
                            idx++;
                            break;
                        }
                        throw new YaraParseException("Alternative hexadecimale '(' non fermee.");
                    }
                    list.Add(new HexAltNode(branches.ToArray()));
                }
                else if (IsHexOrWildcard(c))
                {
                    if (idx + 1 >= s.Length || !IsHexOrWildcard(s[idx + 1]))
                        throw new YaraParseException($"Octet hexadecimal incomplet pres de la position {idx}.");

                    var hi = s[idx];
                    var lo = s[idx + 1];
                    idx += 2;

                    byte value = 0;
                    byte mask = 0;
                    if (hi != '?')
                    {
                        value |= (byte)(HexNibble(hi) << 4);
                        mask |= 0xF0;
                    }
                    if (lo != '?')
                    {
                        value |= (byte)HexNibble(lo);
                        mask |= 0x0F;
                    }
                    list.Add(new HexByteNode(value, mask));
                }
                else
                {
                    throw new YaraParseException($"Caractere inattendu '{c}' dans un motif hexadecimal YARA.");
                }
            }
            return list.ToArray();
        }

        private static void SkipHexTrivia(string s, ref int idx)
        {
            while (idx < s.Length)
            {
                if (char.IsWhiteSpace(s[idx]))
                {
                    idx++;
                }
                else if (s[idx] == '/' && idx + 1 < s.Length && s[idx + 1] == '/')
                {
                    idx += 2;
                    while (idx < s.Length && s[idx] != '\n') idx++;
                }
                else if (s[idx] == '/' && idx + 1 < s.Length && s[idx + 1] == '*')
                {
                    idx += 2;
                    while (idx + 1 < s.Length && !(s[idx] == '*' && s[idx + 1] == '/')) idx++;
                    idx = Math.Min(idx + 2, s.Length);
                }
                else
                {
                    break;
                }
            }
        }

        private static bool IsHexOrWildcard(char c) =>
            c == '?' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');

        private static int HexNibble(char c) => c switch
        {
            >= '0' and <= '9' => c - '0',
            >= 'a' and <= 'f' => c - 'a' + 10,
            >= 'A' and <= 'F' => c - 'A' + 10,
            _ => throw new YaraParseException($"Chiffre hexadecimal invalide : '{c}'.")
        };
    }

    internal abstract class HexNode { }
    internal sealed class HexByteNode(byte value, byte mask) : HexNode
    {
        public byte Value { get; } = value;
        public byte Mask { get; } = mask;
    }
    internal sealed class HexJumpNode(int min, int max) : HexNode
    {
        public int Min { get; } = min;
        public int Max { get; } = max;
    }
    internal sealed class HexAltNode(HexNode[][] branches) : HexNode
    {
        public HexNode[][] Branches { get; } = branches;
    }

    // =========================================================================
    //  Parseur de fichier source YARA (.yar)
    // =========================================================================

    private sealed class YaraSourceParser
    {
        private readonly string _src;
        private readonly string _sourceFile;
        private readonly string _namespace;
        private int _pos;

        public YaraSourceParser(string src, string sourceFile, string @namespace)
        {
            _src = src;
            _sourceFile = sourceFile;
            _namespace = @namespace;
        }

        public IReadOnlyList<ParsedYaraRule> ParseAllRules()
        {
            var rules = new List<ParsedYaraRule>();
            while (true)
            {
                SkipTrivia();
                if (_pos >= _src.Length)
                    break;

                var ruleStart = _pos;
                var word = PeekIdentifier();
                if (word is "import" or "include")
                {
                    ReadIdentifier();
                    SkipTrivia();
                    if (_pos < _src.Length && _src[_pos] == '"')
                        ReadQuotedString();
                    continue;
                }

                var isPrivate = false;
                var isGlobal = false;
                while (word is "private" or "global")
                {
                    ReadIdentifier();
                    if (word == "private") isPrivate = true;
                    if (word == "global") isGlobal = true;
                    SkipTrivia();
                    word = PeekIdentifier();
                }

                if (word != "rule")
                    throw new YaraParseException($"Mot-cle 'rule' attendu a la position {_pos} dans '{_sourceFile}', trouve '{word}'.");

                ReadIdentifier(); // "rule"
                SkipTrivia();
                var ruleId = ReadIdentifier();
                if (string.IsNullOrWhiteSpace(ruleId))
                    throw new YaraParseException($"Identifiant de regle manquant a la position {_pos} dans '{_sourceFile}'.");

                var tags = new List<string>();
                SkipTrivia();
                if (_pos < _src.Length && _src[_pos] == ':')
                {
                    _pos++;
                    while (true)
                    {
                        SkipTrivia();
                        if (_pos >= _src.Length || _src[_pos] == '{')
                            break;
                        var tag = ReadIdentifier();
                        if (string.IsNullOrEmpty(tag))
                            break;
                        tags.Add(tag);
                    }
                }

                SkipTrivia();
                ExpectChar('{');
                var bodyStart = _pos;
                var bodyEnd = FindMatchingBrace(bodyStart);
                var body = _src.Substring(bodyStart, bodyEnd - bodyStart);
                _pos = bodyEnd + 1;
                var rawRuleText = _src.Substring(ruleStart, _pos - ruleStart);

                rules.Add(ParseRuleBody(ruleId, isPrivate, isGlobal, tags, body, rawRuleText));
            }
            return rules;
        }

        private ParsedYaraRule ParseRuleBody(
            string ruleId,
            bool isPrivate,
            bool isGlobal,
            IReadOnlyList<string> tags,
            string body,
            string rawRuleText)
        {
            var meta = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var strings = new List<YaraStringDefinition>();
            var conditionSrc = string.Empty;

            SplitSections(body, out var metaSection, out var stringsSection, out conditionSrc);

            if (!string.IsNullOrWhiteSpace(metaSection))
                ParseMetaSection(metaSection, meta);

            if (!string.IsNullOrWhiteSpace(stringsSection))
                ParseStringsSection(stringsSection, strings);

            if (string.IsNullOrWhiteSpace(conditionSrc))
                throw new YaraParseException($"Section 'condition:' manquante dans la regle '{ruleId}'.");

            var condParser = new YaraConditionParser(conditionSrc);
            var condAst = condParser.Parse();

            return new ParsedYaraRule(
                ruleId,
                _namespace,
                _sourceFile,
                isPrivate,
                isGlobal,
                tags,
                meta,
                strings,
                conditionSrc.Trim(),
                condAst,
                rawRuleText);
        }

        private static void SplitSections(
            string body,
            out string metaSection,
            out string stringsSection,
            out string conditionSection)
        {
            // Localise les en-tetes meta:, strings:, condition: hors chaines/commentaires/regex/accolades
            var positions = new List<(string Name, int HeaderStart, int ContentStart)>();
            var i = 0;
            var braceDepth = 0;
            var prevNonWs = '\0';

            while (i < body.Length)
            {
                var c = body[i];
                if (c == '/' && i + 1 < body.Length && body[i + 1] == '/')
                {
                    i += 2;
                    while (i < body.Length && body[i] != '\n') i++;
                    continue;
                }
                if (c == '/' && i + 1 < body.Length && body[i + 1] == '*')
                {
                    i += 2;
                    while (i + 1 < body.Length && !(body[i] == '*' && body[i + 1] == '/')) i++;
                    i = Math.Min(i + 2, body.Length);
                    continue;
                }
                if (c == '/' && prevNonWs == '=')
                {
                    i = SkipRegexLiteral(body, i);
                    prevNonWs = '/';
                    continue;
                }
                if (c == '"')
                {
                    i++;
                    while (i < body.Length)
                    {
                        if (body[i] == '\\') { i += 2; continue; }
                        if (body[i] == '"') { i++; break; }
                        i++;
                    }
                    prevNonWs = '"';
                    continue;
                }
                if (c == '{') { braceDepth++; prevNonWs = c; i++; continue; }
                if (c == '}') { braceDepth = Math.Max(0, braceDepth - 1); prevNonWs = c; i++; continue; }

                if (braceDepth == 0 && (i == 0 || !IsIdentChar(body[i - 1])))
                {
                    if (TryMatchSectionHeader(body, i, "meta", out var afterMeta))
                    {
                        positions.Add(("meta", i, afterMeta));
                        prevNonWs = ':';
                        i = afterMeta;
                        continue;
                    }
                    if (TryMatchSectionHeader(body, i, "strings", out var afterStrings))
                    {
                        positions.Add(("strings", i, afterStrings));
                        prevNonWs = ':';
                        i = afterStrings;
                        continue;
                    }
                    if (TryMatchSectionHeader(body, i, "condition", out var afterCond))
                    {
                        positions.Add(("condition", i, afterCond));
                        prevNonWs = ':';
                        i = afterCond;
                        continue;
                    }
                }
                if (!char.IsWhiteSpace(c))
                    prevNonWs = c;
                i++;
            }

            metaSection = string.Empty;
            stringsSection = string.Empty;
            conditionSection = string.Empty;

            for (var p = 0; p < positions.Count; p++)
            {
                var cur = positions[p];
                var end = (p + 1 < positions.Count) ? positions[p + 1].HeaderStart : body.Length;
                var slice = body.Substring(cur.ContentStart, end - cur.ContentStart);
                switch (cur.Name)
                {
                    case "meta": metaSection = slice; break;
                    case "strings": stringsSection = slice; break;
                    case "condition": conditionSection = slice; break;
                }
            }
        }

        private static bool TryMatchSectionHeader(string s, int index, string keyword, out int afterColon)
        {
            afterColon = index;
            if (index + keyword.Length >= s.Length)
                return false;
            if (!s.AsSpan(index, keyword.Length).Equals(keyword.AsSpan(), StringComparison.Ordinal))
                return false;

            var j = index + keyword.Length;
            while (j < s.Length && (s[j] == ' ' || s[j] == '\t')) j++;
            if (j < s.Length && s[j] == ':')
            {
                afterColon = j + 1;
                return true;
            }
            return false;
        }

        private static void ParseMetaSection(string section, Dictionary<string, string> meta)
        {
            var p = 0;
            while (p < section.Length)
            {
                SkipSectionTrivia(section, ref p);
                if (p >= section.Length) break;

                var key = ReadSectionIdent(section, ref p);
                if (string.IsNullOrEmpty(key))
                    throw new YaraParseException($"Cle meta invalide pres de la position {p}.");

                SkipSectionTrivia(section, ref p);
                if (p >= section.Length || section[p] != '=')
                    throw new YaraParseException($"'=' attendu apres la cle meta '{key}'.");
                p++;
                SkipSectionTrivia(section, ref p);

                if (p >= section.Length)
                    throw new YaraParseException($"Valeur manquante pour la cle meta '{key}'.");

                string val;
                if (section[p] == '"')
                {
                    val = ReadSectionQuotedString(section, ref p);
                }
                else
                {
                    var start = p;
                    while (p < section.Length && !char.IsWhiteSpace(section[p]) && section[p] != '/')
                        p++;
                    val = section.Substring(start, p - start);
                }
                meta[key] = val;
            }
        }

        private static void ParseStringsSection(string section, List<YaraStringDefinition> list)
        {
            var p = 0;
            var anonIndex = 0;
            while (p < section.Length)
            {
                SkipSectionTrivia(section, ref p);
                if (p >= section.Length) break;

                if (section[p] != '$')
                    throw new YaraParseException($"Identifiant de chaine '$' attendu dans 'strings:' pres de la position {p}.");

                var idStart = p;
                p++;
                while (p < section.Length && IsIdentChar(section[p])) p++;
                var id = section.Substring(idStart, p - idStart);
                if (id == "$")
                    id = $"$__anon_{anonIndex++}";

                SkipSectionTrivia(section, ref p);
                if (p >= section.Length || section[p] != '=')
                    throw new YaraParseException($"'=' attendu apres '{id}'.");
                p++;
                SkipSectionTrivia(section, ref p);

                if (p >= section.Length)
                    throw new YaraParseException($"Definition manquante pour la chaine '{id}'.");

                var defStart = p;
                if (section[p] == '"')
                {
                    var rawBytes = ReadSectionYaraStringBytes(section, ref p);
                    ReadStringModifiers(section, ref p, out var ascii, out var wide, out var noCase, out var fullWord);
                    if (!ascii && !wide)
                        ascii = true;

                    byte[]? asciiPattern = ascii ? rawBytes : null;
                    byte[]? widePattern = wide ? ToUtf16LeBytes(rawBytes) : null;
                    var rawDef = section.Substring(defStart, p - defStart).Trim();

                    list.Add(new YaraStringDefinition(
                        id, YaraStringKind.Text, ascii, wide, noCase, fullWord,
                        asciiPattern, widePattern, null, null, rawDef));
                }
                else if (section[p] == '{')
                {
                    p++;
                    var hexStart = p;
                    while (p < section.Length && section[p] != '}') p++;
                    if (p >= section.Length)
                        throw new YaraParseException($"Motif hexadecimal non ferme pour '{id}'.");
                    var hexBody = section.Substring(hexStart, p - hexStart);
                    p++; // '}'
                    ReadStringModifiers(section, ref p, out _, out _, out _, out _);
                    var hexPattern = HexPattern.Parse(hexBody);
                    var rawDef = section.Substring(defStart, p - defStart).Trim();

                    list.Add(new YaraStringDefinition(
                        id, YaraStringKind.Hex, ascii: false, wide: false, noCase: false, fullWord: false,
                        null, null, hexPattern, null, rawDef));
                }
                else if (section[p] == '/')
                {
                    var (pattern, inlineIgnoreCase, inlineSingleline) = ReadSectionRegex(section, ref p);
                    ReadStringModifiers(section, ref p, out var ascii, out var wide, out var noCase, out var fullWord);
                    if (!ascii && !wide)
                        ascii = true;

                    var opts = RegexOptions.Compiled | RegexOptions.CultureInvariant;
                    if (inlineIgnoreCase || noCase) opts |= RegexOptions.IgnoreCase;
                    if (inlineSingleline) opts |= RegexOptions.Singleline;

                    Regex compiled;
                    try
                    {
                        compiled = new Regex(pattern, opts, RegexMatchTimeout);
                    }
                    catch (ArgumentException ex)
                    {
                        throw new YaraParseException($"Expression reguliere invalide pour '{id}' : {ex.Message}", ex);
                    }

                    var rawDef = section.Substring(defStart, p - defStart).Trim();
                    list.Add(new YaraStringDefinition(
                        id, YaraStringKind.Regex, ascii, wide, noCase || inlineIgnoreCase, fullWord,
                        null, null, null, compiled, rawDef));
                }
                else
                {
                    throw new YaraParseException($"Type de chaine YARA non pris en charge pour '{id}' : '{section[p]}'.");
                }
            }
        }

        private static void ReadStringModifiers(
            string s,
            ref int p,
            out bool ascii,
            out bool wide,
            out bool noCase,
            out bool fullWord)
        {
            ascii = false;
            wide = false;
            noCase = false;
            fullWord = false;

            while (p < s.Length)
            {
                SkipSectionTrivia(s, ref p);
                if (p >= s.Length || s[p] == '$')
                    break;

                var saved = p;
                var mod = ReadSectionIdent(s, ref p);
                if (string.IsNullOrEmpty(mod))
                {
                    p = saved;
                    break;
                }

                switch (mod)
                {
                    case "ascii": ascii = true; break;
                    case "wide": wide = true; break;
                    case "nocase": noCase = true; break;
                    case "fullword": fullWord = true; break;
                    case "private":
                    case "xor":
                    case "base64":
                    case "base64wide":
                        // Supporte la syntaxe xor(0x01-0xff) si presente
                        SkipSectionTrivia(s, ref p);
                        if (p < s.Length && s[p] == '(')
                        {
                            while (p < s.Length && s[p] != ')') p++;
                            if (p < s.Length) p++;
                        }
                        break;
                    default:
                        p = saved;
                        return;
                }
            }
        }

        private static byte[] ToUtf16LeBytes(byte[] asciiBytes)
        {
            var wide = new byte[asciiBytes.Length * 2];
            for (var i = 0; i < asciiBytes.Length; i++)
            {
                wide[i * 2] = asciiBytes[i];
                wide[i * 2 + 1] = 0;
            }
            return wide;
        }

        private static byte[] ReadSectionYaraStringBytes(string s, ref int p)
        {
            p++; // opening '"'
            var bytes = new List<byte>();
            while (p < s.Length)
            {
                var c = s[p++];
                if (c == '"')
                    return bytes.ToArray();

                if (c == '\\' && p < s.Length)
                {
                    var esc = s[p++];
                    switch (esc)
                    {
                        case '\\': bytes.Add((byte)'\\'); break;
                        case '"': bytes.Add((byte)'"'); break;
                        case 'n': bytes.Add((byte)'\n'); break;
                        case 'r': bytes.Add((byte)'\r'); break;
                        case 't': bytes.Add((byte)'\t'); break;
                        case 'x' when p + 1 < s.Length:
                            var hex = s.Substring(p, 2);
                            p += 2;
                            bytes.Add(byte.Parse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture));
                            break;
                        default:
                            bytes.Add((byte)esc);
                            break;
                    }
                }
                else
                {
                    if (c <= 0x7F)
                        bytes.Add((byte)c);
                    else
                        bytes.AddRange(Encoding.UTF8.GetBytes([c]));
                }
            }
            throw new YaraParseException("Chaine YARA non fermee.");
        }

        private static (string Pattern, bool IgnoreCase, bool Singleline) ReadSectionRegex(string s, ref int p)
        {
            p++; // opening '/'
            var sb = new StringBuilder();
            var inCharClass = false;
            while (p < s.Length)
            {
                var c = s[p++];
                if (c == '\\' && p < s.Length)
                {
                    var next = s[p++];
                    if (next == '/')
                        sb.Append('/');
                    else
                    {
                        sb.Append('\\');
                        sb.Append(next);
                    }
                    continue;
                }
                if (c == '[') inCharClass = true;
                else if (c == ']' && inCharClass) inCharClass = false;
                else if (c == '/' && !inCharClass)
                {
                    var ignoreCase = false;
                    var singleline = false;
                    while (p < s.Length && (s[p] == 'i' || s[p] == 's'))
                    {
                        if (s[p] == 'i') ignoreCase = true;
                        if (s[p] == 's') singleline = true;
                        p++;
                    }
                    return (sb.ToString(), ignoreCase, singleline);
                }
                sb.Append(c);
            }
            throw new YaraParseException("Expression reguliere YARA non fermee.");
        }

        private static string ReadSectionQuotedString(string s, ref int p)
        {
            p++; // '"'
            var sb = new StringBuilder();
            while (p < s.Length)
            {
                var c = s[p++];
                if (c == '"') return sb.ToString();
                if (c == '\\' && p < s.Length)
                {
                    var esc = s[p++];
                    sb.Append(esc switch
                    {
                        'n' => '\n',
                        'r' => '\r',
                        't' => '\t',
                        '"' => '"',
                        '\\' => '\\',
                        _ => esc
                    });
                }
                else
                {
                    sb.Append(c);
                }
            }
            throw new YaraParseException("Chaine entre guillemets non fermee.");
        }

        private static void SkipSectionTrivia(string s, ref int p)
        {
            while (p < s.Length)
            {
                if (char.IsWhiteSpace(s[p])) { p++; continue; }
                if (s[p] == '/' && p + 1 < s.Length && s[p + 1] == '/')
                {
                    p += 2;
                    while (p < s.Length && s[p] != '\n') p++;
                    continue;
                }
                if (s[p] == '/' && p + 1 < s.Length && s[p + 1] == '*')
                {
                    p += 2;
                    while (p + 1 < s.Length && !(s[p] == '*' && s[p + 1] == '/')) p++;
                    p = Math.Min(p + 2, s.Length);
                    continue;
                }
                break;
            }
        }

        private static string ReadSectionIdent(string s, ref int p)
        {
            var start = p;
            while (p < s.Length && IsIdentChar(s[p])) p++;
            return s.Substring(start, p - start);
        }

        private int FindMatchingBrace(int startInsideBrace)
        {
            var i = startInsideBrace;
            var depth = 1;
            var prevNonWs = '{';
            while (i < _src.Length)
            {
                var c = _src[i];
                if (c == '/' && i + 1 < _src.Length && _src[i + 1] == '/')
                {
                    i += 2;
                    while (i < _src.Length && _src[i] != '\n') i++;
                    continue;
                }
                if (c == '/' && i + 1 < _src.Length && _src[i + 1] == '*')
                {
                    i += 2;
                    while (i + 1 < _src.Length && !(_src[i] == '*' && _src[i + 1] == '/')) i++;
                    i = Math.Min(i + 2, _src.Length);
                    continue;
                }
                if (c == '/' && prevNonWs == '=')
                {
                    i = SkipRegexLiteral(_src, i);
                    prevNonWs = '/';
                    continue;
                }
                if (c == '"')
                {
                    i++;
                    while (i < _src.Length)
                    {
                        if (_src[i] == '\\') { i += 2; continue; }
                        if (_src[i] == '"') { i++; break; }
                        i++;
                    }
                    prevNonWs = '"';
                    continue;
                }
                if (c == '{') depth++;
                else if (c == '}')
                {
                    depth--;
                    if (depth == 0)
                        return i;
                }
                if (!char.IsWhiteSpace(c))
                    prevNonWs = c;
                i++;
            }
            throw new YaraParseException($"Accolade fermante '}}' manquante dans '{_sourceFile}'.");
        }

        private static int SkipRegexLiteral(string s, int slashStart)
        {
            var i = slashStart + 1;
            var inCharClass = false;
            while (i < s.Length)
            {
                var c = s[i++];
                if (c == '\\' && i < s.Length)
                {
                    i++;
                    continue;
                }
                if (c == '[') inCharClass = true;
                else if (c == ']' && inCharClass) inCharClass = false;
                else if (c == '/' && !inCharClass)
                {
                    while (i < s.Length && (s[i] == 'i' || s[i] == 's'))
                        i++;
                    return i;
                }
            }
            return i;
        }

        private void SkipTrivia()
        {
            while (_pos < _src.Length)
            {
                if (char.IsWhiteSpace(_src[_pos])) { _pos++; continue; }
                if (_src[_pos] == '/' && _pos + 1 < _src.Length && _src[_pos + 1] == '/')
                {
                    _pos += 2;
                    while (_pos < _src.Length && _src[_pos] != '\n') _pos++;
                    continue;
                }
                if (_src[_pos] == '/' && _pos + 1 < _src.Length && _src[_pos + 1] == '*')
                {
                    _pos += 2;
                    while (_pos + 1 < _src.Length && !(_src[_pos] == '*' && _src[_pos + 1] == '/')) _pos++;
                    _pos = Math.Min(_pos + 2, _src.Length);
                    continue;
                }
                break;
            }
        }

        private string PeekIdentifier()
        {
            var i = _pos;
            while (i < _src.Length && IsIdentChar(_src[i])) i++;
            return _src.Substring(_pos, i - _pos);
        }

        private string ReadIdentifier()
        {
            var start = _pos;
            while (_pos < _src.Length && IsIdentChar(_src[_pos])) _pos++;
            return _src.Substring(start, _pos - start);
        }

        private void ReadQuotedString()
        {
            _pos++; // '"'
            while (_pos < _src.Length)
            {
                if (_src[_pos] == '\\') { _pos += 2; continue; }
                if (_src[_pos] == '"') { _pos++; return; }
                _pos++;
            }
        }

        private void ExpectChar(char expected)
        {
            if (_pos >= _src.Length || _src[_pos] != expected)
                throw new YaraParseException($"Caractere '{expected}' attendu a la position {_pos} dans '{_sourceFile}'.");
            _pos++;
        }

        private static bool IsIdentChar(char c) =>
            char.IsLetterOrDigit(c) || c == '_';
    }

    // =========================================================================
    //  AST et parseur des conditions YARA
    // =========================================================================

    internal abstract class YaraExpr
    {
        public abstract long EvalInt(RuleEvalContext ctx);
        public virtual bool EvalBool(RuleEvalContext ctx) => EvalInt(ctx) != 0;
    }

    private sealed class ConstIntExpr(long value) : YaraExpr
    {
        public override long EvalInt(RuleEvalContext ctx) => value;
    }

    private sealed class FileSizeExpr : YaraExpr
    {
        public override long EvalInt(RuleEvalContext ctx) => ctx.FileSize;
    }

    private sealed class NotExpr(YaraExpr inner) : YaraExpr
    {
        public override bool EvalBool(RuleEvalContext ctx) => !inner.EvalBool(ctx);
        public override long EvalInt(RuleEvalContext ctx) => EvalBool(ctx) ? 1 : 0;
    }

    private sealed class BinaryBoolExpr(string op, YaraExpr left, YaraExpr right) : YaraExpr
    {
        public override bool EvalBool(RuleEvalContext ctx) => op switch
        {
            "and" => left.EvalBool(ctx) && right.EvalBool(ctx),
            "or" => left.EvalBool(ctx) || right.EvalBool(ctx),
            _ => false
        };
        public override long EvalInt(RuleEvalContext ctx) => EvalBool(ctx) ? 1 : 0;
    }

    private sealed class CompareExpr(string op, YaraExpr left, YaraExpr right) : YaraExpr
    {
        public override bool EvalBool(RuleEvalContext ctx)
        {
            var l = left.EvalInt(ctx);
            var r = right.EvalInt(ctx);
            return op switch
            {
                "==" => l == r,
                "!=" => l != r,
                "<" => l < r,
                "<=" => l <= r,
                ">" => l > r,
                ">=" => l >= r,
                _ => false
            };
        }
        public override long EvalInt(RuleEvalContext ctx) => EvalBool(ctx) ? 1 : 0;
    }

    private sealed class ArithmeticExpr(string op, YaraExpr left, YaraExpr right) : YaraExpr
    {
        public override long EvalInt(RuleEvalContext ctx)
        {
            var l = left.EvalInt(ctx);
            var r = right.EvalInt(ctx);
            return op switch
            {
                "+" => l + r,
                "-" => l - r,
                "*" => l * r,
                "\\" or "/" => r == 0 ? 0 : l / r,
                "%" => r == 0 ? 0 : l % r,
                _ => 0
            };
        }
    }

    private sealed class StringPresentExpr(string id) : YaraExpr
    {
        public override bool EvalBool(RuleEvalContext ctx) => ctx.GetMatches(id).Count > 0;
        public override long EvalInt(RuleEvalContext ctx) => EvalBool(ctx) ? 1 : 0;
    }

    private sealed class StringCountExpr(string id) : YaraExpr
    {
        public override long EvalInt(RuleEvalContext ctx) => ctx.GetMatches(id).Count;
    }

    private sealed class StringOffsetExpr(string id, YaraExpr? indexExpr) : YaraExpr
    {
        public override long EvalInt(RuleEvalContext ctx)
        {
            var matches = ctx.GetMatches(id);
            var idx = indexExpr is null ? 0 : (int)indexExpr.EvalInt(ctx) - 1;
            if (idx < 0 || idx >= matches.Count)
                return -1;
            return matches[idx].Offset;
        }
    }

    private sealed class StringLengthExpr(string id, YaraExpr? indexExpr) : YaraExpr
    {
        public override long EvalInt(RuleEvalContext ctx)
        {
            var matches = ctx.GetMatches(id);
            var idx = indexExpr is null ? 0 : (int)indexExpr.EvalInt(ctx) - 1;
            if (idx < 0 || idx >= matches.Count)
                return 0;
            return matches[idx].Length;
        }
    }

    private sealed class StringAtExpr(string id, YaraExpr offsetExpr) : YaraExpr
    {
        public override bool EvalBool(RuleEvalContext ctx)
        {
            var target = offsetExpr.EvalInt(ctx);
            var matches = ctx.GetMatches(id);
            foreach (var m in matches)
            {
                if (m.Offset == target)
                    return true;
            }
            return false;
        }
        public override long EvalInt(RuleEvalContext ctx) => EvalBool(ctx) ? 1 : 0;
    }

    private sealed class StringInRangeExpr(string id, YaraExpr minExpr, YaraExpr maxExpr) : YaraExpr
    {
        public override bool EvalBool(RuleEvalContext ctx)
        {
            var min = minExpr.EvalInt(ctx);
            var max = maxExpr.EvalInt(ctx);
            var matches = ctx.GetMatches(id);
            foreach (var m in matches)
            {
                if (m.Offset >= min && m.Offset <= max)
                    return true;
            }
            return false;
        }
        public override long EvalInt(RuleEvalContext ctx) => EvalBool(ctx) ? 1 : 0;
    }

    private sealed class RuleRefExpr(string ruleId) : YaraExpr
    {
        public override bool EvalBool(RuleEvalContext ctx) => ctx.IsRuleMatched(ruleId);
        public override long EvalInt(RuleEvalContext ctx) => EvalBool(ctx) ? 1 : 0;
    }

    private sealed class ByteReadExpr(string funcName, YaraExpr offsetExpr) : YaraExpr
    {
        public override long EvalInt(RuleEvalContext ctx)
        {
            var off = offsetExpr.EvalInt(ctx);
            var bytes = ctx.Bytes;
            if (off < 0 || off >= bytes.Length)
                return -1;

            var i = (int)off;
            return funcName switch
            {
                "uint8" => bytes[i],
                "int8" => (sbyte)bytes[i],
                "uint16" when i + 2 <= bytes.Length => BinaryPrimitives.ReadUInt16LittleEndian(bytes.Slice(i, 2)),
                "int16" when i + 2 <= bytes.Length => BinaryPrimitives.ReadInt16LittleEndian(bytes.Slice(i, 2)),
                "uint16be" when i + 2 <= bytes.Length => BinaryPrimitives.ReadUInt16BigEndian(bytes.Slice(i, 2)),
                "uint32" when i + 4 <= bytes.Length => BinaryPrimitives.ReadUInt32LittleEndian(bytes.Slice(i, 4)),
                "int32" when i + 4 <= bytes.Length => BinaryPrimitives.ReadInt32LittleEndian(bytes.Slice(i, 4)),
                "uint32be" when i + 4 <= bytes.Length => BinaryPrimitives.ReadUInt32BigEndian(bytes.Slice(i, 4)),
                _ => -1
            };
        }
    }

    private sealed class QuantifierOfExpr(string quantifier, long? count, IReadOnlyList<string>? setPatterns) : YaraExpr
    {
        public override bool EvalBool(RuleEvalContext ctx)
        {
            var targets = ResolveTargets(ctx);
            if (targets.Count == 0)
                return quantifier == "none";

            var matched = 0;
            foreach (var id in targets)
            {
                if (ctx.GetMatches(id).Count > 0)
                {
                    matched++;
                    if (quantifier == "any")
                        return true;
                    if (quantifier == "count" && count.HasValue && matched >= count.Value)
                        return true;
                }
                else if (quantifier == "all")
                {
                    return false;
                }
            }

            return quantifier switch
            {
                "any" => matched > 0,
                "all" => matched == targets.Count,
                "none" => matched == 0,
                "count" => count.HasValue && matched >= count.Value,
                _ => false
            };
        }

        public override long EvalInt(RuleEvalContext ctx) => EvalBool(ctx) ? 1 : 0;

        private List<string> ResolveTargets(RuleEvalContext ctx)
        {
            var result = new List<string>();
            if (setPatterns is null)
            {
                foreach (var s in ctx.AllStrings)
                    result.Add(s.Identifier);
                return result;
            }

            foreach (var pat in setPatterns)
            {
                if (pat.EndsWith('*'))
                {
                    var prefix = pat.Substring(0, pat.Length - 1);
                    foreach (var s in ctx.AllStrings)
                    {
                        if (s.Identifier.StartsWith(prefix, StringComparison.Ordinal) && !result.Contains(s.Identifier))
                            result.Add(s.Identifier);
                    }
                }
                else if (!result.Contains(pat))
                {
                    result.Add(pat);
                }
            }
            return result;
        }
    }

    private sealed class YaraConditionParser
    {
        private readonly List<CondToken> _tokens;
        private int _idx;

        public YaraConditionParser(string source)
        {
            _tokens = Tokenize(source);
        }

        public YaraExpr Parse()
        {
            if (_tokens.Count == 0)
                throw new YaraParseException("Condition YARA vide.");
            var expr = ParseOr();
            return expr;
        }

        private YaraExpr ParseOr()
        {
            var left = ParseAnd();
            while (MatchKeyword("or"))
            {
                var right = ParseAnd();
                left = new BinaryBoolExpr("or", left, right);
            }
            return left;
        }

        private YaraExpr ParseAnd()
        {
            var left = ParseNot();
            while (MatchKeyword("and"))
            {
                var right = ParseNot();
                left = new BinaryBoolExpr("and", left, right);
            }
            return left;
        }

        private YaraExpr ParseNot()
        {
            if (MatchKeyword("not"))
                return new NotExpr(ParseNot());
            return ParseComparison();
        }

        private YaraExpr ParseComparison()
        {
            var left = ParseAdditive();
            if (PeekKind() == CondTokenKind.Operator &&
                PeekValue() is "==" or "!=" or "<" or "<=" or ">" or ">=")
            {
                var op = Consume().Value;
                var right = ParseAdditive();
                return new CompareExpr(op, left, right);
            }
            return left;
        }

        private YaraExpr ParseAdditive()
        {
            var left = ParseMultiplicative();
            while (PeekKind() == CondTokenKind.Operator && PeekValue() is "+" or "-")
            {
                var op = Consume().Value;
                var right = ParseMultiplicative();
                left = new ArithmeticExpr(op, left, right);
            }
            return left;
        }

        private YaraExpr ParseMultiplicative()
        {
            var left = ParsePrimary();
            while (PeekKind() == CondTokenKind.Operator && PeekValue() is "*" or "\\" or "/" or "%")
            {
                var op = Consume().Value;
                var right = ParsePrimary();
                left = new ArithmeticExpr(op, left, right);
            }
            return left;
        }

        private YaraExpr ParsePrimary()
        {
            if (_idx >= _tokens.Count)
                throw new YaraParseException("Fin inattendue de la condition YARA.");

            var tok = _tokens[_idx];

            // Parentheses
            if (tok.Kind == CondTokenKind.Symbol && tok.Value == "(")
            {
                _idx++;
                var inner = ParseOr();
                ExpectSymbol(")");
                return inner;
            }

            // Quantifiers: any/all/none of ...
            if (tok.Kind == CondTokenKind.Word && tok.Value is "any" or "all" or "none" &&
                PeekValue(1) == "of")
            {
                var quant = Consume().Value;
                Consume(); // "of"
                return ParseOfTarget(quant, null);
            }

            // Numeric literal or "N of ..."
            if (tok.Kind == CondTokenKind.Number)
            {
                var num = ParseNumber(Consume().Value);
                if (PeekKind() == CondTokenKind.Word && PeekValue() == "of")
                {
                    Consume(); // "of"
                    return ParseOfTarget("count", num);
                }
                return new ConstIntExpr(num);
            }

            // String identifier: $a, $a at offset, $a in (a..b)
            if (tok.Kind == CondTokenKind.StringRef)
            {
                var id = Consume().Value;
                if (MatchKeyword("at"))
                {
                    var offsetExpr = ParseAdditive();
                    return new StringAtExpr(id, offsetExpr);
                }
                if (MatchKeyword("in"))
                {
                    ExpectSymbol("(");
                    var minExpr = ParseAdditive();
                    ExpectSymbol("..");
                    var maxExpr = ParseAdditive();
                    ExpectSymbol(")");
                    return new StringInRangeExpr(id, minExpr, maxExpr);
                }
                return new StringPresentExpr(id);
            }

            // String count (#a), offset (@a / @a[i]), length (!a / !a[i])
            if (tok.Kind == CondTokenKind.StringCount)
            {
                var id = "$" + Consume().Value.Substring(1);
                return new StringCountExpr(id);
            }
            if (tok.Kind == CondTokenKind.StringOffset)
            {
                var id = "$" + Consume().Value.Substring(1);
                YaraExpr? indexExpr = null;
                if (PeekKind() == CondTokenKind.Symbol && PeekValue() == "[")
                {
                    Consume();
                    indexExpr = ParseAdditive();
                    ExpectSymbol("]");
                }
                return new StringOffsetExpr(id, indexExpr);
            }
            if (tok.Kind == CondTokenKind.StringLength)
            {
                var id = "$" + Consume().Value.Substring(1);
                YaraExpr? indexExpr = null;
                if (PeekKind() == CondTokenKind.Symbol && PeekValue() == "[")
                {
                    Consume();
                    indexExpr = ParseAdditive();
                    ExpectSymbol("]");
                }
                return new StringLengthExpr(id, indexExpr);
            }

            if (tok.Kind == CondTokenKind.Word)
            {
                var word = Consume().Value;
                switch (word)
                {
                    case "true": return new ConstIntExpr(1);
                    case "false": return new ConstIntExpr(0);
                    case "filesize": return new FileSizeExpr();
                    case "uint8" or "int8" or "uint16" or "int16" or "uint16be" or "uint32" or "int32" or "uint32be":
                        ExpectSymbol("(");
                        var arg = ParseAdditive();
                        ExpectSymbol(")");
                        return new ByteReadExpr(word, arg);
                    default:
                        return new RuleRefExpr(word);
                }
            }

            throw new YaraParseException($"Jeton inattendu '{tok.Value}' dans la condition YARA.");
        }

        private YaraExpr ParseOfTarget(string quantifier, long? count)
        {
            if (MatchKeyword("them"))
                return new QuantifierOfExpr(quantifier, count, null);

            ExpectSymbol("(");
            var patterns = new List<string>();
            while (_idx < _tokens.Count)
            {
                var t = Consume();
                if (t.Kind != CondTokenKind.StringRef)
                    throw new YaraParseException($"Motif de chaine attendu dans 'of (...)', trouve '{t.Value}'.");
                patterns.Add(t.Value);

                if (PeekKind() == CondTokenKind.Symbol && PeekValue() == ",")
                {
                    Consume();
                    continue;
                }
                break;
            }
            ExpectSymbol(")");
            return new QuantifierOfExpr(quantifier, count, patterns);
        }

        private static long ParseNumber(string raw)
        {
            long multiplier = 1;
            var s = raw;
            if (s.EndsWith("KB", StringComparison.OrdinalIgnoreCase))
            {
                multiplier = 1024;
                s = s.Substring(0, s.Length - 2);
            }
            else if (s.EndsWith("MB", StringComparison.OrdinalIgnoreCase))
            {
                multiplier = 1024 * 1024;
                s = s.Substring(0, s.Length - 2);
            }

            if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                return Convert.ToInt64(s.Substring(2), 16) * multiplier;

            return long.Parse(s, CultureInfo.InvariantCulture) * multiplier;
        }

        private CondTokenKind PeekKind(int offset = 0) =>
            _idx + offset < _tokens.Count ? _tokens[_idx + offset].Kind : CondTokenKind.Eof;

        private string PeekValue(int offset = 0) =>
            _idx + offset < _tokens.Count ? _tokens[_idx + offset].Value : string.Empty;

        private CondToken Consume() => _tokens[_idx++];

        private bool MatchKeyword(string kw)
        {
            if (_idx < _tokens.Count && _tokens[_idx].Kind == CondTokenKind.Word && _tokens[_idx].Value == kw)
            {
                _idx++;
                return true;
            }
            return false;
        }

        private void ExpectSymbol(string sym)
        {
            if (_idx >= _tokens.Count || _tokens[_idx].Value != sym)
                throw new YaraParseException($"Symbole '{sym}' attendu dans la condition YARA.");
            _idx++;
        }

        private static List<CondToken> Tokenize(string s)
        {
            var tokens = new List<CondToken>();
            var i = 0;
            while (i < s.Length)
            {
                var c = s[i];
                if (char.IsWhiteSpace(c)) { i++; continue; }
                if (c == '/' && i + 1 < s.Length && s[i + 1] == '/')
                {
                    i += 2;
                    while (i < s.Length && s[i] != '\n') i++;
                    continue;
                }
                if (c == '/' && i + 1 < s.Length && s[i + 1] == '*')
                {
                    i += 2;
                    while (i + 1 < s.Length && !(s[i] == '*' && s[i + 1] == '/')) i++;
                    i = Math.Min(i + 2, s.Length);
                    continue;
                }

                if (c == '.' && i + 1 < s.Length && s[i + 1] == '.')
                {
                    tokens.Add(new CondToken(CondTokenKind.Symbol, ".."));
                    i += 2;
                    continue;
                }
                if (c is '(' or ')' or '[' or ']' or ',')
                {
                    tokens.Add(new CondToken(CondTokenKind.Symbol, c.ToString()));
                    i++;
                    continue;
                }
                if (i + 1 < s.Length && s.Substring(i, 2) is "==" or "!=" or "<=" or ">=")
                {
                    tokens.Add(new CondToken(CondTokenKind.Operator, s.Substring(i, 2)));
                    i += 2;
                    continue;
                }
                if (c is '<' or '>' or '+' or '-' or '*' or '\\' or '/' or '%')
                {
                    tokens.Add(new CondToken(CondTokenKind.Operator, c.ToString()));
                    i++;
                    continue;
                }
                if (c is '$' or '#' or '@' or '!')
                {
                    var start = i;
                    i++;
                    while (i < s.Length && (char.IsLetterOrDigit(s[i]) || s[i] == '_' || (c == '$' && s[i] == '*')))
                        i++;
                    var val = s.Substring(start, i - start);
                    var kind = c switch
                    {
                        '$' => CondTokenKind.StringRef,
                        '#' => CondTokenKind.StringCount,
                        '@' => CondTokenKind.StringOffset,
                        '!' => CondTokenKind.StringLength,
                        _ => CondTokenKind.StringRef
                    };
                    tokens.Add(new CondToken(kind, val));
                    continue;
                }
                if (char.IsDigit(c))
                {
                    var start = i;
                    if (c == '0' && i + 1 < s.Length && (s[i + 1] == 'x' || s[i + 1] == 'X'))
                    {
                        i += 2;
                        while (i < s.Length && Uri.IsHexDigit(s[i])) i++;
                    }
                    else
                    {
                        while (i < s.Length && char.IsDigit(s[i])) i++;
                        if (i + 1 < s.Length &&
                            ((s[i] is 'K' or 'k' or 'M' or 'm') && (s[i + 1] is 'B' or 'b')))
                        {
                            i += 2;
                        }
                    }
                    tokens.Add(new CondToken(CondTokenKind.Number, s.Substring(start, i - start)));
                    continue;
                }
                if (char.IsLetter(c) || c == '_')
                {
                    var start = i;
                    while (i < s.Length && (char.IsLetterOrDigit(s[i]) || s[i] == '_')) i++;
                    tokens.Add(new CondToken(CondTokenKind.Word, s.Substring(start, i - start)));
                    continue;
                }

                throw new YaraParseException($"Caractere inattendu '{c}' dans la condition YARA.");
            }
            return tokens;
        }

        private enum CondTokenKind
        {
            Word, Number, StringRef, StringCount, StringOffset, StringLength, Operator, Symbol, Eof
        }

        private readonly record struct CondToken(CondTokenKind Kind, string Value);
    }
}
