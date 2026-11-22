using System.Runtime.CompilerServices;

namespace Sentinel.Detection.Sigma;

/// <summary>
/// Automate multi-motifs Aho-Corasick insensible a la casse, optimise sans allocation sur le chemin chaud.
/// Permet de pre-filtrer des milliers de regles Sigma en un seul passage O(n) sur les champs d'un evenement.
/// </summary>
internal sealed class AhoCorasickAutomaton
{
    private const int AsciiTableThreshold = 6;

    private struct Node
    {
        public int[]? AsciiTable;      // Table directe 0..127 pour les noeuds a fort degre (ex. racine)
        public char[]? SmallKeys;      // Transitions compactes pour les noeuds a faible degre
        public int[]? SmallTargets;
        public Dictionary<char, int>? NonAscii;
        public int Fail;
        public int OutputOffset;
        public int OutputCount;
    }

    private readonly Node[] _nodes;
    private readonly int[] _outputs;

    public bool IsEmpty => _outputs.Length == 0;

    private AhoCorasickAutomaton(Node[] nodes, int[] outputs)
    {
        _nodes = nodes;
        _outputs = outputs;
    }

    /// <summary>Construit un automate Aho-Corasick a partir des paires (ancre en minuscules, index de regle).</summary>
    public static AhoCorasickAutomaton Build(IReadOnlyList<(string Pattern, int RuleIndex)> entries)
    {
        if (entries.Count == 0)
            return new AhoCorasickAutomaton([new Node()], Array.Empty<int>());

        var builders = new List<BuilderNode>(entries.Count * 6) { new() };

        // 1. Insertion des motifs dans le trie
        for (var i = 0; i < entries.Count; i++)
        {
            var (pattern, ruleIdx) = entries[i];
            if (string.IsNullOrEmpty(pattern))
                continue;

            var current = 0;
            for (var cIdx = 0; cIdx < pattern.Length; cIdx++)
            {
                var ch = FastToLower(pattern[cIdx]);
                var node = builders[current];
                if (!node.Children.TryGetValue(ch, out var next))
                {
                    next = builders.Count;
                    node.Children[ch] = next;
                    builders.Add(new BuilderNode());
                }
                current = next;
            }

            builders[current].Outputs ??= new List<int>(2);
            if (!builders[current].Outputs!.Contains(ruleIdx))
                builders[current].Outputs!.Add(ruleIdx);
        }

        // 2. Calcul des liens d'echec (BFS) et aplatissement des sorties
        var queue = new Queue<int>(builders.Count);
        foreach (var child in builders[0].Children.Values)
        {
            builders[child].Fail = 0;
            queue.Enqueue(child);
        }

        while (queue.Count > 0)
        {
            var state = queue.Dequeue();
            var stateNode = builders[state];

            foreach (var kv in stateNode.Children)
            {
                var ch = kv.Key;
                var nextState = kv.Value;
                queue.Enqueue(nextState);

                var fail = stateNode.Fail;
                while (fail != 0 && !builders[fail].Children.ContainsKey(ch))
                    fail = builders[fail].Fail;

                if (builders[fail].Children.TryGetValue(ch, out var failTarget))
                    builders[nextState].Fail = failTarget;
                else
                    builders[nextState].Fail = 0;

                var failOutputs = builders[builders[nextState].Fail].Outputs;
                if (failOutputs is { Count: > 0 })
                {
                    builders[nextState].Outputs ??= new List<int>(failOutputs.Count);
                    var targetList = builders[nextState].Outputs!;
                    for (var k = 0; k < failOutputs.Count; k++)
                    {
                        var r = failOutputs[k];
                        if (!targetList.Contains(r))
                            targetList.Add(r);
                    }
                }
            }
        }

        // 3. Compactage en tableaux plats pour des lectures rapides en cache L1/L2
        var finalNodes = new Node[builders.Count];
        var flatOutputs = new List<int>(entries.Count * 2);

        for (var i = 0; i < builders.Count; i++)
        {
            var b = builders[i];
            ref var n = ref finalNodes[i];
            n.Fail = b.Fail;

            if (b.Outputs is { Count: > 0 })
            {
                n.OutputOffset = flatOutputs.Count;
                n.OutputCount = b.Outputs.Count;
                flatOutputs.AddRange(b.Outputs);
            }

            if (b.Children.Count == 0)
                continue;

            var asciiCount = 0;
            foreach (var ch in b.Children.Keys)
            {
                if (ch < 128) asciiCount++;
            }

            if (i == 0 || asciiCount >= AsciiTableThreshold)
            {
                var table = new int[128];
                Array.Fill(table, -1);
                Dictionary<char, int>? nonAscii = null;

                foreach (var kv in b.Children)
                {
                    if (kv.Key < 128)
                    {
                        table[kv.Key] = kv.Value;
                    }
                    else
                    {
                        nonAscii ??= new Dictionary<char, int>();
                        nonAscii[kv.Key] = kv.Value;
                    }
                }

                n.AsciiTable = table;
                n.NonAscii = nonAscii;
            }
            else
            {
                var keys = new char[b.Children.Count];
                var targets = new int[b.Children.Count];
                var idx = 0;
                foreach (var kv in b.Children)
                {
                    keys[idx] = kv.Key;
                    targets[idx] = kv.Value;
                    idx++;
                }
                n.SmallKeys = keys;
                n.SmallTargets = targets;
            }
        }

        return new AhoCorasickAutomaton(finalNodes, flatOutputs.ToArray());
    }

    /// <summary>
    /// Parcourt <paramref name="text"/> en minuscules a la volee (0 allocation) et active le bit
    /// de chaque regle candidate dans <paramref name="candidateBitset"/>.
    /// </summary>
    public void Scan(ReadOnlySpan<char> text, Span<ulong> candidateBitset)
    {
        if (text.IsEmpty || _outputs.Length == 0)
            return;

        var nodes = _nodes;
        var outputs = _outputs;
        var state = 0;

        for (var i = 0; i < text.Length; i++)
        {
            var ch = FastToLower(text[i]);

            while (true)
            {
                var next = TryTransition(in nodes[state], ch);
                if (next >= 0)
                {
                    state = next;
                    break;
                }

                if (state == 0)
                    break;

                state = nodes[state].Fail;
            }

            var outCount = nodes[state].OutputCount;
            if (outCount > 0)
            {
                var offset = nodes[state].OutputOffset;
                for (var k = 0; k < outCount; k++)
                {
                    var ruleIdx = outputs[offset + k];
                    candidateBitset[ruleIdx >> 6] |= 1UL << (ruleIdx & 63);
                }
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int TryTransition(in Node node, char ch)
    {
        if (node.AsciiTable is not null)
        {
            if (ch < 128)
                return node.AsciiTable[ch];
            if (node.NonAscii is not null && node.NonAscii.TryGetValue(ch, out var target))
                return target;
            return -1;
        }

        var keys = node.SmallKeys;
        if (keys is not null)
        {
            for (var i = 0; i < keys.Length; i++)
            {
                if (keys[i] == ch)
                    return node.SmallTargets![i];
            }
        }

        return -1;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static char FastToLower(char c)
    {
        if ((uint)(c - 'A') <= ('Z' - 'A'))
            return (char)(c + 32);
        return c < 128 ? c : char.ToLowerInvariant(c);
    }

    private sealed class BuilderNode
    {
        public Dictionary<char, int> Children { get; } = new();
        public int Fail { get; set; }
        public List<int>? Outputs { get; set; }
    }
}

/// <summary>
/// Analyse statiquement l'AST d'une <see cref="SigmaRule"/> pour extraire un ensemble necessaire
/// d'ancres litterales garantissant zero faux negatif lors du pre-filtrage Aho-Corasick.
/// </summary>
internal static class SigmaAnchorExtractor
{
    private const int MaxAnchorsPerRule = 64;

    public static string[]? ExtractRuleAnchors(SigmaRule rule) =>
        ExtractFromNode(rule.ConditionAst, rule.IndexedSelections);

    private static string[]? ExtractFromNode(SigmaConditionNode node, SigmaSelection[] selections)
    {
        switch (node)
        {
            case SelectionRefNode selRef:
                return selections[selRef.SelectionIndex].ExtractNecessaryAnchors();

            case NotConditionNode:
                // Une negation n'impose aucune sous-chaine positive
                return null;

            case AndConditionNode andNode:
            {
                var left = ExtractFromNode(andNode.Left, selections);
                var right = ExtractFromNode(andNode.Right, selections);
                if (left is null) return right;
                if (right is null) return left;
                return PickMoreSelective(left, right);
            }

            case OrConditionNode orNode:
            {
                var left = ExtractFromNode(orNode.Left, selections);
                var right = ExtractFromNode(orNode.Right, selections);
                if (left is null || right is null)
                    return null;
                return UnionAnchors(left, right);
            }

            case QuantifierConditionNode quant:
            {
                var indices = quant.SelectionIndices;
                if (indices.Length == 0)
                    return null;

                if (quant.RequireAll || quant.RequiredCount >= indices.Length)
                {
                    // Equivalent a un AND sur toutes les selections du quantificateur
                    string[]? best = null;
                    for (var i = 0; i < indices.Length; i++)
                    {
                        var anchors = selections[indices[i]].ExtractNecessaryAnchors();
                        if (anchors is null || anchors.Length == 0)
                            continue;
                        best = best is null ? anchors : PickMoreSelective(best, anchors);
                    }
                    return best;
                }

                // 1 of / k of : l'union des ancres de toutes les branches est une condition necessaire sure
                var union = new HashSet<string>(StringComparer.Ordinal);
                for (var i = 0; i < indices.Length; i++)
                {
                    var anchors = selections[indices[i]].ExtractNecessaryAnchors();
                    if (anchors is null || anchors.Length == 0)
                        return null;

                    for (var j = 0; j < anchors.Length; j++)
                    {
                        union.Add(anchors[j]);
                        if (union.Count > MaxAnchorsPerRule)
                            return null;
                    }
                }
                return union.Count == 0 ? null : union.ToArray();
            }

            default:
                return null;
        }
    }

    private static string[] PickMoreSelective(string[] a, string[] b)
    {
        if (a.Length != b.Length)
            return a.Length < b.Length ? a : b;

        return MinLength(a) >= MinLength(b) ? a : b;
    }

    private static string[]? UnionAnchors(string[] a, string[] b)
    {
        var set = new HashSet<string>(a.Length + b.Length, StringComparer.Ordinal);
        for (var i = 0; i < a.Length; i++) set.Add(a[i]);
        for (var i = 0; i < b.Length; i++)
        {
            set.Add(b[i]);
            if (set.Count > MaxAnchorsPerRule)
                return null;
        }
        return set.ToArray();
    }

    private static int MinLength(string[] arr)
    {
        var min = int.MaxValue;
        for (var i = 0; i < arr.Length; i++)
        {
            if (arr[i].Length < min)
                min = arr[i].Length;
        }
        return min;
    }
}
