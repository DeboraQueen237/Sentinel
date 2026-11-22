using System.Text.RegularExpressions;

namespace Sentinel.Detection.Sigma;

/// <summary>Noeud abstrait de l'arbre syntaxique (AST) d'une expression <c>condition</c> Sigma.</summary>
public abstract class SigmaConditionNode
{
    /// <summary>Evalue ce noeud sur le contexte de selections d'un evenement avec memoisation.</summary>
    internal abstract bool Evaluate(ref SelectionEvalContext ctx);
}

/// <summary>Reference directe a une selection nommee par son index pre-resolu.</summary>
public sealed class SelectionRefNode : SigmaConditionNode
{
    public string SelectionName { get; }
    internal int SelectionIndex { get; }

    public SelectionRefNode(string selectionName, int selectionIndex)
    {
        SelectionName = selectionName;
        SelectionIndex = selectionIndex;
    }

    internal override bool Evaluate(ref SelectionEvalContext ctx) => ctx.EvaluateSelection(SelectionIndex);
}

/// <summary>Conjonction logique (<c>and</c>) avec court-circuit.</summary>
public sealed class AndConditionNode : SigmaConditionNode
{
    public SigmaConditionNode Left { get; }
    public SigmaConditionNode Right { get; }

    public AndConditionNode(SigmaConditionNode left, SigmaConditionNode right)
    {
        Left = left;
        Right = right;
    }

    internal override bool Evaluate(ref SelectionEvalContext ctx) =>
        Left.Evaluate(ref ctx) && Right.Evaluate(ref ctx);
}

/// <summary>Disjonction logique (<c>or</c>) avec court-circuit.</summary>
public sealed class OrConditionNode : SigmaConditionNode
{
    public SigmaConditionNode Left { get; }
    public SigmaConditionNode Right { get; }

    public OrConditionNode(SigmaConditionNode left, SigmaConditionNode right)
    {
        Left = left;
        Right = right;
    }

    internal override bool Evaluate(ref SelectionEvalContext ctx) =>
        Left.Evaluate(ref ctx) || Right.Evaluate(ref ctx);
}

/// <summary>Negation logique (<c>not</c>).</summary>
public sealed class NotConditionNode : SigmaConditionNode
{
    public SigmaConditionNode Operand { get; }

    public NotConditionNode(SigmaConditionNode operand)
    {
        Operand = operand;
    }

    internal override bool Evaluate(ref SelectionEvalContext ctx) => !Operand.Evaluate(ref ctx);
}

/// <summary>
/// Quantificateur Sigma (<c>1 of selection*</c>, <c>all of selection*</c>, <c>1 of them</c>,
/// <c>all of them</c>, <c>N of pattern</c>).
/// </summary>
public sealed class QuantifierConditionNode : SigmaConditionNode
{
    public string Pattern { get; }
    public bool RequireAll { get; }
    public int RequiredCount { get; }
    public IReadOnlyList<string> ResolvedSelections { get; }
    internal int[] SelectionIndices { get; }

    public QuantifierConditionNode(
        string pattern,
        bool requireAll,
        int requiredCount,
        IReadOnlyList<string> resolvedSelections,
        int[] selectionIndices)
    {
        Pattern = pattern;
        RequireAll = requireAll;
        RequiredCount = requiredCount;
        ResolvedSelections = resolvedSelections;
        SelectionIndices = selectionIndices;
    }

    internal override bool Evaluate(ref SelectionEvalContext ctx)
    {
        var indices = SelectionIndices;
        if (indices.Length == 0)
            return false;

        if (RequireAll)
        {
            for (var i = 0; i < indices.Length; i++)
            {
                if (!ctx.EvaluateSelection(indices[i]))
                    return false;
            }
            return true;
        }

        var target = RequiredCount;
        if (target <= 0)
            return true;
        if (target > indices.Length)
            return false;

        var matched = 0;
        for (var i = 0; i < indices.Length; i++)
        {
            if (ctx.EvaluateSelection(indices[i]))
            {
                matched++;
                if (matched >= target)
                    return true;
            }
            else if (matched + (indices.Length - i - 1) < target)
            {
                return false;
            }
        }

        return false;
    }
}

/// <summary>
/// Parseur d'AST recursif descendant pour les expressions <c>condition</c> Sigma.
/// Grammaire :
/// <code>
/// Expr       := OrExpr EOF
/// OrExpr     := AndExpr ( 'or' AndExpr )*
/// AndExpr    := NotExpr ( 'and' NotExpr )*
/// NotExpr    := 'not' NotExpr | Primary
/// Primary    := '(' OrExpr ')'
///             | ('all' | INT) 'of' ('them' | IDENT_PATTERN)
///             | IDENT_PATTERN
/// </code>
/// </summary>
public static class SigmaConditionParser
{
    private enum TokenKind
    {
        Identifier,
        Number,
        And,
        Or,
        Not,
        Of,
        All,
        Them,
        LParen,
        RParen,
        Eof
    }

    private readonly record struct Token(TokenKind Kind, string Text, int Position);

    public static SigmaConditionNode Parse(
        string condition,
        IReadOnlyDictionary<string, int> selectionIndicesByName,
        IReadOnlyList<string> orderedSelectionNames)
    {
        if (string.IsNullOrWhiteSpace(condition))
            throw new SigmaParseException("La condition Sigma est vide.");

        var tokens = Tokenize(condition);
        var state = new ParserState(tokens, selectionIndicesByName, orderedSelectionNames);
        var root = state.ParseOr();

        if (state.Current.Kind != TokenKind.Eof)
        {
            throw new SigmaParseException(
                $"Jeton inattendu '{state.Current.Text}' a la position {state.Current.Position} dans la condition '{condition}'.");
        }

        return root;
    }

    private static List<Token> Tokenize(string input)
    {
        var tokens = new List<Token>(16);
        var i = 0;
        var len = input.Length;

        while (i < len)
        {
            var c = input[i];
            if (char.IsWhiteSpace(c))
            {
                i++;
                continue;
            }

            if (c == '(')
            {
                tokens.Add(new Token(TokenKind.LParen, "(", i));
                i++;
                continue;
            }

            if (c == ')')
            {
                tokens.Add(new Token(TokenKind.RParen, ")", i));
                i++;
                continue;
            }

            if (c == '|')
            {
                throw new SigmaParseException(
                    $"Operateur d'agregation '|' non pris en charge a la position {i} dans la condition '{input}'.");
            }

            if (IsIdentChar(c))
            {
                var start = i;
                while (i < len && IsIdentChar(input[i]))
                    i++;

                var text = input[start..i];
                var kind = ClassifyWord(text);
                tokens.Add(new Token(kind, text, start));
                continue;
            }

            throw new SigmaParseException(
                $"Caractere invalide '{c}' a la position {i} dans la condition '{input}'.");
        }

        tokens.Add(new Token(TokenKind.Eof, string.Empty, len));
        return tokens;
    }

    private static bool IsIdentChar(char c) =>
        char.IsLetterOrDigit(c) || c == '_' || c == '-' || c == '.' || c == '*' || c == '?';

    private static TokenKind ClassifyWord(string text)
    {
        if (text.Equals("and", StringComparison.OrdinalIgnoreCase)) return TokenKind.And;
        if (text.Equals("or", StringComparison.OrdinalIgnoreCase)) return TokenKind.Or;
        if (text.Equals("not", StringComparison.OrdinalIgnoreCase)) return TokenKind.Not;
        if (text.Equals("of", StringComparison.OrdinalIgnoreCase)) return TokenKind.Of;
        if (text.Equals("all", StringComparison.OrdinalIgnoreCase)) return TokenKind.All;
        if (text.Equals("them", StringComparison.OrdinalIgnoreCase)) return TokenKind.Them;

        var allDigits = text.Length > 0;
        for (var i = 0; i < text.Length; i++)
        {
            if (text[i] < '0' || text[i] > '9')
            {
                allDigits = false;
                break;
            }
        }
        return allDigits ? TokenKind.Number : TokenKind.Identifier;
    }

    private sealed class ParserState
    {
        private readonly List<Token> _tokens;
        private readonly IReadOnlyDictionary<string, int> _selectionIndices;
        private readonly IReadOnlyList<string> _orderedSelectionNames;
        private int _pos;

        public ParserState(
            List<Token> tokens,
            IReadOnlyDictionary<string, int> selectionIndices,
            IReadOnlyList<string> orderedSelectionNames)
        {
            _tokens = tokens;
            _selectionIndices = selectionIndices;
            _orderedSelectionNames = orderedSelectionNames;
        }

        public Token Current => _tokens[_pos];
        private Token Peek(int offset) => _pos + offset < _tokens.Count ? _tokens[_pos + offset] : _tokens[^1];
        private Token Advance() => _tokens[_pos++];

        public SigmaConditionNode ParseOr()
        {
            var left = ParseAnd();
            while (Current.Kind == TokenKind.Or)
            {
                Advance();
                var right = ParseAnd();
                left = new OrConditionNode(left, right);
            }
            return left;
        }

        private SigmaConditionNode ParseAnd()
        {
            var left = ParseNot();
            while (Current.Kind == TokenKind.And)
            {
                Advance();
                var right = ParseNot();
                left = new AndConditionNode(left, right);
            }
            return left;
        }

        private SigmaConditionNode ParseNot()
        {
            if (Current.Kind == TokenKind.Not)
            {
                Advance();
                var operand = ParseNot();
                return new NotConditionNode(operand);
            }
            return ParsePrimary();
        }

        private SigmaConditionNode ParsePrimary()
        {
            var tok = Current;

            if (tok.Kind == TokenKind.LParen)
            {
                Advance();
                var inner = ParseOr();
                if (Current.Kind != TokenKind.RParen)
                {
                    throw new SigmaParseException(
                        $"Parenthese fermante ')' attendue a la position {Current.Position}.");
                }
                Advance();
                return inner;
            }

            // Quantificateurs : "1 of selection*", "all of selection*", "1 of them", "all of them", "2 of sel*"
            if ((tok.Kind == TokenKind.All || tok.Kind == TokenKind.Number) && Peek(1).Kind == TokenKind.Of)
            {
                Advance(); // all ou nombre
                Advance(); // of
                return ParseQuantifierTarget(tok);
            }

            // Reference directe ou motif wildcard nu (ex. "selection" ou "selection and not filter*")
            if (tok.Kind is TokenKind.Identifier or TokenKind.All or TokenKind.Them or TokenKind.Number)
            {
                Advance();
                return ResolveSelectionReference(tok.Text, tok.Position);
            }

            throw new SigmaParseException(
                $"Expression attendue a la position {tok.Position}, trouve '{tok.Text}'.");
        }

        private SigmaConditionNode ParseQuantifierTarget(Token countTok)
        {
            var targetTok = Current;
            if (targetTok.Kind is not (TokenKind.Them or TokenKind.Identifier or TokenKind.All or TokenKind.Number))
            {
                throw new SigmaParseException(
                    $"Cible de quantificateur ('them' ou motif de selection) attendue a la position {targetTok.Position}.");
            }
            Advance();

            var requireAll = countTok.Kind == TokenKind.All;
            var requiredCount = 0;
            if (!requireAll)
            {
                if (!int.TryParse(countTok.Text, out requiredCount) || requiredCount < 0)
                    throw new SigmaParseException($"Quantificateur numerique invalide '{countTok.Text}'.");
            }

            if (targetTok.Kind == TokenKind.Them)
            {
                var allNames = _orderedSelectionNames.ToArray();
                var allIndices = new int[allNames.Length];
                for (var i = 0; i < allNames.Length; i++)
                    allIndices[i] = _selectionIndices[allNames[i]];

                if (allIndices.Length == 0)
                    throw new SigmaParseException("Aucune selection definie pour 'of them'.");

                return new QuantifierConditionNode("them", requireAll, requireAll ? allIndices.Length : requiredCount, allNames, allIndices);
            }

            var (matchedNames, matchedIndices) = MatchSelectionPattern(targetTok.Text);
            if (matchedIndices.Length == 0)
            {
                throw new SigmaParseException(
                    $"Aucune selection ne correspond au motif '{targetTok.Text}' a la position {targetTok.Position}.");
            }

            return new QuantifierConditionNode(
                targetTok.Text,
                requireAll,
                requireAll ? matchedIndices.Length : requiredCount,
                matchedNames,
                matchedIndices);
        }

        private SigmaConditionNode ResolveSelectionReference(string name, int position)
        {
            if (_selectionIndices.TryGetValue(name, out var exactIdx))
                return new SelectionRefNode(name, exactIdx);

            // Supporte les motifs wildcard nus comme "selection and not filter*" (= 1 of filter*)
            if (name.Contains('*') || name.Contains('?'))
            {
                var (matchedNames, matchedIndices) = MatchSelectionPattern(name);
                if (matchedIndices.Length == 0)
                {
                    throw new SigmaParseException(
                        $"Aucune selection ne correspond au motif '{name}' a la position {position}.");
                }
                return new QuantifierConditionNode(name, requireAll: false, requiredCount: 1, matchedNames, matchedIndices);
            }

            throw new SigmaParseException(
                $"Selection inconnue '{name}' referencee dans la condition a la position {position}.");
        }

        private (string[] Names, int[] Indices) MatchSelectionPattern(string pattern)
        {
            var regexPattern = "^" + Regex.Escape(pattern).Replace(@"\*", ".*").Replace(@"\?", ".") + "$";
            var rx = new Regex(regexPattern, RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(100));

            var names = new List<string>();
            var indices = new List<int>();
            for (var i = 0; i < _orderedSelectionNames.Count; i++)
            {
                var selName = _orderedSelectionNames[i];
                if (rx.IsMatch(selName))
                {
                    names.Add(selName);
                    indices.Add(_selectionIndices[selName]);
                }
            }

            return (names.ToArray(), indices.ToArray());
        }
    }
}
