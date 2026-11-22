using YamlDotNet.Core;
using YamlDotNet.RepresentationModel;

namespace Sentinel.Detection.Sigma;

/// <summary>
/// Parseur natif de regles Sigma au format YAML base sur <c>YamlDotNet</c>.
/// Pre-compile l'AST de condition, les expressions regulieres (timeout 100 ms),
/// les variantes <c>windash</c>, les encodages <c>base64</c>/<c>base64offset</c> et les plages <c>cidr</c>.
/// </summary>
public sealed class SigmaRuleParser
{
    private static readonly Dictionary<string, SigmaFieldModifiers> ModifierMap =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["contains"] = SigmaFieldModifiers.Contains,
            ["startswith"] = SigmaFieldModifiers.StartsWith,
            ["endswith"] = SigmaFieldModifiers.EndsWith,
            ["re"] = SigmaFieldModifiers.Regex,
            ["all"] = SigmaFieldModifiers.All,
            ["windash"] = SigmaFieldModifiers.WinDash,
            ["base64"] = SigmaFieldModifiers.Base64,
            ["base64offset"] = SigmaFieldModifiers.Base64Offset,
            ["cased"] = SigmaFieldModifiers.Cased,
            ["cidr"] = SigmaFieldModifiers.Cidr,
            ["wide"] = SigmaFieldModifiers.Wide,
            ["utf16le"] = SigmaFieldModifiers.Wide,
            ["utf16"] = SigmaFieldModifiers.Wide,
            ["utf16be"] = SigmaFieldModifiers.Utf16Be,
            ["exists"] = SigmaFieldModifiers.Exists,
            ["gt"] = SigmaFieldModifiers.GreaterThan,
            ["gte"] = SigmaFieldModifiers.GreaterOrEqual,
            ["lt"] = SigmaFieldModifiers.LessThan,
            ["lte"] = SigmaFieldModifiers.LessOrEqual
        };

    /// <summary>Parse une regle Sigma unique depuis une chaine YAML.</summary>
    public SigmaRule Parse(string yamlContent, string sourceFile = "<memory>")
    {
        var rules = ParseAll(yamlContent, sourceFile);
        if (rules.Count == 0)
            throw new SigmaParseException($"Aucune regle Sigma valide trouvee dans '{sourceFile}'.");
        return rules[0];
    }

    /// <summary>Parse une ou plusieurs regles Sigma (fichiers YAML multi-documents compris).</summary>
    public IReadOnlyList<SigmaRule> ParseAll(string yamlContent, string sourceFile = "<memory>")
    {
        if (string.IsNullOrWhiteSpace(yamlContent))
            throw new SigmaParseException($"Contenu YAML vide dans '{sourceFile}'.");

        var stream = new YamlStream();
        try
        {
            using var reader = new StringReader(yamlContent);
            stream.Load(reader);
        }
        catch (YamlException ex)
        {
            throw new SigmaParseException($"Erreur de syntaxe YAML dans '{sourceFile}' : {ex.Message}", ex);
        }

        if (stream.Documents.Count == 0)
            throw new SigmaParseException($"Aucun document YAML dans '{sourceFile}'.");

        YamlMappingNode? globalHeader = null;
        var parsedRules = new List<SigmaRule>(stream.Documents.Count);
        var docIndex = 0;

        foreach (var doc in stream.Documents)
        {
            docIndex++;
            if (doc.RootNode is not YamlMappingNode root || root.Children.Count == 0)
                continue;

            var action = GetScalarString(root, "action");
            if (action is not null && action.Equals("global", StringComparison.OrdinalIgnoreCase))
            {
                globalHeader = root;
                continue;
            }

            if (action is not null && action.Equals("reset", StringComparison.OrdinalIgnoreCase))
            {
                globalHeader = null;
                continue;
            }

            // Ignorer les documents de correlation Sigma (ne contenant pas de bloc detection)
            if (GetChild(root, "correlation") is not null && GetChild(root, "detection") is null)
                continue;

            var effectiveRoot = globalHeader is not null ? MergeMappings(globalHeader, root) : root;
            var rule = ParseSingleDocument(effectiveRoot, sourceFile, docIndex);
            parsedRules.Add(rule);
        }

        if (parsedRules.Count == 0)
            throw new SigmaParseException($"Aucune regle Sigma exploitable dans '{sourceFile}'.");

        return parsedRules;
    }

    /// <summary>Parse un fichier YAML depuis le disque.</summary>
    public IReadOnlyList<SigmaRule> ParseFile(string filePath)
    {
        var content = File.ReadAllText(filePath);
        return ParseAll(content, filePath);
    }

    private static SigmaRule ParseSingleDocument(YamlMappingNode root, string sourceFile, int docIndex)
    {
        var title = GetScalarString(root, "title");
        if (string.IsNullOrWhiteSpace(title))
            throw new SigmaParseException($"Champ obligatoire 'title' manquant dans '{sourceFile}'.");

        var id = GetScalarString(root, "id");
        if (string.IsNullOrWhiteSpace(id))
        {
            var baseName = Path.GetFileNameWithoutExtension(sourceFile);
            id = docIndex == 1 && !string.IsNullOrWhiteSpace(baseName)
                ? $"sigma-{baseName}"
                : $"sigma-{baseName}-{docIndex}";
        }

        var status = GetScalarString(root, "status") ?? "experimental";
        var description = GetScalarString(root, "description") ?? string.Empty;
        var author = GetScalarString(root, "author") ?? string.Empty;
        var license = GetScalarString(root, "license") ?? string.Empty;
        var level = SigmaLevels.Normalize(GetScalarString(root, "level"));
        var logSource = ParseLogSource(GetChild(root, "logsource") as YamlMappingNode);
        var tags = ParseStringList(GetChild(root, "tags"));
        var references = ParseStringList(GetChild(root, "references"));
        var falsePositives = ParseStringList(GetChild(root, "falsepositives"));
        var (mitreTechniques, mitreTactics) = SigmaRule.ExtractMitreFromTags(tags);

        if (GetChild(root, "detection") is not YamlMappingNode detectionNode)
            throw new SigmaParseException($"Bloc obligatoire 'detection' manquant dans '{sourceFile}'.");

        var (selections, orderedNames, indicesByName, conditionText) = ParseDetection(detectionNode, sourceFile);
        var conditionAst = SigmaConditionParser.Parse(conditionText, indicesByName, orderedNames);

        var indexedSelections = new SigmaSelection[orderedNames.Count];
        for (var i = 0; i < orderedNames.Count; i++)
            indexedSelections[i] = selections[orderedNames[i]];

        return new SigmaRule
        {
            Id = id.Trim(),
            Title = title.Trim(),
            Status = status.Trim(),
            Description = description.Trim(),
            Author = author.Trim(),
            License = license.Trim(),
            Level = level,
            LogSource = logSource,
            Tags = tags,
            MitreTechniques = mitreTechniques,
            MitreTactics = mitreTactics,
            References = references,
            FalsePositives = falsePositives,
            Selections = selections,
            Condition = conditionText,
            ConditionAst = conditionAst,
            IndexedSelections = indexedSelections,
            SourceFile = sourceFile,
            Enabled = true
        };
    }

    private static SigmaLogSource ParseLogSource(YamlMappingNode? node)
    {
        if (node is null)
            return new SigmaLogSource(null, null, null);

        return new SigmaLogSource(
            GetScalarString(node, "category")?.Trim(),
            GetScalarString(node, "product")?.Trim(),
            GetScalarString(node, "service")?.Trim());
    }

    private static (
        Dictionary<string, SigmaSelection> Selections,
        List<string> OrderedNames,
        Dictionary<string, int> IndicesByName,
        string Condition) ParseDetection(YamlMappingNode detectionNode, string sourceFile)
    {
        string? condition = null;
        var selections = new Dictionary<string, SigmaSelection>(StringComparer.OrdinalIgnoreCase);
        var orderedNames = new List<string>();
        var indicesByName = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in detectionNode.Children)
        {
            if (entry.Key is not YamlScalarNode keyScalar || string.IsNullOrWhiteSpace(keyScalar.Value))
                continue;

            var key = keyScalar.Value.Trim();

            if (key.Equals("condition", StringComparison.OrdinalIgnoreCase))
            {
                condition = ParseConditionValue(entry.Value, sourceFile);
                continue;
            }

            if (key.Equals("timeframe", StringComparison.OrdinalIgnoreCase))
                continue;

            var selection = ParseSelection(key, entry.Value, sourceFile);
            if (!selections.ContainsKey(key))
            {
                indicesByName[key] = orderedNames.Count;
                orderedNames.Add(key);
            }
            selections[key] = selection;
        }

        if (string.IsNullOrWhiteSpace(condition))
            throw new SigmaParseException($"Champ obligatoire 'detection.condition' manquant dans '{sourceFile}'.");

        if (selections.Count == 0)
            throw new SigmaParseException($"Aucune selection definie dans 'detection' pour '{sourceFile}'.");

        return (selections, orderedNames, indicesByName, condition);
    }

    private static string ParseConditionValue(YamlNode node, string sourceFile)
    {
        if (node is YamlScalarNode scalar && !string.IsNullOrWhiteSpace(scalar.Value))
            return scalar.Value.Trim();

        if (node is YamlSequenceNode seq && seq.Children.Count > 0)
        {
            var parts = new List<string>(seq.Children.Count);
            foreach (var item in seq.Children)
            {
                if (item is YamlScalarNode s && !string.IsNullOrWhiteSpace(s.Value))
                    parts.Add($"({s.Value.Trim()})");
            }
            if (parts.Count > 0)
                return string.Join(" or ", parts);
        }

        throw new SigmaParseException($"Condition invalide dans '{sourceFile}'.");
    }

    private static SigmaSelection ParseSelection(string name, YamlNode node, string sourceFile)
    {
        // Forme 1 : dictionnaire de champs (AND entre champs)
        if (node is YamlMappingNode mapNode)
        {
            var group = ParseFieldGroup(mapNode, sourceFile);
            return new SigmaSelection(name, fieldGroups: [group]);
        }

        // Forme 2 : liste de dictionnaires (OR de AND) OU liste de mots-cles scalaires (OR)
        if (node is YamlSequenceNode seqNode)
        {
            var groups = new List<SigmaFieldGroup>();
            var keywords = new List<SigmaValueMatcher>();

            foreach (var item in seqNode.Children)
            {
                if (item is YamlMappingNode itemMap)
                {
                    groups.Add(ParseFieldGroup(itemMap, sourceFile));
                }
                else if (item is YamlScalarNode itemScalar)
                {
                    var val = ExtractScalarValue(itemScalar);
                    if (val is not null)
                        keywords.Add(SigmaValueMatcher.Compile(val, SigmaFieldModifiers.Contains));
                }
            }

            if (groups.Count == 0 && keywords.Count == 0)
                throw new SigmaParseException($"Selection vide '{name}' dans '{sourceFile}'.");

            return new SigmaSelection(name, fieldGroups: groups, keywordMatchers: keywords);
        }

        // Forme 3 : scalaire unique traite comme mot-cle
        if (node is YamlScalarNode singleScalar)
        {
            var val = ExtractScalarValue(singleScalar);
            if (val is not null)
            {
                return new SigmaSelection(
                    name,
                    keywordMatchers: [SigmaValueMatcher.Compile(val, SigmaFieldModifiers.Contains)]);
            }
        }

        throw new SigmaParseException($"Format de selection non pris en charge pour '{name}' dans '{sourceFile}'.");
    }

    private static SigmaFieldGroup ParseFieldGroup(YamlMappingNode mapNode, string sourceFile)
    {
        var fieldMatchers = new List<SigmaFieldMatcher>(mapNode.Children.Count);

        foreach (var kv in mapNode.Children)
        {
            if (kv.Key is not YamlScalarNode keyScalar || string.IsNullOrWhiteSpace(keyScalar.Value))
                continue;

            var (fieldName, modifiers) = ParseFieldAndModifiers(keyScalar.Value.Trim(), sourceFile);
            var valueMatchers = ParseFieldValues(kv.Value, modifiers, sourceFile);
            fieldMatchers.Add(new SigmaFieldMatcher(fieldName, modifiers, valueMatchers));
        }

        if (fieldMatchers.Count == 0)
            throw new SigmaParseException($"Dictionnaire de selection vide dans '{sourceFile}'.");

        return new SigmaFieldGroup(fieldMatchers);
    }

    private static (string FieldName, SigmaFieldModifiers Modifiers) ParseFieldAndModifiers(
        string rawKey,
        string sourceFile)
    {
        var pipeIdx = rawKey.IndexOf('|');
        if (pipeIdx < 0)
            return (rawKey, SigmaFieldModifiers.None);

        var parts = rawKey.Split('|');
        var fieldName = parts[0].Trim();
        var modifiers = SigmaFieldModifiers.None;

        for (var i = 1; i < parts.Length; i++)
        {
            var modName = parts[i].Trim();
            if (modName.Length == 0)
                continue;

            if (!ModifierMap.TryGetValue(modName, out var flag))
                throw new SigmaParseException($"Modificateur Sigma inconnu '|{modName}' sur le champ '{rawKey}' dans '{sourceFile}'.");

            modifiers |= flag;
        }

        return (fieldName, modifiers);
    }

    private static IReadOnlyList<SigmaValueMatcher> ParseFieldValues(
        YamlNode valueNode,
        SigmaFieldModifiers modifiers,
        string sourceFile)
    {
        if (valueNode is YamlScalarNode scalar)
        {
            var val = ExtractScalarValue(scalar);
            return [SigmaValueMatcher.Compile(val, modifiers)];
        }

        if (valueNode is YamlSequenceNode seq)
        {
            if (seq.Children.Count == 0)
                throw new SigmaParseException($"Liste de valeurs vide dans '{sourceFile}'.");

            var list = new List<SigmaValueMatcher>(seq.Children.Count);
            foreach (var child in seq.Children)
            {
                if (child is YamlScalarNode childScalar)
                {
                    var val = ExtractScalarValue(childScalar);
                    list.Add(SigmaValueMatcher.Compile(val, modifiers));
                }
                else
                {
                    throw new SigmaParseException(
                        $"Valeur non scalaire dans une liste de criteres dans '{sourceFile}'.");
                }
            }
            return list;
        }

        throw new SigmaParseException($"Valeur de champ non prise en charge dans '{sourceFile}'.");
    }

    private static string? ExtractScalarValue(YamlScalarNode scalar)
    {
        if (scalar.Style == ScalarStyle.Plain)
        {
            if (scalar.Value is null ||
                scalar.Value == "~" ||
                scalar.Value.Equals("null", StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }
        }
        return scalar.Value ?? string.Empty;
    }

    private static YamlNode? GetChild(YamlMappingNode map, string key)
    {
        foreach (var kv in map.Children)
        {
            if (kv.Key is YamlScalarNode s &&
                s.Value is not null &&
                s.Value.Equals(key, StringComparison.OrdinalIgnoreCase))
            {
                return kv.Value;
            }
        }
        return null;
    }

    private static string? GetScalarString(YamlMappingNode map, string key)
    {
        var child = GetChild(map, key);
        return child is YamlScalarNode scalar ? ExtractScalarValue(scalar) : null;
    }

    private static IReadOnlyList<string> ParseStringList(YamlNode? node)
    {
        if (node is null)
            return Array.Empty<string>();

        if (node is YamlScalarNode single && !string.IsNullOrWhiteSpace(single.Value))
            return [single.Value.Trim()];

        if (node is YamlSequenceNode seq && seq.Children.Count > 0)
        {
            var list = new List<string>(seq.Children.Count);
            foreach (var item in seq.Children)
            {
                if (item is YamlScalarNode s && !string.IsNullOrWhiteSpace(s.Value))
                    list.Add(s.Value.Trim());
            }
            return list.Count == 0 ? Array.Empty<string>() : list.ToArray();
        }

        return Array.Empty<string>();
    }

    private static YamlMappingNode MergeMappings(YamlMappingNode baseNode, YamlMappingNode overlayNode)
    {
        var merged = new YamlMappingNode();
        var keys = new Dictionary<string, YamlNode>(StringComparer.OrdinalIgnoreCase);

        foreach (var kv in baseNode.Children)
        {
            if (kv.Key is YamlScalarNode ks && ks.Value is not null &&
                !ks.Value.Equals("action", StringComparison.OrdinalIgnoreCase))
            {
                keys[ks.Value] = kv.Value;
            }
        }

        foreach (var kv in overlayNode.Children)
        {
            if (kv.Key is YamlScalarNode ks && ks.Value is not null)
            {
                if (keys.TryGetValue(ks.Value, out var existing) &&
                    existing is YamlMappingNode existingMap &&
                    kv.Value is YamlMappingNode overlayMap)
                {
                    keys[ks.Value] = MergeMappings(existingMap, overlayMap);
                }
                else
                {
                    keys[ks.Value] = kv.Value;
                }
            }
        }

        foreach (var kv in keys)
            merged.Add(new YamlScalarNode(kv.Key), kv.Value);

        return merged;
    }
}
