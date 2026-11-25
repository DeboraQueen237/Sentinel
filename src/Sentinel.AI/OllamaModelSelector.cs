using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Sentinel.AI;

/// <summary>Métadonnées d'un modèle Ollama installé localement (issu de <c>GET /api/tags</c>).</summary>
public sealed record OllamaInstalledModel(
    string Name,
    long SizeBytes = 0,
    string? Family = null,
    string? ParameterSize = null,
    string? QuantizationLevel = null);

/// <summary>Résultat explicable de la sélection automatique du modèle Ollama local.</summary>
public sealed record OllamaModelSelection(
    string? SelectedModel,
    bool AutoSelected,
    bool IsQwen,
    double HostRamGb,
    string Reason,
    IReadOnlyList<OllamaInstalledModel> Candidates);

/// <summary>
/// Sélectionne localement le meilleur modèle Qwen déjà installé dans Ollama en tenant compte
/// de la génération Qwen, de la taille en paramètres, de la quantification et de la RAM disponible du poste.
/// Ne télécharge JAMAIS de modèle automatiquement (100 % hors ligne).
/// </summary>
public static partial class OllamaModelSelector
{
    /// <summary>Retourne la mémoire vive disponible sur la machine hôte en Gio.</summary>
    public static double GetHostRamGb()
    {
        try
        {
            var bytes = GC.GetGCMemoryInfo().TotalAvailableMemoryBytes;
            if (bytes > 0)
            {
                return Math.Round(bytes / (1024.0 * 1024.0 * 1024.0), 1);
            }
        }
        catch
        {
            // Repli conservateur
        }

        return 8.0;
    }

    /// <summary>Parse la réponse JSON de <c>GET /api/tags</c> en liste structurée de modèles installés.</summary>
    public static IReadOnlyList<OllamaInstalledModel> ParseTagsResponse(JsonElement tagsRoot)
    {
        if (tagsRoot.ValueKind != JsonValueKind.Object ||
            !tagsRoot.TryGetProperty("models", out var modelsEl) ||
            modelsEl.ValueKind != JsonValueKind.Array)
        {
            return Array.Empty<OllamaInstalledModel>();
        }

        var list = new List<OllamaInstalledModel>();
        foreach (var item in modelsEl.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object) continue;
            var name = TryGetString(item, "name") ?? TryGetString(item, "model");
            if (string.IsNullOrWhiteSpace(name)) continue;

            long sizeBytes = 0;
            if (item.TryGetProperty("size", out var sizeEl) && sizeEl.ValueKind == JsonValueKind.Number)
            {
                sizeEl.TryGetInt64(out sizeBytes);
            }

            string? family = null;
            string? paramSize = null;
            string? quant = null;
            if (item.TryGetProperty("details", out var detailsEl) && detailsEl.ValueKind == JsonValueKind.Object)
            {
                family = TryGetString(detailsEl, "family");
                paramSize = TryGetString(detailsEl, "parameter_size");
                quant = TryGetString(detailsEl, "quantization_level");
            }

            list.Add(new OllamaInstalledModel(name.Trim(), Math.Max(0, sizeBytes), family, paramSize, quant));
        }

        return list;
    }

    /// <summary>Détermine si un modèle local appartient à la famille Qwen.</summary>
    public static bool IsQwenModel(OllamaInstalledModel model)
    {
        ArgumentNullException.ThrowIfNull(model);
        var lowerName = model.Name.ToLowerInvariant();
        var baseName = lowerName.Contains(':') ? lowerName[..lowerName.IndexOf(':')] : lowerName;
        var repoLeaf = baseName.Contains('/') ? baseName[(baseName.LastIndexOf('/') + 1)..] : baseName;

        if (repoLeaf.StartsWith("qwen", StringComparison.Ordinal) ||
            repoLeaf.StartsWith("qwq", StringComparison.Ordinal))
        {
            return true;
        }

        if (!string.IsNullOrWhiteSpace(model.Family) &&
            model.Family.StartsWith("qwen", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return false;
    }

    /// <summary>Indique si le modèle est un modèle d'embedding pur (impropre au chat/scoring JSON).</summary>
    public static bool IsEmbeddingModel(OllamaInstalledModel model)
    {
        ArgumentNullException.ThrowIfNull(model);
        var lower = model.Name.ToLowerInvariant();
        return lower.Contains("embed", StringComparison.Ordinal) ||
               lower.StartsWith("bge-", StringComparison.Ordinal) ||
               lower.Contains("/bge-", StringComparison.Ordinal) ||
               lower.StartsWith("all-minilm", StringComparison.Ordinal) ||
               lower.StartsWith("snowflake-arctic-embed", StringComparison.Ordinal);
    }

    /// <summary>
    /// Sélectionne le modèle optimal parmi ceux installés localement dans Ollama.
    /// </summary>
    public static OllamaModelSelection SelectBestModel(
        IReadOnlyList<OllamaInstalledModel> installed,
        string? configuredModel,
        bool autoSelectBestQwen,
        double hostRamGb = 0)
    {
        ArgumentNullException.ThrowIfNull(installed);

        var effectiveRamGb = hostRamGb > 0.5 ? Math.Round(hostRamGb, 1) : GetHostRamGb();
        var chatCandidates = installed.Where(m => !IsEmbeddingModel(m)).ToList();

        if (chatCandidates.Count == 0)
        {
            return new OllamaModelSelection(
                SelectedModel: null,
                AutoSelected: false,
                IsQwen: false,
                HostRamGb: effectiveRamGb,
                Reason: "Aucun modèle de chat/scoring installé localement dans Ollama.",
                Candidates: installed);
        }

        // Mode manuel : respecter strictement le modèle configuré s'il est installé
        if (!autoSelectBestQwen)
        {
            var matched = FindMatchingInstalled(chatCandidates, configuredModel);
            if (matched is not null)
            {
                return new OllamaModelSelection(
                    SelectedModel: matched.Name,
                    AutoSelected: false,
                    IsQwen: IsQwenModel(matched),
                    HostRamGb: effectiveRamGb,
                    Reason: $"Modèle configuré manuellement détecté localement ({matched.Name}).",
                    Candidates: installed);
            }

            // Repli transparent vers le meilleur modèle Qwen ou local si le modèle configuré manque
            var fallback = PickHighestRanked(chatCandidates, configuredModel, effectiveRamGb, qwenOnly: true)
                           ?? PickHighestRanked(chatCandidates, configuredModel, effectiveRamGb, qwenOnly: false);

            return new OllamaModelSelection(
                SelectedModel: fallback!.Model.Name,
                AutoSelected: true,
                IsQwen: fallback.IsQwen,
                HostRamGb: effectiveRamGb,
                Reason: $"Modèle configuré '{configuredModel}' absent ; repli automatique sur '{fallback.Model.Name}' ({fallback.Summary}).",
                Candidates: installed);
        }

        // Mode auto-sélection Qwen (par défaut) : privilégie le meilleur Qwen adapté à la RAM du poste
        var bestQwen = PickHighestRanked(chatCandidates, configuredModel, effectiveRamGb, qwenOnly: true);
        if (bestQwen is not null)
        {
            var isDifferent = string.IsNullOrWhiteSpace(configuredModel) ||
                              !MatchesModelName(bestQwen.Model.Name, configuredModel);
            var prefix = isDifferent
                ? $"Meilleur modèle Qwen local sélectionné automatiquement : {bestQwen.Model.Name}"
                : $"Modèle Qwen optimal déjà actif : {bestQwen.Model.Name}";
            return new OllamaModelSelection(
                SelectedModel: bestQwen.Model.Name,
                AutoSelected: true,
                IsQwen: true,
                HostRamGb: effectiveRamGb,
                Reason: $"{prefix} ({bestQwen.Summary}, RAM hôte {effectiveRamGb:F1} Go).",
                Candidates: installed);
        }

        // Aucun Qwen installé : si le modèle configuré est présent, le retenir ; sinon meilleur modèle local
        var configuredMatch = FindMatchingInstalled(chatCandidates, configuredModel);
        if (configuredMatch is not null)
        {
            return new OllamaModelSelection(
                SelectedModel: configuredMatch.Name,
                AutoSelected: false,
                IsQwen: false,
                HostRamGb: effectiveRamGb,
                Reason: $"Aucun modèle Qwen installé ; utilisation du modèle configuré ({configuredMatch.Name}).",
                Candidates: installed);
        }

        var bestLocal = PickHighestRanked(chatCandidates, configuredModel, effectiveRamGb, qwenOnly: false)!;
        return new OllamaModelSelection(
            SelectedModel: bestLocal.Model.Name,
            AutoSelected: true,
            IsQwen: false,
            HostRamGb: effectiveRamGb,
            Reason: $"Aucun modèle Qwen installé ; meilleur modèle local disponible sélectionné : {bestLocal.Model.Name} ({bestLocal.Summary}).",
            Candidates: installed);
    }

    /// <summary>Recommande un nom de modèle Qwen adapté à la RAM si aucun modèle n'est encore installé (sans téléchargement).</summary>
    public static string RecommendQwenForRam(double hostRamGb) =>
        hostRamGb <= 8.5 ? "qwen2.5-coder:1.5b"
        : hostRamGb <= 20.0 ? "qwen2.5-coder:3b"
        : hostRamGb <= 36.0 ? "qwen2.5:7b"
        : "qwen2.5:14b";

    /// <summary>Estime le nombre de milliards de paramètres (ex. 3.0 pour 3B, 7.6 pour 7.6B).</summary>
    public static double EstimateParametersBillions(OllamaInstalledModel model)
    {
        ArgumentNullException.ThrowIfNull(model);

        if (TryParseParamString(model.ParameterSize, out var parsedFromMeta))
        {
            return parsedFromMeta;
        }

        var tagMatch = ParamInNameRegex().Match(model.Name);
        if (tagMatch.Success &&
            double.TryParse(tagMatch.Groups[1].Value, NumberStyles.Float, CultureInfo.InvariantCulture, out var val))
        {
            var unit = tagMatch.Groups[2].Value;
            return unit.Equals("m", StringComparison.OrdinalIgnoreCase) ? val / 1000.0 : val;
        }

        if (model.SizeBytes > 0)
        {
            var gb = model.SizeBytes / (1024.0 * 1024.0 * 1024.0);
            return Math.Round(Math.Max(0.5, gb / 0.65), 1);
        }

        return 7.0;
    }

    private sealed record ScoredCandidate(OllamaInstalledModel Model, double Score, bool IsQwen, string Summary);

    private static ScoredCandidate? PickHighestRanked(
        List<OllamaInstalledModel> candidates,
        string? configuredModel,
        double hostRamGb,
        bool qwenOnly)
    {
        var pool = qwenOnly ? candidates.Where(IsQwenModel).ToList() : candidates;
        if (pool.Count == 0) return null;

        ScoredCandidate? best = null;
        foreach (var model in pool)
        {
            var scored = ScoreCandidate(model, configuredModel, hostRamGb);
            if (best is null ||
                scored.Score > best.Score ||
                (Math.Abs(scored.Score - best.Score) < 0.001 &&
                 string.CompareOrdinal(scored.Model.Name, best.Model.Name) < 0))
            {
                best = scored;
            }
        }

        return best;
    }

    private static ScoredCandidate ScoreCandidate(OllamaInstalledModel model, string? configuredModel, double hostRamGb)
    {
        var lower = model.Name.ToLowerInvariant();
        var isQwen = IsQwenModel(model);
        var paramB = EstimateParametersBillions(model);

        // Empreinte RAM estimée (poids + cache KV num_ctx=2048 + marge runtime)
        var weightGb = model.SizeBytes > 0
            ? model.SizeBytes / (1024.0 * 1024.0 * 1024.0)
            : paramB * 0.65;
        var estimatedRamGb = weightGb * 1.25 + 0.5;
        var safeBudgetGb = Math.Max(2.2, hostRamGb * 0.55);
        var hardBudgetGb = Math.Max(3.0, hostRamGb * 0.72);

        double score = 0;

        // 1. Adéquation à la RAM (évite le swap disque qui fait exploser les timeouts)
        string ramNote;
        if (estimatedRamGb <= safeBudgetGb)
        {
            score += 120;
            ramNote = "adapté à la RAM";
        }
        else if (estimatedRamGb <= hardBudgetGb)
        {
            score += 20;
            ramNote = "RAM limite";
        }
        else
        {
            score -= 120;
            ramNote = "dépasse le budget RAM recommandé";
        }

        // 2. Génération Qwen (plus récente = meilleure qualité JSON et compréhension SOC)
        if (isQwen)
        {
            score += GetQwenGenerationScore(lower);
        }

        // 3. Puissance paramétrique (plafonnée pour préserver la réactivité temps réel SOC)
        score += paramB switch
        {
            <= 0.7 => 8,
            <= 1.8 => 20,
            <= 4.2 => 34,
            <= 9.5 => 48,
            <= 16.5 => 58,
            <= 35.0 => 62,
            _ => 52
        };

        // 4. Spécialisation du variant (instruct & coder excellent sur JSON structuré + lignes de commande)
        if (lower.Contains("-vl", StringComparison.Ordinal) ||
            lower.Contains("vision", StringComparison.Ordinal) ||
            lower.Contains("audio", StringComparison.Ordinal))
        {
            score -= 18;
        }
        else if (lower.Contains("-base", StringComparison.Ordinal) || lower.EndsWith(":base", StringComparison.Ordinal))
        {
            score -= 15;
        }
        else if (lower.Contains("qwq", StringComparison.Ordinal))
        {
            // Modèle de raisonnement long : excellent mais lent pour du scoring temps réel
            score -= 10;
        }
        else if (lower.Contains("instruct", StringComparison.Ordinal))
        {
            score += 12;
        }
        else if (lower.Contains("coder", StringComparison.Ordinal))
        {
            score += 10;
        }
        else
        {
            score += 11;
        }

        // 5. Qualité de quantification
        var quant = (model.QuantizationLevel ?? string.Empty).ToUpperInvariant();
        if (quant.Contains("Q8", StringComparison.Ordinal) || quant.Contains("Q6", StringComparison.Ordinal))
            score += 5;
        else if (quant.Contains("Q5", StringComparison.Ordinal) || quant.Contains("Q4_K_M", StringComparison.Ordinal))
            score += 4;
        else if (quant.Contains("Q4", StringComparison.Ordinal))
            score += 2;
        else if (quant.Contains("Q2", StringComparison.Ordinal) || quant.Contains("Q3", StringComparison.Ordinal))
            score -= 4;

        // 6. Léger bonus de stabilité si déjà configuré par l'utilisateur
        if (!string.IsNullOrWhiteSpace(configuredModel) && MatchesModelName(model.Name, configuredModel))
        {
            score += 1.5;
        }

        var sizeLabel = model.ParameterSize ?? $"{paramB:0.#}B";
        var summary = $"{sizeLabel}, ~{weightGb:F1} Go, {ramNote}";
        return new ScoredCandidate(model, score, isQwen, summary);
    }

    private static double GetQwenGenerationScore(string lowerName)
    {
        if (lowerName.Contains("qwen3.5", StringComparison.Ordinal)) return 56;
        if (lowerName.Contains("qwen3", StringComparison.Ordinal)) return 52;
        if (lowerName.Contains("qwen2.5", StringComparison.Ordinal)) return 40;
        if (lowerName.Contains("qwen2", StringComparison.Ordinal)) return 26;
        if (lowerName.Contains("qwq", StringComparison.Ordinal)) return 24;
        return 14; // qwen v1 / 1.5
    }

    internal static OllamaInstalledModel? FindMatchingInstalled(
        IReadOnlyList<OllamaInstalledModel> installed,
        string? configuredModel)
    {
        if (string.IsNullOrWhiteSpace(configuredModel)) return null;
        return installed.FirstOrDefault(m => MatchesModelName(m.Name, configuredModel));
    }

    internal static bool MatchesModelName(string installedName, string configuredModel)
    {
        if (string.IsNullOrWhiteSpace(installedName) || string.IsNullOrWhiteSpace(configuredModel))
            return false;

        var target = configuredModel.Trim();
        var targetHasTag = target.Contains(':');
        var targetBase = targetHasTag ? target[..target.IndexOf(':')] : target;

        if (installedName.Equals(target, StringComparison.OrdinalIgnoreCase))
            return true;

        if (targetHasTag)
        {
            if (installedName.StartsWith(target, StringComparison.OrdinalIgnoreCase))
                return true;
            if (target.EndsWith(":latest", StringComparison.OrdinalIgnoreCase) &&
                installedName.Equals(targetBase, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        else
        {
            if (installedName.StartsWith(targetBase + ":", StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    private static bool TryParseParamString(string? raw, out double billions)
    {
        billions = 0;
        if (string.IsNullOrWhiteSpace(raw)) return false;

        var m = ParamValueRegex().Match(raw.Trim());
        if (!m.Success) return false;
        if (!double.TryParse(m.Groups[1].Value, NumberStyles.Float, CultureInfo.InvariantCulture, out var val))
            return false;

        billions = m.Groups[2].Value.Equals("m", StringComparison.OrdinalIgnoreCase)
            ? val / 1000.0
            : val;
        return billions > 0;
    }

    private static string? TryGetString(JsonElement obj, string prop) =>
        obj.ValueKind == JsonValueKind.Object &&
        obj.TryGetProperty(prop, out var el) &&
        el.ValueKind == JsonValueKind.String
            ? el.GetString()
            : null;

    [GeneratedRegex(@"[:\-_](\d+(?:\.\d+)?)(b|m)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ParamInNameRegex();

    [GeneratedRegex(@"^(\d+(?:\.\d+)?)\s*(b|m)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ParamValueRegex();
}
