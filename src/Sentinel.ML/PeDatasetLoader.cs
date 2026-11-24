using System.Globalization;
using System.Text.Json;

namespace Sentinel.ML;

/// <summary>
/// Charge des jeux de données étiquetés PE au format CSV ou JSONL EMBER 2018
/// (extraits légalement par l'utilisateur hors du dépôt Git).
/// </summary>
public static class PeDatasetLoader
{
    private static readonly Dictionary<string, float> EmberSubsystemMap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["UNKNOWN"] = 0f,
        ["NATIVE"] = 1f,
        ["WINDOWS_GUI"] = 2f,
        ["WINDOWS_CUI"] = 3f,
        ["OS2_CUI"] = 5f,
        ["POSIX_CUI"] = 7f,
        ["WINDOWS_CE_GUI"] = 9f,
        ["EFI_APPLICATION"] = 10f,
        ["EFI_BOOT_SERVICE_DRIVER"] = 11f,
        ["EFI_RUNTIME_DRIVER"] = 12f,
        ["EFI_ROM"] = 13f,
        ["XBOX"] = 14f,
        ["WINDOWS_BOOT_APPLICATION"] = 16f
    };

    /// <summary>
    /// Charge un fichier CSV de caractéristiques PE (avec en-tête nommé ou ordre positionnel Label, f0..f50).
    /// Les lignes non étiquetées (<c>-1</c>) ou commentées (<c>#</c>) sont ignorées.
    /// </summary>
    public static IReadOnlyList<PeTrainingSample> LoadFromCsv(string csvPath, int? maxSamples = null)
    {
        if (string.IsNullOrWhiteSpace(csvPath) || !File.Exists(csvPath))
        {
            throw new FileNotFoundException($"Fichier CSV introuvable : '{csvPath}'.", csvPath);
        }

        var samples = new List<PeTrainingSample>();
        int labelCol = 0;
        int[]? featureColMap = null;
        var headerParsed = false;

        using var reader = new StreamReader(csvPath);
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            if (maxSamples.HasValue && samples.Count >= maxSamples.Value)
            {
                break;
            }

            if (string.IsNullOrWhiteSpace(line) || line.TrimStart().StartsWith('#'))
            {
                continue;
            }

            var parts = line.Split(',');
            if (!headerParsed)
            {
                headerParsed = true;
                if (LooksLikeHeader(parts))
                {
                    ParseCsvHeader(parts, out labelCol, out featureColMap);
                    continue;
                }

                // Sans en-tête : colonne 0 = Label, colonnes 1..51 = caractéristiques
                labelCol = 0;
                featureColMap = Enumerable.Range(1, PeFeatureVector.FeatureCount).ToArray();
            }

            if (featureColMap is null || labelCol >= parts.Length)
            {
                continue;
            }

            if (!TryParseLabel(parts[labelCol], out var label))
            {
                continue; // Ignore -1 (non étiqueté) ou ligne invalide
            }

            var values = new float[PeFeatureVector.FeatureCount];
            for (var f = 0; f < PeFeatureVector.FeatureCount; f++)
            {
                var col = featureColMap[f];
                if (col >= 0 && col < parts.Length &&
                    float.TryParse(parts[col].Trim(), NumberStyles.Float, CultureInfo.InvariantCulture, out var parsed) &&
                    float.IsFinite(parsed))
                {
                    values[f] = parsed;
                }
            }

            samples.Add(new PeTrainingSample { Label = label, Features = values });
        }

        return samples;
    }

    /// <summary>
    /// Charge un fichier JSONL au format natif EMBER 2018 (<c>train_features_*.jsonl</c>)
    /// ou au format plat (<c>{"label": 0|1, "features": [51 floats]}</c>).
    /// Les enregistrements EMBER non étiquetés (<c>label == -1</c>) sont automatiquement écartés.
    /// </summary>
    public static IReadOnlyList<PeTrainingSample> LoadFromEmberJsonl(string jsonlPath, int? maxSamples = null)
    {
        if (string.IsNullOrWhiteSpace(jsonlPath) || !File.Exists(jsonlPath))
        {
            throw new FileNotFoundException($"Fichier JSONL introuvable : '{jsonlPath}'.", jsonlPath);
        }

        var samples = new List<PeTrainingSample>();
        using var reader = new StreamReader(jsonlPath);
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            if (maxSamples.HasValue && samples.Count >= maxSamples.Value)
            {
                break;
            }

            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            if (TryParseEmberJsonLine(line, out var sample) && sample is not null)
            {
                samples.Add(sample);
            }
        }

        return samples;
    }

    /// <summary>Parse une ligne JSON EMBER 2018 ou un vecteur plat en <see cref="PeTrainingSample"/>.</summary>
    public static bool TryParseEmberJsonLine(string jsonLine, out PeTrainingSample? sample)
    {
        sample = null;
        try
        {
            using var doc = JsonDocument.Parse(jsonLine);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            if (!TryExtractJsonLabel(root, out var label))
            {
                return false;
            }

            // Format plat optionnel : {"label": 1, "features": [51 floats]}
            if (TryGetPropertyIgnoreCase(root, "features", out var flatFeatures) &&
                flatFeatures.ValueKind == JsonValueKind.Array &&
                flatFeatures.GetArrayLength() == PeFeatureVector.FeatureCount)
            {
                var flat = new float[PeFeatureVector.FeatureCount];
                var idx = 0;
                foreach (var el in flatFeatures.EnumerateArray())
                {
                    var val = el.ValueKind == JsonValueKind.Number ? (float)el.GetDouble() : 0f;
                    flat[idx++] = float.IsFinite(val) ? val : 0f;
                }
                sample = new PeTrainingSample { Label = label, Features = flat };
                return true;
            }

            // Format EMBER 2018 natif
            var features = new float[PeFeatureVector.FeatureCount];
            ParseEmberGeneral(root, features);
            ParseEmberHeader(root, features);
            ParseEmberSections(root, features);
            ParseEmberImportsAndExports(root, features);
            ParseEmberHistogram(root, features);
            ParseEmberStrings(root, features);

            sample = new PeTrainingSample { Label = label, Features = features };
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static void ParseEmberGeneral(JsonElement root, float[] features)
    {
        if (!TryGetPropertyIgnoreCase(root, "general", out var general) || general.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        var size = GetLong(general, "size");
        features[PeFeatureIndex.LogFileSize] = MathF.Log10(1f + Math.Max(0L, size));
        features[PeFeatureIndex.HasDebugInfo] = GetBoolOrIntFlag(general, "has_debug");
        features[PeFeatureIndex.HasRelocations] = GetBoolOrIntFlag(general, "has_relocations");
        features[PeFeatureIndex.HasResources] = GetBoolOrIntFlag(general, "has_resources");
        features[PeFeatureIndex.IsSigned] = GetBoolOrIntFlag(general, "has_signature");
        features[PeFeatureIndex.HasTls] = GetBoolOrIntFlag(general, "has_tls");
        features[PeFeatureIndex.ExportCount] = GetFloat(general, "exports");
        features[PeFeatureIndex.ImportFunctionCount] = GetFloat(general, "imports");
    }

    private static void ParseEmberHeader(JsonElement root, float[] features)
    {
        if (!TryGetPropertyIgnoreCase(root, "header", out var header) || header.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        if (TryGetPropertyIgnoreCase(header, "coff", out var coff) && coff.ValueKind == JsonValueKind.Object)
        {
            var ts = (uint)Math.Clamp(GetLong(coff, "timestamp"), 0L, uint.MaxValue);
            var (anomaly, yearNorm) = PeFeatureExtractor.EvaluateTimestamp(ts);
            features[PeFeatureIndex.TimestampAnomaly] = anomaly ? 1f : 0f;
            features[PeFeatureIndex.TimestampYearNorm] = yearNorm;

            if (TryGetPropertyIgnoreCase(coff, "machine", out var machine) && machine.ValueKind == JsonValueKind.String)
            {
                var m = machine.GetString() ?? string.Empty;
                if (m.Contains("64", StringComparison.OrdinalIgnoreCase))
                {
                    features[PeFeatureIndex.Is64Bit] = 1f;
                }
            }

            if (TryGetPropertyIgnoreCase(coff, "characteristics", out var chars) && chars.ValueKind == JsonValueKind.Array)
            {
                foreach (var c in chars.EnumerateArray())
                {
                    if (c.ValueKind == JsonValueKind.String &&
                        string.Equals(c.GetString(), "DLL", StringComparison.OrdinalIgnoreCase))
                    {
                        features[PeFeatureIndex.IsDll] = 1f;
                        break;
                    }
                }
            }
        }

        if (TryGetPropertyIgnoreCase(header, "optional", out var opt) && opt.ValueKind == JsonValueKind.Object)
        {
            if (TryGetPropertyIgnoreCase(opt, "magic", out var magic) && magic.ValueKind == JsonValueKind.String &&
                string.Equals(magic.GetString(), "PE32+", StringComparison.OrdinalIgnoreCase))
            {
                features[PeFeatureIndex.Is64Bit] = 1f;
            }

            if (TryGetPropertyIgnoreCase(opt, "subsystem", out var sub))
            {
                if (sub.ValueKind == JsonValueKind.String &&
                    EmberSubsystemMap.TryGetValue(sub.GetString() ?? string.Empty, out var code))
                {
                    features[PeFeatureIndex.Subsystem] = code;
                }
                else if (sub.ValueKind == JsonValueKind.Number)
                {
                    features[PeFeatureIndex.Subsystem] = Math.Clamp((float)sub.GetDouble(), 0f, 32f);
                }
            }
        }
    }

    private static void ParseEmberSections(JsonElement root, float[] features)
    {
        if (!TryGetPropertyIgnoreCase(root, "section", out var secObj) || secObj.ValueKind != JsonValueKind.Object ||
            !TryGetPropertyIgnoreCase(secObj, "sections", out var secArr) || secArr.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        var count = 0;
        var execCount = 0;
        var rwxCount = 0;
        var hasPacker = false;
        double maxEntropy = 0.0;
        double minEntropy = 8.0;
        double sumEntropy = 0.0;
        double totalVirtual = 0.0;
        double totalRaw = 0.0;

        foreach (var sec in secArr.EnumerateArray())
        {
            if (sec.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            count++;
            if (!hasPacker && TryGetPropertyIgnoreCase(sec, "name", out var nameEl) && nameEl.ValueKind == JsonValueKind.String)
            {
                hasPacker = PeFeatureExtractor.IsPackerSectionName(nameEl.GetString());
            }

            var entropy = Math.Clamp(GetDouble(sec, "entropy"), 0.0, 8.0);
            if (entropy > maxEntropy) maxEntropy = entropy;
            if (entropy < minEntropy) minEntropy = entropy;
            sumEntropy += entropy;

            totalRaw += Math.Max(0.0, GetDouble(sec, "size"));
            totalVirtual += Math.Max(0.0, GetDouble(sec, "vsize"));

            var isExec = false;
            var isWrite = false;
            if (TryGetPropertyIgnoreCase(sec, "props", out var props) && props.ValueKind == JsonValueKind.Array)
            {
                foreach (var p in props.EnumerateArray())
                {
                    if (p.ValueKind != JsonValueKind.String) continue;
                    var s = p.GetString();
                    if (string.Equals(s, "MEM_EXECUTE", StringComparison.OrdinalIgnoreCase)) isExec = true;
                    if (string.Equals(s, "MEM_WRITE", StringComparison.OrdinalIgnoreCase)) isWrite = true;
                }
            }

            if (isExec)
            {
                execCount++;
                if (isWrite) rwxCount++;
            }
        }

        features[PeFeatureIndex.SectionCount] = count;
        features[PeFeatureIndex.ExecutableSectionCount] = execCount;
        features[PeFeatureIndex.WritableExecutableSectionCount] = rwxCount;
        features[PeFeatureIndex.MaxSectionEntropy] = count > 0 ? (float)maxEntropy : 0f;
        features[PeFeatureIndex.MeanSectionEntropy] = count > 0 ? (float)(sumEntropy / count) : 0f;
        features[PeFeatureIndex.MinSectionEntropy] = count > 0 ? (float)minEntropy : 0f;
        features[PeFeatureIndex.VirtualToRawSizeRatio] = totalRaw > 0
            ? Math.Clamp((float)(totalVirtual / totalRaw), 0f, 100f)
            : (totalVirtual > 0 ? 100f : 0f);
        features[PeFeatureIndex.HasPackerSectionName] = hasPacker ? 1f : 0f;
    }

    private static void ParseEmberImportsAndExports(JsonElement root, float[] features)
    {
        if (TryGetPropertyIgnoreCase(root, "imports", out var imports) && imports.ValueKind == JsonValueKind.Object)
        {
            var dllCount = 0;
            var funcNames = new List<string>();
            foreach (var dllProp in imports.EnumerateObject())
            {
                dllCount++;
                if (dllProp.Value.ValueKind == JsonValueKind.Array)
                {
                    foreach (var fn in dllProp.Value.EnumerateArray())
                    {
                        if (fn.ValueKind == JsonValueKind.String)
                        {
                            var name = fn.GetString();
                            if (!string.IsNullOrWhiteSpace(name))
                            {
                                funcNames.Add(name);
                            }
                        }
                    }
                }
            }

            features[PeFeatureIndex.ImportDllCount] = dllCount;
            if (funcNames.Count > 0)
            {
                features[PeFeatureIndex.ImportFunctionCount] = funcNames.Count;
            }

            PeFeatureExtractor.PopulateImportCategories(
                funcNames,
                out var suspicious,
                out var crypto,
                out var network,
                out var injection,
                out var antiDebug);

            features[PeFeatureIndex.SuspiciousImportCount] = suspicious;
            features[PeFeatureIndex.CryptoApiCount] = crypto;
            features[PeFeatureIndex.NetworkApiCount] = network;
            features[PeFeatureIndex.InjectionApiCount] = injection;
            features[PeFeatureIndex.AntiDebugApiCount] = antiDebug;
        }

        if (TryGetPropertyIgnoreCase(root, "exports", out var exports) && exports.ValueKind == JsonValueKind.Array)
        {
            features[PeFeatureIndex.ExportCount] = exports.GetArrayLength();
        }
    }

    private static void ParseEmberHistogram(JsonElement root, float[] features)
    {
        if (!TryGetPropertyIgnoreCase(root, "histogram", out var hist) || hist.ValueKind != JsonValueKind.Array ||
            hist.GetArrayLength() != 256)
        {
            return;
        }

        Span<double> counts = stackalloc double[256];
        double total = 0.0;
        var idx = 0;
        foreach (var el in hist.EnumerateArray())
        {
            var c = el.ValueKind == JsonValueKind.Number ? Math.Max(0.0, el.GetDouble()) : 0.0;
            counts[idx++] = c;
            total += c;
        }

        if (total <= 0.0)
        {
            return;
        }

        for (var bin = 0; bin < PeFeatureIndex.ByteHistBinCount; bin++)
        {
            double sum = 0.0;
            var start = bin * 16;
            for (var j = 0; j < 16; j++)
            {
                sum += counts[start + j];
            }
            features[PeFeatureIndex.ByteHistBinStart + bin] = (float)(sum / total);
        }

        double entropy = 0.0;
        double printable = 0.0;
        for (var b = 0; b < 256; b++)
        {
            var c = counts[b];
            if (c <= 0.0) continue;
            var p = c / total;
            entropy -= p * Math.Log2(p);
            if ((b >= 0x20 && b <= 0x7E) || b is 0x09 or 0x0A or 0x0D)
            {
                printable += c;
            }
        }

        features[PeFeatureIndex.GlobalByteEntropy] = (float)Math.Clamp(entropy, 0.0, 8.0);
        features[PeFeatureIndex.NullByteRatio] = (float)(counts[0] / total);
        features[PeFeatureIndex.PrintableAsciiRatio] = (float)(printable / total);
    }

    private static void ParseEmberStrings(JsonElement root, float[] features)
    {
        if (!TryGetPropertyIgnoreCase(root, "strings", out var strings) || strings.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        features[PeFeatureIndex.PrintableStringCount] = GetFloat(strings, "numstrings");
        features[PeFeatureIndex.AvgStringLength] = GetFloat(strings, "avlength");
        features[PeFeatureIndex.UrlLikeStringCount] = GetFloat(strings, "urls");
        features[PeFeatureIndex.PathLikeStringCount] = GetFloat(strings, "paths");
        features[PeFeatureIndex.RegistryStringCount] = GetFloat(strings, "registry");
    }

    private static bool LooksLikeHeader(string[] parts)
    {
        if (parts.Length == 0) return false;
        var first = parts[0].Trim();
        return first.Equals("label", StringComparison.OrdinalIgnoreCase) ||
               first.Equals("is_malicious", StringComparison.OrdinalIgnoreCase) ||
               first.Equals("malicious", StringComparison.OrdinalIgnoreCase) ||
               first.Equals("y", StringComparison.OrdinalIgnoreCase) ||
               PeFeatureExtractor.IndexOf(first) >= 0;
    }

    private static void ParseCsvHeader(string[] headers, out int labelCol, out int[] featureColMap)
    {
        labelCol = 0;
        featureColMap = new int[PeFeatureVector.FeatureCount];
        Array.Fill(featureColMap, -1);

        var namedMatches = 0;
        for (var i = 0; i < headers.Length; i++)
        {
            var h = headers[i].Trim();
            if (h.Equals("label", StringComparison.OrdinalIgnoreCase) ||
                h.Equals("is_malicious", StringComparison.OrdinalIgnoreCase) ||
                h.Equals("malicious", StringComparison.OrdinalIgnoreCase) ||
                h.Equals("y", StringComparison.OrdinalIgnoreCase))
            {
                labelCol = i;
                continue;
            }

            var featIdx = PeFeatureExtractor.IndexOf(h);
            if (featIdx >= 0)
            {
                featureColMap[featIdx] = i;
                namedMatches++;
            }
        }

        if (namedMatches == 0)
        {
            // En-tête générique (ex. label,f0,f1,...) : mappage positionnel hors colonne label
            var f = 0;
            for (var i = 0; i < headers.Length && f < PeFeatureVector.FeatureCount; i++)
            {
                if (i == labelCol) continue;
                featureColMap[f++] = i;
            }
        }
    }

    private static bool TryParseLabel(string raw, out bool label)
    {
        label = false;
        var s = raw.Trim();
        if (s.Equals("1", StringComparison.Ordinal) ||
            s.Equals("true", StringComparison.OrdinalIgnoreCase) ||
            s.Equals("malicious", StringComparison.OrdinalIgnoreCase))
        {
            label = true;
            return true;
        }

        if (s.Equals("0", StringComparison.Ordinal) ||
            s.Equals("false", StringComparison.OrdinalIgnoreCase) ||
            s.Equals("benign", StringComparison.OrdinalIgnoreCase))
        {
            label = false;
            return true;
        }

        return false;
    }

    private static bool TryExtractJsonLabel(JsonElement root, out bool label)
    {
        label = false;
        if (!TryGetPropertyIgnoreCase(root, "label", out var el) &&
            !TryGetPropertyIgnoreCase(root, "is_malicious", out el))
        {
            return false;
        }

        if (el.ValueKind == JsonValueKind.True) { label = true; return true; }
        if (el.ValueKind == JsonValueKind.False) { label = false; return true; }
        if (el.ValueKind == JsonValueKind.Number && el.TryGetInt32(out var iv))
        {
            if (iv == 1) { label = true; return true; }
            if (iv == 0) { label = false; return true; }
            return false; // -1 = non étiqueté dans EMBER
        }
        if (el.ValueKind == JsonValueKind.String)
        {
            return TryParseLabel(el.GetString() ?? string.Empty, out label);
        }

        return false;
    }

    private static bool TryGetPropertyIgnoreCase(JsonElement obj, string name, out JsonElement value)
    {
        if (obj.TryGetProperty(name, out value))
        {
            return true;
        }

        foreach (var prop in obj.EnumerateObject())
        {
            if (prop.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                value = prop.Value;
                return true;
            }
        }

        value = default;
        return false;
    }

    private static long GetLong(JsonElement obj, string name) =>
        TryGetPropertyIgnoreCase(obj, name, out var el) && el.ValueKind == JsonValueKind.Number
            ? (long)el.GetDouble()
            : 0L;

    private static double GetDouble(JsonElement obj, string name) =>
        TryGetPropertyIgnoreCase(obj, name, out var el) && el.ValueKind == JsonValueKind.Number
            ? el.GetDouble()
            : 0.0;

    private static float GetFloat(JsonElement obj, string name)
    {
        var d = (float)GetDouble(obj, name);
        return float.IsFinite(d) ? d : 0f;
    }

    private static float GetBoolOrIntFlag(JsonElement obj, string name)
    {
        if (!TryGetPropertyIgnoreCase(obj, name, out var el)) return 0f;
        return el.ValueKind switch
        {
            JsonValueKind.True => 1f,
            JsonValueKind.False => 0f,
            JsonValueKind.Number => el.GetDouble() > 0 ? 1f : 0f,
            _ => 0f
        };
    }
}
