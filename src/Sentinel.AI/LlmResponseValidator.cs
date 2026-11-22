using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Sentinel.Shared.Models;

namespace Sentinel.AI;

/// <summary>
/// Valide et extrait strictement le JSON retourné par le LLM local (doc §7.1-4 &amp; §7.4).
/// En cas d'anomalie, retourne <c>null</c> afin de basculer immédiatement sur le repli déterministe par règles.
/// </summary>
public static partial class LlmResponseValidator
{
    public const int MaxJustificationLength = 600;

    private static readonly Dictionary<string, ThreatType> TypeAliases = new(StringComparer.OrdinalIgnoreCase)
    {
        ["none"] = ThreatType.None,
        ["aucun"] = ThreatType.None,
        ["aucune"] = ThreatType.None,
        ["benin"] = ThreatType.None,
        ["benign"] = ThreatType.None,
        ["normal"] = ThreatType.None,
        ["safe"] = ThreatType.None,
        ["info"] = ThreatType.None,

        ["phishing"] = ThreatType.Phishing,
        ["hameconnage"] = ThreatType.Phishing,
        ["spearphishing"] = ThreatType.Phishing,
        ["liensuspect"] = ThreatType.Phishing,
        ["suspiciouslink"] = ThreatType.Phishing,

        ["malware"] = ThreatType.Malware,
        ["logicielmalveillant"] = ThreatType.Malware,
        ["malveillant"] = ThreatType.Malware,
        ["executablemalveillant"] = ThreatType.Malware,
        ["maliciousfile"] = ThreatType.Malware,
        ["trojan"] = ThreatType.Malware,
        ["virus"] = ThreatType.Malware,
        ["backdoor"] = ThreatType.Malware,
        ["payload"] = ThreatType.Malware,

        ["ransomware"] = ThreatType.Ransomware,
        ["rancongiciel"] = ThreatType.Ransomware,
        ["chiffrement"] = ThreatType.Ransomware,

        ["badusb"] = ThreatType.BadUsb,
        ["usb"] = ThreatType.BadUsb,
        ["peripherique"] = ThreatType.BadUsb,
        ["peripheriquesuspect"] = ThreatType.BadUsb,
        ["hid"] = ThreatType.BadUsb,
        ["hardware"] = ThreatType.BadUsb,

        ["exfiltration"] = ThreatType.Exfiltration,
        ["fuite"] = ThreatType.Exfiltration,
        ["fuitededonnees"] = ThreatType.Exfiltration,
        ["dataexfiltration"] = ThreatType.Exfiltration,
        ["voldonnees"] = ThreatType.Exfiltration,

        ["intrusion"] = ThreatType.Intrusion,
        ["bruteforce"] = ThreatType.Intrusion,
        ["forcebrute"] = ThreatType.Intrusion,
        ["accesnonautorise"] = ThreatType.Intrusion,
        ["unauthorizedaccess"] = ThreatType.Intrusion,
        ["compromission"] = ThreatType.Intrusion,

        ["socialengineering"] = ThreatType.SocialEngineering,
        ["ingenieriesociale"] = ThreatType.SocialEngineering,
        ["social"] = ThreatType.SocialEngineering,

        ["persistence"] = ThreatType.Persistence,
        ["persistance"] = ThreatType.Persistence,
        ["autostart"] = ThreatType.Persistence,
        ["demarrage"] = ThreatType.Persistence,

        ["anomaly"] = ThreatType.Anomaly,
        ["anomalie"] = ThreatType.Anomaly,
        ["anomaliecomportementale"] = ThreatType.Anomaly,
        ["behavioralanomaly"] = ThreatType.Anomaly,
        ["comportementanormal"] = ThreatType.Anomaly,
        ["suspect"] = ThreatType.Anomaly,
        ["suspicious"] = ThreatType.Anomaly,

        ["tampering"] = ThreatType.Tampering,
        ["alteration"] = ThreatType.Tampering,
        ["sabotage"] = ThreatType.Tampering,
        ["autoprotection"] = ThreatType.Tampering,
        ["desactivation"] = ThreatType.Tampering,
        ["impairdefenses"] = ThreatType.Tampering
    };

    /// <summary>
    /// Extrait et valide un objet JSON de scoring depuis une réponse brute du LLM.
    /// Retourne <c>null</c> si la réponse est malformée, hors bornes ou incomplète.
    /// </summary>
    public static LlmAssessmentResult? Validate(string? rawResponse, double latencyMs = 0)
    {
        if (string.IsNullOrWhiteSpace(rawResponse)) return null;

        var json = ExtractJsonObject(rawResponse);
        if (json is null) return null;

        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return null;

            if (!TryGetPropertyIgnoreCase(doc.RootElement, "score", out var scoreEl) ||
                !TryReadScore(scoreEl, out var score))
            {
                return null;
            }

            if (!TryGetPropertyIgnoreCase(doc.RootElement, "type", out var typeEl) ||
                typeEl.ValueKind != JsonValueKind.String ||
                !TryParseThreatType(typeEl.GetString(), out var threatType))
            {
                return null;
            }

            if (!TryGetPropertyIgnoreCase(doc.RootElement, "justification", out var justEl) ||
                justEl.ValueKind != JsonValueKind.String)
            {
                return null;
            }

            var justification = justEl.GetString()?.Trim();
            if (string.IsNullOrWhiteSpace(justification)) return null;
            if (justification.Length > MaxJustificationLength)
            {
                justification = string.Concat(justification.AsSpan(0, MaxJustificationLength - 1), "…");
            }

            if (!TryGetPropertyIgnoreCase(doc.RootElement, "confidence", out var confEl) ||
                !TryReadConfidence(confEl, out var confidence))
            {
                return null;
            }

            return new LlmAssessmentResult(score, threatType, justification, confidence, latencyMs);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>Résout un nom de type de menace (insensible à la casse, accents et alias FR/EN).</summary>
    public static bool TryParseThreatType(string? raw, out ThreatType threatType)
    {
        threatType = ThreatType.None;
        if (string.IsNullOrWhiteSpace(raw)) return false;

        if (Enum.TryParse<ThreatType>(raw.Trim(), ignoreCase: true, out var parsed) &&
            Enum.IsDefined(parsed))
        {
            threatType = parsed;
            return true;
        }

        var normalized = NormalizeKey(raw);
        return TypeAliases.TryGetValue(normalized, out threatType);
    }

    /// <summary>Extrait le premier objet JSON équilibré, même entouré de Markdown ou de texte parasite.</summary>
    public static string? ExtractJsonObject(string raw)
    {
        var candidate = raw.Trim();

        // Extraction éventuelle depuis un bloc de code Markdown ```json ... ```
        var fenceMatch = MarkdownFenceRegex().Match(candidate);
        if (fenceMatch.Success)
        {
            candidate = fenceMatch.Groups[1].Value.Trim();
        }

        var start = candidate.IndexOf('{');
        if (start < 0) return null;

        var depth = 0;
        var inString = false;
        var escaped = false;

        for (var i = start; i < candidate.Length; i++)
        {
            var c = candidate[i];
            if (inString)
            {
                if (escaped)
                {
                    escaped = false;
                }
                else if (c == '\\')
                {
                    escaped = true;
                }
                else if (c == '"')
                {
                    inString = false;
                }
                continue;
            }

            if (c == '"')
            {
                inString = true;
            }
            else if (c == '{')
            {
                depth++;
            }
            else if (c == '}')
            {
                depth--;
                if (depth == 0)
                {
                    return candidate.Substring(start, i - start + 1);
                }
            }
        }

        return null;
    }

    private static bool TryGetPropertyIgnoreCase(JsonElement obj, string name, out JsonElement value)
    {
        if (obj.TryGetProperty(name, out value)) return true;
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

    private static bool TryReadScore(JsonElement el, out int score)
    {
        score = 0;
        if (el.ValueKind != JsonValueKind.Number) return false;
        if (el.TryGetInt32(out var intVal))
        {
            if (intVal is < 0 or > 100) return false;
            score = intVal;
            return true;
        }
        if (el.TryGetDouble(out var dblVal) && double.IsFinite(dblVal) && dblVal >= 0.0 && dblVal <= 100.0)
        {
            score = (int)Math.Round(dblVal);
            return true;
        }
        return false;
    }

    private static bool TryReadConfidence(JsonElement el, out double confidence)
    {
        confidence = 0;
        if (el.ValueKind != JsonValueKind.Number) return false;
        if (!el.TryGetDouble(out var val) || !double.IsFinite(val) || val < 0.0 || val > 1.0)
        {
            return false;
        }
        confidence = val;
        return true;
    }

    private static string NormalizeKey(string input)
    {
        var formD = input.Normalize(NormalizationForm.FormD);
        var sb = new StringBuilder(formD.Length);
        foreach (var ch in formD)
        {
            var cat = CharUnicodeInfo.GetUnicodeCategory(ch);
            if (cat == UnicodeCategory.NonSpacingMark) continue;
            if (char.IsLetterOrDigit(ch))
            {
                sb.Append(char.ToLowerInvariant(ch));
            }
        }
        return sb.ToString();
    }

    [GeneratedRegex(@"```(?:json)?\s*([\s\S]*?)```", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex MarkdownFenceRegex();
}
