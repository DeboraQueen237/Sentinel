using System.Text.RegularExpressions;
using Sentinel.Shared.Models;
using Sentinel.Shared.Security;

namespace Sentinel.Tray.Collectors;

/// <summary>
/// Résultat d'analyse en mémoire du presse-papiers. Ne contient JAMAIS le texte brut copié (doc §2.1, §6.3).
/// </summary>
public sealed record ClipboardAnalysisResult(
    string EventType,
    string Subject,
    string ContentType,
    string ContentHash,
    string? Domain,
    string? UrlScheme,
    bool IsShortener,
    string? CommandKind);

/// <summary>
/// Analyseur respectueux de la vie privée pour le canal presse-papiers (doc §2.1, §6.3) :
/// inspecte le texte exclusivement en mémoire pour détecter URLs, raccourcisseurs, domaines suspects
/// et motifs de commandes PowerShell/cmd/LOLBins.
/// Seuls <c>content.type</c>, <c>domain</c>, <c>url.shortener</c>, <c>command.kind</c> et <c>content.hash</c>
/// (SHA-256) sont produits : JAMAIS le contenu brut ni aucun mot de passe.
/// </summary>
public static partial class ClipboardAnalyzer
{
    private static readonly HashSet<string> UrlShorteners = new(StringComparer.OrdinalIgnoreCase)
    {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
        "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "rebrand.ly", "lnkd.in",
        "v.gd", "s.id", "bl.ink", "clck.ru", "shrtco.de", "adf.ly", "soo.gd"
    };

    public static ClipboardAnalysisResult? Analyze(string? rawText)
    {
        if (string.IsNullOrWhiteSpace(rawText))
        {
            return null;
        }

        // Empreinte cryptographique irréversible calculée sur le contenu en mémoire uniquement.
        var contentHash = HashChain.Sha256Hex(rawText);

        // 1. Détection de motifs de commande potentiellement dangereux (prioritaire si présent).
        var commandKind = DetectCommandKind(rawText);
        if (commandKind is not null)
        {
            var embeddedDomain = TryExtractFirstDomain(rawText, out var scheme, out var isShortener);
            return new ClipboardAnalysisResult(
                EventType: EventTypes.ClipboardCommand,
                Subject: commandKind,
                ContentType: "command",
                ContentHash: contentHash,
                Domain: embeddedDomain,
                UrlScheme: scheme,
                IsShortener: isShortener,
                CommandKind: commandKind);
        }

        // 2. Détection d'URL (http / https).
        var domain = TryExtractFirstDomain(rawText, out var urlScheme, out var shortener);
        if (domain is not null)
        {
            return new ClipboardAnalysisResult(
                EventType: EventTypes.ClipboardUrl,
                Subject: domain,
                ContentType: "url",
                ContentHash: contentHash,
                Domain: domain,
                UrlScheme: urlScheme,
                IsShortener: shortener,
                CommandKind: null);
        }

        // Texte ordinaire / mot de passe / conversation : ignoré intégralement.
        return null;
    }

    public static SecurityEvent? AnalyzeToEvent(string? rawText, string hostId, string userId, DateTimeOffset? timestamp = null)
    {
        var analysis = Analyze(rawText);
        if (analysis is null)
        {
            return null;
        }

        var attrs = new Dictionary<string, string>
        {
            [AttributeKeys.ContentType] = analysis.ContentType,
            [AttributeKeys.ContentHash] = analysis.ContentHash
        };

        if (!string.IsNullOrEmpty(analysis.Domain))
        {
            attrs[AttributeKeys.Domain] = analysis.Domain;
            attrs[AttributeKeys.IsShortener] = analysis.IsShortener ? "true" : "false";
        }

        if (!string.IsNullOrEmpty(analysis.UrlScheme))
        {
            attrs[AttributeKeys.UrlScheme] = analysis.UrlScheme;
        }

        if (!string.IsNullOrEmpty(analysis.CommandKind))
        {
            attrs[AttributeKeys.CommandKind] = analysis.CommandKind;
        }

        var hints = !string.IsNullOrEmpty(analysis.Domain)
            ? $"domain:{analysis.Domain};hash:{analysis.ContentHash}"
            : $"cmd:{analysis.CommandKind};hash:{analysis.ContentHash}";

        return SecurityEvent.Create(
            hostId,
            userId,
            EventCategory.Clipboard,
            analysis.EventType,
            analysis.Subject,
            attrs,
            hints,
            timestamp);
    }

    private static string? DetectCommandKind(string text)
    {
        // Limite l'analyse regex aux 8192 premiers caractères pour éviter tout coût CPU excessif.
        var sample = text.Length > 8192 ? text[..8192] : text;

        if (PowerShellEncodedRegex().IsMatch(sample))
        {
            return "powershell-encoded";
        }

        if (PowerShellDownloadExecRegex().IsMatch(sample))
        {
            return "powershell";
        }

        if (LolBinCommandRegex().IsMatch(sample))
        {
            return "lolbin";
        }

        if (CmdExecRegex().IsMatch(sample))
        {
            return "cmd";
        }

        if (BashPipeExecRegex().IsMatch(sample))
        {
            return "bash";
        }

        return null;
    }

    private static string? TryExtractFirstDomain(string text, out string? scheme, out bool isShortener)
    {
        scheme = null;
        isShortener = false;

        var sample = text.Length > 4096 ? text[..4096] : text;
        var match = HttpUrlRegex().Match(sample);
        if (!match.Success)
        {
            return null;
        }

        var rawUrl = match.Value;
        if (!Uri.TryCreate(rawUrl, UriKind.Absolute, out var uri))
        {
            // Secours robuste pour les URLs contenant des caractères spéciaux dans user:pass@host
            var schemeEnd = rawUrl.IndexOf("://", StringComparison.Ordinal);
            if (schemeEnd <= 0)
            {
                return null;
            }
            var rawScheme = rawUrl[..schemeEnd].ToLowerInvariant();
            if (rawScheme is not ("http" or "https"))
            {
                return null;
            }
            var rest = rawUrl[(schemeEnd + 3)..];
            var slashIdx = rest.IndexOfAny(['/', '?']);
            var authority = slashIdx >= 0 ? rest[..slashIdx] : rest;
            var atIdx = authority.LastIndexOf('@');
            if (atIdx < 0 || atIdx + 1 >= authority.Length)
            {
                return null;
            }
            var hostPort = authority[(atIdx + 1)..];
            if (!Uri.TryCreate($"{rawScheme}://{hostPort}", UriKind.Absolute, out uri))
            {
                return null;
            }
        }

        if ((uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps) ||
            string.IsNullOrWhiteSpace(uri.Host))
        {
            return null;
        }

        var host = uri.Host.Trim().TrimEnd('.').ToLowerInvariant();
        if (string.IsNullOrEmpty(host))
        {
            return null;
        }

        scheme = uri.Scheme.ToLowerInvariant();
        isShortener = IsUrlShortener(host);
        return host;
    }

    public static bool IsUrlShortener(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain)) return false;
        var norm = domain.Trim().TrimEnd('.').ToLowerInvariant();
        if (UrlShorteners.Contains(norm)) return true;
        foreach (var shortener in UrlShorteners)
        {
            if (norm.EndsWith("." + shortener, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    [GeneratedRegex(@"https?://[^\s""'<>()]+", RegexOptions.IgnoreCase)]
    private static partial Regex HttpUrlRegex();

    [GeneratedRegex(@"(?:powershell|pwsh)(?:\.exe)?\b.*(?:-e(?:nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{16,}|FromBase64String)", RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    private static partial Regex PowerShellEncodedRegex();

    [GeneratedRegex(@"(?:(?:powershell|pwsh)(?:\.exe)?\b.*(?:-w(?:indowstyle)?\s+hidden|-ep\s+bypass|-exec(?:utionpolicy)?\s+bypass|\biex\b|Invoke-Expression|Invoke-WebRequest|\biwr\b|DownloadString|DownloadFile)|(?:\biex\b|Invoke-Expression)\s*\(.*(?:Invoke-WebRequest|\biwr\b|Net\.WebClient|DownloadString))", RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    private static partial Regex PowerShellDownloadExecRegex();

    [GeneratedRegex(@"\b(?:certutil(?:\.exe)?\s+.*-urlcache|mshta(?:\.exe)?\s+https?://|bitsadmin(?:\.exe)?\s+.*/transfer|regsvr32(?:\.exe)?\s+.*scrobj\.dll|rundll32(?:\.exe)?\s+javascript:)", RegexOptions.IgnoreCase)]
    private static partial Regex LolBinCommandRegex();

    [GeneratedRegex(@"\bcmd(?:\.exe)?\s+/[ck]\s+.+", RegexOptions.IgnoreCase)]
    private static partial Regex CmdExecRegex();

    [GeneratedRegex(@"\b(?:curl|wget)\s+https?://[^\r\n]+\|\s*(?:ba)?sh\b", RegexOptions.IgnoreCase)]
    private static partial Regex BashPipeExecRegex();
}
