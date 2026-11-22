using System.Globalization;
using System.Net;
using Sentinel.Shared.Models;

namespace Sentinel.ThreatIntel;

/// <summary>Types canoniques d'indicateurs de compromission (IoC).</summary>
public static class IndicatorTypes
{
    public const string Hash = "hash";
    public const string Domain = "domain";
    public const string Url = "url";
    public const string Ip = "ip";

    /// <summary>Normalise un libellé de type d'indicateur vers sa forme canonique.</summary>
    public static string? Normalize(string? indicatorType)
    {
        if (string.IsNullOrWhiteSpace(indicatorType))
        {
            return null;
        }

        return indicatorType.Trim().ToLowerInvariant() switch
        {
            "hash" or "sha256" or "sha-256" or "sha256_hash" or "filehash" or "file_hash" => Hash,
            "domain" or "host" or "hostname" or "fqdn" => Domain,
            "url" or "uri" => Url,
            "ip" or "ipv4" or "ipv6" or "ip_address" or "ip:port" => Ip,
            _ => null
        };
    }
}

/// <summary>Noms canoniques des flux de renseignement sur les menaces.</summary>
public static class ThreatIntelFeedNames
{
    public const string MalwareBazaar = "MalwareBazaar";
    public const string UrlHaus = "URLhaus";
    public const string ThreatFox = "ThreatFox";
    public const string FeodoTracker = "FeodoTracker";
    public const string OpenPhish = "OpenPhish";
    public const string PhishTank = "PhishTank";
    public const string VirusTotal = "VirusTotal";
}

/// <summary>Licences explicites des sources de renseignement sur les menaces.</summary>
public static class ThreatIntelLicenses
{
    public const string AbuseChCc0 = "CC0 1.0 Public Domain (abuse.ch)";
    public const string OpenPhishNonCommercial = "Non-Commercial Community";
    public const string PhishTankTerms = "PhishTank Terms of Service (API Key & User-Agent Required)";
    public const string VirusTotalOnDemand = "VirusTotal API Terms (On-Demand Hash Lookup Only)";
}

/// <summary>Noms des clients HTTP enregistrés dans <c>IHttpClientFactory</c>.</summary>
public static class ThreatIntelHttpClientNames
{
    public const string Feeds = "Sentinel.ThreatIntel.Feeds";
    public const string VirusTotal = "Sentinel.ThreatIntel.VirusTotal";
}

/// <summary>Indicateur normalisé persisté dans le magasin local SQLite.</summary>
public sealed record ThreatIntelIndicator(
    string Type,
    string Value,
    string Source,
    string ThreatType,
    DateTimeOffset FirstSeenUtc,
    DateTimeOffset LastSeenUtc,
    DateTimeOffset ExpiresAtUtc,
    int Confidence);

/// <summary>Résultat enrichi d'une correspondance locale de renseignement sur les menaces.</summary>
public sealed record ThreatIntelMatch(
    string IndicatorType,
    string Value,
    string Source,
    string ThreatType,
    DateTimeOffset FirstSeenUtc,
    DateTimeOffset LastSeenUtc,
    DateTimeOffset ExpiresAtUtc,
    int Confidence,
    int SuggestedScore,
    string Justification,
    string? MatchedParent = null);

/// <summary>État persisté d'un flux de renseignement dans SQLite.</summary>
public sealed record ThreatIntelFeedState(
    string Name,
    string License,
    DateTimeOffset? LastUpdatedUtc,
    int IndicatorCount,
    string? LastError);

/// <summary>Résultat de récupération et d'analyse d'un flux distant.</summary>
public sealed record ThreatIntelFeedFetchResult(
    string FeedName,
    string License,
    IReadOnlyList<ThreatIntelIndicator> Indicators,
    DateTimeOffset FetchedAtUtc);

/// <summary>Paramètres de résilience Polly v8 pour les appels HTTP Threat Intelligence.</summary>
public sealed class ThreatIntelResilienceOptions
{
    /// <summary>Nombre de tentatives de réessai exponentiel avec jitter (défaut : 2).</summary>
    public int MaxRetryAttempts { get; set; } = 2;

    /// <summary>Délai initial avant le premier réessai exponentiel (défaut : 500 ms).</summary>
    public TimeSpan RetryBaseDelay { get; set; } = TimeSpan.FromMilliseconds(500);

    /// <summary>Délai maximal strict par tentative HTTP (défaut : 15 s).</summary>
    public TimeSpan RequestTimeout { get; set; } = TimeSpan.FromSeconds(15);

    /// <summary>Nombre minimal d'échecs dans la fenêtre d'échantillonnage pour ouvrir le disjoncteur (min. 2).</summary>
    public int CircuitBreakerMinimumThroughput { get; set; } = 3;

    /// <summary>Ratio d'échecs déclenchant l'ouverture du disjoncteur (défaut : 1.0 = échecs consécutifs).</summary>
    public double CircuitBreakerFailureRatio { get; set; } = 1.0;

    /// <summary>Fenêtre d'échantillonnage du disjoncteur (min. 500 ms).</summary>
    public TimeSpan CircuitBreakerSamplingDuration { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>Durée d'ouverture du disjoncteur avant passage en semi-ouvert (défaut : 30 s).</summary>
    public TimeSpan CircuitBreakerBreakDuration { get; set; } = TimeSpan.FromSeconds(30);
}

/// <summary>Points de terminaison des flux Threat Intelligence (surchargeables pour les tests).</summary>
public sealed class ThreatIntelFeedEndpoints
{
    public string MalwareBazaarUrl { get; set; } = "https://bazaar.abuse.ch/export/txt/sha256/recent/";
    public string UrlHausUrl { get; set; } = "https://urlhaus.abuse.ch/downloads/csv_recent/";
    public string ThreatFoxUrl { get; set; } = "https://threatfox.abuse.ch/export/csv/recent/";
    public string FeodoTrackerUrl { get; set; } = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt";
    public string OpenPhishUrl { get; set; } = "https://openphish.com/feed.txt";

    /// <summary>Modèle d'URL PhishTank contenant <c>{apiKey}</c>.</summary>
    public string PhishTankUrlTemplate { get; set; } = "https://data.phishtank.com/data/{apiKey}/online-valid.json";

    /// <summary>Modèle d'URL VirusTotal v3 contenant <c>{sha256}</c> (hash uniquement, jamais d'upload).</summary>
    public string VirusTotalFileUrlTemplate { get; set; } = "https://www.virustotal.com/api/v3/files/{sha256}";
}

/// <summary>Options globales du module <c>Sentinel.ThreatIntel</c>.</summary>
public sealed class ThreatIntelOptions
{
    /// <summary>Chemin de la base SQLite (par défaut <c>SentinelPaths.ThreatIntelDatabase</c>).</summary>
    public string? DatabasePath { get; set; }

    /// <summary>Dossier des secrets DPAPI (par défaut <c>SentinelPaths.Secrets</c>).</summary>
    public string? SecretsDirectory { get; set; }

    /// <summary>Paramètres fonctionnels (activation des flux, TTL, fréquence).</summary>
    public ThreatIntelSettings Settings { get; set; } = new();

    /// <summary>Paramètres de résilience Polly v8.</summary>
    public ThreatIntelResilienceOptions Resilience { get; set; } = new();

    /// <summary>URLs des flux et APIs.</summary>
    public ThreatIntelFeedEndpoints Endpoints { get; set; } = new();

    /// <summary>Capacité initiale du filtre de Bloom en mémoire (défaut : 500 000 indicateurs).</summary>
    public int BloomExpectedCapacity { get; set; } = 500_000;

    /// <summary>Taux de faux positifs cible du filtre de Bloom (défaut : 0.0005, soit &lt; 0.1 %).</summary>
    public double BloomFalsePositiveRate { get; set; } = 0.0005;

    /// <summary>Délai initial avant le premier rafraîchissement en arrière-plan.</summary>
    public TimeSpan InitialRefreshDelay { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>Surcharge optionnelle de l'intervalle du worker (utile pour les tests).</summary>
    public TimeSpan? RefreshIntervalOverride { get; set; }
}

/// <summary>Utilitaires déterministes de normalisation des indicateurs (hash, domaine, URL, IP).</summary>
public static class IndicatorNormalizer
{
    /// <summary>Vérifie qu'une chaîne est un condensat SHA-256 hexadécimal valide (64 caractères).</summary>
    public static bool IsValidSha256(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var span = value.AsSpan().Trim();
        if (span.Length != 64)
        {
            return false;
        }

        for (var i = 0; i < span.Length; i++)
        {
            var c = span[i];
            var isHex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!isHex)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Normalise un hash SHA-256 en minuscules (retourne null si vide ou invalide).</summary>
    public static string? NormalizeHash(string? sha256)
    {
        if (!IsValidSha256(sha256))
        {
            return null;
        }

        return sha256!.Trim().ToLowerInvariant();
    }

    /// <summary>Normalise un nom de domaine en minuscules sans point final ni préfixe wildcard.</summary>
    public static string? NormalizeDomain(string? domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            return null;
        }

        var candidate = domain.Trim();
        if (candidate.Contains("://", StringComparison.Ordinal) &&
            Uri.TryCreate(candidate, UriKind.Absolute, out var uri))
        {
            candidate = uri.Host;
        }
        else
        {
            var slashIdx = candidate.IndexOf('/');
            if (slashIdx >= 0)
            {
                candidate = candidate[..slashIdx];
            }

            var colonIdx = candidate.IndexOf(':');
            if (colonIdx > 0 && candidate.IndexOf(':', colonIdx + 1) < 0)
            {
                candidate = candidate[..colonIdx];
            }
        }

        while (candidate.StartsWith("*.", StringComparison.Ordinal))
        {
            candidate = candidate[2..];
        }

        candidate = candidate.Trim().TrimStart('.').TrimEnd('.').ToLowerInvariant();
        if (candidate.Length == 0 || candidate.Length > 253)
        {
            return null;
        }

        // Exclure les adresses IP pures
        if (IPAddress.TryParse(candidate, out _))
        {
            return null;
        }

        // Validation minimale des caractères DNS autorisés
        for (var i = 0; i < candidate.Length; i++)
        {
            var c = candidate[i];
            var ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c is '-' or '.' or '_';
            if (!ok)
            {
                return null;
            }
        }

        return candidate;
    }

    /// <summary>
    /// Énumère le domaine normalisé puis chacun de ses domaines parents jusqu'au domaine enregistrable
    /// (au moins deux étiquettes, ex. <c>a.sub.evil.xyz</c> → <c>sub.evil.xyz</c> → <c>evil.xyz</c>).
    /// </summary>
    public static IEnumerable<string> EnumerateDomainHierarchy(string normalizedDomain)
    {
        if (string.IsNullOrWhiteSpace(normalizedDomain))
        {
            yield break;
        }

        yield return normalizedDomain;

        var idx = normalizedDomain.IndexOf('.');
        while (idx >= 0 && idx + 1 < normalizedDomain.Length)
        {
            var parent = normalizedDomain[(idx + 1)..];
            // Ne jamais remonter jusqu'au TLD seul (ex. "xyz" ou "com")
            if (!parent.Contains('.'))
            {
                yield break;
            }

            yield return parent;
            idx = normalizedDomain.IndexOf('.', idx + 1);
        }
    }

    /// <summary>
    /// Normalise une URL : schéma en minuscules (défaut <c>http</c>), hôte et chemin en minuscules,
    /// suppression du port par défaut, du fragment et des barres obliques finales du chemin.
    /// </summary>
    public static string? NormalizeUrl(string? url)
    {
        if (string.IsNullOrWhiteSpace(url))
        {
            return null;
        }

        var trimmed = url.Trim();
        if (!trimmed.Contains("://", StringComparison.Ordinal))
        {
            trimmed = "http://" + trimmed;
        }

        if (!Uri.TryCreate(trimmed, UriKind.Absolute, out var uri))
        {
            return null;
        }

        var scheme = uri.Scheme.ToLowerInvariant();
        if (scheme is not ("http" or "https" or "ftp"))
        {
            return null;
        }

        var host = uri.Host.TrimEnd('.').ToLowerInvariant();
        if (string.IsNullOrEmpty(host))
        {
            return null;
        }

        // Entourer les adresses IPv6 littérales entre crochets
        if (uri.HostNameType == UriHostNameType.IPv6 && !host.StartsWith('['))
        {
            host = $"[{host}]";
        }

        var portPart = uri.IsDefaultPort ? string.Empty : ":" + uri.Port.ToString(CultureInfo.InvariantCulture);
        var path = uri.AbsolutePath.TrimEnd('/');
        var query = uri.Query;

        return string.Concat(scheme, "://", host, portPart, path, query).ToLowerInvariant();
    }

    /// <summary>Retourne l'URL équivalente avec le schéma alternatif (<c>http</c> ↔ <c>https</c>).</summary>
    public static string? TryGetAlternateSchemeUrl(string normalizedUrl)
    {
        if (normalizedUrl.StartsWith("https://", StringComparison.Ordinal))
        {
            return "http://" + normalizedUrl["https://".Length..];
        }

        if (normalizedUrl.StartsWith("http://", StringComparison.Ordinal))
        {
            return "https://" + normalizedUrl["http://".Length..];
        }

        return null;
    }

    /// <summary>Normalise une adresse IPv4 ou IPv6 (en retirant un éventuel port, ex. <c>ip:port</c>).</summary>
    public static string? NormalizeIp(string? ip)
    {
        if (string.IsNullOrWhiteSpace(ip))
        {
            return null;
        }

        var candidate = ip.Trim();

        // Format [ipv6]:port
        if (candidate.StartsWith('['))
        {
            var closeBracket = candidate.IndexOf(']');
            if (closeBracket > 1)
            {
                candidate = candidate[1..closeBracket];
            }
        }
        else
        {
            // Format ipv4:port (un seul ':')
            var firstColon = candidate.IndexOf(':');
            if (firstColon > 0 && candidate.IndexOf(':', firstColon + 1) < 0)
            {
                candidate = candidate[..firstColon];
            }
        }

        if (!IPAddress.TryParse(candidate, out var parsed))
        {
            return null;
        }

        if (parsed.IsIPv4MappedToIPv6)
        {
            parsed = parsed.MapToIPv4();
        }

        return parsed.ToString().ToLowerInvariant();
    }
}

/// <summary>Calcul déterministe du score suggéré (90–96) et des justifications datées Threat Intelligence.</summary>
public static class ThreatIntelScoring
{
    /// <summary>Calcule un score immédiat élevé dans la bande critique/haute [90, 96].</summary>
    public static int ComputeSuggestedScore(string indicatorType, int confidence, string? source = null)
    {
        var baseScore = indicatorType switch
        {
            IndicatorTypes.Hash => 94,
            IndicatorTypes.Ip => 92,
            IndicatorTypes.Url => 92,
            IndicatorTypes.Domain => 91,
            _ => 90
        };

        var bonus = confidence switch
        {
            >= 95 => 2,
            >= 85 => 1,
            >= 70 => 0,
            _ => -1
        };

        if (string.Equals(source, ThreatIntelFeedNames.MalwareBazaar, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(source, ThreatIntelFeedNames.FeodoTracker, StringComparison.OrdinalIgnoreCase))
        {
            bonus = Math.Max(bonus, 1);
        }

        return Math.Clamp(baseScore + bonus, 90, 96);
    }

    /// <summary>
    /// Formate une justification explicite et datée, par exemple :
    /// « URL listée par URLhaus le 2026-11-20 (malware_download) ».
    /// </summary>
    public static string FormatJustification(
        string indicatorType,
        string source,
        DateTimeOffset firstSeenUtc,
        string? threatType,
        string? matchedParent = null)
    {
        var subject = indicatorType switch
        {
            IndicatorTypes.Hash => "Hash SHA-256 listé",
            IndicatorTypes.Url => "URL listée",
            IndicatorTypes.Domain => "Domaine listé",
            IndicatorTypes.Ip => "Adresse IP listée",
            _ => "Indicateur listé"
        };

        var dateText = firstSeenUtc.ToUniversalTime().ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        var threatPart = string.IsNullOrWhiteSpace(threatType) ? string.Empty : $" ({threatType})";
        var parentPart = string.IsNullOrWhiteSpace(matchedParent) ? string.Empty : $" [domaine parent : {matchedParent}]";

        return $"{subject} par {source} le {dateText}{threatPart}{parentPart}";
    }

    /// <summary>Construit un <see cref="ThreatIntelMatch"/> à partir d'un indicateur persisté.</summary>
    public static ThreatIntelMatch ToMatch(ThreatIntelIndicator indicator, string? matchedParent = null)
    {
        var score = ComputeSuggestedScore(indicator.Type, indicator.Confidence, indicator.Source);
        var justification = FormatJustification(
            indicator.Type,
            indicator.Source,
            indicator.FirstSeenUtc,
            indicator.ThreatType,
            matchedParent);

        return new ThreatIntelMatch(
            indicator.Type,
            indicator.Value,
            indicator.Source,
            indicator.ThreatType,
            indicator.FirstSeenUtc,
            indicator.LastSeenUtc,
            indicator.ExpiresAtUtc,
            indicator.Confidence,
            score,
            justification,
            matchedParent);
    }
}
