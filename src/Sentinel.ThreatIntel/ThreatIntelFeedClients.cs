using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Polly;
using Polly.CircuitBreaker;
using Polly.Retry;
using Polly.Timeout;
using Sentinel.Shared.Api;

namespace Sentinel.ThreatIntel;

/// <summary>
/// Clients HTTP résilients (Polly v8 : retry exponentiel avec jitter, disjoncteur, timeout strict 15 s)
/// et analyseurs pour les 4 flux abuse.ch (MalwareBazaar, URLhaus, ThreatFox, FeodoTracker),
/// OpenPhish Community, PhishTank et VirusTotal v3 (à la demande uniquement).
/// </summary>
public sealed class ThreatIntelFeedClients
{
    private const string DefaultUserAgent = "Sentinel-ThreatIntel/2.0";
    private const string DefaultPhishTankUserAgent = "phishtank/sentinel-v2";

    private readonly Func<string, HttpClient> _httpClientResolver;
    private readonly IThreatIntelSecretProvider _secretProvider;
    private readonly ThreatIntelFeedEndpoints _endpoints;
    private readonly ThreatIntelResilienceOptions _resilienceOptions;
    private readonly TimeProvider _clock;
    private readonly ILogger<ThreatIntelFeedClients> _logger;
    private readonly ConcurrentDictionary<string, ResiliencePipeline<HttpResponseMessage>> _pipelines = new(StringComparer.OrdinalIgnoreCase);

    public ThreatIntelFeedClients(
        IHttpClientFactory httpClientFactory,
        IThreatIntelSecretProvider secretProvider,
        ThreatIntelOptions? options = null,
        TimeProvider? clock = null,
        ILogger<ThreatIntelFeedClients>? logger = null)
        : this(
            name => httpClientFactory.CreateClient(name),
            secretProvider,
            options,
            clock,
            logger)
    {
        ArgumentNullException.ThrowIfNull(httpClientFactory);
    }

    /// <summary>Constructeur pratique acceptant un <see cref="HttpClient"/> injecté (idéal pour les tests unitaires).</summary>
    public ThreatIntelFeedClients(
        HttpClient httpClient,
        IThreatIntelSecretProvider secretProvider,
        ThreatIntelOptions? options = null,
        TimeProvider? clock = null,
        ILogger<ThreatIntelFeedClients>? logger = null)
        : this(
            _ => httpClient,
            secretProvider,
            options,
            clock,
            logger)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
    }

    private ThreatIntelFeedClients(
        Func<string, HttpClient> httpClientResolver,
        IThreatIntelSecretProvider secretProvider,
        ThreatIntelOptions? options,
        TimeProvider? clock,
        ILogger<ThreatIntelFeedClients>? logger)
    {
        _httpClientResolver = httpClientResolver;
        _secretProvider = secretProvider ?? throw new ArgumentNullException(nameof(secretProvider));
        var effective = options ?? new ThreatIntelOptions();
        _endpoints = effective.Endpoints ?? new ThreatIntelFeedEndpoints();
        _resilienceOptions = effective.Resilience ?? new ThreatIntelResilienceOptions();
        _clock = clock ?? TimeProvider.System;
        _logger = logger ?? NullLogger<ThreatIntelFeedClients>.Instance;
    }

    /// <summary>Retourne (ou crée) le pipeline Polly v8 dédié à une source donnée.</summary>
    public ResiliencePipeline<HttpResponseMessage> GetPipeline(string feedName) =>
        _pipelines.GetOrAdd(feedName, BuildPipeline);

    /// <summary>Télécharge et analyse le flux abuse.ch MalwareBazaar (SHA-256 récents, licence CC0).</summary>
    public async Task<ThreatIntelFeedFetchResult> FetchMalwareBazaarAsync(int ttlDays, CancellationToken ct = default)
    {
        var nowUtc = _clock.GetUtcNow();
        var authKey = _secretProvider.GetSecret(ThreatIntelSecretNames.AbuseChAuthKey);
        var content = await FetchStringResilientAsync(
            ThreatIntelFeedNames.MalwareBazaar,
            ThreatIntelHttpClientNames.Feeds,
            () => CreateAbuseChRequest(_endpoints.MalwareBazaarUrl, authKey),
            ct,
            authKey).ConfigureAwait(false);

        var indicators = ParseMalwareBazaar(content, nowUtc, ttlDays);
        return new ThreatIntelFeedFetchResult(ThreatIntelFeedNames.MalwareBazaar, ThreatIntelLicenses.AbuseChCc0, indicators, nowUtc);
    }

    /// <summary>Télécharge et analyse le flux abuse.ch URLhaus (URLs malveillantes récentes, licence CC0).</summary>
    public async Task<ThreatIntelFeedFetchResult> FetchUrlHausAsync(int ttlDays, CancellationToken ct = default)
    {
        var nowUtc = _clock.GetUtcNow();
        var authKey = _secretProvider.GetSecret(ThreatIntelSecretNames.AbuseChAuthKey);
        var content = await FetchStringResilientAsync(
            ThreatIntelFeedNames.UrlHaus,
            ThreatIntelHttpClientNames.Feeds,
            () => CreateAbuseChRequest(_endpoints.UrlHausUrl, authKey),
            ct,
            authKey).ConfigureAwait(false);

        var indicators = ParseUrlHaus(content, nowUtc, ttlDays);
        return new ThreatIntelFeedFetchResult(ThreatIntelFeedNames.UrlHaus, ThreatIntelLicenses.AbuseChCc0, indicators, nowUtc);
    }

    /// <summary>Télécharge et analyse le flux abuse.ch ThreatFox (IoC multi-types récents, licence CC0).</summary>
    public async Task<ThreatIntelFeedFetchResult> FetchThreatFoxAsync(int ttlDays, CancellationToken ct = default)
    {
        var nowUtc = _clock.GetUtcNow();
        var authKey = _secretProvider.GetSecret(ThreatIntelSecretNames.AbuseChAuthKey);
        var content = await FetchStringResilientAsync(
            ThreatIntelFeedNames.ThreatFox,
            ThreatIntelHttpClientNames.Feeds,
            () => CreateAbuseChRequest(_endpoints.ThreatFoxUrl, authKey),
            ct,
            authKey).ConfigureAwait(false);

        var indicators = ParseThreatFox(content, nowUtc, ttlDays);
        return new ThreatIntelFeedFetchResult(ThreatIntelFeedNames.ThreatFox, ThreatIntelLicenses.AbuseChCc0, indicators, nowUtc);
    }

    /// <summary>Télécharge et analyse le flux abuse.ch FeodoTracker (IPs C2 botnet, licence CC0).</summary>
    public async Task<ThreatIntelFeedFetchResult> FetchFeodoTrackerAsync(int ttlDays, CancellationToken ct = default)
    {
        var nowUtc = _clock.GetUtcNow();
        var authKey = _secretProvider.GetSecret(ThreatIntelSecretNames.AbuseChAuthKey);
        var content = await FetchStringResilientAsync(
            ThreatIntelFeedNames.FeodoTracker,
            ThreatIntelHttpClientNames.Feeds,
            () => CreateAbuseChRequest(_endpoints.FeodoTrackerUrl, authKey),
            ct,
            authKey).ConfigureAwait(false);

        var indicators = ParseFeodoTracker(content, nowUtc, ttlDays);
        return new ThreatIntelFeedFetchResult(ThreatIntelFeedNames.FeodoTracker, ThreatIntelLicenses.AbuseChCc0, indicators, nowUtc);
    }

    /// <summary>Télécharge et analyse OpenPhish Community (licence Non-Commercial Community, désactivé par défaut).</summary>
    public async Task<ThreatIntelFeedFetchResult> FetchOpenPhishAsync(int ttlDays, CancellationToken ct = default)
    {
        var nowUtc = _clock.GetUtcNow();
        var content = await FetchStringResilientAsync(
            ThreatIntelFeedNames.OpenPhish,
            ThreatIntelHttpClientNames.Feeds,
            () =>
            {
                var req = new HttpRequestMessage(HttpMethod.Get, _endpoints.OpenPhishUrl);
                req.Headers.UserAgent.ParseAdd(DefaultUserAgent);
                return req;
            },
            ct).ConfigureAwait(false);

        var indicators = ParseOpenPhish(content, nowUtc, ttlDays);
        return new ThreatIntelFeedFetchResult(ThreatIntelFeedNames.OpenPhish, ThreatIntelLicenses.OpenPhishNonCommercial, indicators, nowUtc);
    }

    /// <summary>Télécharge et analyse PhishTank (clé API et User-Agent requis, désactivé par défaut).</summary>
    public async Task<ThreatIntelFeedFetchResult> FetchPhishTankAsync(int ttlDays, CancellationToken ct = default)
    {
        var apiKey = _secretProvider.GetSecret(ThreatIntelSecretNames.PhishTankApiKey);
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            throw new InvalidOperationException("Clé API PhishTank non configurée (ThreatIntel:PhishTankApiKey).");
        }

        var userAgent = _secretProvider.GetSecret(ThreatIntelSecretNames.PhishTankUserAgent);
        if (string.IsNullOrWhiteSpace(userAgent))
        {
            userAgent = DefaultPhishTankUserAgent;
        }

        var nowUtc = _clock.GetUtcNow();
        var url = _endpoints.PhishTankUrlTemplate.Replace("{apiKey}", Uri.EscapeDataString(apiKey), StringComparison.Ordinal);

        var content = await FetchStringResilientAsync(
            ThreatIntelFeedNames.PhishTank,
            ThreatIntelHttpClientNames.Feeds,
            () =>
            {
                var req = new HttpRequestMessage(HttpMethod.Get, url);
                req.Headers.TryAddWithoutValidation("User-Agent", userAgent);
                return req;
            },
            ct,
            apiKey).ConfigureAwait(false);

        var indicators = ParsePhishTank(content, nowUtc, ttlDays);
        return new ThreatIntelFeedFetchResult(ThreatIntelFeedNames.PhishTank, ThreatIntelLicenses.PhishTankTerms, indicators, nowUtc);
    }

    /// <summary>
    /// Interroge VirusTotal v3 pour un condensat SHA-256 uniquement (GET <c>/api/v3/files/{sha256}</c>).
    /// N'envoie jamais de fichier et exige une clé API fournie via <see cref="IThreatIntelSecretProvider"/>.
    /// </summary>
    public async Task<ThreatIntelLookupDto?> QueryVirusTotalHashAsync(string sha256, CancellationToken ct = default)
    {
        var normalized = IndicatorNormalizer.NormalizeHash(sha256);
        if (normalized is null)
        {
            return null;
        }

        var apiKey = _secretProvider.GetSecret(ThreatIntelSecretNames.VirusTotalApiKey);
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            return null;
        }

        var startTs = Stopwatch.GetTimestamp();
        var url = _endpoints.VirusTotalFileUrlTemplate.Replace("{sha256}", normalized, StringComparison.Ordinal);
        var client = _httpClientResolver(ThreatIntelHttpClientNames.VirusTotal);
        var pipeline = GetPipeline(ThreatIntelFeedNames.VirusTotal);

        using var response = await pipeline.ExecuteAsync(
            async token =>
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, url);
                req.Headers.TryAddWithoutValidation("x-apikey", apiKey);
                req.Headers.TryAddWithoutValidation("Accept", "application/json");
                req.Headers.UserAgent.ParseAdd(DefaultUserAgent);
                return await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, token).ConfigureAwait(false);
            },
            ct).ConfigureAwait(false);

        var elapsedMs = Math.Round(Stopwatch.GetElapsedTime(startTs).TotalMilliseconds, 4);

        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return new ThreatIntelLookupDto(
                Found: false,
                IndicatorType: IndicatorTypes.Hash,
                Indicator: normalized,
                Source: ThreatIntelFeedNames.VirusTotal,
                ThreatType: null,
                FirstSeen: null,
                ExpiresAt: null,
                SuggestedScore: 0,
                Justification: "Hash SHA-256 inconnu de VirusTotal.",
                ElapsedMs: elapsedMs);
        }

        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException(
                $"Erreur HTTP VirusTotal ({(int)response.StatusCode} {response.ReasonPhrase}).",
                inner: null,
                statusCode: response.StatusCode);
        }

        var json = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        return ParseVirusTotalResponse(normalized, json, _clock.GetUtcNow(), elapsedMs);
    }

    // -------------------------------------------------------------------------
    //  Analyseurs déterministes des flux (publics pour testabilité directe)
    // -------------------------------------------------------------------------

    /// <summary>Analyse le format texte (SHA-256 par ligne), CSV ou JSON API de MalwareBazaar.</summary>
    public static IReadOnlyList<ThreatIntelIndicator> ParseMalwareBazaar(string content, DateTimeOffset nowUtc, int ttlDays = 30)
    {
        var results = new List<ThreatIntelIndicator>();
        if (string.IsNullOrWhiteSpace(content))
        {
            return results;
        }

        var ttl = TimeSpan.FromDays(Math.Max(ttlDays, 1));
        var trimmed = content.TrimStart();

        // Format API JSON ({"query_status":"ok","data":[...]})
        if (trimmed.StartsWith('{'))
        {
            try
            {
                using var doc = JsonDocument.Parse(trimmed);
                if (doc.RootElement.TryGetProperty("data", out var data) && data.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in data.EnumerateArray())
                    {
                        var rawHash = TryGetJsonString(item, "sha256_hash");
                        var hash = IndicatorNormalizer.NormalizeHash(rawHash);
                        if (hash is null)
                        {
                            continue;
                        }

                        var firstSeen = ParseUtcTimestamp(TryGetJsonString(item, "first_seen"), nowUtc);
                        var signature = TryGetJsonString(item, "signature");
                        var fileType = TryGetJsonString(item, "file_type");
                        var threatType = !string.IsNullOrWhiteSpace(signature)
                            ? signature
                            : !string.IsNullOrWhiteSpace(fileType)
                                ? $"malware_{fileType}"
                                : "malware_sample";

                        results.Add(new ThreatIntelIndicator(
                            IndicatorTypes.Hash,
                            hash,
                            ThreatIntelFeedNames.MalwareBazaar,
                            threatType,
                            firstSeen,
                            nowUtc,
                            nowUtc + ttl,
                            Confidence: 95));
                    }
                }
            }
            catch (JsonException)
            {
                // JSON invalide ignoré
            }

            return results;
        }

        // Format texte (1 SHA-256 par ligne) ou CSV récent MalwareBazaar
        var seen = new HashSet<string>(StringComparer.Ordinal);
        using var reader = new StringReader(content);
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            var clean = line.Trim();
            if (clean.Length == 0 || clean.StartsWith('#'))
            {
                continue;
            }

            if (clean.Contains(','))
            {
                var fields = ParseCsvLine(clean);
                if (fields.Count < 2 || fields[0].Equals("first_seen_utc", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var hash = IndicatorNormalizer.NormalizeHash(fields[1]);
                if (hash is null || !seen.Add(hash))
                {
                    continue;
                }

                var firstSeen = ParseUtcTimestamp(fields[0], nowUtc);
                var signature = fields.Count > 8 ? fields[8].Trim() : string.Empty;
                var threatType = !string.IsNullOrWhiteSpace(signature) && !signature.Equals("n/a", StringComparison.OrdinalIgnoreCase)
                    ? signature
                    : "malware_sample";

                results.Add(new ThreatIntelIndicator(
                    IndicatorTypes.Hash,
                    hash,
                    ThreatIntelFeedNames.MalwareBazaar,
                    threatType,
                    firstSeen,
                    nowUtc,
                    nowUtc + ttl,
                    Confidence: 95));
            }
            else
            {
                var hash = IndicatorNormalizer.NormalizeHash(clean);
                if (hash is null || !seen.Add(hash))
                {
                    continue;
                }

                results.Add(new ThreatIntelIndicator(
                    IndicatorTypes.Hash,
                    hash,
                    ThreatIntelFeedNames.MalwareBazaar,
                    "malware_sample",
                    nowUtc,
                    nowUtc,
                    nowUtc + ttl,
                    Confidence: 95));
            }
        }

        return results;
    }

    /// <summary>Analyse le flux CSV récent ou JSON d'abuse.ch URLhaus.</summary>
    public static IReadOnlyList<ThreatIntelIndicator> ParseUrlHaus(string content, DateTimeOffset nowUtc, int ttlDays = 30)
    {
        var results = new List<ThreatIntelIndicator>();
        if (string.IsNullOrWhiteSpace(content))
        {
            return results;
        }

        var ttl = TimeSpan.FromDays(Math.Max(ttlDays, 1));
        var trimmed = content.TrimStart();

        if (trimmed.StartsWith('{'))
        {
            try
            {
                using var doc = JsonDocument.Parse(trimmed);
                if (doc.RootElement.TryGetProperty("urls", out var urls) && urls.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in urls.EnumerateArray())
                    {
                        var normalizedUrl = IndicatorNormalizer.NormalizeUrl(TryGetJsonString(item, "url"));
                        if (normalizedUrl is null)
                        {
                            continue;
                        }

                        var firstSeen = ParseUtcTimestamp(TryGetJsonString(item, "date_added") ?? TryGetJsonString(item, "dateadded"), nowUtc);
                        var threat = TryGetJsonString(item, "threat");
                        var status = TryGetJsonString(item, "url_status");
                        var confidence = string.Equals(status, "online", StringComparison.OrdinalIgnoreCase) ? 95 : 88;

                        results.Add(new ThreatIntelIndicator(
                            IndicatorTypes.Url,
                            normalizedUrl,
                            ThreatIntelFeedNames.UrlHaus,
                            string.IsNullOrWhiteSpace(threat) ? "malware_download" : threat.Trim(),
                            firstSeen,
                            nowUtc,
                            nowUtc + ttl,
                            confidence));
                    }
                }
            }
            catch (JsonException)
            {
                // JSON invalide ignoré
            }

            return results;
        }

        // CSV URLhaus : id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
        using var reader = new StringReader(content);
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            var clean = line.Trim();
            if (clean.Length == 0 || clean.StartsWith('#'))
            {
                continue;
            }

            var fields = ParseCsvLine(clean);
            if (fields.Count < 6 || fields[0].Equals("id", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var normalizedUrl = IndicatorNormalizer.NormalizeUrl(fields[2]);
            if (normalizedUrl is null)
            {
                continue;
            }

            var firstSeen = ParseUtcTimestamp(fields[1], nowUtc);
            var urlStatus = fields[3].Trim();
            var lastSeen = ParseUtcTimestamp(fields[4], firstSeen);
            var threat = fields[5].Trim();
            var confidence = string.Equals(urlStatus, "online", StringComparison.OrdinalIgnoreCase) ? 95 : 88;

            results.Add(new ThreatIntelIndicator(
                IndicatorTypes.Url,
                normalizedUrl,
                ThreatIntelFeedNames.UrlHaus,
                string.IsNullOrWhiteSpace(threat) ? "malware_download" : threat,
                firstSeen,
                lastSeen > firstSeen ? lastSeen : nowUtc,
                nowUtc + ttl,
                confidence));
        }

        return results;
    }

    /// <summary>Analyse le flux CSV récent ou JSON d'abuse.ch ThreatFox (hash SHA-256, domaine, URL, IP:port).</summary>
    public static IReadOnlyList<ThreatIntelIndicator> ParseThreatFox(string content, DateTimeOffset nowUtc, int ttlDays = 30)
    {
        var results = new List<ThreatIntelIndicator>();
        if (string.IsNullOrWhiteSpace(content))
        {
            return results;
        }

        var ttl = TimeSpan.FromDays(Math.Max(ttlDays, 1));
        var trimmed = content.TrimStart();

        if (trimmed.StartsWith('{'))
        {
            try
            {
                using var doc = JsonDocument.Parse(trimmed);
                if (doc.RootElement.TryGetProperty("data", out var data) && data.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in data.EnumerateArray())
                    {
                        var iocValue = TryGetJsonString(item, "ioc") ?? TryGetJsonString(item, "ioc_value");
                        var iocType = TryGetJsonString(item, "ioc_type");
                        var threatType = TryGetJsonString(item, "threat_type");
                        var malware = TryGetJsonString(item, "malware_printable");
                        var firstSeen = ParseUtcTimestamp(TryGetJsonString(item, "first_seen") ?? TryGetJsonString(item, "first_seen_utc"), nowUtc);
                        var lastSeen = ParseUtcTimestamp(TryGetJsonString(item, "last_seen") ?? TryGetJsonString(item, "last_seen_utc"), nowUtc);
                        var confidence = TryGetJsonInt(item, "confidence_level") ?? 85;

                        if (TryBuildThreatFoxIndicator(iocType, iocValue, threatType, malware, firstSeen, lastSeen, nowUtc + ttl, confidence, out var indicator))
                        {
                            results.Add(indicator!);
                        }
                    }
                }
            }
            catch (JsonException)
            {
                // JSON invalide ignoré
            }

            return results;
        }

        // CSV ThreatFox : first_seen_utc,ioc_id,ioc_value,ioc_type,threat_type,fk_malware,malware_alias,malware_printable,last_seen_utc,confidence_level,...
        using var reader = new StringReader(content);
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            var clean = line.Trim();
            if (clean.Length == 0 || clean.StartsWith('#'))
            {
                continue;
            }

            var fields = ParseCsvLine(clean);
            if (fields.Count < 6 || fields[0].Equals("first_seen_utc", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var firstSeen = ParseUtcTimestamp(fields[0], nowUtc);
            var iocValue = fields[2].Trim();
            var iocType = fields[3].Trim();
            var threatType = fields[4].Trim();
            var malware = fields.Count > 7 ? fields[7].Trim() : string.Empty;
            var lastSeen = fields.Count > 8 ? ParseUtcTimestamp(fields[8], nowUtc) : nowUtc;
            var confidence = fields.Count > 9 && int.TryParse(fields[9].Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var c)
                ? c
                : 85;

            if (TryBuildThreatFoxIndicator(iocType, iocValue, threatType, malware, firstSeen, lastSeen, nowUtc + ttl, confidence, out var indicator))
            {
                results.Add(indicator!);
            }
        }

        return results;
    }

    private static bool TryBuildThreatFoxIndicator(
        string? iocType,
        string? iocValue,
        string? threatType,
        string? malwarePrintable,
        DateTimeOffset firstSeenUtc,
        DateTimeOffset lastSeenUtc,
        DateTimeOffset expiresAtUtc,
        int confidence,
        out ThreatIntelIndicator? indicator)
    {
        indicator = null;
        if (string.IsNullOrWhiteSpace(iocType) || string.IsNullOrWhiteSpace(iocValue))
        {
            return false;
        }

        string? canonicalType;
        string? normalizedValue;

        switch (iocType.Trim().ToLowerInvariant())
        {
            case "sha256_hash":
            case "sha256":
                canonicalType = IndicatorTypes.Hash;
                normalizedValue = IndicatorNormalizer.NormalizeHash(iocValue);
                break;
            case "domain":
                canonicalType = IndicatorTypes.Domain;
                normalizedValue = IndicatorNormalizer.NormalizeDomain(iocValue);
                break;
            case "url":
                canonicalType = IndicatorTypes.Url;
                normalizedValue = IndicatorNormalizer.NormalizeUrl(iocValue);
                break;
            case "ip:port":
            case "ip":
                canonicalType = IndicatorTypes.Ip;
                normalizedValue = IndicatorNormalizer.NormalizeIp(iocValue);
                break;
            default:
                return false;
        }

        if (normalizedValue is null)
        {
            return false;
        }

        var cleanThreat = string.IsNullOrWhiteSpace(threatType) ? "malicious_ioc" : threatType.Trim();
        var cleanMalware = !string.IsNullOrWhiteSpace(malwarePrintable) &&
                           !malwarePrintable.Equals("Unknown malware", StringComparison.OrdinalIgnoreCase) &&
                           !malwarePrintable.Equals("None", StringComparison.OrdinalIgnoreCase)
            ? malwarePrintable.Trim()
            : null;

        var combinedThreat = cleanMalware is not null ? $"{cleanThreat} - {cleanMalware}" : cleanThreat;

        indicator = new ThreatIntelIndicator(
            canonicalType,
            normalizedValue,
            ThreatIntelFeedNames.ThreatFox,
            combinedThreat,
            firstSeenUtc,
            lastSeenUtc >= firstSeenUtc ? lastSeenUtc : firstSeenUtc,
            expiresAtUtc,
            Math.Clamp(confidence, 1, 100));

        return true;
    }

    /// <summary>Analyse la liste recommandée d'adresses IP C2 FeodoTracker (texte brut ou CSV).</summary>
    public static IReadOnlyList<ThreatIntelIndicator> ParseFeodoTracker(string content, DateTimeOffset nowUtc, int ttlDays = 30)
    {
        var results = new List<ThreatIntelIndicator>();
        if (string.IsNullOrWhiteSpace(content))
        {
            return results;
        }

        var ttl = TimeSpan.FromDays(Math.Max(ttlDays, 1));
        var headerDate = nowUtc;
        var seen = new HashSet<string>(StringComparer.Ordinal);

        using var reader = new StringReader(content);
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            var clean = line.Trim();
            if (clean.Length == 0)
            {
                continue;
            }

            if (clean.StartsWith('#'))
            {
                const string prefix = "# Last updated:";
                if (clean.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    headerDate = ParseUtcTimestamp(clean[prefix.Length..].Trim(), headerDate);
                }
                continue;
            }

            if (clean.Contains(','))
            {
                var fields = ParseCsvLine(clean);
                if (fields.Count < 2 || fields[0].Equals("first_seen", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var ip = IndicatorNormalizer.NormalizeIp(fields[1]);
                if (ip is null || !seen.Add(ip))
                {
                    continue;
                }

                var firstSeen = ParseUtcTimestamp(fields[0], headerDate);
                var malware = fields.Count > 5 && !string.IsNullOrWhiteSpace(fields[5])
                    ? $"botnet_c2 - {fields[5].Trim()}"
                    : "botnet_c2";

                results.Add(new ThreatIntelIndicator(
                    IndicatorTypes.Ip,
                    ip,
                    ThreatIntelFeedNames.FeodoTracker,
                    malware,
                    firstSeen,
                    nowUtc,
                    nowUtc + ttl,
                    Confidence: 95));
            }
            else
            {
                var ip = IndicatorNormalizer.NormalizeIp(clean);
                if (ip is null || !seen.Add(ip))
                {
                    continue;
                }

                results.Add(new ThreatIntelIndicator(
                    IndicatorTypes.Ip,
                    ip,
                    ThreatIntelFeedNames.FeodoTracker,
                    "botnet_c2",
                    headerDate,
                    nowUtc,
                    nowUtc + ttl,
                    Confidence: 95));
            }
        }

        return results;
    }

    /// <summary>Analyse le flux OpenPhish Community (une URL de phishing par ligne).</summary>
    public static IReadOnlyList<ThreatIntelIndicator> ParseOpenPhish(string content, DateTimeOffset nowUtc, int ttlDays = 30)
    {
        var results = new List<ThreatIntelIndicator>();
        if (string.IsNullOrWhiteSpace(content))
        {
            return results;
        }

        var ttl = TimeSpan.FromDays(Math.Max(ttlDays, 1));
        var seen = new HashSet<string>(StringComparer.Ordinal);

        using var reader = new StringReader(content);
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            var clean = line.Trim();
            if (clean.Length == 0 || clean.StartsWith('#'))
            {
                continue;
            }

            var normalizedUrl = IndicatorNormalizer.NormalizeUrl(clean);
            if (normalizedUrl is null || !seen.Add(normalizedUrl))
            {
                continue;
            }

            results.Add(new ThreatIntelIndicator(
                IndicatorTypes.Url,
                normalizedUrl,
                ThreatIntelFeedNames.OpenPhish,
                "phishing",
                nowUtc,
                nowUtc,
                nowUtc + ttl,
                Confidence: 90));
        }

        return results;
    }

    /// <summary>Analyse le flux PhishTank JSON (<c>online-valid.json</c>) ou CSV.</summary>
    public static IReadOnlyList<ThreatIntelIndicator> ParsePhishTank(string content, DateTimeOffset nowUtc, int ttlDays = 30)
    {
        var results = new List<ThreatIntelIndicator>();
        if (string.IsNullOrWhiteSpace(content))
        {
            return results;
        }

        var ttl = TimeSpan.FromDays(Math.Max(ttlDays, 1));
        var trimmed = content.TrimStart();

        if (trimmed.StartsWith('['))
        {
            try
            {
                using var doc = JsonDocument.Parse(trimmed);
                foreach (var item in doc.RootElement.EnumerateArray())
                {
                    var verified = TryGetJsonString(item, "verified");
                    var online = TryGetJsonString(item, "online");
                    if (string.Equals(verified, "no", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(online, "no", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    var normalizedUrl = IndicatorNormalizer.NormalizeUrl(TryGetJsonString(item, "url"));
                    if (normalizedUrl is null)
                    {
                        continue;
                    }

                    var firstSeen = ParseUtcTimestamp(
                        TryGetJsonString(item, "verification_time") ?? TryGetJsonString(item, "submission_time"),
                        nowUtc);

                    var target = TryGetJsonString(item, "target");
                    var threat = !string.IsNullOrWhiteSpace(target) && !target.Equals("Other", StringComparison.OrdinalIgnoreCase)
                        ? $"phishing ({target.Trim()})"
                        : "phishing";

                    results.Add(new ThreatIntelIndicator(
                        IndicatorTypes.Url,
                        normalizedUrl,
                        ThreatIntelFeedNames.PhishTank,
                        threat,
                        firstSeen,
                        nowUtc,
                        nowUtc + ttl,
                        Confidence: 92));
                }
            }
            catch (JsonException)
            {
                // JSON invalide ignoré
            }

            return results;
        }

        // CSV PhishTank : phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target
        using var reader = new StringReader(content);
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            var clean = line.Trim();
            if (clean.Length == 0 || clean.StartsWith('#'))
            {
                continue;
            }

            var fields = ParseCsvLine(clean);
            if (fields.Count < 7 || fields[0].Equals("phish_id", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (fields[4].Equals("no", StringComparison.OrdinalIgnoreCase) ||
                fields[6].Equals("no", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var normalizedUrl = IndicatorNormalizer.NormalizeUrl(fields[1]);
            if (normalizedUrl is null)
            {
                continue;
            }

            var firstSeen = ParseUtcTimestamp(
                !string.IsNullOrWhiteSpace(fields[5]) ? fields[5] : fields[3],
                nowUtc);
            var target = fields.Count > 7 ? fields[7].Trim() : string.Empty;
            var threat = !string.IsNullOrWhiteSpace(target) && !target.Equals("Other", StringComparison.OrdinalIgnoreCase)
                ? $"phishing ({target})"
                : "phishing";

            results.Add(new ThreatIntelIndicator(
                IndicatorTypes.Url,
                normalizedUrl,
                ThreatIntelFeedNames.PhishTank,
                threat,
                firstSeen,
                nowUtc,
                nowUtc + ttl,
                Confidence: 92));
        }

        return results;
    }

    /// <summary>Analyse la réponse JSON VirusTotal API v3 (<c>/api/v3/files/{sha256}</c>).</summary>
    public static ThreatIntelLookupDto ParseVirusTotalResponse(
        string normalizedSha256,
        string json,
        DateTimeOffset nowUtc,
        double elapsedMs)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        if (!root.TryGetProperty("data", out var data) ||
            !data.TryGetProperty("attributes", out var attrs))
        {
            return new ThreatIntelLookupDto(
                Found: false,
                IndicatorType: IndicatorTypes.Hash,
                Indicator: normalizedSha256,
                Source: ThreatIntelFeedNames.VirusTotal,
                ThreatType: null,
                FirstSeen: null,
                ExpiresAt: null,
                SuggestedScore: 0,
                Justification: "Réponse VirusTotal incomplète pour le hash SHA-256.",
                ElapsedMs: elapsedMs);
        }

        int malicious = 0, suspicious = 0, undetected = 0, harmless = 0;
        if (attrs.TryGetProperty("last_analysis_stats", out var stats) && stats.ValueKind == JsonValueKind.Object)
        {
            malicious = TryGetJsonInt(stats, "malicious") ?? 0;
            suspicious = TryGetJsonInt(stats, "suspicious") ?? 0;
            undetected = TryGetJsonInt(stats, "undetected") ?? 0;
            harmless = TryGetJsonInt(stats, "harmless") ?? 0;
        }

        var total = malicious + suspicious + undetected + harmless;

        DateTimeOffset firstSeen = nowUtc;
        if (TryGetJsonLong(attrs, "first_submission_date") is { } firstUnix && firstUnix > 0)
        {
            firstSeen = DateTimeOffset.FromUnixTimeSeconds(firstUnix);
        }
        else if (TryGetJsonLong(attrs, "last_analysis_date") is { } lastUnix && lastUnix > 0)
        {
            firstSeen = DateTimeOffset.FromUnixTimeSeconds(lastUnix);
        }

        string? threatLabel = null;
        if (attrs.TryGetProperty("popular_threat_classification", out var classification) &&
            classification.ValueKind == JsonValueKind.Object)
        {
            threatLabel = TryGetJsonString(classification, "suggested_threat_label");
        }

        if (malicious <= 0)
        {
            return new ThreatIntelLookupDto(
                Found: false,
                IndicatorType: IndicatorTypes.Hash,
                Indicator: normalizedSha256,
                Source: ThreatIntelFeedNames.VirusTotal,
                ThreatType: null,
                FirstSeen: firstSeen,
                ExpiresAt: null,
                SuggestedScore: 0,
                Justification: $"Hash SHA-256 non signalé comme malveillant sur VirusTotal (0/{total} détection).",
                ElapsedMs: elapsedMs);
        }

        var label = string.IsNullOrWhiteSpace(threatLabel) ? "malware" : threatLabel.Trim();
        var score = malicious >= 10 ? 96 : malicious >= 5 ? 94 : malicious >= 2 ? 92 : 90;
        var threatSummary = $"{label}, {malicious}/{total} moteurs";
        var justification = ThreatIntelScoring.FormatJustification(
            IndicatorTypes.Hash,
            ThreatIntelFeedNames.VirusTotal,
            firstSeen,
            threatSummary);

        return new ThreatIntelLookupDto(
            Found: true,
            IndicatorType: IndicatorTypes.Hash,
            Indicator: normalizedSha256,
            Source: ThreatIntelFeedNames.VirusTotal,
            ThreatType: label,
            FirstSeen: firstSeen,
            ExpiresAt: null,
            SuggestedScore: score,
            Justification: justification,
            ElapsedMs: elapsedMs);
    }

    // -------------------------------------------------------------------------
    //  Polly v8 & utilitaires HTTP / CSV
    // -------------------------------------------------------------------------

    private HttpRequestMessage CreateAbuseChRequest(string url, string? authKey)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, url);
        req.Headers.UserAgent.ParseAdd(DefaultUserAgent);
        if (!string.IsNullOrWhiteSpace(authKey))
        {
            req.Headers.TryAddWithoutValidation("Auth-Key", authKey);
        }
        return req;
    }

    private async Task<string> FetchStringResilientAsync(
        string feedName,
        string clientName,
        Func<HttpRequestMessage> requestFactory,
        CancellationToken ct,
        string? secretToRedact = null)
    {
        var client = _httpClientResolver(clientName);
        var pipeline = GetPipeline(feedName);

        try
        {
            using var response = await pipeline.ExecuteAsync(
                async token =>
                {
                    using var req = requestFactory();
                    return await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, token).ConfigureAwait(false);
                },
                ct).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                throw new HttpRequestException(
                    $"Erreur HTTP sur le flux {feedName} ({(int)response.StatusCode} {response.ReasonPhrase}).",
                    inner: null,
                    statusCode: response.StatusCode);
            }

            return await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            var safeMessage = RedactSecret(ex.Message, secretToRedact);
            _logger.LogWarning("Échec de récupération du flux {FeedName} : {Error}", feedName, safeMessage);
            if (!ReferenceEquals(safeMessage, ex.Message))
            {
                throw new HttpRequestException(safeMessage);
            }
            throw;
        }
    }

    private ResiliencePipeline<HttpResponseMessage> BuildPipeline(string feedName)
    {
        var opts = _resilienceOptions;
        var builder = new ResiliencePipelineBuilder<HttpResponseMessage>();

        static bool IsTransientStatus(HttpResponseMessage response) =>
            (int)response.StatusCode >= 500 ||
            response.StatusCode == HttpStatusCode.RequestTimeout ||
            response.StatusCode == HttpStatusCode.TooManyRequests;

        var transientPredicate = new PredicateBuilder<HttpResponseMessage>()
            .Handle<HttpRequestException>()
            .Handle<TimeoutRejectedException>()
            .HandleResult(IsTransientStatus);

        // 1. Retry exponentiel avec jitter (externe)
        if (opts.MaxRetryAttempts > 0)
        {
            builder.AddRetry(new RetryStrategyOptions<HttpResponseMessage>
            {
                MaxRetryAttempts = opts.MaxRetryAttempts,
                BackoffType = DelayBackoffType.Exponential,
                UseJitter = true,
                Delay = opts.RetryBaseDelay >= TimeSpan.Zero ? opts.RetryBaseDelay : TimeSpan.FromMilliseconds(500),
                ShouldHandle = transientPredicate,
                OnRetry = args =>
                {
                    args.Outcome.Result?.Dispose();
                    _logger.LogDebug(
                        "Nouvelle tentative ({Attempt}/{Max}) pour le flux {FeedName} après {DelayMs} ms.",
                        args.AttemptNumber + 1,
                        opts.MaxRetryAttempts,
                        feedName,
                        Math.Round(args.RetryDelay.TotalMilliseconds, 1));
                    return ValueTask.CompletedTask;
                }
            });
        }

        // 2. Disjoncteur sur échecs consécutifs (intermédiaire)
        var minThroughput = Math.Max(2, opts.CircuitBreakerMinimumThroughput);
        var failureRatio = Math.Clamp(opts.CircuitBreakerFailureRatio, 0.05, 1.0);
        var samplingDuration = opts.CircuitBreakerSamplingDuration >= TimeSpan.FromMilliseconds(500)
            ? opts.CircuitBreakerSamplingDuration
            : TimeSpan.FromMilliseconds(500);
        var breakDuration = opts.CircuitBreakerBreakDuration >= TimeSpan.FromMilliseconds(500)
            ? opts.CircuitBreakerBreakDuration
            : TimeSpan.FromMilliseconds(500);

        builder.AddCircuitBreaker(new CircuitBreakerStrategyOptions<HttpResponseMessage>
        {
            FailureRatio = failureRatio,
            MinimumThroughput = minThroughput,
            SamplingDuration = samplingDuration,
            BreakDuration = breakDuration,
            ShouldHandle = transientPredicate,
            OnOpened = args =>
            {
                _logger.LogWarning(
                    "Disjoncteur ouvert pour le flux {FeedName} pendant {BreakSeconds} s.",
                    feedName,
                    args.BreakDuration.TotalSeconds);
                return ValueTask.CompletedTask;
            }
        });

        // 3. Timeout strict par tentative HTTP (interne, défaut 15 s)
        var timeout = opts.RequestTimeout >= TimeSpan.FromMilliseconds(10)
            ? opts.RequestTimeout
            : TimeSpan.FromSeconds(15);

        builder.AddTimeout(new TimeoutStrategyOptions
        {
            Timeout = timeout
        });

        return builder.Build();
    }

    internal static string RedactSecret(string message, string? secret)
    {
        if (string.IsNullOrWhiteSpace(message) || string.IsNullOrWhiteSpace(secret))
        {
            return message;
        }

        var redacted = message.Replace(secret, "[REDACTED]", StringComparison.Ordinal);
        var escaped = Uri.EscapeDataString(secret);
        if (!string.Equals(escaped, secret, StringComparison.Ordinal))
        {
            redacted = redacted.Replace(escaped, "[REDACTED]", StringComparison.Ordinal);
        }
        return redacted;
    }

    /// <summary>Analyseur CSV RFC 4180 tolérant les espaces hors guillemets (format ThreatFox <c>", "</c>).</summary>
    internal static List<string> ParseCsvLine(string line)
    {
        var fields = new List<string>(16);
        var sb = new StringBuilder();
        var i = 0;
        var n = line.Length;

        while (i <= n)
        {
            while (i < n && line[i] is ' ' or '\t')
            {
                i++;
            }

            sb.Clear();
            if (i < n && line[i] == '"')
            {
                i++;
                while (i < n)
                {
                    if (line[i] == '"')
                    {
                        if (i + 1 < n && line[i + 1] == '"')
                        {
                            sb.Append('"');
                            i += 2;
                        }
                        else
                        {
                            i++;
                            break;
                        }
                    }
                    else
                    {
                        sb.Append(line[i++]);
                    }
                }

                while (i < n && line[i] != ',')
                {
                    i++;
                }
            }
            else
            {
                while (i < n && line[i] != ',')
                {
                    sb.Append(line[i++]);
                }

                while (sb.Length > 0 && sb[^1] is ' ' or '\t')
                {
                    sb.Length--;
                }
            }

            fields.Add(sb.ToString());

            if (i < n && line[i] == ',')
            {
                i++;
                if (i == n)
                {
                    fields.Add(string.Empty);
                    break;
                }
            }
            else
            {
                break;
            }
        }

        return fields;
    }

    private static DateTimeOffset ParseUtcTimestamp(string? raw, DateTimeOffset fallback)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return fallback;
        }

        var cleaned = raw.Trim();
        if (cleaned.Equals("None", StringComparison.OrdinalIgnoreCase) ||
            cleaned.Equals("null", StringComparison.OrdinalIgnoreCase))
        {
            return fallback;
        }

        if (cleaned.EndsWith(" UTC", StringComparison.OrdinalIgnoreCase))
        {
            cleaned = cleaned[..^4].TrimEnd();
        }

        return DateTimeOffset.TryParse(
            cleaned,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out var parsed)
            ? parsed
            : fallback;
    }

    private static string? TryGetJsonString(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var prop))
        {
            return null;
        }

        return prop.ValueKind switch
        {
            JsonValueKind.String => prop.GetString(),
            JsonValueKind.Number => prop.GetRawText(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            _ => null
        };
    }

    private static int? TryGetJsonInt(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var prop))
        {
            return null;
        }

        if (prop.ValueKind == JsonValueKind.Number && prop.TryGetInt32(out var val))
        {
            return val;
        }

        if (prop.ValueKind == JsonValueKind.String &&
            int.TryParse(prop.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed))
        {
            return parsed;
        }

        return null;
    }

    private static long? TryGetJsonLong(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var prop))
        {
            return null;
        }

        if (prop.ValueKind == JsonValueKind.Number && prop.TryGetInt64(out var val))
        {
            return val;
        }

        return null;
    }
}
