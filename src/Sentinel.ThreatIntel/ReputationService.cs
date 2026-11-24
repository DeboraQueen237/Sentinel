using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Shared.Api;
using Sentinel.Shared.Models;

namespace Sentinel.ThreatIntel;

/// <summary>
/// Implémentation thread-safe de <see cref="IReputationService"/> :
/// recherches locales ultra-rapides via filtre de Bloom + SQLite indexé,
/// rafraîchissement différentiel résilient, continuité 100 % hors ligne sur la dernière base connue,
/// et interrogation VirusTotal v3 strictement à la demande.
/// </summary>
public sealed class ReputationService : IReputationService, IDisposable
{
    private readonly ThreatIntelStore _store;
    private readonly ThreatIntelFeedClients _clients;
    private readonly IThreatIntelSecretProvider _secretProvider;
    private readonly TimeProvider _clock;
    private readonly ILogger<ReputationService> _logger;
    private readonly SemaphoreSlim _refreshGate = new(1, 1);
    private readonly bool _ownsStore;

    private volatile ThreatIntelSettings _settings;
    private volatile bool _offlineMode;
    private bool _disposed;

    public ReputationService(
        ThreatIntelStore store,
        ThreatIntelFeedClients clients,
        ThreatIntelOptions? options = null,
        IThreatIntelSecretProvider? secretProvider = null,
        TimeProvider? clock = null,
        ILogger<ReputationService>? logger = null,
        bool ownsStore = false)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _clients = clients ?? throw new ArgumentNullException(nameof(clients));
        _secretProvider = secretProvider ?? new InMemoryThreatIntelSecretProvider();
        _clock = clock ?? TimeProvider.System;
        _logger = logger ?? NullLogger<ReputationService>.Instance;
        _ownsStore = ownsStore;
        _settings = CloneSettings(options?.Settings ?? new ThreatIntelSettings());
    }

    /// <summary>Paramètres actifs du service Threat Intelligence.</summary>
    public ThreatIntelSettings CurrentSettings => CloneSettings(_settings);

    /// <summary>Met à jour dynamiquement les paramètres Threat Intelligence de manière thread-safe.</summary>
    public void UpdateSettings(ThreatIntelSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        _settings = CloneSettings(settings);
    }

    /// <inheritdoc />
    public ThreatIntelMatch? LookupHash(string sha256)
    {
        if (!_settings.Enabled)
        {
            return null;
        }

        var normalized = IndicatorNormalizer.NormalizeHash(sha256);
        if (normalized is null)
        {
            return null;
        }

        var indicator = _store.FindIndicator(IndicatorTypes.Hash, normalized, _clock.GetUtcNow());
        return indicator is null ? null : ThreatIntelScoring.ToMatch(indicator);
    }

    /// <inheritdoc />
    public ThreatIntelMatch? LookupDomain(string domain)
    {
        if (!_settings.Enabled)
        {
            return null;
        }

        var normalized = IndicatorNormalizer.NormalizeDomain(domain);
        if (normalized is null)
        {
            return null;
        }

        var nowUtc = _clock.GetUtcNow();
        foreach (var candidate in IndicatorNormalizer.EnumerateDomainHierarchy(normalized))
        {
            var indicator = _store.FindIndicator(IndicatorTypes.Domain, candidate, nowUtc);
            if (indicator is not null)
            {
                var matchedParent = string.Equals(candidate, normalized, StringComparison.Ordinal)
                    ? null
                    : candidate;
                return ThreatIntelScoring.ToMatch(indicator, matchedParent);
            }
        }

        return null;
    }

    /// <inheritdoc />
    public ThreatIntelMatch? LookupUrl(string url)
    {
        if (!_settings.Enabled)
        {
            return null;
        }

        var normalized = IndicatorNormalizer.NormalizeUrl(url);
        if (normalized is null)
        {
            return null;
        }

        var nowUtc = _clock.GetUtcNow();
        var indicator = _store.FindIndicator(IndicatorTypes.Url, normalized, nowUtc);
        if (indicator is null)
        {
            var altScheme = IndicatorNormalizer.TryGetAlternateSchemeUrl(normalized);
            if (altScheme is not null)
            {
                indicator = _store.FindIndicator(IndicatorTypes.Url, altScheme, nowUtc);
            }
        }

        return indicator is null ? null : ThreatIntelScoring.ToMatch(indicator);
    }

    /// <inheritdoc />
    public ThreatIntelMatch? LookupIp(string ip)
    {
        if (!_settings.Enabled)
        {
            return null;
        }

        var normalized = IndicatorNormalizer.NormalizeIp(ip);
        if (normalized is null)
        {
            return null;
        }

        var indicator = _store.FindIndicator(IndicatorTypes.Ip, normalized, _clock.GetUtcNow());
        return indicator is null ? null : ThreatIntelScoring.ToMatch(indicator);
    }

    /// <inheritdoc />
    public ThreatIntelLookupDto Lookup(string indicatorType, string value)
    {
        var startTs = Stopwatch.GetTimestamp();
        var canonicalType = IndicatorTypes.Normalize(indicatorType);
        var cleanValue = value?.Trim() ?? string.Empty;

        ThreatIntelMatch? match = canonicalType switch
        {
            IndicatorTypes.Hash => LookupHash(cleanValue),
            IndicatorTypes.Domain => LookupDomain(cleanValue),
            IndicatorTypes.Url => LookupUrl(cleanValue),
            IndicatorTypes.Ip => LookupIp(cleanValue),
            _ => null
        };

        var elapsedMs = Math.Round(Stopwatch.GetElapsedTime(startTs).TotalMilliseconds, 4);

        if (match is not null)
        {
            return new ThreatIntelLookupDto(
                Found: true,
                IndicatorType: match.IndicatorType,
                Indicator: match.Value,
                Source: match.Source,
                ThreatType: match.ThreatType,
                FirstSeen: match.FirstSeenUtc,
                ExpiresAt: match.ExpiresAtUtc,
                SuggestedScore: match.SuggestedScore,
                Justification: match.Justification,
                ElapsedMs: elapsedMs);
        }

        var normalizedDisplay = canonicalType switch
        {
            IndicatorTypes.Hash => IndicatorNormalizer.NormalizeHash(cleanValue) ?? cleanValue,
            IndicatorTypes.Domain => IndicatorNormalizer.NormalizeDomain(cleanValue) ?? cleanValue,
            IndicatorTypes.Url => IndicatorNormalizer.NormalizeUrl(cleanValue) ?? cleanValue,
            IndicatorTypes.Ip => IndicatorNormalizer.NormalizeIp(cleanValue) ?? cleanValue,
            _ => cleanValue
        };

        return new ThreatIntelLookupDto(
            Found: false,
            IndicatorType: canonicalType ?? (indicatorType?.Trim().ToLowerInvariant() ?? string.Empty),
            Indicator: normalizedDisplay,
            Source: null,
            ThreatType: null,
            FirstSeen: null,
            ExpiresAt: null,
            SuggestedScore: 0,
            Justification: "Aucun indicateur correspondant trouvé dans la base locale de renseignement sur les menaces.",
            ElapsedMs: elapsedMs);
    }

    /// <inheritdoc />
    public ThreatIntelStatusDto GetStatus()
    {
        var nowUtc = _clock.GetUtcNow();
        var settings = _settings;
        var counts = _store.GetIndicatorCounts(nowUtc);
        var persistedStates = _store.GetFeedStates()
            .ToDictionary(s => s.Name, StringComparer.OrdinalIgnoreCase);

        var definitions = GetFeedDefinitions(settings);
        var feeds = new List<ThreatIntelFeedDto>(definitions.Count);
        DateTimeOffset? lastRefresh = null;

        foreach (var (name, license, enabled) in definitions)
        {
            persistedStates.TryGetValue(name, out var state);
            if (state?.LastUpdatedUtc is { } updated && (!lastRefresh.HasValue || updated > lastRefresh.Value))
            {
                lastRefresh = updated;
            }

            var isOnline = enabled && state is not null && state.LastUpdatedUtc.HasValue && string.IsNullOrEmpty(state.LastError);
            feeds.Add(new ThreatIntelFeedDto(
                Name: name,
                License: license,
                Enabled: enabled,
                Online: isOnline,
                LastUpdated: state?.LastUpdatedUtc,
                IndicatorCount: state?.IndicatorCount ?? 0,
                LastError: state?.LastError));
        }

        return new ThreatIntelStatusDto(
            TotalIndicators: counts.Total,
            HashCount: counts.HashCount,
            DomainCount: counts.DomainCount,
            UrlCount: counts.UrlCount,
            IpCount: counts.IpCount,
            LastRefresh: lastRefresh,
            OfflineMode: _offlineMode,
            Feeds: feeds);
    }

    /// <inheritdoc />
    public async Task<ThreatIntelStatusDto> RefreshNowAsync(CancellationToken ct = default)
    {
        await _refreshGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var settings = _settings;
            var nowUtc = _clock.GetUtcNow();
            var ttlDays = Math.Max(settings.IndicatorTtlDays, 1);

            if (!settings.Enabled)
            {
                _store.PurgeExpired(nowUtc, rebuildBloom: true);
                return GetStatus();
            }

            var jobs = new List<(string Name, string License, Func<CancellationToken, Task<ThreatIntelFeedFetchResult>> Fetch)>();

            if (settings.EnableAbuseChFeeds)
            {
                jobs.Add((ThreatIntelFeedNames.MalwareBazaar, ThreatIntelLicenses.AbuseChCc0, token => _clients.FetchMalwareBazaarAsync(ttlDays, token)));
                jobs.Add((ThreatIntelFeedNames.UrlHaus, ThreatIntelLicenses.AbuseChCc0, token => _clients.FetchUrlHausAsync(ttlDays, token)));
                jobs.Add((ThreatIntelFeedNames.ThreatFox, ThreatIntelLicenses.AbuseChCc0, token => _clients.FetchThreatFoxAsync(ttlDays, token)));
                jobs.Add((ThreatIntelFeedNames.FeodoTracker, ThreatIntelLicenses.AbuseChCc0, token => _clients.FetchFeodoTrackerAsync(ttlDays, token)));
            }

            if (settings.EnableOpenPhishCommunity)
            {
                jobs.Add((ThreatIntelFeedNames.OpenPhish, ThreatIntelLicenses.OpenPhishNonCommercial, token => _clients.FetchOpenPhishAsync(ttlDays, token)));
            }

            if (settings.EnablePhishTank)
            {
                jobs.Add((ThreatIntelFeedNames.PhishTank, ThreatIntelLicenses.PhishTankTerms, token => _clients.FetchPhishTankAsync(ttlDays, token)));
            }

            var succeeded = 0;
            var anyMutated = false;

            foreach (var job in jobs)
            {
                ct.ThrowIfCancellationRequested();

                try
                {
                    var result = await job.Fetch(ct).ConfigureAwait(false);
                    var count = _store.UpsertIndicators(result.Indicators, rebuildBloom: false, nowUtc: nowUtc);
                    _store.UpsertFeedState(new ThreatIntelFeedState(
                        Name: result.FeedName,
                        License: result.License,
                        LastUpdatedUtc: result.FetchedAtUtc,
                        IndicatorCount: count,
                        LastError: null));

                    succeeded++;
                    anyMutated = true;
                    _logger.LogInformation("Flux {FeedName} synchronisé ({Count} indicateurs).", result.FeedName, count);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    var safeError = ThreatIntelFeedClients.RedactSecret(
                        ex.Message,
                        _secretProvider.GetSecret(ThreatIntelSecretNames.PhishTankApiKey));
                    safeError = ThreatIntelFeedClients.RedactSecret(
                        safeError,
                        _secretProvider.GetSecret(ThreatIntelSecretNames.AbuseChAuthKey));

                    _store.RecordFeedError(job.Name, job.License, safeError);
                    _logger.LogWarning("Flux {FeedName} indisponible (conservation de la base locale) : {Error}", job.Name, safeError);
                }
            }

            if (jobs.Count > 0)
            {
                _offlineMode = succeeded == 0;
            }

            // Purge des indicateurs expirés et reconstruction atomique du filtre de Bloom
            var purged = _store.PurgeExpired(nowUtc, rebuildBloom: false);
            if (anyMutated || purged > 0)
            {
                _store.RebuildBloomFilter(nowUtc);
            }

            return GetStatus();
        }
        finally
        {
            _refreshGate.Release();
        }
    }

    /// <inheritdoc />
    public async Task<ThreatIntelLookupDto?> QueryVirusTotalHashOnDemandAsync(string sha256, CancellationToken ct = default)
    {
        var settings = _settings;
        if (!settings.Enabled || !settings.EnableVirusTotalOnDemand)
        {
            return null;
        }

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

        try
        {
            return await _clients.QueryVirusTotalHashAsync(normalized, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            var safeError = ThreatIntelFeedClients.RedactSecret(ex.Message, apiKey);
            _logger.LogWarning("Échec de l'interrogation à la demande VirusTotal : {Error}", safeError);
            return null;
        }
    }

    private static IReadOnlyList<(string Name, string License, bool Enabled)> GetFeedDefinitions(ThreatIntelSettings settings) =>
    [
        (ThreatIntelFeedNames.MalwareBazaar, ThreatIntelLicenses.AbuseChCc0, settings.Enabled && settings.EnableAbuseChFeeds),
        (ThreatIntelFeedNames.UrlHaus, ThreatIntelLicenses.AbuseChCc0, settings.Enabled && settings.EnableAbuseChFeeds),
        (ThreatIntelFeedNames.ThreatFox, ThreatIntelLicenses.AbuseChCc0, settings.Enabled && settings.EnableAbuseChFeeds),
        (ThreatIntelFeedNames.FeodoTracker, ThreatIntelLicenses.AbuseChCc0, settings.Enabled && settings.EnableAbuseChFeeds),
        (ThreatIntelFeedNames.OpenPhish, ThreatIntelLicenses.OpenPhishNonCommercial, settings.Enabled && settings.EnableOpenPhishCommunity),
        (ThreatIntelFeedNames.PhishTank, ThreatIntelLicenses.PhishTankTerms, settings.Enabled && settings.EnablePhishTank)
    ];

    private static ThreatIntelSettings CloneSettings(ThreatIntelSettings source) => new()
    {
        Enabled = source.Enabled,
        EnableAbuseChFeeds = source.EnableAbuseChFeeds,
        EnableOpenPhishCommunity = source.EnableOpenPhishCommunity,
        EnablePhishTank = source.EnablePhishTank,
        EnableVirusTotalOnDemand = source.EnableVirusTotalOnDemand,
        RefreshIntervalHours = source.RefreshIntervalHours,
        IndicatorTtlDays = source.IndicatorTtlDays
    };

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _refreshGate.Dispose();
        if (_ownsStore)
        {
            _store.Dispose();
        }
    }
}
