using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Text;
using FluentAssertions;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Polly.CircuitBreaker;
using Polly.Timeout;
using Sentinel.ThreatIntel;
using Xunit;

namespace Sentinel.Detection.Tests;

public sealed class ThreatIntelTests : IDisposable
{
    private const string SampleHashA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    private const string SampleHashB = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
    private const string SampleHashC = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    private readonly string _tempDir;
    private readonly string _dbPath;

    public ThreatIntelTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"sentinel-ti-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
        _dbPath = Path.Combine(_tempDir, "threat-intel.db");
    }

    [Fact]
    public async Task RefreshNowAsync_AbuseChFourFeeds_ShouldParseStoreAndForwardAuthKey()
    {
        var fixedNow = new DateTimeOffset(2026, 11, 22, 12, 0, 0, TimeSpan.Zero);
        var clock = new FixedTimeProvider(fixedNow);
        var requestedUrls = new ConcurrentBag<string>();
        var seenAuthKeys = new ConcurrentBag<string>();

        var handler = new MockHttpMessageHandler((req, _) =>
        {
            var url = req.RequestUri!.ToString();
            requestedUrls.Add(url);

            if (req.Headers.TryGetValues("Auth-Key", out var authValues))
            {
                foreach (var v in authValues)
                {
                    seenAuthKeys.Add(v);
                }
            }

            if (url.Contains("bazaar.abuse.ch", StringComparison.OrdinalIgnoreCase))
            {
                return Task.FromResult(OkText($"""
                    # MalwareBazaar recent SHA256
                    # Generated: 2026-11-20
                    {SampleHashA.ToUpperInvariant()}
                    {SampleHashB}
                    not-a-valid-hash
                    """));
            }

            if (url.Contains("urlhaus.abuse.ch", StringComparison.OrdinalIgnoreCase))
            {
                return Task.FromResult(OkText("""
                    # URLhaus csv_recent
                    # id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
                    "3141592","2026-11-20 08:15:22","HTTP://Drop.Evil-Host.XYZ:80/Malware/Loader.exe/","online","2026-11-21 09:00:00","malware_download","exe,Lumma","https://urlhaus.abuse.ch/url/3141592/","abuse_ch"
                    """));
            }

            if (url.Contains("threatfox.abuse.ch", StringComparison.OrdinalIgnoreCase))
            {
                return Task.FromResult(OkText($"""
                    # first_seen_utc,ioc_id,ioc_value,ioc_type,threat_type,fk_malware,malware_alias,malware_printable,last_seen_utc,confidence_level,reference,tags,anonymous,reporter
                    "2026-11-20 10:12:33", "1001", "198.51.100.42:443", "ip:port", "botnet_cc", "win.cobalt_strike", "CobaltStrike", "Cobalt Strike", "2026-11-21 04:00:00", "100", "", "c2", "0", "analyst"
                    "2026-11-20 11:00:00", "1002", "evil-actor.xyz", "domain", "botnet_cc", "win.lumma", "Lumma", "Lumma Stealer", "", "90", "", "stealer", "0", "analyst"
                    "2026-11-20 11:05:00", "1003", "https://c2.evil-actor.xyz/gate.php/", "url", "payload_delivery", "win.asyncrat", "", "AsyncRAT", "", "95", "", "", "0", "analyst"
                    "2026-11-20 11:10:00", "1004", "{SampleHashC}", "sha256_hash", "payload", "win.redline", "", "RedLine Stealer", "", "100", "", "", "0", "analyst"
                    "2026-11-20 11:15:00", "1005", "d41d8cd98f00b204e9800998ecf8427e", "md5_hash", "payload", "win.ignored", "", "Ignored", "", "100", "", "", "0", "analyst"
                    """));
            }

            if (url.Contains("feodotracker.abuse.ch", StringComparison.OrdinalIgnoreCase))
            {
                return Task.FromResult(OkText("""
                    # Feodo Tracker Recommended IP Blocklist
                    # Last updated: 2026-11-20 06:05:12 UTC
                    203.0.113.77
                    198.51.100.99
                    """));
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        });

        var secrets = new InMemoryThreatIntelSecretProvider(new Dictionary<string, string>
        {
            [ThreatIntelSecretNames.AbuseChAuthKey] = "abuse-ch-free-test-key"
        });

        var options = CreateFastOptions();
        using var httpClient = new HttpClient(handler);
        using var store = new ThreatIntelStore(_dbPath, bloomExpectedCapacity: 10_000, initialNowUtc: fixedNow);
        var clients = new ThreatIntelFeedClients(httpClient, secrets, options, clock);
        using var service = new ReputationService(store, clients, options, secrets, clock);

        var status = await service.RefreshNowAsync();

        status.OfflineMode.Should().BeFalse();
        status.HashCount.Should().Be(3);
        status.UrlCount.Should().Be(2);
        status.DomainCount.Should().Be(1);
        status.IpCount.Should().Be(3);
        status.TotalIndicators.Should().Be(9);

        // Auth-Key transmis sur les 4 flux abuse.ch
        seenAuthKeys.Should().HaveCount(4).And.OnlyContain(k => k == "abuse-ch-free-test-key");

        // OpenPhish et PhishTank désactivés par défaut (aucun appel réseau) et licences consignées
        requestedUrls.Should().NotContain(u => u.Contains("openphish", StringComparison.OrdinalIgnoreCase));
        requestedUrls.Should().NotContain(u => u.Contains("phishtank", StringComparison.OrdinalIgnoreCase));
        requestedUrls.Should().NotContain(u => u.Contains("virustotal", StringComparison.OrdinalIgnoreCase));

        var openPhishFeed = status.Feeds.Single(f => f.Name == ThreatIntelFeedNames.OpenPhish);
        openPhishFeed.Enabled.Should().BeFalse();
        openPhishFeed.License.Should().Be(ThreatIntelLicenses.OpenPhishNonCommercial);

        var phishTankFeed = status.Feeds.Single(f => f.Name == ThreatIntelFeedNames.PhishTank);
        phishTankFeed.Enabled.Should().BeFalse();
        phishTankFeed.License.Should().Contain("PhishTank");

        status.Feeds.Where(f => f.Name is ThreatIntelFeedNames.MalwareBazaar or ThreatIntelFeedNames.UrlHaus or ThreatIntelFeedNames.ThreatFox or ThreatIntelFeedNames.FeodoTracker)
            .Should().OnlyContain(f => f.Enabled && f.Online && f.License.Contains("CC0 1.0 Public Domain"));

        // Vérification des correspondances par type
        service.LookupHash(SampleHashA)!.Source.Should().Be(ThreatIntelFeedNames.MalwareBazaar);
        service.LookupHash(SampleHashC)!.Source.Should().Be(ThreatIntelFeedNames.ThreatFox);
        service.LookupIp("203.0.113.77")!.Source.Should().Be(ThreatIntelFeedNames.FeodoTracker);
        service.LookupIp("198.51.100.42:8443")!.Source.Should().Be(ThreatIntelFeedNames.ThreatFox);

        // Correspondance URL avec normalisation schéma / casse / slash final + justification datée
        var urlLookup = service.Lookup("url", "https://DROP.EVIL-HOST.XYZ/malware/loader.exe");
        urlLookup.Found.Should().BeTrue();
        urlLookup.Source.Should().Be(ThreatIntelFeedNames.UrlHaus);
        urlLookup.SuggestedScore.Should().BeInRange(90, 96);
        urlLookup.Justification.Should().Be("URL listée par URLhaus le 2026-11-20 (malware_download)");
        urlLookup.ElapsedMs.Should().BeGreaterThanOrEqualTo(0);

        // Correspondance sous-domaine -> domaine parent
        var subDomainMatch = service.LookupDomain("sub.deep.evil-actor.xyz.");
        subDomainMatch.Should().NotBeNull();
        subDomainMatch!.Value.Should().Be("evil-actor.xyz");
        subDomainMatch.MatchedParent.Should().Be("evil-actor.xyz");
        subDomainMatch.SuggestedScore.Should().BeInRange(90, 96);
        subDomainMatch.Justification.Should().Contain("Domaine listé par ThreatFox le 2026-11-20");

        // Ne doit pas matcher un TLD ou un autre domaine
        service.LookupDomain("safe-actor.xyz").Should().BeNull();
    }

    [Fact]
    public async Task RefreshNowAsync_OpenPhishAndPhishTankEnabled_ShouldParseFeedsAndRequireUserAgentAndKey()
    {
        var fixedNow = new DateTimeOffset(2026, 11, 22, 14, 0, 0, TimeSpan.Zero);
        var clock = new FixedTimeProvider(fixedNow);
        string? phishTankUserAgent = null;
        string? phishTankUrl = null;

        var handler = new MockHttpMessageHandler((req, _) =>
        {
            var url = req.RequestUri!.ToString();
            if (url.Contains("openphish.com", StringComparison.OrdinalIgnoreCase))
            {
                return Task.FromResult(OkText("""
                    # OpenPhish Community Feed
                    https://secure-login-verify.phish.test/signin/
                    http://account-update.phish.test/auth
                    """));
            }

            if (url.Contains("phishtank.com", StringComparison.OrdinalIgnoreCase))
            {
                phishTankUrl = url;
                phishTankUserAgent = req.Headers.UserAgent.ToString();
                return Task.FromResult(OkJson("""
                    [
                      {
                        "phish_id": "9001",
                        "url": "https://paypal-verify.evil.test/login/",
                        "submission_time": "2026-11-20T08:00:00+00:00",
                        "verified": "yes",
                        "verification_time": "2026-11-20T09:15:00+00:00",
                        "online": "yes",
                        "target": "PayPal"
                      },
                      {
                        "phish_id": "9002",
                        "url": "https://offline-phish.evil.test/old",
                        "submission_time": "2026-11-19T08:00:00+00:00",
                        "verified": "yes",
                        "verification_time": "2026-11-19T09:00:00+00:00",
                        "online": "no",
                        "target": "Other"
                      }
                    ]
                    """));
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        });

        var secrets = new InMemoryThreatIntelSecretProvider(new Dictionary<string, string>
        {
            [ThreatIntelSecretNames.PhishTankApiKey] = "pt-secret-api-key",
            [ThreatIntelSecretNames.PhishTankUserAgent] = "phishtank/sentinel-unit-test"
        });

        var options = CreateFastOptions();
        options.Settings.EnableAbuseChFeeds = false;
        options.Settings.EnableOpenPhishCommunity = true;
        options.Settings.EnablePhishTank = true;

        using var httpClient = new HttpClient(handler);
        using var store = new ThreatIntelStore(_dbPath, bloomExpectedCapacity: 10_000, initialNowUtc: fixedNow);
        var clients = new ThreatIntelFeedClients(httpClient, secrets, options, clock);
        using var service = new ReputationService(store, clients, options, secrets, clock);

        var status = await service.RefreshNowAsync();

        status.OfflineMode.Should().BeFalse();
        status.UrlCount.Should().Be(3); // 2 OpenPhish + 1 PhishTank online/verified
        phishTankUserAgent.Should().Contain("phishtank/sentinel-unit-test");
        phishTankUrl.Should().Contain("pt-secret-api-key");

        var openPhishHit = service.LookupUrl("https://secure-login-verify.phish.test/signin");
        openPhishHit.Should().NotBeNull();
        openPhishHit!.Source.Should().Be(ThreatIntelFeedNames.OpenPhish);
        openPhishHit.ThreatType.Should().Be("phishing");

        var phishTankHit = service.LookupUrl("https://paypal-verify.evil.test/login");
        phishTankHit.Should().NotBeNull();
        phishTankHit!.Source.Should().Be(ThreatIntelFeedNames.PhishTank);
        phishTankHit.ThreatType.Should().Be("phishing (PayPal)");
        phishTankHit.Justification.Should().Be("URL listée par PhishTank le 2026-11-20 (phishing (PayPal))");

        // L'entrée offline de PhishTank doit être ignorée
        service.LookupUrl("https://offline-phish.evil.test/old").Should().BeNull();
    }

    [Fact]
    public async Task QueryVirusTotalHashOnDemandAsync_ShouldBeStrictlyOnDemandAndParseV3Response()
    {
        var fixedNow = new DateTimeOffset(2026, 11, 22, 15, 0, 0, TimeSpan.Zero);
        var clock = new FixedTimeProvider(fixedNow);
        var vtCallCount = 0;
        HttpMethod? observedMethod = null;
        string? observedApiKey = null;

        var handler = new MockHttpMessageHandler((req, _) =>
        {
            if (req.RequestUri!.Host.Contains("virustotal.com", StringComparison.OrdinalIgnoreCase))
            {
                Interlocked.Increment(ref vtCallCount);
                observedMethod = req.Method;
                if (req.Headers.TryGetValues("x-apikey", out var keys))
                {
                    observedApiKey = keys.FirstOrDefault();
                }

                if (req.RequestUri.AbsolutePath.EndsWith(SampleHashA, StringComparison.OrdinalIgnoreCase))
                {
                    var firstSub = new DateTimeOffset(2026, 11, 18, 0, 0, 0, TimeSpan.Zero).ToUnixTimeSeconds();
                    return Task.FromResult(OkJson($$"""
                        {
                          "data": {
                            "id": "{{SampleHashA}}",
                            "type": "file",
                            "attributes": {
                              "first_submission_date": {{firstSub}},
                              "last_analysis_stats": {
                                "malicious": 41,
                                "suspicious": 2,
                                "undetected": 27,
                                "harmless": 0
                              },
                              "popular_threat_classification": {
                                "suggested_threat_label": "trojan.agenttesla/stealer"
                              }
                            }
                          }
                        }
                        """));
                }

                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            }

            return Task.FromResult(OkText(string.Empty));
        });

        var secrets = new InMemoryThreatIntelSecretProvider();
        var options = CreateFastOptions();
        options.Settings.EnableAbuseChFeeds = false;
        options.Settings.EnableVirusTotalOnDemand = false;

        using var httpClient = new HttpClient(handler);
        using var store = new ThreatIntelStore(_dbPath, bloomExpectedCapacity: 10_000, initialNowUtc: fixedNow);
        var clients = new ThreatIntelFeedClients(httpClient, secrets, options, clock);
        using var service = new ReputationService(store, clients, options, secrets, clock);

        // 1. Jamais automatique lors d'un RefreshNow ou LookupHash
        await service.RefreshNowAsync();
        service.LookupHash(SampleHashA).Should().BeNull();
        vtCallCount.Should().Be(0);

        // 2. Désactivé par défaut -> aucun appel HTTP
        (await service.QueryVirusTotalHashOnDemandAsync(SampleHashA)).Should().BeNull();
        vtCallCount.Should().Be(0);

        // 3. Activé sans clé API -> toujours aucun appel HTTP
        var enabledSettings = service.CurrentSettings;
        enabledSettings.EnableVirusTotalOnDemand = true;
        service.UpdateSettings(enabledSettings);
        (await service.QueryVirusTotalHashOnDemandAsync(SampleHashA)).Should().BeNull();
        vtCallCount.Should().Be(0);

        // 4. Activé + clé configurée -> GET /api/v3/files/{sha256} (jamais d'upload POST)
        secrets.SetSecret(ThreatIntelSecretNames.VirusTotalApiKey, "vt-api-key-test");
        var hit = await service.QueryVirusTotalHashOnDemandAsync(SampleHashA.ToUpperInvariant());

        vtCallCount.Should().Be(1);
        observedMethod.Should().Be(HttpMethod.Get);
        observedApiKey.Should().Be("vt-api-key-test");
        hit.Should().NotBeNull();
        hit!.Found.Should().BeTrue();
        hit.Source.Should().Be(ThreatIntelFeedNames.VirusTotal);
        hit.SuggestedScore.Should().BeInRange(90, 96);
        hit.Justification.Should().Contain("VirusTotal").And.Contain("2026-11-18").And.Contain("41/70");

        // 5. Hash inconnu (404) -> Found = false
        var miss = await service.QueryVirusTotalHashOnDemandAsync(SampleHashB);
        miss.Should().NotBeNull();
        miss!.Found.Should().BeFalse();
        miss.SuggestedScore.Should().Be(0);
    }

    [Fact]
    public async Task PollyResilience_ShouldHandleExponentialRetryCircuitBreakerAndStrictTimeout()
    {
        var fixedNow = new DateTimeOffset(2026, 11, 22, 16, 0, 0, TimeSpan.Zero);
        var clock = new FixedTimeProvider(fixedNow);

        // --- A. Retry exponentiel (2 tentatives) : 2 échecs 503 puis succès au 3e appel ---
        var retryCalls = 0;
        var retryHandler = new MockHttpMessageHandler((_, _) =>
        {
            var attempt = Interlocked.Increment(ref retryCalls);
            if (attempt <= 2)
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
            }
            return Task.FromResult(OkText("203.0.113.55\n"));
        });

        var retryOptions = CreateFastOptions();
        retryOptions.Resilience.MaxRetryAttempts = 2;
        retryOptions.Resilience.RetryBaseDelay = TimeSpan.FromMilliseconds(10);
        retryOptions.Resilience.CircuitBreakerMinimumThroughput = 3;

        using (var retryClient = new HttpClient(retryHandler))
        {
            var clients = new ThreatIntelFeedClients(retryClient, new InMemoryThreatIntelSecretProvider(), retryOptions, clock);
            var result = await clients.FetchFeodoTrackerAsync(30);
            retryCalls.Should().Be(3);
            result.Indicators.Should().ContainSingle(i => i.Value == "203.0.113.55");
        }

        // --- B. Circuit Breaker : 3 échecs consécutifs ouvrent le circuit ; l'appel suivant échoue sans toucher le réseau ---
        var cbCalls = 0;
        var cbHandler = new MockHttpMessageHandler((_, _) =>
        {
            Interlocked.Increment(ref cbCalls);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.InternalServerError));
        });

        var cbOptions = CreateFastOptions();
        cbOptions.Resilience.MaxRetryAttempts = 2;
        cbOptions.Resilience.RetryBaseDelay = TimeSpan.FromMilliseconds(5);
        cbOptions.Resilience.CircuitBreakerMinimumThroughput = 3;
        cbOptions.Resilience.CircuitBreakerFailureRatio = 1.0;
        cbOptions.Resilience.CircuitBreakerBreakDuration = TimeSpan.FromSeconds(10);

        using (var cbClient = new HttpClient(cbHandler))
        {
            var clients = new ThreatIntelFeedClients(cbClient, new InMemoryThreatIntelSecretProvider(), cbOptions, clock);

            // 1er appel : 1 tentative initiale + 2 retries = 3 échecs -> ouverture du circuit
            await FluentActions.Awaiting(() => clients.FetchFeodoTrackerAsync(30))
                .Should().ThrowAsync<HttpRequestException>();
            cbCalls.Should().Be(3);

            // 2e appel : rejet immédiat par BrokenCircuitException sans nouvel appel HTTP
            await FluentActions.Awaiting(() => clients.FetchFeodoTrackerAsync(30))
                .Should().ThrowAsync<BrokenCircuitException>();
            cbCalls.Should().Be(3);
        }

        // --- C. Timeout strict : annule une réponse bloquée ---
        var timeoutHandler = new MockHttpMessageHandler(async (_, ct) =>
        {
            await Task.Delay(TimeSpan.FromSeconds(5), ct);
            return OkText("203.0.113.66\n");
        });

        var timeoutOptions = CreateFastOptions();
        timeoutOptions.Resilience.MaxRetryAttempts = 0;
        timeoutOptions.Resilience.RequestTimeout = TimeSpan.FromMilliseconds(120);

        using (var timeoutClient = new HttpClient(timeoutHandler))
        {
            var clients = new ThreatIntelFeedClients(timeoutClient, new InMemoryThreatIntelSecretProvider(), timeoutOptions, clock);
            var sw = Stopwatch.StartNew();

            await FluentActions.Awaiting(() => clients.FetchFeodoTrackerAsync(30))
                .Should().ThrowAsync<TimeoutRejectedException>();

            sw.Stop();
            sw.Elapsed.Should().BeLessThan(TimeSpan.FromSeconds(2));
        }
    }

    [Fact]
    public void ThreatIntelStore_ShouldCreateIndexesUpsertDifferentiallyAndPurgeExpiredIndicators()
    {
        var t0 = new DateTimeOffset(2026, 11, 20, 10, 0, 0, TimeSpan.Zero);
        var t1 = t0.AddDays(2);

        using var store = new ThreatIntelStore(_dbPath, bloomExpectedCapacity: 10_000, initialNowUtc: t0);

        // Vérification du schéma et des index SQLite
        using (var verifyConn = new SqliteConnection($"Data Source={_dbPath};Pooling=False"))
        {
            verifyConn.Open();
            using var cmd = verifyConn.CreateCommand();
            cmd.CommandText = "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'Indicators';";
            var indexes = new List<string>();
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                indexes.Add(reader.GetString(0));
            }
            indexes.Should().Contain("IX_Indicators_Type_Value");
            indexes.Should().Contain("IX_Indicators_ExpiresAtUtc");
        }

        // Insertion initiale : 1 actif + 1 expirant à t0+1j
        store.UpsertIndicators(
        [
            new ThreatIntelIndicator(IndicatorTypes.Hash, SampleHashA, ThreatIntelFeedNames.MalwareBazaar, "AgentTesla", t0, t0, t0.AddDays(30), 80),
            new ThreatIntelIndicator(IndicatorTypes.Ip, "198.51.100.10", ThreatIntelFeedNames.FeodoTracker, "botnet_c2", t0.AddDays(-10), t0.AddDays(-5), t0.AddDays(1), 95)
        ], nowUtc: t0);

        // Upsert différentiel sur le même indicateur : préserve FirstSeenUtc, rehausse Confidence et prolonge ExpiresAtUtc
        store.UpsertIndicators(
        [
            new ThreatIntelIndicator(IndicatorTypes.Hash, SampleHashA, ThreatIntelFeedNames.MalwareBazaar, "AgentTesla", t1, t1, t1.AddDays(30), 96)
        ], nowUtc: t1);

        var updated = store.FindIndicator(IndicatorTypes.Hash, SampleHashA, t1);
        updated.Should().NotBeNull();
        updated!.FirstSeenUtc.Should().Be(t0);
        updated.LastSeenUtc.Should().Be(t1);
        updated.ExpiresAtUtc.Should().Be(t1.AddDays(30));
        updated.Confidence.Should().Be(96);

        // À t1 (t0 + 2j), l'IP expirée à t0 + 1j n'est plus renvoyée et est purgée avec reconstruction atomique du BloomFilter
        store.FindIndicator(IndicatorTypes.Ip, "198.51.100.10", t1).Should().BeNull();

        var bloomBefore = store.CurrentBloomFilter;
        var purged = store.PurgeExpired(t1, rebuildBloom: true);
        purged.Should().Be(1);

        var bloomAfter = store.CurrentBloomFilter;
        ReferenceEquals(bloomBefore, bloomAfter).Should().BeFalse();
        bloomAfter.MightContain(IndicatorTypes.Ip.AsSpan(), "198.51.100.10".AsSpan()).Should().BeFalse();
        bloomAfter.MightContain(IndicatorTypes.Hash.AsSpan(), SampleHashA.AsSpan()).Should().BeTrue();
    }

    [Fact]
    public void BloomFilter_ShouldMaintainSub01PercentFalsePositiveRateAt500kCapacityAndBeThreadSafe()
    {
        const int capacity = 500_000;
        var bloom = new BloomFilter(expectedCapacity: capacity, falsePositiveRate: 0.0005);

        // Insertion concurrente de 500 000 indicateurs distincts sans allocation chaîne
        Parallel.For(0, capacity, i =>
        {
            Span<char> buffer = stackalloc char[32];
            "ioc-".AsSpan().CopyTo(buffer);
            i.TryFormat(buffer[4..], out var written, provider: CultureInfo.InvariantCulture);
            bloom.Add("hash".AsSpan(), buffer[..(4 + written)]);
        });

        bloom.AddedCount.Should().Be(capacity);
        bloom.EstimatedFalsePositiveRate.Should().BeLessThan(0.001);

        // 0 faux négatif sur un échantillon de 10 000 clés présentes
        for (var i = 0; i < 10_000; i++)
        {
            var key = $"ioc-{i * 50}";
            bloom.MightContain("hash".AsSpan(), key.AsSpan()).Should().BeTrue();
        }

        // Mesure empirique du taux de faux positifs sur 20 000 clés absentes
        const int negativeProbes = 20_000;
        var falsePositives = 0;
        for (var i = 0; i < negativeProbes; i++)
        {
            var absent = $"absent-probe-{i}";
            if (bloom.MightContain("hash".AsSpan(), absent.AsSpan()))
            {
                falsePositives++;
            }
        }

        var empiricalFpr = (double)falsePositives / negativeProbes;
        empiricalFpr.Should().BeLessThan(0.0015, "le taux de faux positifs pour 500 000 indicateurs doit rester ~0.05 % (< 0.1 %)");
    }

    [Fact]
    public void LookupBenchmark_NegativeBloomAndIndexedSqliteHit_ShouldBeUnder5Ms()
    {
        var fixedNow = new DateTimeOffset(2026, 11, 22, 12, 0, 0, TimeSpan.Zero);
        var clock = new FixedTimeProvider(fixedNow);

        using var store = new ThreatIntelStore(_dbPath, bloomExpectedCapacity: 100_000, initialNowUtc: fixedNow);
        var batch = new List<ThreatIntelIndicator>(10_000);
        for (var i = 0; i < 10_000; i++)
        {
            var hex = i.ToString("x64", CultureInfo.InvariantCulture);
            batch.Add(new ThreatIntelIndicator(
                IndicatorTypes.Hash,
                hex,
                ThreatIntelFeedNames.MalwareBazaar,
                "malware_sample",
                fixedNow.AddDays(-2),
                fixedNow,
                fixedNow.AddDays(30),
                95));
        }

        store.UpsertIndicators(batch, rebuildBloom: true, nowUtc: fixedNow);

        using var httpClient = new HttpClient(new MockHttpMessageHandler((_, _) => Task.FromResult(OkText(string.Empty))));
        var clients = new ThreatIntelFeedClients(httpClient, new InMemoryThreatIntelSecretProvider(), CreateFastOptions(), clock);
        using var service = new ReputationService(store, clients, CreateFastOptions(), clock: clock);

        // Préchauffage JIT + cache SQLite
        service.Lookup("hash", batch[0].Value).Found.Should().BeTrue();
        service.Lookup("hash", SampleHashA).Found.Should().BeFalse();

        // Benchmark rejet négatif (filtre de Bloom) : 1 000 lookups
        var negStart = Stopwatch.GetTimestamp();
        for (var i = 0; i < 1_000; i++)
        {
            var absentHash = (1_000_000 + i).ToString("x64", CultureInfo.InvariantCulture);
            var dto = service.Lookup("hash", absentHash);
            dto.Found.Should().BeFalse();
        }
        var avgNegMs = Stopwatch.GetElapsedTime(negStart).TotalMilliseconds / 1_000.0;
        avgNegMs.Should().BeLessThan(0.5, "le rejet négatif via filtre de Bloom doit être quasi instantané (< 0.05 ms typique)");

        // Benchmark hit SQLite indexé : 200 lookups
        var hitStart = Stopwatch.GetTimestamp();
        for (var i = 0; i < 200; i++)
        {
            var dto = service.Lookup("hash", batch[i * 40].Value);
            dto.Found.Should().BeTrue();
            dto.SuggestedScore.Should().BeInRange(90, 96);
            dto.ElapsedMs.Should().BeLessThan(25.0);
        }
        var avgHitMs = Stopwatch.GetElapsedTime(hitStart).TotalMilliseconds / 200.0;
        avgHitMs.Should().BeLessThan(2.0, "un lookup SQLite indexé après hit Bloom doit rester sous 2 ms");
    }

    [Fact]
    public async Task ReputationService_ShouldOperate100PercentOfflineWithLastKnownDatabase()
    {
        var fixedNow = new DateTimeOffset(2026, 11, 22, 12, 0, 0, TimeSpan.Zero);
        var clock = new FixedTimeProvider(fixedNow);
        var options = CreateFastOptions();

        // Phase 1 : synchronisation en ligne réussie
        var onlineHandler = new MockHttpMessageHandler((req, _) =>
        {
            var url = req.RequestUri!.ToString();
            if (url.Contains("bazaar.abuse.ch", StringComparison.OrdinalIgnoreCase))
            {
                return Task.FromResult(OkText(SampleHashA));
            }
            if (url.Contains("urlhaus.abuse.ch", StringComparison.OrdinalIgnoreCase))
            {
                return Task.FromResult(OkText("\"1\",\"2026-11-20 08:00:00\",\"http://offline-test.evil/drop.bin\",\"online\",\"2026-11-20 09:00:00\",\"malware_download\",\"\",\"\",\"\""));
            }
            if (url.Contains("threatfox.abuse.ch", StringComparison.OrdinalIgnoreCase))
            {
                return Task.FromResult(OkText("\"2026-11-20 10:00:00\", \"1\", \"offline-c2.evil\", \"domain\", \"botnet_cc\", \"win.test\", \"\", \"TestBot\", \"\", \"90\", \"\", \"\", \"0\", \"r\""));
            }
            if (url.Contains("feodotracker.abuse.ch", StringComparison.OrdinalIgnoreCase))
            {
                return Task.FromResult(OkText("198.51.100.123"));
            }
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        });

        using (var onlineClient = new HttpClient(onlineHandler))
        using (var onlineStore = new ThreatIntelStore(_dbPath, bloomExpectedCapacity: 10_000, initialNowUtc: fixedNow))
        using (var onlineService = new ReputationService(onlineStore, new ThreatIntelFeedClients(onlineClient, new InMemoryThreatIntelSecretProvider(), options, clock), options, clock: clock))
        {
            var initialStatus = await onlineService.RefreshNowAsync();
            initialStatus.OfflineMode.Should().BeFalse();
            initialStatus.TotalIndicators.Should().Be(4);
        }

        // Phase 2 : redémarrage 100 % hors ligne sur la même base SQLite
        var offlineHandler = new MockHttpMessageHandler((_, _) =>
            throw new HttpRequestException("Réseau indisponible (mode hors ligne simulé)."));

        using var offlineClient = new HttpClient(offlineHandler);
        using var offlineStore = new ThreatIntelStore(_dbPath, bloomExpectedCapacity: 10_000, initialNowUtc: fixedNow.AddHours(6));
        using var offlineService = new ReputationService(offlineStore, new ThreatIntelFeedClients(offlineClient, new InMemoryThreatIntelSecretProvider(), options, clock), options, clock: clock);

        // Les lookups fonctionnent immédiatement dès le redémarrage avant même tout refresh
        offlineService.LookupHash(SampleHashA).Should().NotBeNull();
        offlineService.LookupDomain("node1.offline-c2.evil").Should().NotBeNull();

        // Une tentative de refresh hors ligne ne plante pas, passe OfflineMode=true et conserve toute la base
        var offlineStatus = await offlineService.RefreshNowAsync();
        offlineStatus.OfflineMode.Should().BeTrue();
        offlineStatus.TotalIndicators.Should().Be(4);
        offlineStatus.LastRefresh.Should().NotBeNull();
        offlineStatus.Feeds.Where(f => f.Enabled).Should().OnlyContain(f => !string.IsNullOrEmpty(f.LastError) && f.LastUpdated.HasValue);

        // Tous les indicateurs restent détectés hors ligne
        offlineService.LookupHash(SampleHashA)!.SuggestedScore.Should().BeInRange(90, 96);
        offlineService.LookupUrl("https://OFFLINE-TEST.EVIL/drop.bin/")!.Source.Should().Be(ThreatIntelFeedNames.UrlHaus);
        offlineService.LookupDomain("sub.offline-c2.evil")!.Source.Should().Be(ThreatIntelFeedNames.ThreatFox);
        offlineService.LookupIp("198.51.100.123")!.Source.Should().Be(ThreatIntelFeedNames.FeodoTracker);
    }

    [Fact]
    public async Task SecretProvider_AndDiWorker_ShouldProtectSecretsAndSurviveOfflineCycles()
    {
        var secretsDir = Path.Combine(_tempDir, "secrets");

        // 1. DPAPI via SecretProtector + priorité IConfiguration (user-secrets)
        var dpapiProvider = new ThreatIntelSecretProvider(configuration: null, secretsDirectory: secretsDir, machineScope: false);
        dpapiProvider.SaveProtectedSecret(ThreatIntelSecretNames.AbuseChAuthKey, "dpapi-protected-key");
        dpapiProvider.GetSecret(ThreatIntelSecretNames.AbuseChAuthKey).Should().Be("dpapi-protected-key");

        if (OperatingSystem.IsWindows())
        {
            var dpapiFile = Directory.GetFiles(secretsDir, "*.dpapi").Single();
            File.ReadAllText(dpapiFile).Should().NotContain("dpapi-protected-key");
        }

        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                [ThreatIntelSecretNames.AbuseChAuthKey] = "user-secret-override"
            })
            .Build();
        var configProvider = new ThreatIntelSecretProvider(config, secretsDir, machineScope: false);
        configProvider.GetSecret(ThreatIntelSecretNames.AbuseChAuthKey).Should().Be("user-secret-override");

        // 2. Enregistrement DI AddSentinelThreatIntel
        var services = new ServiceCollection();
        services.AddSentinelThreatIntel(opts =>
        {
            opts.DatabasePath = _dbPath;
            opts.SecretsDirectory = secretsDir;
            opts.InitialRefreshDelay = TimeSpan.Zero;
            opts.RefreshIntervalOverride = TimeSpan.FromSeconds(10);
            opts.Settings.Enabled = false;
        });

        await using var sp = services.BuildServiceProvider();
        var reputation = sp.GetRequiredService<IReputationService>();
        reputation.GetStatus().Feeds.Should().HaveCount(6);
        sp.GetServices<IHostedService>().OfType<ThreatIntelRefreshWorker>().Should().ContainSingle();

        // 3. Cycle réel du ThreatIntelRefreshWorker en mode hors ligne (ne plante jamais)
        var workerOpts = CreateFastOptions();
        workerOpts.Resilience.MaxRetryAttempts = 0;
        workerOpts.InitialRefreshDelay = TimeSpan.Zero;
        workerOpts.RefreshIntervalOverride = TimeSpan.FromMilliseconds(50);
        workerOpts.Settings.Enabled = true;

        var offlineHandler = new MockHttpMessageHandler((_, _) =>
            throw new HttpRequestException("Hors ligne"));
        using var offlineClient = new HttpClient(offlineHandler);
        using var offlineStore = new ThreatIntelStore(Path.Combine(_tempDir, "worker.db"), bloomExpectedCapacity: 10_000);
        using var offlineRep = new ReputationService(
            offlineStore,
            new ThreatIntelFeedClients(offlineClient, new InMemoryThreatIntelSecretProvider(), workerOpts),
            workerOpts);

        using var worker = new ThreatIntelRefreshWorker(offlineRep, workerOpts);
        await worker.StartAsync(CancellationToken.None);
        var waitDeadline = Stopwatch.StartNew();
        while (!offlineRep.GetStatus().OfflineMode && waitDeadline.Elapsed < TimeSpan.FromSeconds(3))
        {
            await Task.Delay(15);
        }
        await worker.StopAsync(CancellationToken.None);

        offlineRep.GetStatus().OfflineMode.Should().BeTrue();
    }

    [Fact]
    public async Task Parsers_ShouldHandleAlternateJsonAndCsvFormatsAndMissingPhishTankKey()
    {
        var now = new DateTimeOffset(2026, 11, 22, 10, 0, 0, TimeSpan.Zero);

        // MalwareBazaar JSON + CSV
        var mbJson = ThreatIntelFeedClients.ParseMalwareBazaar($$"""
            {"query_status":"ok","data":[{"sha256_hash":"{{SampleHashA}}","first_seen":"2026-11-20 12:00:00","signature":"LummaStealer"}]}
            """, now, 30);
        mbJson.Should().ContainSingle(i => i.Value == SampleHashA && i.ThreatType == "LummaStealer");

        var mbCsv = ThreatIntelFeedClients.ParseMalwareBazaar($"""
            # first_seen_utc,sha256_hash,md5_hash,sha1_hash,reporter,file_name,file_type_guess,mime_type,signature
            "2026-11-20 09:00:00","{SampleHashB}","md5","sha1","rep","drop.exe","exe","app","RedLine"
            """, now, 30);
        mbCsv.Should().ContainSingle(i => i.Value == SampleHashB && i.ThreatType == "RedLine");

        // URLhaus JSON
        var uhJson = ThreatIntelFeedClients.ParseUrlHaus("""
            {"urls":[{"url":"HTTP://BAD.TEST/a.bin/","date_added":"2026-11-20 07:00:00","threat":"malware_download","url_status":"online"}]}
            """, now, 30);
        uhJson.Should().ContainSingle(i => i.Value == "http://bad.test/a.bin" && i.ThreatType == "malware_download");

        // ThreatFox JSON
        var tfJson = ThreatIntelFeedClients.ParseThreatFox("""
            {"query_status":"ok","data":[{"ioc":"c2.bad-fox.test","ioc_type":"domain","threat_type":"botnet_cc","malware_printable":"Sliver","first_seen":"2026-11-20 08:00:00","confidence_level":95}]}
            """, now, 30);
        tfJson.Should().ContainSingle(i => i.Type == IndicatorTypes.Domain && i.Value == "c2.bad-fox.test" && i.ThreatType.Contains("Sliver"));

        // FeodoTracker CSV
        var ftCsv = ThreatIntelFeedClients.ParseFeodoTracker("""
            first_seen,dst_ip,dst_port,c2_status,last_online,malware
            2026-11-20 05:00:00,203.0.113.200,443,online,2026-11-21,QakBot
            """, now, 30);
        ftCsv.Should().ContainSingle(i => i.Value == "203.0.113.200" && i.ThreatType.Contains("QakBot"));

        // PhishTank CSV + erreur gracieuse si clé absente
        var ptCsv = ThreatIntelFeedClients.ParsePhishTank("""
            phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target
            101,https://login-check.evil.test/auth/,https://phishtank.org/101,2026-11-20T08:00:00+00:00,yes,2026-11-20T09:00:00+00:00,yes,Microsoft
            """, now, 30);
        ptCsv.Should().ContainSingle(i => i.Value == "https://login-check.evil.test/auth" && i.ThreatType == "phishing (Microsoft)");

        var ptOptions = CreateFastOptions();
        ptOptions.Settings.EnableAbuseChFeeds = false;
        ptOptions.Settings.EnablePhishTank = true;
        using var httpClient = new HttpClient(new MockHttpMessageHandler((_, _) => Task.FromResult(OkText(string.Empty))));
        using var store = new ThreatIntelStore(Path.Combine(_tempDir, "pt-missing-key.db"), bloomExpectedCapacity: 10_000, initialNowUtc: now);
        using var service = new ReputationService(
            store,
            new ThreatIntelFeedClients(httpClient, new InMemoryThreatIntelSecretProvider(), ptOptions, new FixedTimeProvider(now)),
            ptOptions,
            clock: new FixedTimeProvider(now));

        var status = await service.RefreshNowAsync();
        status.OfflineMode.Should().BeTrue();
        status.Feeds.Single(f => f.Name == ThreatIntelFeedNames.PhishTank).LastError.Should().Contain("Clé API PhishTank");
    }

    private static ThreatIntelOptions CreateFastOptions() => new()
    {
        Resilience = new ThreatIntelResilienceOptions
        {
            MaxRetryAttempts = 1,
            RetryBaseDelay = TimeSpan.FromMilliseconds(5),
            RequestTimeout = TimeSpan.FromSeconds(2),
            CircuitBreakerMinimumThroughput = 3,
            CircuitBreakerFailureRatio = 1.0,
            CircuitBreakerSamplingDuration = TimeSpan.FromSeconds(30),
            CircuitBreakerBreakDuration = TimeSpan.FromSeconds(2)
        }
    };

    private static HttpResponseMessage OkText(string content) =>
        new(HttpStatusCode.OK) { Content = new StringContent(content, Encoding.UTF8, "text/plain") };

    private static HttpResponseMessage OkJson(string content) =>
        new(HttpStatusCode.OK) { Content = new StringContent(content, Encoding.UTF8, "application/json") };

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempDir))
            {
                Directory.Delete(_tempDir, recursive: true);
            }
        }
        catch
        {
            // Ignoré lors du nettoyage des tests.
        }
    }

    private sealed class MockHttpMessageHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> responder) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            responder(request, cancellationToken);
    }

    private sealed class FixedTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        private DateTimeOffset _utcNow = utcNow;
        public override DateTimeOffset GetUtcNow() => _utcNow;
        public void Advance(TimeSpan delta) => _utcNow = _utcNow.Add(delta);
    }
}
