using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using FluentAssertions;
using OtpNet;
using Sentinel.Shared.Api;
using Sentinel.Shared.Json;
using Sentinel.Shared.Models;
using Sentinel.Shared.Security;
using Sentinel.Storage;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Sentinel.Server.Tests;

public sealed class V2HardeningAndDetectionEndpointsTests
{
    [Fact]
    public async Task AuthLockout_BlocksAfterFiveFailedLoginsAndAuditsEvent()
    {
        await using var factory = new SentinelServerFactory();
        using var client = factory.CreateClient();

        var setupResp = await client.PostAsJsonAsync(ApiRoutes.AuthSetup, new SetupRequest("socadmin", "SuperStr0ng!2026"));
        setupResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var setup = await setupResp.Content.ReadFromJsonAsync<SetupResponse>(SentinelJson.Options);
        setup.Should().NotBeNull();

        // 4 échecs -> 401
        for (var i = 0; i < 4; i++)
        {
            var bad = await client.PostAsJsonAsync(ApiRoutes.AuthLogin, new LoginRequest("socadmin", "WrongPassword!", "000000"));
            bad.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

        // 5e échec -> 429 TooManyRequests (verrouillage)
        var fifth = await client.PostAsJsonAsync(ApiRoutes.AuthLogin, new LoginRequest("socadmin", "WrongPassword!", "000000"));
        fifth.StatusCode.Should().Be(HttpStatusCode.TooManyRequests);

        // Même avec les bons identifiants pendant le lockout -> reste 429
        var totp = new Totp(Base32Encoding.ToBytes(setup!.TotpSecret)).ComputeTotp();
        var whileLocked = await client.PostAsJsonAsync(ApiRoutes.AuthLogin, new LoginRequest("socadmin", "SuperStr0ng!2026", totp));
        whileLocked.StatusCode.Should().Be(HttpStatusCode.TooManyRequests);
    }

    [Fact]
    public async Task V2DetectionEndpoints_ReturnStatusRulesMlScanAndPrivacyVerified()
    {
        await using var factory = new SentinelServerFactory();
        using var client = factory.CreateClient();

        var setupResp = await client.PostAsJsonAsync(ApiRoutes.AuthSetup, new SetupRequest("adminv2", "SentinelV2!Secure"));
        var setup = await setupResp.Content.ReadFromJsonAsync<SetupResponse>(SentinelJson.Options);
        var totp = new Totp(Base32Encoding.ToBytes(setup!.TotpSecret)).ComputeTotp();
        var loginResp = await client.PostAsJsonAsync(ApiRoutes.AuthLogin, new LoginRequest("adminv2", "SentinelV2!Secure", totp));
        loginResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var login = await loginResp.Content.ReadFromJsonAsync<LoginResponse>(SentinelJson.Options);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", login!.Token);

        // Threat Intel status
        var ti = await client.GetFromJsonAsync<ThreatIntelStatusDto>(ApiRoutes.ThreatIntelStatus, SentinelJson.Options);
        ti.Should().NotBeNull();
        ti!.Feeds.Should().NotBeEmpty();

        // Rules Sigma & YARA
        var rules = await client.GetFromJsonAsync<List<RuleSummaryDto>>(ApiRoutes.Rules, SentinelJson.Options);
        rules.Should().NotBeNull();

        // ML Status
        var ml = await client.GetFromJsonAsync<MlModelStatusDto>(ApiRoutes.MlStatus, SentinelJson.Options);
        ml.Should().NotBeNull();
        ml!.FeatureCount.Should().BeGreaterThan(30);

        // Agents Health
        var agents = await client.GetFromJsonAsync<List<AgentHealthDto>>(ApiRoutes.AgentsHealth, SentinelJson.Options);
        agents.Should().NotBeNull();

        // On-demand static scan on Sentinel.Shared.dll
        var targetDll = typeof(SecurityEvent).Assembly.Location;
        var scanResp = await client.PostAsJsonAsync(ApiRoutes.StaticScan, new StaticScanRequest(targetDll));
        scanResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var scan = await scanResp.Content.ReadFromJsonAsync<StaticScanResultDto>(SentinelJson.Options);
        scan.Should().NotBeNull();
        scan!.IsPe.Should().BeTrue();
        scan.Sha256.Should().HaveLength(64);
    }

    [Fact]
    public void DirectorySecurityHardener_ManifestSigningRoundTripSucceeds()
    {
        var key = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        const string payload = """{"version":"2.0.0","files":{"Sentinel.Agent.exe":"abc123"}}""";
        var sig = DirectorySecurityHardener.SignManifestPayload(payload, key);

        DirectorySecurityHardener.VerifyManifestSignature(payload, sig, key).Should().BeTrue();
        DirectorySecurityHardener.VerifyManifestSignature(payload + " ", sig, key).Should().BeFalse();
    }

    [Fact]
    public async Task PrivacyInvariant_NoUserSensitiveContentStoredInDatabase()
    {
        await using var factory = new SentinelServerFactory();
        var ingestion = factory.Services.GetRequiredService<Sentinel.Server.Services.EventIngestionService>();

        // Simule des événements de tous les canaux sensibles (presse-papiers, saisie, script 4104, fichiers)
        var secretMarker = "CONFIDENTIAL_USER_MESSAGE_DO_NOT_STORE_998877";
        var events = new[]
        {
            SecurityEvent.Create("HOST-PRIV", "alice", EventCategory.Clipboard, EventTypes.ClipboardUrl, "https://example.test",
                new Dictionary<string, string> { [AttributeKeys.Domain] = "example.test", [AttributeKeys.ContentHash] = HashChain.Sha256Hex(secretMarker) }),
            SecurityEvent.Create("HOST-PRIV", "alice", EventCategory.Typing, EventTypes.TypingStats, "TypingRhythm",
                new Dictionary<string, string> { [AttributeKeys.KeysPerSecond] = "4.8", [AttributeKeys.MeanIntervalMs] = "208", [AttributeKeys.IntervalStdDevMs] = "44" }),
            SecurityEvent.Create("HOST-PRIV", "alice", EventCategory.Script, EventTypes.PowerShellScriptBlock, "ScriptBlock:001",
                new Dictionary<string, string> { [AttributeKeys.ScriptHash] = HashChain.Sha256Hex(secretMarker), [AttributeKeys.ScriptLength] = "128", [AttributeKeys.ScriptIndicators] = "EncodedCommand" })
        };

        await ingestion.IngestBatchAsync(events);

        var dbFactory = factory.Services.GetRequiredService<IDbContextFactory<SentinelDbContext>>();
        await using var db = await dbFactory.CreateDbContextAsync();
        var stored = await db.Events.AsNoTracking().ToListAsync();
        stored.Should().HaveCount(3);
        foreach (var row in stored)
        {
            row.Subject.Should().NotContain(secretMarker);
            row.AttributesJson.Should().NotContain(secretMarker);
            row.Justification.Should().NotContain(secretMarker);
        }
    }
}
