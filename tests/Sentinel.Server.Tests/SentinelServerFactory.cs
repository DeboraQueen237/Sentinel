using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using OtpNet;
using Sentinel.Shared.Api;
using Sentinel.Shared.Json;

namespace Sentinel.Server.Tests;

/// <summary>
/// Fabrique <see cref="WebApplicationFactory{Program}"/> isolant chaque suite de tests
/// sur sa propre base SQLite temporaire (sans mTLS ni pollution de <c>%ProgramData%</c>).
/// </summary>
public sealed class SentinelServerFactory : WebApplicationFactory<Program>
{
    public string TempDirectory { get; }
    public string DatabasePath { get; }
    public string ConnectionString { get; }

    public SentinelServerFactory()
    {
        TempDirectory = Path.Combine(Path.GetTempPath(), "sentinel-server-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(TempDirectory);
        DatabasePath = Path.Combine(TempDirectory, "sentinel-test.db");
        ConnectionString = $"Data Source={DatabasePath}";
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.UseSetting("Sentinel:UseMtls", "false");
        builder.UseSetting("Sentinel:ConnectionString", ConnectionString);
        builder.UseSetting("Sentinel:SessionTtlMinutes", "30");
        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Sentinel:UseMtls"] = "false",
                ["Sentinel:ConnectionString"] = ConnectionString,
                ["Sentinel:SessionTtlMinutes"] = "30"
            });
        });
    }

    /// <summary>Configure le compte admin, génère un code TOTP valide et retourne un client authentifié + secret TOTP.</summary>
    public async Task<(HttpClient Client, string TotpSecret, LoginResponse Login)> CreateAuthenticatedClientAsync(
        string username = "admin",
        string password = "Sentinel#Password2026!")
    {
        var client = CreateClient();

        var setupResp = await client.PostAsJsonAsync(
            ApiRoutes.AuthSetup,
            new SetupRequest(username, password),
            SentinelJson.Options);
        setupResp.EnsureSuccessStatusCode();

        var setup = (await setupResp.Content.ReadFromJsonAsync<SetupResponse>(SentinelJson.Options))!;
        var code = ComputeTotp(setup.TotpSecret);

        var loginResp = await client.PostAsJsonAsync(
            ApiRoutes.AuthLogin,
            new LoginRequest(username, password, code),
            SentinelJson.Options);
        loginResp.EnsureSuccessStatusCode();

        var login = (await loginResp.Content.ReadFromJsonAsync<LoginResponse>(SentinelJson.Options))!;
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", login.Token);
        return (client, setup.TotpSecret, login);
    }

    public static string ComputeTotp(string base32Secret)
    {
        var bytes = Base32Encoding.ToBytes(base32Secret);
        var totp = new Totp(bytes, step: 30, mode: OtpHashMode.Sha1, totpSize: 6);
        return totp.ComputeTotp();
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing)
        {
            try
            {
                SqliteConnection.ClearAllPools();
                if (Directory.Exists(TempDirectory))
                    Directory.Delete(TempDirectory, recursive: true);
            }
            catch
            {
                // Nettoyage au mieux
            }
        }
    }
}
