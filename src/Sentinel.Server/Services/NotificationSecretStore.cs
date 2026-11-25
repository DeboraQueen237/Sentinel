using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;
using Sentinel.Shared.Api;
using Sentinel.Shared.Infrastructure;
using Sentinel.Shared.Json;
using Sentinel.Shared.Security;

namespace Sentinel.Server.Services;

/// <summary>Secrets sensibles des canaux de notification (jamais persistés en clair dans SQLite ni Git).</summary>
public sealed record NotificationSecrets(
    string? SmtpPassword = null,
    string? WhatsAppAccessToken = null,
    string? WebhookSecret = null);

/// <summary>
/// Stockage chiffré au repos des identifiants de notification (DPAPI Windows dans <see cref="SentinelPaths.NotificationSecretsFile"/>,
/// avec repli sur <c>IConfiguration</c> / <c>dotnet user-secrets</c> en développement).
/// </summary>
public sealed class NotificationSecretStore
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<NotificationSecretStore> _logger;
    private readonly object _gate = new();
    private readonly string? _customFilePath;

    public NotificationSecretStore(
        IConfiguration configuration,
        ILogger<NotificationSecretStore> logger,
        string? customFilePath = null)
    {
        _configuration = configuration;
        _logger = logger;
        _customFilePath = customFilePath;
    }

    private string FilePath => _customFilePath ?? SentinelPaths.NotificationSecretsFile;

    public NotificationSecrets Load()
    {
        lock (_gate)
        {
            var fileSecrets = ReadFromProtectedFile();

            // Repli sur dotnet user-secrets / variables d'environnement si absent du coffre DPAPI
            var smtp = FirstNonEmpty(fileSecrets.SmtpPassword, _configuration["Notifications:SmtpPassword"]);
            var wa = FirstNonEmpty(fileSecrets.WhatsAppAccessToken, _configuration["Notifications:WhatsAppAccessToken"]);
            var wh = FirstNonEmpty(fileSecrets.WebhookSecret, _configuration["Notifications:WebhookSecret"]);

            return new NotificationSecrets(smtp, wa, wh);
        }
    }

    public NotificationSecretsStatusDto Update(NotificationSecretsRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        lock (_gate)
        {
            var current = ReadFromProtectedFile();

            var nextSmtp = request.ClearSmtpPassword
                ? null
                : (!string.IsNullOrWhiteSpace(request.SmtpPassword) ? request.SmtpPassword.Trim() : current.SmtpPassword);

            var nextWa = request.ClearWhatsAppToken
                ? null
                : (!string.IsNullOrWhiteSpace(request.WhatsAppAccessToken) ? request.WhatsAppAccessToken.Trim() : current.WhatsAppAccessToken);

            var nextWh = request.ClearWebhookSecret
                ? null
                : (!string.IsNullOrWhiteSpace(request.WebhookSecret) ? request.WebhookSecret.Trim() : current.WebhookSecret);

            var updated = new NotificationSecrets(nextSmtp, nextWa, nextWh);
            WriteToProtectedFile(updated);
            return BuildStatus(Load());
        }
    }

    public NotificationSecretsStatusDto GetStatus() => BuildStatus(Load());

    private NotificationSecrets ReadFromProtectedFile()
    {
        var path = FilePath;
        if (!File.Exists(path))
        {
            return new NotificationSecrets();
        }

        try
        {
            var encoded = File.ReadAllText(path, Encoding.UTF8).Trim();
            if (string.IsNullOrWhiteSpace(encoded))
                return new NotificationSecrets();

            string json;
            try
            {
                json = SecretProtector.UnprotectString(encoded, machineScope: true);
            }
            catch (CryptographicException)
            {
                json = SecretProtector.UnprotectString(encoded, machineScope: false);
            }

            return SentinelJson.Deserialize<NotificationSecrets>(json) ?? new NotificationSecrets();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Impossible de déchiffrer le coffre de secrets de notification ({Path}).", path);
            return new NotificationSecrets();
        }
    }

    private void WriteToProtectedFile(NotificationSecrets secrets)
    {
        var path = FilePath;
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrWhiteSpace(dir))
        {
            Directory.CreateDirectory(dir);
        }

        var json = SentinelJson.Serialize(secrets);
        string protectedPayload;
        try
        {
            protectedPayload = SecretProtector.ProtectString(json, machineScope: true);
        }
        catch (CryptographicException)
        {
            protectedPayload = SecretProtector.ProtectString(json, machineScope: false);
        }

        File.WriteAllText(path, protectedPayload, new UTF8Encoding(false));
    }

    private static NotificationSecretsStatusDto BuildStatus(NotificationSecrets s) => new(
        HasSmtpPassword: !string.IsNullOrWhiteSpace(s.SmtpPassword),
        HasWhatsAppToken: !string.IsNullOrWhiteSpace(s.WhatsAppAccessToken),
        HasWebhookSecret: !string.IsNullOrWhiteSpace(s.WebhookSecret),
        StorageMode: OperatingSystem.IsWindows() ? "DPAPI (LocalMachine) + UserSecrets" : "UserSecrets");

    private static string? FirstNonEmpty(params string?[] candidates) =>
        candidates.FirstOrDefault(c => !string.IsNullOrWhiteSpace(c))?.Trim();
}
