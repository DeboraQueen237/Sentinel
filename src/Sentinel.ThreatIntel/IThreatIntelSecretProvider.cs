using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Shared.Infrastructure;
using Sentinel.Shared.Security;

namespace Sentinel.ThreatIntel;

/// <summary>Identifiants de secrets utilisés par les clients Threat Intelligence (jamais codés en dur).</summary>
public static class ThreatIntelSecretNames
{
    public const string AbuseChAuthKey = "ThreatIntel:AbuseChAuthKey";
    public const string PhishTankApiKey = "ThreatIntel:PhishTankApiKey";
    public const string PhishTankUserAgent = "ThreatIntel:PhishTankUserAgent";
    public const string VirusTotalApiKey = "ThreatIntel:VirusTotalApiKey";
}

/// <summary>
/// Fournisseur sécurisé de clés API pour les flux Threat Intelligence
/// (configuration <c>user-secrets</c>, variables d'environnement ou stockage DPAPI local via <see cref="SecretProtector"/>).
/// </summary>
public interface IThreatIntelSecretProvider
{
    /// <summary>Récupère la valeur déchiffrée d'un secret, ou <see langword="null"/> s'il n'est pas configuré.</summary>
    string? GetSecret(string name);
}

/// <summary>
/// Implémentation par défaut de <see cref="IThreatIntelSecretProvider"/> :
/// consulte d'abord <see cref="IConfiguration"/> (user-secrets, variables d'environnement, appsettings),
/// puis les fichiers chiffrés DPAPI dans <c>SentinelPaths.Secrets</c> via <see cref="SecretProtector"/>.
/// </summary>
public sealed class ThreatIntelSecretProvider : IThreatIntelSecretProvider
{
    private readonly IConfiguration? _configuration;
    private readonly string _secretsDirectory;
    private readonly bool _machineScope;
    private readonly ILogger<ThreatIntelSecretProvider> _logger;

    public ThreatIntelSecretProvider(
        IConfiguration? configuration = null,
        string? secretsDirectory = null,
        bool machineScope = true,
        ILogger<ThreatIntelSecretProvider>? logger = null)
    {
        _configuration = configuration;
        _secretsDirectory = string.IsNullOrWhiteSpace(secretsDirectory)
            ? SentinelPaths.Secrets
            : secretsDirectory;
        _machineScope = machineScope;
        _logger = logger ?? NullLogger<ThreatIntelSecretProvider>.Instance;
    }

    /// <inheritdoc />
    public string? GetSecret(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return null;
        }

        // 1. Configuration ASP.NET / .NET (user-secrets, variables d'environnement, appsettings)
        var configured = _configuration?[name];
        if (!string.IsNullOrWhiteSpace(configured))
        {
            return configured.Trim();
        }

        // 2. Fichier protégé DPAPI via SecretProtector
        var filePath = GetDpapiFilePath(name);
        if (!File.Exists(filePath))
        {
            return null;
        }

        try
        {
            var protectedContent = File.ReadAllText(filePath).Trim();
            if (string.IsNullOrEmpty(protectedContent))
            {
                return null;
            }

            var value = SecretProtector.UnprotectString(protectedContent, _machineScope).Trim();
            return string.IsNullOrEmpty(value) ? null : value;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Impossible de déchiffrer le secret Threat Intelligence '{SecretName}' via DPAPI.", name);
            return null;
        }
    }

    /// <summary>Chiffre et enregistre un secret au repos via <see cref="SecretProtector"/> (DPAPI).</summary>
    public void SaveProtectedSecret(string name, string secretValue)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentException.ThrowIfNullOrWhiteSpace(secretValue);

        Directory.CreateDirectory(_secretsDirectory);
        var filePath = GetDpapiFilePath(name);
        var encrypted = SecretProtector.ProtectString(secretValue.Trim(), _machineScope);
        File.WriteAllText(filePath, encrypted);
    }

    private string GetDpapiFilePath(string name)
    {
        var safeFileName = SanitizeFileName(name);
        return Path.Combine(_secretsDirectory, safeFileName + ".dpapi");
    }

    private static string SanitizeFileName(string name)
    {
        Span<char> buffer = stackalloc char[name.Length];
        for (var i = 0; i < name.Length; i++)
        {
            var c = char.ToLowerInvariant(name[i]);
            buffer[i] = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' ? c : '-';
        }
        return new string(buffer);
    }
}

/// <summary>Fournisseur de secrets en mémoire (destiné aux tests unitaires et à l'injection explicite).</summary>
public sealed class InMemoryThreatIntelSecretProvider : IThreatIntelSecretProvider
{
    private readonly Dictionary<string, string> _secrets;

    public InMemoryThreatIntelSecretProvider(IDictionary<string, string>? initialSecrets = null)
    {
        _secrets = initialSecrets is null
            ? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, string>(initialSecrets, StringComparer.OrdinalIgnoreCase);
    }

    public string? GetSecret(string name) =>
        !string.IsNullOrWhiteSpace(name) && _secrets.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value.Trim()
            : null;

    public void SetSecret(string name, string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        _secrets[name] = value;
    }
}
