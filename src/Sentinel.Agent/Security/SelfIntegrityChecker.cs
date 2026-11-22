using System.Reflection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Sentinel.Agent.Configuration;
using Sentinel.Agent.Pipeline;
using Sentinel.Shared.Infrastructure;
using Sentinel.Shared.Json;
using Sentinel.Shared.Models;
using Sentinel.Shared.Security;

namespace Sentinel.Agent.Security;

/// <summary>Manifeste d'intégrité SHA-256 des binaires SENTINEL généré à l'installation.</summary>
public sealed record IntegrityManifest(
    DateTimeOffset GeneratedAtUtc,
    string Version,
    Dictionary<string, string> FileHashes);

/// <summary>
/// Auto-protection de l'agent au démarrage (doc §11) : calcule le SHA-256 du binaire exécuté,
/// le compare au manifeste d'intégrité s'il existe, et émet <see cref="EventTypes.AgentStarted"/>
/// ou <see cref="EventTypes.IntegrityViolation"/>.
/// </summary>
public sealed class SelfIntegrityChecker
{
    public const string DefaultManifestFileName = "integrity-manifest.json";

    private readonly AgentStateStore _stateStore;
    private readonly IEventSink _sink;
    private readonly ILogger<SelfIntegrityChecker> _logger;
    private readonly string _manifestPath;

    public string BinaryPath { get; }
    public string BinarySha256 { get; }
    public string AgentVersion { get; }
    public bool IntegrityOk { get; private set; } = true;
    public string? ViolationReason { get; private set; }

    public SelfIntegrityChecker(
        AgentStateStore stateStore,
        IEventSink sink,
        IOptions<AgentOptions> options,
        ILogger<SelfIntegrityChecker> logger)
    {
        _stateStore = stateStore;
        _sink = sink;
        _logger = logger;

        _manifestPath = string.IsNullOrWhiteSpace(options.Value.IntegrityManifestPath)
            ? Path.Combine(SentinelPaths.Data, DefaultManifestFileName)
            : options.Value.IntegrityManifestPath;

        var assembly = Assembly.GetExecutingAssembly();
        AgentVersion = assembly.GetName().Version?.ToString(3) ?? "1.0.0";
        BinaryPath = !string.IsNullOrWhiteSpace(assembly.Location) && File.Exists(assembly.Location)
            ? assembly.Location
            : (Environment.ProcessPath ?? string.Empty);

        BinarySha256 = ComputeHashSafe(BinaryPath);
    }

    public bool VerifyAndReportStartup()
    {
        IntegrityOk = true;
        ViolationReason = null;

        try
        {
            if (File.Exists(_manifestPath))
            {
                var manifest = SentinelJson.Deserialize<IntegrityManifest>(File.ReadAllText(_manifestPath));
                if (manifest?.FileHashes is { Count: > 0 })
                {
                    var fileName = Path.GetFileName(BinaryPath);
                    if (!string.IsNullOrWhiteSpace(fileName) &&
                        manifest.FileHashes.TryGetValue(fileName, out var expectedHash) &&
                        !string.Equals(expectedHash, BinarySha256, StringComparison.OrdinalIgnoreCase))
                    {
                        IntegrityOk = false;
                        ViolationReason = $"Empreinte SHA-256 non conforme pour {fileName} (attendu {expectedHash[..Math.Min(12, expectedHash.Length)]}…, observé {BinarySha256[..Math.Min(12, BinarySha256.Length)]}…).";
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Impossible de vérifier le manifeste d'intégrité {Path}.", _manifestPath);
        }

        if (!IntegrityOk)
        {
            _logger.LogCritical("ALERTE INTÉGRITÉ : {Reason}", ViolationReason);
            _sink.Publish(SecurityEvent.Create(
                _stateStore.HostId,
                Environment.UserName,
                EventCategory.System,
                EventTypes.IntegrityViolation,
                BinaryPath,
                new Dictionary<string, string>
                {
                    [AttributeKeys.Component] = "Sentinel.Agent",
                    [AttributeKeys.AgentVersion] = AgentVersion,
                    [AttributeKeys.Sha256] = BinarySha256,
                    [AttributeKeys.Reason] = ViolationReason ?? "Modification non autorisée du binaire."
                },
                $"component:Sentinel.Agent;hash:{BinarySha256}"));
            return false;
        }

        _logger.LogInformation("Contrôle d'intégrité réussi pour Sentinel.Agent v{Version} (SHA-256: {Hash}).", AgentVersion, BinarySha256);
        _sink.Publish(SecurityEvent.Create(
            _stateStore.HostId,
            Environment.UserName,
            EventCategory.System,
            EventTypes.AgentStarted,
            BinaryPath,
            new Dictionary<string, string>
            {
                [AttributeKeys.Component] = "Sentinel.Agent",
                [AttributeKeys.AgentVersion] = AgentVersion,
                [AttributeKeys.Sha256] = BinarySha256
            },
            $"component:Sentinel.Agent"));
        return true;
    }

    private string ComputeHashSafe(string path)
    {
        try
        {
            if (!string.IsNullOrWhiteSpace(path) && File.Exists(path))
            {
                return HashChain.Sha256File(path);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Impossible de calculer le SHA-256 du binaire {Path}.", path);
        }

        return string.Empty;
    }
}
