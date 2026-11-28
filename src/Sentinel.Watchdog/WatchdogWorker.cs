using System.Diagnostics;
using System.IO.Pipes;
using System.ServiceProcess;
using System.Text;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Sentinel.Shared.Infrastructure;
using Sentinel.Shared.Ipc;
using Sentinel.Shared.Json;
using Sentinel.Shared.Models;
using Sentinel.Shared.Security;

namespace Sentinel.Watchdog;

/// <summary>
/// Service Watchdog d'auto-protection SENTINEL (doc §11) :
/// 1) Surveille <c>SentinelAgent</c> (et <c>SentinelServer</c> si installé) toutes les 10 s via <see cref="ServiceController"/>,
///    redémarre automatiquement un service arrêté de façon inattendue et consigne une alerte <see cref="EventTypes.AgentTampering"/>.
/// 2) Vérifie toutes les 60 s l'empreinte SHA-256 des binaires SENTINEL par rapport au manifeste d'intégrité
///    (<c>integrity-manifest.json</c>) généré à l'installation.
/// </summary>
public sealed class WatchdogWorker : BackgroundService
{
    private static readonly TimeSpan ServiceTamperingAlertCooldown = TimeSpan.FromMinutes(15);

    private readonly WatchdogOptions _options;
    private readonly ILogger<WatchdogWorker> _logger;
    private readonly string _alertFilePath;
    private readonly string _manifestPath;
    private readonly HashSet<string> _reportedViolations = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _knownInstalledServices = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _reportedDeletedServices = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTimeOffset> _lastStoppedAlertUtc = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTimeOffset> _nextRestartAttemptUtc = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, int> _consecutiveRestartFailures = new(StringComparer.OrdinalIgnoreCase);

    public WatchdogWorker(IOptions<WatchdogOptions> options, ILogger<WatchdogWorker> logger)
    {
        _options = options.Value;
        _logger = logger;
        _alertFilePath = Path.Combine(SentinelPaths.Data, "watchdog-alerts.jsonl");
        _manifestPath = Path.Combine(SentinelPaths.Data, "integrity-manifest.json");
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var checkInterval = TimeSpan.FromSeconds(Math.Clamp(_options.CheckIntervalSeconds, 5, 120));
        var integrityInterval = TimeSpan.FromSeconds(Math.Clamp(_options.IntegrityIntervalSeconds, 30, 3600));
        var lastIntegrityCheck = DateTimeOffset.MinValue;

        _logger.LogInformation("Sentinel.Watchdog démarré (intervalle services={Svc}s, intégrité={Int}s).",
            checkInterval.TotalSeconds, integrityInterval.TotalSeconds);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await CheckMonitoredServicesAsync(stoppingToken);

                var now = DateTimeOffset.UtcNow;
                if (now - lastIntegrityCheck >= integrityInterval)
                {
                    lastIntegrityCheck = now;
                    await VerifyBinaryIntegrityAsync(stoppingToken);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erreur dans la boucle Watchdog.");
            }

            try
            {
                await Task.Delay(checkInterval, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    private async Task CheckMonitoredServicesAsync(CancellationToken ct)
    {
        ServiceController[] installed;
        try
        {
            installed = ServiceController.GetServices();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Impossible d'énumérer les services Windows.");
            return;
        }

        try
        {
            var byName = installed.ToDictionary(s => s.ServiceName, StringComparer.OrdinalIgnoreCase);

            foreach (var serviceName in _options.MonitoredServices)
            {
                if (!byName.TryGetValue(serviceName, out var sc))
                {
                    if (_knownInstalledServices.Contains(serviceName) && _reportedDeletedServices.Add(serviceName))
                    {
                        var deletedReason = $"ALERTE CRITIQUE : le service Windows « {serviceName} » a été supprimé du gestionnaire de services !";
                        _logger.LogCritical("ALERTE WATCHDOG : {Reason}", deletedReason);
                        var deletedEvt = SecurityEvent.Create(
                            hostId: Environment.MachineName.ToLowerInvariant(),
                            userId: "SYSTEM",
                            EventCategory.System,
                            EventTypes.AgentTampering,
                            serviceName,
                            new Dictionary<string, string>
                            {
                                [AttributeKeys.Component] = serviceName,
                                [AttributeKeys.Reason] = deletedReason,
                                ["watchdog.service.deleted"] = "true"
                            },
                            $"component:{serviceName};tampering:service-deleted");
                        await EmitWatchdogAlertAsync(deletedEvt, deletedReason, ct);
                    }
                    continue;
                }

                _knownInstalledServices.Add(serviceName);
                _reportedDeletedServices.Remove(serviceName);

                sc.Refresh();
                if (sc.Status is ServiceControllerStatus.Running or ServiceControllerStatus.StartPending)
                {
                    _consecutiveRestartFailures.Remove(serviceName);
                    _nextRestartAttemptUtc.Remove(serviceName);
                    continue;
                }

                var now = DateTimeOffset.UtcNow;
                if (_nextRestartAttemptUtc.TryGetValue(serviceName, out var nextTry) && now < nextTry)
                {
                    continue;
                }

                var previousStatus = sc.Status.ToString();
                var reason = $"Arrêt inattendu détecté pour le service {serviceName} (état={previousStatus}). Tentative de redémarrage automatique.";
                _logger.LogWarning("ALERTE WATCHDOG : {Reason}", reason);

                var restarted = false;
                try
                {
                    sc.Start();
                    sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(15));
                    restarted = true;
                    _consecutiveRestartFailures.Remove(serviceName);
                    _nextRestartAttemptUtc.Remove(serviceName);
                    _logger.LogInformation("Service {Service} redémarré avec succès par Sentinel.Watchdog.", serviceName);
                }
                catch (Exception startEx)
                {
                    var failCount = _consecutiveRestartFailures.GetValueOrDefault(serviceName) + 1;
                    _consecutiveRestartFailures[serviceName] = failCount;
                    var backoffSeconds = failCount switch
                    {
                        1 => 30,
                        2 => 120,
                        3 => 300,
                        _ => 900
                    };
                    _nextRestartAttemptUtc[serviceName] = now.AddSeconds(backoffSeconds);
                    reason += $" Échec du redémarrage (tentative #{failCount}, prochain essai dans {backoffSeconds}s) : {startEx.Message}";
                    _logger.LogError(startEx, "Impossible de redémarrer le service {Service} (backoff {Sec}s).", serviceName, backoffSeconds);
                }

                // Anti-spam : n'émet qu'une seule alerte AgentTampering par fenêtre de 15 minutes pour un même service arrêté
                if (_lastStoppedAlertUtc.TryGetValue(serviceName, out var lastAlert) &&
                    (now - lastAlert) < ServiceTamperingAlertCooldown)
                {
                    continue;
                }

                _lastStoppedAlertUtc[serviceName] = now;

                var evt = SecurityEvent.Create(
                    hostId: Environment.MachineName.ToLowerInvariant(),
                    userId: "SYSTEM",
                    EventCategory.System,
                    EventTypes.AgentTampering,
                    serviceName,
                    new Dictionary<string, string>
                    {
                        [AttributeKeys.Component] = serviceName,
                        [AttributeKeys.Reason] = reason,
                        ["watchdog.restarted"] = restarted ? "true" : "false",
                        ["watchdog.previous.state"] = previousStatus
                    },
                    $"component:{serviceName};tampering:service-stopped");

                await EmitWatchdogAlertAsync(evt, reason, ct);
            }
        }
        finally
        {
            foreach (var s in installed)
            {
                s.Dispose();
            }
        }
    }

    private async Task VerifyBinaryIntegrityAsync(CancellationToken ct)
    {
        if (!File.Exists(_manifestPath))
        {
            return;
        }

        WatchdogIntegrityManifest? manifest;
        try
        {
            manifest = SentinelJson.Deserialize<WatchdogIntegrityManifest>(await File.ReadAllTextAsync(_manifestPath, ct));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Manifeste d'intégrité illisible : {Path}.", _manifestPath);
            return;
        }

        if (manifest?.FileHashes is null || manifest.FileHashes.Count == 0)
        {
            return;
        }

        var installDir = !string.IsNullOrWhiteSpace(_options.InstallDirectory)
            ? _options.InstallDirectory
            : (!string.IsNullOrWhiteSpace(manifest.InstallDirectory)
                ? manifest.InstallDirectory
                : AppContext.BaseDirectory);

        foreach (var (fileName, expectedHash) in manifest.FileHashes)
        {
            var fullPath = Path.Combine(installDir, fileName);
            string? violation = null;
            string actualHash = string.Empty;

            if (!File.Exists(fullPath))
            {
                violation = $"Binaire SENTINEL manquant : {fullPath}.";
            }
            else
            {
                try
                {
                    actualHash = HashChain.Sha256File(fullPath);
                    if (!string.Equals(actualHash, expectedHash, StringComparison.OrdinalIgnoreCase))
                    {
                        violation = $"Modification non autorisée détectée sur {fileName} (SHA-256 attendu={expectedHash}, observé={actualHash}).";
                    }
                }
                catch (Exception ex)
                {
                    violation = $"Impossible de vérifier le hash de {fileName} : {ex.Message}";
                }
            }

            if (violation is null)
            {
                _reportedViolations.Remove(fileName);
                continue;
            }

            if (!_reportedViolations.Add(fileName))
            {
                continue; // Déjà signalé tant que non corrigé.
            }

            _logger.LogCritical("VIOLATION D'INTÉGRITÉ : {Violation}", violation);
            var evt = SecurityEvent.Create(
                hostId: Environment.MachineName.ToLowerInvariant(),
                userId: "SYSTEM",
                EventCategory.System,
                EventTypes.IntegrityViolation,
                fullPath,
                new Dictionary<string, string>
                {
                    [AttributeKeys.Component] = fileName,
                    [AttributeKeys.Sha256] = actualHash,
                    [AttributeKeys.Reason] = violation
                },
                $"component:{fileName};integrity:violation");

            await EmitWatchdogAlertAsync(evt, violation, ct);
        }
    }

    private async Task EmitWatchdogAlertAsync(SecurityEvent evt, string summary, CancellationToken ct)
    {
        // 1. Journal Windows EventLog (tolérant si exécuté sans privilèges admin)
        try
        {
            if (!EventLog.SourceExists(SentinelEndpoints.EventLogSource))
            {
                EventLog.CreateEventSource(SentinelEndpoints.EventLogSource, "Application");
            }
            EventLog.WriteEntry(SentinelEndpoints.EventLogSource, $"[{evt.EventType}] {summary}", EventLogEntryType.Warning, 4100);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Écriture dans le journal EventLog impossible (droits insuffisants).");
        }

        // 2. Fichier d'alerte persistant JSONL (trace locale inviolable par redémarrage)
        try
        {
            var line = SentinelJson.Serialize(evt) + Environment.NewLine;
            await File.AppendAllTextAsync(_alertFilePath, line, Encoding.UTF8, ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Échec d'écriture dans {Path}.", _alertFilePath);
        }

        // 3. Tentative d'envoi temps réel à Sentinel.Agent via Named Pipe IPC
        try
        {
            using var pipe = new NamedPipeClientStream(".", IpcProtocol.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(1500, ct);
            using var writer = new StreamWriter(pipe, new UTF8Encoding(false), leaveOpen: true) { AutoFlush = true };
            var msg = IpcMessage.Create(IpcProtocol.Event, evt);
            await writer.WriteLineAsync(SentinelJson.Serialize(msg).AsMemory(), ct);
        }
        catch
        {
            // L'agent peut être momentanément arrêté ; l'alerte reste consignée dans EventLog et watchdog-alerts.jsonl.
        }
    }

    private sealed record WatchdogIntegrityManifest(
        DateTimeOffset GeneratedAtUtc,
        string Version,
        string? InstallDirectory,
        Dictionary<string, string> FileHashes);
}
