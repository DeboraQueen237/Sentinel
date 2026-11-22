using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using Sentinel.Agent.Configuration;
using Sentinel.Agent.Ipc;
using Sentinel.Shared.Grpc;
using Sentinel.Shared.Ipc;
using Sentinel.Shared.Json;
using Sentinel.Shared.Models;

namespace Sentinel.Agent.Response;

/// <summary>
/// Exécuteur central de toutes les commandes de réponse (<see cref="ResponseActionType"/>) reçues du serveur
/// (doc §9.2, §9.3). Prend en charge le mode simulation (<c>AgentCommand.Simulate</c>) ainsi que l'annulation
/// réversible (<c>AgentCommand.Revert</c>) à partir de <c>revert_state_json</c>.
/// </summary>
public sealed class ActionExecutor
{
    private readonly AgentStateStore _stateStore;
    private readonly QuarantineManager _quarantine;
    private readonly HostsFileManager _hosts;
    private readonly FirewallManager _firewall;
    private readonly ProcessController _processes;
    private readonly FolderProtector _folders;
    private readonly DeviceController _devices;
    private readonly AgentIpcServer _ipc;
    private readonly ILogger<ActionExecutor> _logger;

    private readonly ConcurrentDictionary<string, DateTimeOffset> _watchedHashes = new(StringComparer.OrdinalIgnoreCase);

    public ActionExecutor(
        AgentStateStore stateStore,
        QuarantineManager quarantine,
        HostsFileManager hosts,
        FirewallManager firewall,
        ProcessController processes,
        FolderProtector folders,
        DeviceController devices,
        AgentIpcServer ipc,
        ILogger<ActionExecutor> logger)
    {
        _stateStore = stateStore;
        _quarantine = quarantine;
        _hosts = hosts;
        _firewall = firewall;
        _processes = processes;
        _folders = folders;
        _devices = devices;
        _ipc = ipc;
        _logger = logger;
    }

    public IReadOnlyCollection<string> WatchedHashes => _watchedHashes.Keys.ToArray();

    public async Task<ActionResultReport> ExecuteAsync(AgentCommand command, CancellationToken ct)
    {
        var actionType = Enum.IsDefined(typeof(ResponseActionType), command.ActionType)
            ? (ResponseActionType)command.ActionType
            : ResponseActionType.LogOnly;

        var report = new ActionResultReport
        {
            CommandId = command.CommandId,
            HostId = _stateStore.HostId,
            WasRevert = command.Revert
        };

        if (command.Simulate)
        {
            var verb = command.Revert ? "annuler" : "exécuter";
            var simMsg = $"[Simulation] Action {actionType} ({verb}) validée pour la cible « {command.Target} » sans modification système.";
            _logger.LogInformation("{Message} (commande {CommandId})", simMsg, command.CommandId);
            report.Success = true;
            report.Message = simMsg;
            return report;
        }

        try
        {
            return command.Revert
                ? await ExecuteRevertAsync(command, actionType, report, ct)
                : await ExecuteApplyAsync(command, actionType, report, ct);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erreur lors de l'exécution de la commande {CommandId} ({Action}, revert={Revert}).",
                command.CommandId, actionType, command.Revert);
            report.Success = false;
            report.Message = $"Erreur : {ex.Message}";
            return report;
        }
    }

    private async Task<ActionResultReport> ExecuteApplyAsync(
        AgentCommand cmd,
        ResponseActionType actionType,
        ActionResultReport report,
        CancellationToken ct)
    {
        switch (actionType)
        {
            case ResponseActionType.LogOnly:
            case ResponseActionType.MarkForCorrelation:
            case ResponseActionType.AlertAdmin:
            case ResponseActionType.EnhancedMonitoring:
                _logger.LogInformation("Action passive {Action} enregistrée pour cible « {Target} ».", actionType, cmd.Target);
                report.Success = true;
                report.Message = $"Action {actionType} appliquée.";
                return report;

            case ResponseActionType.WatchHash:
                if (!string.IsNullOrWhiteSpace(cmd.Target))
                {
                    _watchedHashes[cmd.Target.Trim()] = DateTimeOffset.UtcNow;
                }
                report.Success = true;
                report.Message = $"Empreinte {cmd.Target} ajoutée à la liste de surveillance locale.";
                report.RevertStateJson = SentinelJson.Serialize(new ActionRevertState { Kind = "watchHash", Value = cmd.Target });
                return report;

            case ResponseActionType.NotifyUser:
            case ResponseActionType.UserAwareness:
                var title = cmd.Parameters.TryGetValue("title", out var t) && !string.IsNullOrWhiteSpace(t)
                    ? t
                    : (actionType == ResponseActionType.UserAwareness ? "SENTINEL — Sensibilisation sécurité" : "SENTINEL — Alerte de vigilance");
                var msg = cmd.Parameters.TryGetValue("message", out var m) && !string.IsNullOrWhiteSpace(m)
                    ? m
                    : $"Activité suspecte détectée concernant : {cmd.Target}. Vérifiez l'origine avant de poursuivre.";
                var severity = actionType == ResponseActionType.UserAwareness ? NotificationSeverity.Info : NotificationSeverity.Warning;
                var alertId = cmd.Parameters.TryGetValue("alertId", out var aid) ? aid : null;

                var notified = await _ipc.SendNotificationAsync(new UserNotification(title, msg, severity, alertId), ct);
                report.Success = true;
                report.Message = notified > 0
                    ? $"Notification affichée à {notified} session(s) utilisateur."
                    : "Notification enregistrée (aucune session Tray connectée actuellement).";
                return report;

            case ResponseActionType.BlockDomain:
                var domain = HostsFileManager.NormalizeDomain(cmd.Target);
                if (domain is null)
                {
                    report.Success = false;
                    report.Message = $"Domaine invalide : « {cmd.Target} ».";
                    return report;
                }

                _hosts.BlockDomain(domain);
                var allBlocked = _hosts.GetBlockedDomains();
                var reason = cmd.Parameters.TryGetValue("reason", out var r) ? r : "Domaine bloqué par SENTINEL";
                await _ipc.SendBlockDomainsAsync(new BrowserCommand(null, null, allBlocked, reason), ct);

                report.Success = true;
                report.Message = $"Domaine {domain} bloqué (fichier hosts + extension navigateur).";
                report.RevertStateJson = SentinelJson.Serialize(new ActionRevertState { Kind = "domain", Value = domain });
                return report;

            case ResponseActionType.CloseBrowserTab:
                var tabId = cmd.Parameters.TryGetValue("tabId", out var tid) ? tid : cmd.Target;
                var url = cmd.Parameters.TryGetValue("url", out var u) ? u : null;
                var closeReason = cmd.Parameters.TryGetValue("reason", out var cr) ? cr : "Onglet malveillant fermé par SENTINEL";
                var browsers = await _ipc.SendCloseTabAsync(new BrowserCommand(tabId, url, null, closeReason), ct);
                report.Success = true;
                report.Message = browsers > 0
                    ? $"Commande de fermeture d'onglet envoyée à {browsers} navigateur(s)."
                    : "Commande transmise (aucune extension navigateur connectée).";
                return report;

            case ResponseActionType.SuspendProcess:
                var suspendPid = _processes.ResolvePid(cmd.Target, cmd.Parameters);
                if (!suspendPid.HasValue)
                {
                    report.Success = false;
                    report.Message = $"Impossible de résoudre le PID pour « {cmd.Target} ».";
                    return report;
                }

                var suspendRes = _processes.SuspendProcess(suspendPid.Value);
                report.Success = suspendRes.Success;
                report.Message = suspendRes.Message;
                if (suspendRes.Success)
                {
                    report.RevertStateJson = SentinelJson.Serialize(new ActionRevertState { Kind = "suspendPid", Pid = suspendPid.Value });
                }
                return report;

            case ResponseActionType.KillProcess:
                var killPid = _processes.ResolvePid(cmd.Target, cmd.Parameters);
                if (!killPid.HasValue)
                {
                    report.Success = false;
                    report.Message = $"Impossible de résoudre le PID pour « {cmd.Target} ».";
                    return report;
                }

                var killRes = _processes.KillProcess(killPid.Value);
                report.Success = killRes.Success;
                report.Message = killRes.Message;
                return report;

            case ResponseActionType.QuarantineFile:
                var qRecord = _quarantine.Quarantine(cmd.Target);
                report.Success = true;
                report.Message = $"Fichier déplacé en quarantaine chiffrée ({qRecord.QuarantineId}).";
                report.RevertStateJson = SentinelJson.Serialize(new ActionRevertState
                {
                    Kind = "quarantine",
                    Value = qRecord.QuarantineId,
                    OriginalPath = qRecord.OriginalPath,
                    Sha256 = qRecord.OriginalSha256
                });
                return report;

            case ResponseActionType.IsolateNetwork:
                var isoRes = await _firewall.IsolateHostAsync(cmd.CommandId, ct);
                report.Success = isoRes.Success;
                report.Message = isoRes.Message;
                if (isoRes.Success)
                {
                    report.RevertStateJson = SentinelJson.Serialize(new ActionRevertState { Kind = "firewallRule", Value = isoRes.RuleName });
                }
                return report;

            case ResponseActionType.ProtectFolders:
                var targetFolders = !string.IsNullOrWhiteSpace(cmd.Target) && Directory.Exists(Environment.ExpandEnvironmentVariables(cmd.Target))
                    ? new[] { cmd.Target }
                    : _stateStore.CurrentSettings.WatchedFolders.ToArray();
                var protRes = _folders.Protect(targetFolders);
                report.Success = protRes.Success;
                report.Message = protRes.Message;
                if (protRes.Success)
                {
                    report.RevertStateJson = SentinelJson.Serialize(new ActionRevertState
                    {
                        Kind = "folders",
                        Folders = protRes.ProtectedFolders,
                        AccountSid = protRes.AccountSid
                    });
                }
                return report;

            case ResponseActionType.DisableDevice:
                var devRes = await _devices.DisableDeviceAsync(cmd.Target, ct);
                report.Success = devRes.Success;
                report.Message = devRes.Message;
                if (devRes.Success)
                {
                    report.RevertStateJson = SentinelJson.Serialize(new ActionRevertState { Kind = "device", Value = cmd.Target });
                }
                return report;

            case ResponseActionType.BlockProcessConnections:
            case ResponseActionType.ThrottleTraffic:
                var progPath = cmd.Parameters.TryGetValue("process.path", out var pp) && !string.IsNullOrWhiteSpace(pp)
                    ? pp
                    : cmd.Target;
                var progRes = await _firewall.BlockProgramAsync(cmd.CommandId, progPath, ct);
                report.Success = progRes.Success;
                report.Message = progRes.Message;
                if (progRes.Success)
                {
                    report.RevertStateJson = SentinelJson.Serialize(new ActionRevertState { Kind = "firewallRule", Value = progRes.RuleName });
                }
                return report;

            case ResponseActionType.BlockIp:
                var ipRes = await _firewall.BlockIpAsync(cmd.CommandId, cmd.Target, ct);
                report.Success = ipRes.Success;
                report.Message = ipRes.Message;
                if (ipRes.Success)
                {
                    report.RevertStateJson = SentinelJson.Serialize(new ActionRevertState { Kind = "firewallRule", Value = ipRes.RuleName });
                }
                return report;

            case ResponseActionType.LockSession:
            case ResponseActionType.LockAccount:
                var locked = await _ipc.SendLockSessionAsync(ct);
                report.Success = true;
                report.Message = locked > 0
                    ? $"Verrouillage de session déclenché sur {locked} session(s) active(s)."
                    : "Demande de verrouillage enregistrée (aucune session Tray interactive connectée).";
                return report;

            default:
                report.Success = false;
                report.Message = $"Type d'action non supporté : {actionType}.";
                return report;
        }
    }

    private async Task<ActionResultReport> ExecuteRevertAsync(
        AgentCommand cmd,
        ResponseActionType actionType,
        ActionResultReport report,
        CancellationToken ct)
    {
        var state = string.IsNullOrWhiteSpace(cmd.RevertStateJson)
            ? null
            : SentinelJson.Deserialize<ActionRevertState>(cmd.RevertStateJson);

        switch (state?.Kind)
        {
            case "domain":
                var dom = state.Value ?? cmd.Target;
                _hosts.UnblockDomain(dom);
                var remaining = _hosts.GetBlockedDomains();
                await _ipc.SendBlockDomainsAsync(new BrowserCommand(null, null, remaining, "Annulation du blocage par l'administrateur"), ct);
                report.Success = true;
                report.Message = $"Domaine {dom} débloqué (hosts + navigateur).";
                return report;

            case "quarantine":
                var qId = state.Value ?? cmd.Target;
                var restoredPath = _quarantine.Restore(qId, state.OriginalPath);
                report.Success = true;
                report.Message = $"Fichier restauré à l'identique vers {restoredPath}.";
                return report;

            case "firewallRule":
                var fwRes = await _firewall.RemoveRuleAsync(state.Value ?? string.Empty, ct);
                report.Success = fwRes.Success;
                report.Message = fwRes.Message;
                return report;

            case "suspendPid":
                var resumeRes = _processes.ResumeProcess(state.Pid);
                report.Success = resumeRes.Success;
                report.Message = resumeRes.Message;
                return report;

            case "folders":
                var unprotRes = _folders.Unprotect(state.Folders ?? [], state.AccountSid ?? string.Empty);
                report.Success = unprotRes.Success;
                report.Message = unprotRes.Message;
                return report;

            case "device":
                var enRes = await _devices.EnableDeviceAsync(state.Value ?? cmd.Target, ct);
                report.Success = enRes.Success;
                report.Message = enRes.Message;
                return report;

            case "watchHash":
                if (!string.IsNullOrWhiteSpace(state.Value))
                {
                    _watchedHashes.TryRemove(state.Value, out _);
                }
                report.Success = true;
                report.Message = $"Empreinte {state.Value} retirée de la liste de surveillance.";
                return report;

            default:
                // Repli si l'état JSON n'était pas renseigné pour un domaine.
                if (actionType == ResponseActionType.BlockDomain && !string.IsNullOrWhiteSpace(cmd.Target))
                {
                    _hosts.UnblockDomain(cmd.Target);
                    await _ipc.SendBlockDomainsAsync(new BrowserCommand(null, null, _hosts.GetBlockedDomains(), "Déblocage"), ct);
                    report.Success = true;
                    report.Message = $"Domaine {cmd.Target} débloqué.";
                    return report;
                }

                report.Success = false;
                report.Message = $"Action {actionType} non réversible ou état initial manquant.";
                return report;
        }
    }

    private sealed class ActionRevertState
    {
        public string Kind { get; set; } = string.Empty;
        public string? Value { get; set; }
        public string? OriginalPath { get; set; }
        public string? Sha256 { get; set; }
        public int Pid { get; set; }
        public List<string>? Folders { get; set; }
        public string? AccountSid { get; set; }
    }
}
