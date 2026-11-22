using Sentinel.Core.Enrichment;
using Sentinel.Shared.Models;

namespace Sentinel.Core.Decision;

/// <summary>
/// Moteur de décision déterministe implémentant la matrice complète §9.1 &amp; §9.2
/// (<see cref="ThreatType"/> × <see cref="ThreatLevel"/> → <see cref="PlannedAction"/>s).
/// Toutes les actions automatiques sont strictement réversibles ; aucune action destructive n'est jamais planifiée.
/// </summary>
public sealed class DecisionEngine
{
    /// <summary>
    /// Détermine le mode opérationnel effectif (bascule automatiquement de <see cref="OperatingMode.Learning"/>
    /// à <see cref="OperatingMode.Active"/> après <see cref="SentinelSettings.LearningPeriodDays"/> si activé).
    /// </summary>
    public OperatingMode ResolveEffectiveMode(SentinelSettings settings, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(settings);
        if (settings.Mode == OperatingMode.Learning &&
            settings.AutoLeaveLearning &&
            (now - settings.LearningStartedAt).TotalDays >= Math.Max(0, settings.LearningPeriodDays))
        {
            return OperatingMode.Active;
        }
        return settings.Mode;
    }

    public ResponseDecision Decide(
        SecurityEvent triggerEvent,
        ThreatAssessment assessment,
        CorrelationCluster? cluster,
        IReadOnlyList<SecurityEvent>? clusterEvents,
        SentinelSettings settings,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(triggerEvent);
        ArgumentNullException.ThrowIfNull(assessment);
        ArgumentNullException.ThrowIfNull(settings);

        var effectiveMode = ResolveEffectiveMode(settings, now);
        var eventLevel = settings.Thresholds.LevelOf(assessment.Score);

        var useCluster = cluster is not null &&
                         (cluster.Level > eventLevel || cluster.Score >= assessment.Score);

        var effectiveScore = useCluster ? cluster!.Score : assessment.Score;
        var effectiveLevel = useCluster ? cluster!.Level : eventLevel;
        var effectiveType = useCluster
            ? (cluster!.DominantType != ThreatType.None ? cluster.DominantType : assessment.Type)
            : assessment.Type;

        var targets = ExtractedTargets.Extract(triggerEvent, clusterEvents);
        var canAutoExecute = effectiveMode == OperatingMode.Active;

        var actions = BuildActions(effectiveType, effectiveLevel, targets, triggerEvent, effectiveMode, canAutoExecute);
        var alertAdmin = effectiveLevel >= ThreatLevel.High;
        var requiresHumanApproval = effectiveLevel == ThreatLevel.High;
        var notifyUser = effectiveLevel == ThreatLevel.Moderate;

        var justification = BuildJustification(
            effectiveScore,
            effectiveLevel,
            effectiveType,
            effectiveMode,
            cluster,
            assessment);

        return new ResponseDecision
        {
            Id = Guid.NewGuid(),
            HostId = triggerEvent.HostId,
            TriggerEventId = triggerEvent.Id,
            ClusterId = cluster?.Id,
            Score = effectiveScore,
            Level = effectiveLevel,
            Type = effectiveType,
            Actions = actions,
            RequiresHumanApproval = requiresHumanApproval,
            AlertAdmin = alertAdmin,
            NotifyUser = notifyUser,
            Justification = justification,
            Mode = effectiveMode
        };
    }

    private static IReadOnlyList<PlannedAction> BuildActions(
        ThreatType type,
        ThreatLevel level,
        ExtractedTargets t,
        SecurityEvent evt,
        OperatingMode mode,
        bool canAutoExecute)
    {
        var list = new List<PlannedAction>(4);

        // Niveau 0 : Info -> journalisation seule
        if (level == ThreatLevel.Info)
        {
            list.Add(MakeAction(
                ResponseActionType.LogOnly,
                evt.Subject,
                BaseParams(evt, mode),
                automatic: false,
                "Niveau Info : journalisation seule."));
            return list;
        }

        // Niveau 1 : Faible -> journalisation + marquage pour corrélation (+ actions passives de la matrice)
        if (level == ThreatLevel.Low)
        {
            list.Add(MakeAction(
                ResponseActionType.MarkForCorrelation,
                evt.Subject,
                BaseParams(evt, mode),
                automatic: false,
                "Signal faible (niveau 1) : marqué pour corrélation dans les fenêtres glissantes."));

            if (type == ThreatType.Malware && !string.IsNullOrWhiteSpace(t.Sha256))
            {
                list.Add(MakeAction(
                    ResponseActionType.WatchHash,
                    t.Sha256,
                    WithParam(BaseParams(evt, mode), "sha256", t.Sha256),
                    automatic: false,
                    "Mise en surveillance de l'empreinte SHA-256."));
            }
            else if (type == ThreatType.Ransomware)
            {
                list.Add(MakeAction(
                    ResponseActionType.EnhancedMonitoring,
                    t.WatchedFolder ?? evt.HostId,
                    BaseParams(evt, mode),
                    automatic: false,
                    "Surveillance renforcée des dossiers sensibles (suspicion ransomware)."));
            }
            else if (type == ThreatType.SocialEngineering)
            {
                list.Add(MakeAction(
                    ResponseActionType.UserAwareness,
                    t.UserId,
                    BaseParams(evt, mode),
                    automatic: false,
                    "Sensibilisation préventive de l'utilisateur face à un lien suspect."));
            }

            return list;
        }

        // Niveau 2 : Modéré -> notification discrète à l'utilisateur + surveillance renforcée
        if (level == ThreatLevel.Moderate)
        {
            if (type == ThreatType.SocialEngineering)
            {
                list.Add(MakeAction(
                    ResponseActionType.UserAwareness,
                    t.UserId,
                    BaseParams(evt, mode),
                    automatic: false,
                    "Message de sensibilisation à l'utilisateur (ingénierie sociale détectée)."));
            }

            list.Add(MakeAction(
                ResponseActionType.NotifyUser,
                t.UserId,
                BaseParams(evt, mode),
                automatic: false,
                $"Notification discrète à l'utilisateur ({type}, niveau Modéré)."));

            list.Add(MakeAction(
                ResponseActionType.EnhancedMonitoring,
                t.Domain ?? t.ProcessName ?? t.FilePath ?? evt.HostId,
                BaseParams(evt, mode),
                automatic: false,
                "Surveillance renforcée activée sur l'entité concernée."));

            if (type == ThreatType.Malware && !string.IsNullOrWhiteSpace(t.Sha256))
            {
                list.Add(MakeAction(
                    ResponseActionType.WatchHash,
                    t.Sha256,
                    WithParam(BaseParams(evt, mode), "sha256", t.Sha256),
                    automatic: false,
                    "Inscription de l'empreinte SHA-256 sur liste de surveillance."));
            }

            return list;
        }

        // Niveau 3 (Élevé : décision humaine requise, Automatic = false)
        // et Niveau 4 (Critique : blocage automatique réversible si mode Active, sinon Automatic = false)
        var isCritical = level >= ThreatLevel.Critical;
        var auto = isCritical && canAutoExecute;

        list.Add(MakeAction(
            ResponseActionType.AlertAdmin,
            evt.HostId,
            BaseParams(evt, mode),
            automatic: false,
            isCritical
                ? "Alerte critique immédiate envoyée à l'administrateur."
                : "Alerte élevée : validation humaine requise avant exécution des actions proposées."));

        switch (type)
        {
            case ThreatType.Phishing:
            {
                var domainTarget = t.Domain ?? t.Url ?? evt.Subject;
                list.Add(MakeAction(
                    ResponseActionType.BlockDomain,
                    domainTarget,
                    WithParam(BaseParams(evt, mode), "domain", domainTarget),
                    auto,
                    isCritical
                        ? $"Blocage réversible du domaine de phishing {domainTarget} (hosts/pare-feu)."
                        : $"Proposition de blocage du domaine suspect {domainTarget}."));

                if (isCritical)
                {
                    var tabTarget = t.TabId ?? t.Url ?? domainTarget;
                    var p = BaseParams(evt, mode);
                    if (t.TabId is not null) p["tabId"] = t.TabId;
                    if (t.Url is not null) p["url"] = t.Url;
                    list.Add(MakeAction(
                        ResponseActionType.CloseBrowserTab,
                        tabTarget,
                        p,
                        auto,
                        "Fermeture de l'onglet malveillant via l'extension navigateur."));
                }
                break;
            }

            case ThreatType.Malware:
            {
                var procTarget = t.Pid ?? t.ProcessName ?? evt.Subject;
                var procParams = BaseParams(evt, mode);
                if (t.Pid is not null) procParams["pid"] = t.Pid;
                if (t.ProcessName is not null) procParams["processName"] = t.ProcessName;

                if (!isCritical)
                {
                    list.Add(MakeAction(
                        ResponseActionType.SuspendProcess,
                        procTarget,
                        procParams,
                        automatic: false,
                        $"Proposition de suspension réversible du processus suspect ({procTarget})."));
                }
                else
                {
                    list.Add(MakeAction(
                        ResponseActionType.KillProcess,
                        procTarget,
                        procParams,
                        auto,
                        $"Arrêt du processus malveillant ({procTarget})."));

                    var fileTarget = t.FilePath ?? t.ProcessPath ?? evt.Subject;
                    var fileParams = BaseParams(evt, mode);
                    fileParams["filePath"] = fileTarget;
                    if (t.Sha256 is not null) fileParams["sha256"] = t.Sha256;
                    list.Add(MakeAction(
                        ResponseActionType.QuarantineFile,
                        fileTarget,
                        fileParams,
                        auto,
                        $"Mise en quarantaine réversible (chiffrée) du fichier {fileTarget}."));
                }
                break;
            }

            case ThreatType.Ransomware:
            {
                var procTarget = t.Pid ?? t.ProcessName ?? evt.HostId;
                var procParams = BaseParams(evt, mode);
                if (t.Pid is not null) procParams["pid"] = t.Pid;

                if (!isCritical)
                {
                    list.Add(MakeAction(
                        ResponseActionType.SuspendProcess,
                        procTarget,
                        procParams,
                        automatic: false,
                        $"Proposition de suspension immédiate du processus suspecté de chiffrement ({procTarget})."));
                }
                else
                {
                    list.Add(MakeAction(
                        ResponseActionType.KillProcess,
                        procTarget,
                        procParams,
                        auto,
                        $"Arrêt d'urgence du processus ransomware ({procTarget})."));

                    list.Add(MakeAction(
                        ResponseActionType.IsolateNetwork,
                        evt.HostId,
                        BaseParams(evt, mode),
                        auto,
                        "Isolement réseau réversible du poste pour empêcher la propagation latérale."));

                    list.Add(MakeAction(
                        ResponseActionType.ProtectFolders,
                        t.WatchedFolder ?? evt.HostId,
                        BaseParams(evt, mode),
                        auto,
                        "Activation de la protection en écriture réversible des dossiers surveillés."));
                }
                break;
            }

            case ThreatType.BadUsb:
            {
                var devTarget = t.DeviceId ?? evt.Subject;
                list.Add(MakeAction(
                    ResponseActionType.DisableDevice,
                    devTarget,
                    WithParam(BaseParams(evt, mode), "deviceId", devTarget),
                    auto,
                    isCritical
                        ? $"Désactivation PnP réversible du périphérique suspect ({devTarget})."
                        : $"Proposition de désactivation du périphérique HID suspect ({devTarget})."));
                break;
            }

            case ThreatType.Exfiltration:
            {
                var target = t.Pid ?? t.ProcessName ?? t.Domain ?? t.RemoteIp ?? evt.Subject;
                var p = BaseParams(evt, mode);
                if (t.Pid is not null) p["pid"] = t.Pid;
                if (t.Domain is not null) p["domain"] = t.Domain;
                if (t.RemoteIp is not null) p["remoteIp"] = t.RemoteIp;

                if (!isCritical)
                {
                    list.Add(MakeAction(
                        ResponseActionType.ThrottleTraffic,
                        target,
                        p,
                        automatic: false,
                        $"Proposition de limitation du trafic sortant ({target})."));
                }
                else
                {
                    list.Add(MakeAction(
                        ResponseActionType.BlockProcessConnections,
                        target,
                        p,
                        auto,
                        $"Coupure réversible des connexions sortantes du processus par règle pare-feu ({target})."));

                    if (!string.IsNullOrWhiteSpace(t.DeviceId))
                    {
                        list.Add(MakeAction(
                            ResponseActionType.DisableDevice,
                            t.DeviceId,
                            WithParam(BaseParams(evt, mode), "deviceId", t.DeviceId),
                            auto,
                            $"Désactivation réversible du support USB impliqué ({t.DeviceId})."));
                    }
                }
                break;
            }

            case ThreatType.Intrusion:
            {
                var userTarget = t.TargetUser ?? t.UserId;
                if (!isCritical)
                {
                    list.Add(MakeAction(
                        ResponseActionType.LockSession,
                        userTarget,
                        WithParam(BaseParams(evt, mode), "userId", userTarget),
                        automatic: false,
                        $"Proposition de verrouillage de la session utilisateur ({userTarget})."));
                }
                else
                {
                    list.Add(MakeAction(
                        ResponseActionType.LockAccount,
                        userTarget,
                        WithParam(BaseParams(evt, mode), "userId", userTarget),
                        auto,
                        $"Verrouillage réversible du compte ciblé ({userTarget})."));

                    var ipTarget = t.RemoteIp ?? evt.HostId;
                    list.Add(MakeAction(
                        ResponseActionType.BlockIp,
                        ipTarget,
                        WithParam(BaseParams(evt, mode), "ip", ipTarget),
                        auto,
                        $"Blocage pare-feu réversible de l'adresse IP source ({ipTarget})."));
                }
                break;
            }

            case ThreatType.SocialEngineering:
            {
                var domainTarget = t.Domain ?? t.Url ?? evt.Subject;
                list.Add(MakeAction(
                    ResponseActionType.BlockDomain,
                    domainTarget,
                    WithParam(BaseParams(evt, mode), "domain", domainTarget),
                    auto,
                    isCritical
                        ? $"Blocage réversible du domaine d'ingénierie sociale ({domainTarget})."
                        : $"Proposition de blocage du domaine d'ingénierie sociale ({domainTarget})."));

                if (!isCritical)
                {
                    list.Add(MakeAction(
                        ResponseActionType.UserAwareness,
                        t.UserId,
                        BaseParams(evt, mode),
                        automatic: false,
                        "Rapport administrateur + sensibilisation de l'utilisateur."));
                }
                else if (t.TabId is not null || t.Url is not null)
                {
                    list.Add(MakeAction(
                        ResponseActionType.CloseBrowserTab,
                        t.TabId ?? t.Url!,
                        BaseParams(evt, mode),
                        auto,
                        "Fermeture de l'onglet lié à la campagne d'ingénierie sociale."));
                }
                break;
            }

            case ThreatType.Persistence:
            {
                var target = t.Pid ?? t.FilePath ?? t.ProcessPath ?? evt.Subject;
                if (!isCritical)
                {
                    list.Add(MakeAction(
                        ResponseActionType.SuspendProcess,
                        target,
                        BaseParams(evt, mode),
                        automatic: false,
                        $"Proposition de suspension / revue du mécanisme de persistance ({target})."));
                }
                else
                {
                    if (!string.IsNullOrWhiteSpace(t.Pid))
                    {
                        list.Add(MakeAction(
                            ResponseActionType.KillProcess,
                            t.Pid,
                            WithParam(BaseParams(evt, mode), "pid", t.Pid),
                            auto,
                            $"Arrêt du processus établissant la persistance (PID {t.Pid})."));
                    }
                    list.Add(MakeAction(
                        ResponseActionType.QuarantineFile,
                        t.FilePath ?? t.ProcessPath ?? evt.Subject,
                        BaseParams(evt, mode),
                        auto,
                        $"Mise en quarantaine réversible de l'élément persistant ({t.FilePath ?? evt.Subject})."));
                }
                break;
            }

            case ThreatType.Tampering:
            {
                if (!isCritical)
                {
                    list.Add(MakeAction(
                        ResponseActionType.LockSession,
                        t.UserId,
                        BaseParams(evt, mode),
                        automatic: false,
                        "Alerte auto-protection : proposition de verrouillage de session."));
                }
                else
                {
                    list.Add(MakeAction(
                        ResponseActionType.IsolateNetwork,
                        evt.HostId,
                        BaseParams(evt, mode),
                        auto,
                        "Auto-protection critique : isolement réseau réversible du poste suite à altération de l'agent."));
                    list.Add(MakeAction(
                        ResponseActionType.LockSession,
                        t.UserId,
                        BaseParams(evt, mode),
                        auto,
                        "Verrouillage immédiat de la session active."));
                }
                break;
            }

            default: // ThreatType.Anomaly / ThreatType.None
            {
                if (isCritical)
                {
                    list.Add(MakeAction(
                        ResponseActionType.LockSession,
                        t.UserId,
                        WithParam(BaseParams(evt, mode), "userId", t.UserId),
                        auto,
                        $"Anomalie comportementale critique : verrouillage réversible de la session ({t.UserId})."));
                }
                break;
            }
        }

        return list;
    }

    private static PlannedAction MakeAction(
        ResponseActionType type,
        string target,
        Dictionary<string, string> parameters,
        bool automatic,
        string rationale) =>
        new(type, string.IsNullOrWhiteSpace(target) ? "unknown" : target, parameters, automatic, rationale);

    private static Dictionary<string, string> BaseParams(SecurityEvent evt, OperatingMode mode) =>
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["hostId"] = evt.HostId,
            ["reversible"] = "true",
            ["mode"] = mode.ToString()
        };

    private static Dictionary<string, string> WithParam(Dictionary<string, string> dict, string key, string value)
    {
        dict[key] = value;
        return dict;
    }

    private static string BuildJustification(
        int score,
        ThreatLevel level,
        ThreatType type,
        OperatingMode mode,
        CorrelationCluster? cluster,
        ThreatAssessment assessment)
    {
        var origin = cluster is not null && cluster.Score >= assessment.Score
            ? cluster.Justification
            : assessment.Justification;

        var modeNote = mode switch
        {
            OperatingMode.Learning => "Mode Apprentissage : aucune action automatique exécutée.",
            OperatingMode.Simulation => "Mode Simulation : actions journalisées mais non exécutées.",
            _ => level switch
            {
                ThreatLevel.Critical => "Mode Actif : blocage automatique réversible déclenché.",
                ThreatLevel.High => "Mode Actif : validation humaine requise par l'administrateur.",
                ThreatLevel.Moderate => "Mode Actif : notification discrète et surveillance renforcée.",
                _ => "Mode Actif : observation."
            }
        };

        return $"Décision {ThreatLevels.Label(level)} ({score}/100, {type}) — {modeNote} Origine : {origin}";
    }

    private sealed class ExtractedTargets
    {
        public string? Domain { get; init; }
        public string? Url { get; init; }
        public string? TabId { get; init; }
        public string? Pid { get; init; }
        public string? ProcessName { get; init; }
        public string? ProcessPath { get; init; }
        public string? FilePath { get; init; }
        public string? Sha256 { get; init; }
        public string? DeviceId { get; init; }
        public string? RemoteIp { get; init; }
        public string? TargetUser { get; init; }
        public string? WatchedFolder { get; init; }
        public required string UserId { get; init; }

        public static ExtractedTargets Extract(SecurityEvent trigger, IReadOnlyList<SecurityEvent>? clusterEvents)
        {
            // Parcourt d'abord l'événement déclencheur puis les événements du cluster du plus récent au plus ancien
            var ordered = new List<SecurityEvent>(1 + (clusterEvents?.Count ?? 0)) { trigger };
            if (clusterEvents is not null)
            {
                for (var i = clusterEvents.Count - 1; i >= 0; i--)
                {
                    if (clusterEvents[i].Id != trigger.Id) ordered.Add(clusterEvents[i]);
                }
            }

            string? domain = null, url = null, tabId = null, pid = null, processName = null, processPath = null;
            string? filePath = null, sha256 = null, deviceId = null, remoteIp = null, targetUser = null, watchedFolder = null;

            foreach (var e in ordered)
            {
                url ??= e.Attr(AttributeKeys.Url) ?? (e.Subject.Contains("://", StringComparison.Ordinal) ? e.Subject : null);
                domain ??= e.Attr(AttributeKeys.Domain) ?? ThreatIndicators.ExtractDomain(url) ?? ThreatIndicators.ExtractDomain(e.Subject);
                tabId ??= e.Attr(AttributeKeys.TabId);
                pid ??= e.Attr(AttributeKeys.ProcessId);
                processName ??= e.Attr(AttributeKeys.ProcessName);
                processPath ??= e.Attr(AttributeKeys.ProcessPath) ?? (e.Category == EventCategory.Process ? e.Subject : null);
                filePath ??= e.Attr(AttributeKeys.FilePath) ?? (e.Category == EventCategory.File ? e.Subject : null);
                sha256 ??= e.Attr(AttributeKeys.Sha256) ?? e.Attr(AttributeKeys.ContentHash);
                deviceId ??= e.Attr(AttributeKeys.DeviceId) ?? (e.Category == EventCategory.Device ? e.Subject : null);
                remoteIp ??= e.Attr(AttributeKeys.RemoteIp) ?? e.Attr(AttributeKeys.SourceIp);
                targetUser ??= e.Attr(AttributeKeys.TargetUser);
                watchedFolder ??= e.Attr(AttributeKeys.WatchedFolder);
            }

            return new ExtractedTargets
            {
                Domain = domain,
                Url = url,
                TabId = tabId,
                Pid = pid,
                ProcessName = processName,
                ProcessPath = processPath,
                FilePath = filePath,
                Sha256 = sha256,
                DeviceId = deviceId,
                RemoteIp = remoteIp,
                TargetUser = targetUser,
                WatchedFolder = watchedFolder,
                UserId = string.IsNullOrWhiteSpace(trigger.UserId) ? "unknown" : trigger.UserId
            };
        }
    }
}
