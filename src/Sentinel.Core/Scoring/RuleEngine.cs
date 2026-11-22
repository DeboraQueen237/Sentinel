using Sentinel.Core.Enrichment;
using Sentinel.Shared.Models;

namespace Sentinel.Core.Scoring;

/// <summary>Correspondance d'une règle déterministe avec poids, type de menace, MITRE ATT&amp;CK et justification.</summary>
public sealed record RuleMatch(
    string RuleId,
    int Weight,
    ThreatType ThreatType,
    IReadOnlyList<string> MitreTechniques,
    string Reason);

/// <summary>Résultat agrégé de l'évaluation par règles déterministes.</summary>
public sealed record RuleEvaluationResult(
    int Score,
    ThreatType ThreatType,
    IReadOnlyList<RuleMatch> Matches,
    IReadOnlyList<string> MitreTechniques,
    string Justification);

/// <summary>
/// Moteur de règles déterministes couvrant toutes les <see cref="EventCategory"/>,
/// <see cref="EventTypes"/> et <see cref="AttributeKeys"/> de SENTINEL.
/// Combinaison non-linéaire bornée : <c>100 * (1 - ∏(1 - w_i / 100))</c>, calibrée pour que
/// les signaux faibles isolés restent dans la plage 30–60 afin de démontrer le gain de la corrélation.
/// </summary>
public sealed class RuleEngine
{
    public RuleEvaluationResult Evaluate(EnrichedEvent enriched)
    {
        ArgumentNullException.ThrowIfNull(enriched);
        var matches = new List<RuleMatch>(4);

        switch (enriched.Event.Category)
        {
            case EventCategory.Process:
                EvaluateProcess(enriched, matches);
                break;
            case EventCategory.Network:
                EvaluateNetwork(enriched, matches);
                break;
            case EventCategory.Clipboard:
                EvaluateClipboard(enriched, matches);
                break;
            case EventCategory.File:
                EvaluateFile(enriched, matches);
                break;
            case EventCategory.Session:
                EvaluateSession(enriched, matches);
                break;
            case EventCategory.Typing:
                EvaluateTyping(enriched, matches);
                break;
            case EventCategory.Device:
                EvaluateDevice(enriched, matches);
                break;
            case EventCategory.Browser:
                EvaluateBrowser(enriched, matches);
                break;
            case EventCategory.Installation:
                EvaluateInstallation(enriched, matches);
                break;
            case EventCategory.System:
                EvaluateSystem(enriched, matches);
                break;
            case EventCategory.Defender:
                EvaluateDefender(enriched, matches);
                break;
            case EventCategory.Script:
                EvaluateScript(enriched, matches);
                break;
            case EventCategory.Canary:
                EvaluateCanary(enriched, matches);
                break;
            case EventCategory.StaticAnalysis:
                EvaluateStaticAnalysis(enriched, matches);
                break;
            case EventCategory.ThreatIntel:
                EvaluateThreatIntel(enriched, matches);
                break;
        }

        if (matches.Count == 0)
        {
            return new RuleEvaluationResult(
                0,
                ThreatType.None,
                Array.Empty<RuleMatch>(),
                Array.Empty<string>(),
                "Aucune règle de menace déclenchée (activité normale).");
        }

        var score = CombineWeights(matches);
        var dominantType = SelectDominantThreatType(matches);
        var mitre = matches
            .SelectMany(m => m.MitreTechniques)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var justification = string.Join(" ; ", matches.Select(m => m.Reason));

        return new RuleEvaluationResult(score, dominantType, matches, mitre, justification);
    }

    /// <summary>Combinaison non-linéaire bornée 0–100 : <c>100 * (1 - ∏(1 - w_i / 100))</c>.</summary>
    public static int CombineWeights(IReadOnlyList<RuleMatch> matches)
    {
        if (matches.Count == 0) return 0;
        var complementProduct = 1.0;
        for (var i = 0; i < matches.Count; i++)
        {
            var w = Math.Clamp(matches[i].Weight, 0, 100);
            complementProduct *= 1.0 - (w / 100.0);
        }
        return Math.Clamp((int)Math.Round(100.0 * (1.0 - complementProduct)), 0, 100);
    }

    private static ThreatType SelectDominantThreatType(List<RuleMatch> matches)
    {
        // Privilégie le type porté par la règle au poids maximal (départage par cumul de poids)
        var best = matches
            .Where(m => m.ThreatType != ThreatType.None)
            .GroupBy(m => m.ThreatType)
            .OrderByDescending(g => g.Max(m => m.Weight))
            .ThenByDescending(g => g.Sum(m => m.Weight))
            .FirstOrDefault();

        return best?.Key ?? ThreatType.Anomaly;
    }

    private static void EvaluateProcess(EnrichedEvent e, List<RuleMatch> matches)
    {
        var evt = e.Event;
        if (evt.EventType == EventTypes.ProcessStop) return;

        if (e.IsKnownBadHash)
        {
            matches.Add(new RuleMatch(
                "PROC-KNOWN-BAD-HASH", 92, ThreatType.Malware, ["T1204.002"],
                $"Exécution d'un binaire à empreinte SHA-256 malveillante connue ({e.ProcessName ?? evt.Subject})"));
        }

        if (e.HasDoubleExtension)
        {
            matches.Add(new RuleMatch(
                "PROC-DOUBLE-EXT-EXEC", 68, ThreatType.Malware, ["T1036.007", "T1204.002"],
                $"Exécution d'un fichier à double extension masquée ({e.FileName ?? evt.Subject})"));
        }

        if (e.IsLolBin && e.HasEncodedCommand)
        {
            var mitre = e.ProcessName is "powershell" or "pwsh"
                ? new[] { "T1059.001", "T1218" }
                : new[] { "T1059.003", "T1218" };
            matches.Add(new RuleMatch(
                "PROC-LOLBIN-ENCODED", 68, ThreatType.Malware, mitre,
                $"LOLBin ({e.ProcessName}) invoqué avec commande encodée, masquée ou téléchargement distant"));
        }
        else if (e.IsLolBin && !string.IsNullOrWhiteSpace(e.CommandLine) &&
                 (e.CommandLine.Contains("http://", StringComparison.OrdinalIgnoreCase) ||
                  e.CommandLine.Contains("https://", StringComparison.OrdinalIgnoreCase) ||
                  e.CommandLine.Contains("/s ", StringComparison.OrdinalIgnoreCase) ||
                  e.ProcessName is "mshta" or "bitsadmin" or "certutil" or "wscript" or "cscript"))
        {
            matches.Add(new RuleMatch(
                "PROC-LOLBIN-EXEC", 38, ThreatType.Malware, ["T1059", "T1218"],
                $"Exécution suspecte via outil système détournable (LOLBin : {e.ProcessName})"));
        }

        if (e.IsObfuscatedCommand)
        {
            matches.Add(new RuleMatch(
                "PROC-CMD-OBFUSCATED", 55, ThreatType.Malware, ["T1059"],
                $"Ligne de commande fortement obfusquée détectée ({e.ProcessName ?? evt.Subject})"));
        }

        if (!string.IsNullOrWhiteSpace(e.ParentProcessName) &&
            ThreatIndicators.IsOfficeApp(e.ParentProcessName) &&
            (e.IsLolBin || e.IsSigned == false))
        {
            matches.Add(new RuleMatch(
                "PROC-OFFICE-SPAWN-SHELL", 65, ThreatType.Malware, ["T1566", "T1059"],
                $"Application bureautique ({e.ParentProcessName}) lançant un interpréteur ou binaire suspect ({e.ProcessName})"));
        }

        if (!string.IsNullOrWhiteSpace(e.ParentProcessName) &&
            ThreatIndicators.IsBrowser(e.ParentProcessName) &&
            (e.IsLolBin || e.IsSigned == false || e.IsDownloadsDirectory))
        {
            matches.Add(new RuleMatch(
                "PROC-BROWSER-SPAWN-EXE", 52, ThreatType.Phishing, ["T1204.002"],
                $"Navigateur ({e.ParentProcessName}) lançant un exécutable ou script suspect ({e.ProcessName})"));
        }

        if (e.IsSigned == false && e.IsSuspiciousDirectory && !e.IsDownloadsDirectory)
        {
            matches.Add(new RuleMatch(
                "PROC-UNSIGNED-TEMP", 48, ThreatType.Malware, ["T1204.002"],
                $"Exécutable non signé lancé depuis un répertoire temporaire ou utilisateur ({e.ProcessPath ?? evt.Subject})"));
        }
        else if (e.IsDownloadsDirectory && (e.IsSigned != true || !e.IsTrustedPublisher))
        {
            matches.Add(new RuleMatch(
                "PROC-SUSPICIOUS-DOWNLOAD-EXEC", 48, ThreatType.Malware, ["T1204.002"],
                $"Exécution d'un programme non vérifié depuis le dossier Téléchargements ({e.FileName ?? evt.Subject})"));
        }

        if (evt.AttrIsTrue(AttributeKeys.Elevated) && e.IsSigned == false)
        {
            matches.Add(new RuleMatch(
                "PROC-ELEVATED-UNSIGNED", 58, ThreatType.Intrusion, ["T1204.002"],
                $"Processus non signé exécuté avec privilèges élevés ({e.ProcessName ?? evt.Subject})"));
        }
        else if (matches.Count == 0 && e.IsSigned == false && !e.IsTrustedPublisher &&
                 !string.IsNullOrWhiteSpace(e.ProcessPath) &&
                 !e.ProcessPath.Contains("\\Program Files", StringComparison.OrdinalIgnoreCase) &&
                 !e.ProcessPath.Contains("\\Windows\\", StringComparison.OrdinalIgnoreCase))
        {
            matches.Add(new RuleMatch(
                "PROC-UNSIGNED-UNUSUAL", 32, ThreatType.Anomaly, ["T1204"],
                $"Exécutable non signé lancé hors répertoires système ({e.ProcessName ?? evt.Subject})"));
        }
    }

    private static void EvaluateNetwork(EnrichedEvent e, List<RuleMatch> matches)
    {
        var evt = e.Event;
        var domainAge = evt.AttrDouble(AttributeKeys.DomainAgeDays);
        var remotePort = evt.AttrLong(AttributeKeys.RemotePort);
        var bytesSent = evt.AttrLong(AttributeKeys.BytesSent) ?? 0;
        var isPrivateExplicit = evt.Attributes.TryGetValue(AttributeKeys.IsPrivateIp, out var privRaw)
            ? privRaw == "1" || privRaw.Equals("true", StringComparison.OrdinalIgnoreCase)
            : (bool?)null;

        if (e.IsKnownBadDomain || e.IsKnownBadIp)
        {
            matches.Add(new RuleMatch(
                "NET-KNOWN-BAD-DOMAIN", 85, ThreatType.Malware, ["T1071"],
                $"Communication vers un domaine ou une IP de mauvaise réputation ({e.Domain ?? e.RemoteIp})"));
        }

        if (domainAge is <= 30 && !string.IsNullOrWhiteSpace(e.Domain))
        {
            var weight = domainAge <= 7 ? 46 : 36;
            matches.Add(new RuleMatch(
                "NET-RARE-DOMAIN", weight, ThreatType.Phishing, ["T1071"],
                $"Communication vers un domaine récent ou rare ({e.Domain}, âge {domainAge:F0} j)"));
        }

        if (e.HasRiskyTld && !string.IsNullOrWhiteSpace(e.Domain))
        {
            matches.Add(new RuleMatch(
                "NET-RISKY-TLD", 40, ThreatType.Phishing, ["T1071"],
                $"Connexion vers un domaine à TLD à risque ({e.Domain})"));
        }

        if (bytesSent >= 10_000_000)
        {
            var weight = bytesSent >= 50_000_000 ? 60 : 48;
            matches.Add(new RuleMatch(
                "NET-LARGE-OUTBOUND", weight, ThreatType.Exfiltration, ["T1041"],
                $"Volume sortant inhabituellement élevé ({bytesSent / (1024.0 * 1024.0):F1} Mo vers {e.Domain ?? e.RemoteIp ?? evt.Subject})"));
        }

        var isPublicRawIp = string.IsNullOrWhiteSpace(e.Domain) &&
                            !string.IsNullOrWhiteSpace(e.RemoteIp) &&
                            (isPrivateExplicit == false || ThreatIndicators.IsPublicIp(e.RemoteIp));
        if (isPublicRawIp && evt.EventType != EventTypes.DnsQuery)
        {
            matches.Add(new RuleMatch(
                "NET-RAW-PUBLIC-IP", 42, ThreatType.Malware, ["T1071"],
                $"Connexion directe vers une IP publique sans résolution DNS ({e.RemoteIp})"));
        }

        if (remotePort is > 0 && ThreatIndicators.UnusualC2Ports.Contains((int)remotePort.Value))
        {
            matches.Add(new RuleMatch(
                "NET-UNUSUAL-PORT", 45, ThreatType.Intrusion, ["T1071"],
                $"Connexion sortante sur un port inhabituel ou associé à un C2 (port {remotePort})"));
        }

        if ((evt.EventType == EventTypes.DnsQuery || !string.IsNullOrWhiteSpace(e.Domain)) &&
            ThreatIndicators.IsSuspiciousDnsName(e.Domain))
        {
            matches.Add(new RuleMatch(
                "NET-SUSPICIOUS-DNS", 46, ThreatType.Exfiltration, ["T1071"],
                $"Requête DNS suspecte (sous-domaine très long ou forte entropie : {e.Domain})"));
        }

        if (e.IsLolBin && evt.EventType == EventTypes.NetworkConnection &&
            (isPrivateExplicit == false || !string.IsNullOrWhiteSpace(e.Domain) || ThreatIndicators.IsPublicIp(e.RemoteIp)))
        {
            matches.Add(new RuleMatch(
                "NET-LOLBIN-OUTBOUND", 52, ThreatType.Malware, ["T1105", "T1071"],
                $"Connexion réseau sortante initiée par un LOLBin ({e.ProcessName})"));
        }
    }

    private static void EvaluateClipboard(EnrichedEvent e, List<RuleMatch> matches)
    {
        var evt = e.Event;
        var cmdKind = evt.Attr(AttributeKeys.CommandKind);
        var domainAge = evt.AttrDouble(AttributeKeys.DomainAgeDays);

        if (e.IsShortener)
        {
            matches.Add(new RuleMatch(
                "CLIP-SHORTENER-URL", 38, ThreatType.Phishing, ["T1566.002"],
                $"URL raccourcie copiée dans le presse-papiers ({e.Domain ?? evt.Subject})"));
        }

        if (evt.EventType == EventTypes.ClipboardUrl &&
            (e.HasRiskyTld || domainAge is <= 30 || e.IsKnownBadDomain || ThreatIndicators.IsPublicIp(e.RemoteIp)))
        {
            matches.Add(new RuleMatch(
                "CLIP-RISKY-URL", 42, ThreatType.Phishing, ["T1566.002"],
                $"URL vers un domaine à risque ou récent copiée dans le presse-papiers ({e.Domain ?? evt.Subject})"));
        }

        if (evt.EventType == EventTypes.ClipboardCommand || !string.IsNullOrWhiteSpace(cmdKind))
        {
            var isEncoded = string.Equals(cmdKind, "encoded", StringComparison.OrdinalIgnoreCase) ||
                            e.HasEncodedCommand || e.IsObfuscatedCommand;
            if (isEncoded)
            {
                matches.Add(new RuleMatch(
                    "CLIP-OBFUSCATED-CMD", 60, ThreatType.Malware, ["T1059.001"],
                    "Commande encodée ou obfusquée détectée dans le presse-papiers"));
            }
            else
            {
                matches.Add(new RuleMatch(
                    "CLIP-PS-COMMAND", 45, ThreatType.Malware, ["T1059.001"],
                    $"Motif de commande shell/PowerShell copié dans le presse-papiers ({cmdKind ?? "script"})"));
            }
        }
    }

    private static void EvaluateFile(EnrichedEvent e, List<RuleMatch> matches)
    {
        var evt = e.Event;
        var entropy = evt.AttrDouble(AttributeKeys.Entropy);
        var fileSize = evt.AttrLong(AttributeKeys.FileSize) ?? 0;
        var isExecutable = evt.AttrIsTrue(AttributeKeys.IsExecutable) || ThreatIndicators.IsExecutableExtension(e.Extension ?? e.FilePath);
        var isArchive = evt.AttrIsTrue(AttributeKeys.IsArchive) || ThreatIndicators.IsArchiveExtension(e.Extension ?? e.FilePath);

        if (e.IsKnownBadHash ||
            string.Equals(e.Sha256, ThreatIndicators.EicarSha256, StringComparison.OrdinalIgnoreCase))
        {
            matches.Add(new RuleMatch(
                "FILE-EICAR-HASH", 95, ThreatType.Malware, ["T1204.002"],
                $"Fichier correspondant à une signature malveillante ou de test EICAR ({e.FileName ?? evt.Subject})"));
        }

        if (e.HasDoubleExtension)
        {
            matches.Add(new RuleMatch(
                "FILE-DOUBLE-EXT", 62, ThreatType.Malware, ["T1036.007"],
                $"Double extension trompeuse détectée sur fichier ({e.FileName ?? evt.Subject})"));
        }

        if (isExecutable &&
            evt.EventType is EventTypes.FileCreated or EventTypes.FileModified or EventTypes.FileRenamed &&
            (e.IsDownloadsDirectory || e.IsSuspiciousDirectory ||
             string.Equals(evt.Attr(AttributeKeys.WatchedFolder), WatchedFolders.Desktop, StringComparison.OrdinalIgnoreCase)))
        {
            matches.Add(new RuleMatch(
                "FILE-EXECUTABLE-DOWNLOAD", 46, ThreatType.Malware, ["T1105", "T1204.002"],
                $"Création d'un exécutable ou script dans un dossier sensible ({e.FilePath ?? evt.Subject})"));
        }

        if (evt.EventType == EventTypes.FileBurst)
        {
            var burstCount = evt.AttrLong(AttributeKeys.BurstCount) ?? 0;
            var burstEntropy = evt.AttrDouble(AttributeKeys.BurstAvgEntropy) ?? entropy ?? 0;
            var distinctExt = evt.AttrLong(AttributeKeys.BurstDistinctExtensions) ?? 0;
            if (burstCount >= 10)
            {
                var weight = 68;
                if (burstEntropy >= 7.0) weight += 10;
                if (distinctExt >= 2 || burstCount >= 30) weight += 8;
                matches.Add(new RuleMatch(
                    "FILE-RANSOMWARE-BURST", Math.Min(weight, 88), ThreatType.Ransomware, ["T1486"],
                    $"Rafale suspecte de modifications de fichiers ({burstCount} fichiers, entropie moy. {burstEntropy:F2})"));
            }
        }

        if (entropy is >= 7.2 && !ThreatIndicators.IsCompressedOrMedia(e.Extension ?? e.FilePath))
        {
            matches.Add(new RuleMatch(
                "FILE-HIGH-ENTROPY", 48, ThreatType.Ransomware, ["T1486"],
                $"Entropie de Shannon anormalement élevée ({entropy:F2} bits/octet) sur {e.FileName ?? evt.Subject}"));
        }

        if (isArchive && evt.EventType is EventTypes.FileCreated or EventTypes.FileModified)
        {
            if (fileSize >= 5_000_000)
            {
                matches.Add(new RuleMatch(
                    "FILE-ARCHIVE-LARGE", 42, ThreatType.Exfiltration, ["T1560"],
                    $"Création d'une archive volumineuse ({fileSize / (1024.0 * 1024.0):F1} Mo : {e.FileName ?? evt.Subject})"));
            }
            else if (e.IsSuspiciousDirectory)
            {
                matches.Add(new RuleMatch(
                    "FILE-ARCHIVE-LARGE", 32, ThreatType.Exfiltration, ["T1560"],
                    $"Création d'archive dans un répertoire sensible ({e.FileName ?? evt.Subject})"));
            }
        }

        if (evt.EventType == EventTypes.FileRenamed)
        {
            var oldExt = evt.Attr(AttributeKeys.OldExtension) ?? ThreatIndicators.ExtractExtension(evt.Attr(AttributeKeys.OldFilePath));
            var newExt = e.Extension;
            var extChanged = !string.IsNullOrWhiteSpace(oldExt) &&
                             !string.IsNullOrWhiteSpace(newExt) &&
                             !oldExt.Equals(newExt, StringComparison.OrdinalIgnoreCase);

            if (ThreatIndicators.IsRansomwareExtension(newExt) || (extChanged && entropy is >= 7.0))
            {
                matches.Add(new RuleMatch(
                    "FILE-SUSPICIOUS-RENAME", 54, ThreatType.Ransomware, ["T1486"],
                    $"Renommage de fichier suspect vers l'extension {newExt} ({e.FileName ?? evt.Subject})"));
            }
        }
    }

    private static void EvaluateSession(EnrichedEvent e, List<RuleMatch> matches)
    {
        var evt = e.Event;
        var failureCount = evt.AttrLong(AttributeKeys.FailureCount) ?? 0;
        var logonType = evt.Attr(AttributeKeys.LogonType);

        if (evt.EventType == EventTypes.LogonFailure)
        {
            if (failureCount >= 5)
            {
                matches.Add(new RuleMatch(
                    "SESS-BRUTEFORCE-BURST", 68, ThreatType.Intrusion, ["T1110"],
                    $"Rafale d'échecs d'authentification ({failureCount} tentatives pour {evt.Attr(AttributeKeys.TargetUser) ?? evt.UserId})"));
            }
            else if (failureCount >= 3)
            {
                matches.Add(new RuleMatch(
                    "SESS-BRUTEFORCE-BURST", 52, ThreatType.Intrusion, ["T1110"],
                    $"Échecs d'authentification répétés ({failureCount} tentatives)"));
            }
            else
            {
                matches.Add(new RuleMatch(
                    "SESS-LOGON-FAILURE", 34, ThreatType.Intrusion, ["T1110"],
                    $"Échec d'authentification sur le compte {evt.Attr(AttributeKeys.TargetUser) ?? evt.UserId}"));
            }
        }

        if (evt.EventType == EventTypes.LogonSuccess)
        {
            if (failureCount >= 3)
            {
                matches.Add(new RuleMatch(
                    "SESS-LOGON-AFTER-FAILURES", 58, ThreatType.Intrusion, ["T1110", "T1078"],
                    $"Connexion réussie immédiatement après {failureCount} échecs d'authentification"));
            }

            var hour = evt.Timestamp.Hour;
            var isOffHours = hour is >= 0 and <= 5;
            var isExternalRdp = (logonType is "10" or "3" or "RemoteInteractive") &&
                                ThreatIndicators.IsPublicIp(e.RemoteIp);
            if (isOffHours || isExternalRdp)
            {
                matches.Add(new RuleMatch(
                    "SESS-UNUSUAL-HOUR", isExternalRdp ? 48 : 36, ThreatType.Intrusion, ["T1078"],
                    isExternalRdp
                        ? $"Connexion distante depuis une IP publique ({e.RemoteIp})"
                        : $"Ouverture de session à une heure inhabituelle ({hour:D2}h)"));
            }
        }
    }

    private static void EvaluateTyping(EnrichedEvent e, List<RuleMatch> matches)
    {
        var evt = e.Event;
        var kps = evt.AttrDouble(AttributeKeys.KeysPerSecond);
        var meanMs = evt.AttrDouble(AttributeKeys.MeanIntervalMs);
        var stdMs = evt.AttrDouble(AttributeKeys.IntervalStdDevMs);
        var samples = evt.AttrLong(AttributeKeys.SampleSize) ?? 0;

        if (evt.AttrIsTrue(AttributeKeys.Injected))
        {
            matches.Add(new RuleMatch(
                "TYPING-INJECTED", 58, ThreatType.BadUsb, ["T1056"],
                "Frappe clavier injectée synthétiquement détectée (drapeau LLKHF_INJECTED)"));
        }

        if ((kps is >= 18.0 || (meanMs is > 0 and <= 45.0)) && (samples == 0 || samples >= 8))
        {
            matches.Add(new RuleMatch(
                "TYPING-SUPERHUMAN-SPEED", 55, ThreatType.BadUsb, ["T1056"],
                $"Vitesse de frappe surhumaine ({kps?.ToString("F1") ?? "?"} touches/s, intervalle moy. {meanMs?.ToString("F0") ?? "?"} ms)"));
        }

        if (stdMs is >= 0 and <= 8.0 && (kps is >= 8.0 || meanMs is > 0 and <= 125.0) && (samples == 0 || samples >= 12))
        {
            matches.Add(new RuleMatch(
                "TYPING-ROBOTIC-VARIANCE", 46, ThreatType.BadUsb, ["T1056"],
                $"Régularité inter-touches mécanique/scriptée (écart-type {stdMs:F1} ms)"));
        }
    }

    private static void EvaluateDevice(EnrichedEvent e, List<RuleMatch> matches)
    {
        var evt = e.Event;
        if (evt.EventType == EventTypes.UsbRemoved) return;

        var deviceClass = evt.Attr(AttributeKeys.DeviceClass) ?? string.Empty;
        var vid = evt.Attr(AttributeKeys.VendorId);
        var isKeyboard = evt.AttrIsTrue(AttributeKeys.IsKeyboard) ||
                         deviceClass.Contains("HID", StringComparison.OrdinalIgnoreCase) ||
                         deviceClass.Contains("Keyboard", StringComparison.OrdinalIgnoreCase);
        var isStorage = evt.AttrIsTrue(AttributeKeys.IsStorage) ||
                        deviceClass.Contains("USBSTOR", StringComparison.OrdinalIgnoreCase) ||
                        deviceClass.Contains("Storage", StringComparison.OrdinalIgnoreCase) ||
                        deviceClass.Contains("Disk", StringComparison.OrdinalIgnoreCase);

        if (isKeyboard)
        {
            matches.Add(new RuleMatch(
                "USB-NEW-HID-KEYBOARD", 46, ThreatType.BadUsb, ["T1200"],
                $"Nouveau clavier/périphérique HID USB branché ({evt.Attr(AttributeKeys.DeviceName) ?? evt.Subject})"));
        }

        if (isStorage)
        {
            matches.Add(new RuleMatch(
                "USB-MASS-STORAGE", 36, ThreatType.Exfiltration, ["T1052"],
                $"Support de stockage amovible USB branché ({evt.Attr(AttributeKeys.DeviceName) ?? evt.Subject})"));
        }

        if (!string.IsNullOrWhiteSpace(vid) && ThreatIndicators.SuspiciousUsbVendorIds.Contains(vid.Trim()))
        {
            matches.Add(new RuleMatch(
                "USB-UNKNOWN-DEVICE", 50, ThreatType.BadUsb, ["T1200"],
                $"Périphérique USB à VID de microcontrôleur programmable détecté (VID={vid})"));
        }
        else if (!isKeyboard && !isStorage && string.IsNullOrWhiteSpace(vid))
        {
            matches.Add(new RuleMatch(
                "USB-UNKNOWN-DEVICE", 32, ThreatType.BadUsb, ["T1200"],
                $"Périphérique USB non identifié branché ({evt.Subject})"));
        }
    }

    private static void EvaluateBrowser(EnrichedEvent e, List<RuleMatch> matches)
    {
        var evt = e.Event;
        var domainAge = evt.AttrDouble(AttributeKeys.DomainAgeDays);
        var redirectCount = evt.AttrLong(AttributeKeys.RedirectCount) ?? 0;

        if (e.IsShortener)
        {
            matches.Add(new RuleMatch(
                "BROW-SHORTENER-CLICK", 38, ThreatType.SocialEngineering, ["T1566.002"],
                $"Ouverture d'un lien raccourci dans le navigateur ({e.Domain ?? evt.Subject})"));
        }

        if (domainAge is <= 30 && !string.IsNullOrWhiteSpace(e.Domain))
        {
            var weight = domainAge <= 7 ? 48 : 40;
            matches.Add(new RuleMatch(
                "BROW-RECENT-DOMAIN", weight, ThreatType.Phishing, ["T1566.002"],
                $"Navigation vers un domaine très récent ({e.Domain}, {domainAge:F0} jours)"));
        }

        if (redirectCount >= 3 || (evt.EventType == EventTypes.Redirect && redirectCount >= 2))
        {
            matches.Add(new RuleMatch(
                "BROW-MULTI-REDIRECT", 40, ThreatType.Phishing, ["T1566.002"],
                $"Chaîne de redirections multiples ({redirectCount} sauts vers {e.Domain ?? evt.Subject})"));
        }

        if (evt.EventType == EventTypes.DownloadStarted)
        {
            var dlName = e.FileName ?? evt.Subject;
            if (e.HasDoubleExtension)
            {
                matches.Add(new RuleMatch(
                    "BROW-EXE-DOWNLOAD", 60, ThreatType.Malware, ["T1105", "T1036.007", "T1204.002"],
                    $"Téléchargement d'un fichier à double extension suspecte ({dlName})"));
            }
            else if (evt.AttrIsTrue(AttributeKeys.IsExecutable) || ThreatIndicators.IsExecutableExtension(dlName))
            {
                matches.Add(new RuleMatch(
                    "BROW-EXE-DOWNLOAD", 46, ThreatType.Malware, ["T1105", "T1204.002"],
                    $"Téléchargement d'un exécutable ou script depuis le navigateur ({dlName})"));
            }
        }

        if (e.HasRiskyTld && !string.IsNullOrWhiteSpace(e.Domain))
        {
            matches.Add(new RuleMatch(
                "BROW-RISKY-TLD", 40, ThreatType.Phishing, ["T1566.002"],
                $"Navigation vers un domaine à extension (TLD) à risque ({e.Domain})"));
        }
    }

    private static void EvaluateInstallation(EnrichedEvent e, List<RuleMatch> matches)
    {
        var evt = e.Event;

        if (evt.EventType == EventTypes.AppInstalled && (e.IsSigned == false || !e.IsTrustedPublisher))
        {
            var weight = e.IsSigned == false ? 48 : 34;
            matches.Add(new RuleMatch(
                "INST-UNSIGNED-APP", weight, ThreatType.Persistence, ["T1204"],
                $"Installation d'une application non signée ou d'éditeur inconnu ({evt.Attr(AttributeKeys.AppName) ?? evt.Subject})"));
        }

        if (evt.EventType == EventTypes.StartupEntryAdded)
        {
            var regValue = evt.Attr(AttributeKeys.RegistryValue) ?? evt.Subject;
            var suspiciousTarget = ThreatIndicators.IsSuspiciousDirectory(regValue) ||
                                   ThreatIndicators.HasEncodedOrSuspiciousCommand(regValue) ||
                                   e.IsSigned == false;
            matches.Add(new RuleMatch(
                "PERS-STARTUP-KEY", suspiciousTarget ? 62 : 48, ThreatType.Persistence, ["T1547.001"],
                $"Ajout d'une entrée de démarrage automatique ({evt.Attr(AttributeKeys.RegistryKey) ?? evt.Subject})"));
        }

        if (evt.EventType == EventTypes.ScheduledTaskCreated)
        {
            var taskTarget = e.CommandLine ?? evt.Subject;
            var suspiciousTarget = ThreatIndicators.IsSuspiciousDirectory(taskTarget) ||
                                   ThreatIndicators.HasEncodedOrSuspiciousCommand(taskTarget) ||
                                   e.IsLolBin;
            matches.Add(new RuleMatch(
                "PERS-SCHEDULED-TASK", suspiciousTarget ? 64 : 48, ThreatType.Persistence, ["T1053.005"],
                $"Création d'une tâche planifiée ({evt.Attr(AttributeKeys.TaskName) ?? evt.Subject})"));
        }
    }

    private static void EvaluateSystem(EnrichedEvent e, List<RuleMatch> matches)
    {
        var evt = e.Event;
        switch (evt.EventType)
        {
            case EventTypes.AgentTampering:
                matches.Add(new RuleMatch(
                    "SYS-AGENT-TAMPERING", 94, ThreatType.Tampering, ["T1562"],
                    $"Tentative d'altération ou de contournement de l'agent SENTINEL ({evt.Attr(AttributeKeys.Reason) ?? evt.Subject})"));
                break;

            case EventTypes.IntegrityViolation:
                matches.Add(new RuleMatch(
                    "SYS-INTEGRITY-VIOLATION", 96, ThreatType.Tampering, ["T1562"],
                    $"Violation d'intégrité binaire ou journal détectée ({evt.Attr(AttributeKeys.Component) ?? evt.Subject})"));
                break;

            case EventTypes.AgentStopped:
                var reason = evt.Attr(AttributeKeys.Reason) ?? string.Empty;
                var planned = reason.Contains("maintenance", StringComparison.OrdinalIgnoreCase) ||
                              reason.Contains("update", StringComparison.OrdinalIgnoreCase) ||
                              reason.Contains("shutdown", StringComparison.OrdinalIgnoreCase);
                if (!planned)
                {
                    matches.Add(new RuleMatch(
                        "SYS-AGENT-STOPPED", 78, ThreatType.Tampering, ["T1562"],
                        $"Arrêt inattendu du service SENTINEL ({(string.IsNullOrWhiteSpace(reason) ? "motif inconnu" : reason)})"));
                }
                break;
        }
    }

    private static void EvaluateDefender(EnrichedEvent e, List<RuleMatch> matches)
    {
        var evt = e.Event;
        var threatName = evt.Attr(AttributeKeys.DefenderThreatName) ?? evt.Subject;
        var severity = evt.Attr(AttributeKeys.DefenderSeverity) ?? "High";
        var status = evt.Attr(AttributeKeys.DefenderStatus) ?? string.Empty;

        switch (evt.EventType)
        {
            case EventTypes.DefenderThreatDetected:
                var detWeight = severity.Equals("Severe", StringComparison.OrdinalIgnoreCase) ||
                                status.Equals("ActionFailed", StringComparison.OrdinalIgnoreCase)
                    ? 94 : 88;
                matches.Add(new RuleMatch(
                    "DEF-THREAT-DETECTED", detWeight, ThreatType.Malware, ["T1204.002"],
                    $"Microsoft Defender a détecté la menace « {threatName} » (gravité {severity})"));
                break;

            case EventTypes.DefenderActionTaken:
                matches.Add(new RuleMatch(
                    "DEF-ACTION-TAKEN", 65, ThreatType.Malware, ["T1204.002"],
                    $"Microsoft Defender a appliqué une action ({evt.Attr(AttributeKeys.DefenderAction) ?? "remédiation"}) sur « {threatName} »"));
                break;

            case EventTypes.DefenderRealtimeDisabled:
                matches.Add(new RuleMatch(
                    "DEF-REALTIME-DISABLED", 92, ThreatType.Tampering, ["T1562.001"],
                    "Affaiblissement critique : protection temps réel Microsoft Defender désactivée"));
                break;

            case EventTypes.DefenderExclusionAdded:
                matches.Add(new RuleMatch(
                    "DEF-EXCLUSION-ADDED", 86, ThreatType.Tampering, ["T1562.001"],
                    $"Affaiblissement Defender : ajout d'une exclusion ({evt.Attr(AttributeKeys.DefenderExclusion) ?? evt.Subject})"));
                break;

            case EventTypes.DefenderServiceStopped:
                matches.Add(new RuleMatch(
                    "DEF-SERVICE-STOPPED", 94, ThreatType.Tampering, ["T1562.001"],
                    "Affaiblissement critique : service Microsoft Defender (WinDefend) arrêté"));
                break;

            case EventTypes.DefenderTampering:
                matches.Add(new RuleMatch(
                    "DEF-TAMPERING", 90, ThreatType.Tampering, ["T1562.001"],
                    $"Tentative d'affaiblissement de Microsoft Defender ({evt.Attr(AttributeKeys.Reason) ?? evt.Subject})"));
                break;
        }
    }

    private static void EvaluateCanary(EnrichedEvent e, List<RuleMatch> matches)
    {
        var evt = e.Event;
        var isEncrypted = evt.EventType == EventTypes.CanaryEncrypted || (evt.AttrDouble(AttributeKeys.Entropy) is >= 7.2);
        var weight = isEncrypted ? 98 : 94;
        matches.Add(new RuleMatch(
            isEncrypted ? "CANARY-ENCRYPTED" : "CANARY-TAMPERED",
            weight,
            ThreatType.Ransomware,
            ["T1486"],
            evt.Attr(AttributeKeys.Reason) ?? $"Fichier canari anti-ransomware touché ({evt.EventType} : {evt.Subject})"));
    }

    private static void EvaluateScript(EnrichedEvent e, List<RuleMatch> matches)
    {
        var evt = e.Event;
        var indicators = evt.Attr(AttributeKeys.ScriptIndicators) ?? string.Empty;

        if (evt.EventType == EventTypes.ScriptLoggingBypass ||
            indicators.Contains("LoggingOrDefenseBypass", StringComparison.OrdinalIgnoreCase))
        {
            matches.Add(new RuleMatch(
                "SCRIPT-LOGGING-BYPASS", 88, ThreatType.Tampering, ["T1562.006", "T1059.001"],
                $"Tentative de contournement de la journalisation ou de la protection script ({evt.Subject})"));
        }

        if (indicators.Contains("RecoveryOrCredentialAbuse", StringComparison.OrdinalIgnoreCase))
        {
            matches.Add(new RuleMatch(
                "SCRIPT-RECOVERY-CRED-ABUSE", 86, ThreatType.Ransomware, ["T1490", "T1003"],
                $"Script tentant d'inhiber la restauration système ou d'accéder aux identifiants ({evt.Subject})"));
        }

        if (indicators.Contains("DownloadAndExecute", StringComparison.OrdinalIgnoreCase))
        {
            matches.Add(new RuleMatch(
                "SCRIPT-DOWNLOAD-EXEC", 74, ThreatType.Malware, ["T1059.001", "T1105"],
                $"Bloc de script PowerShell avec téléchargement et exécution en mémoire ({evt.Subject})"));
        }

        if (indicators.Contains("EncodedCommand", StringComparison.OrdinalIgnoreCase))
        {
            matches.Add(new RuleMatch(
                "SCRIPT-ENCODED-BLOCK", 64, ThreatType.Malware, ["T1059.001", "T1027", "T1140"],
                $"Bloc de script PowerShell encodé détecté ({evt.Subject})"));
        }

        if (indicators.Contains("HighObfuscation", StringComparison.OrdinalIgnoreCase))
        {
            matches.Add(new RuleMatch(
                "SCRIPT-HIGH-OBFUSCATION", 56, ThreatType.Malware, ["T1027", "T1059.001"],
                $"Bloc de script fortement obfusqué (score {evt.Attr(AttributeKeys.ScriptObfuscationScore) ?? "?"})"));
        }
        else if (matches.Count == 0 && indicators.Contains("RemoteDownload", StringComparison.OrdinalIgnoreCase))
        {
            matches.Add(new RuleMatch(
                "SCRIPT-REMOTE-DOWNLOAD", 44, ThreatType.Malware, ["T1105", "T1059.001"],
                $"Téléchargement distant dans un bloc de script PowerShell ({evt.Subject})"));
        }
    }

    private static void EvaluateStaticAnalysis(EnrichedEvent e, List<RuleMatch> matches)
    {
        var evt = e.Event;
        if (evt.EventType == EventTypes.YaraMatch)
        {
            var rule = evt.Attr(AttributeKeys.YaraRule) ?? "YARA";
            var weight = rule.Contains("EICAR", StringComparison.OrdinalIgnoreCase) ? 95 : 86;
            matches.Add(new RuleMatch(
                $"YARA-{rule}", weight, ThreatType.Malware, ["T1204.002", "T1027"],
                $"Correspondance règle YARA « {rule} » sur {evt.Attr(AttributeKeys.FilePath) ?? evt.Subject}"));
            return;
        }

        if (!string.IsNullOrWhiteSpace(evt.Attr(AttributeKeys.PePacker)))
        {
            matches.Add(new RuleMatch(
                "PE-PACKER-DETECTED", 46, ThreatType.Malware, ["T1027.002"],
                $"Exécutable PE probablement empaqueté ({evt.Attr(AttributeKeys.PePacker)})"));
        }

        if (!string.IsNullOrWhiteSpace(evt.Attr(AttributeKeys.PeSuspiciousImports)))
        {
            matches.Add(new RuleMatch(
                "PE-SUSPICIOUS-IMPORTS", 52, ThreatType.Malware, ["T1055", "T1204.002"],
                $"Imports PE suspects détectés ({evt.Attr(AttributeKeys.PeSuspiciousImports)})"));
        }

        if (evt.AttrDouble(AttributeKeys.PeMaxEntropy) is >= 7.2)
        {
            matches.Add(new RuleMatch(
                "PE-HIGH-SECTION-ENTROPY", 42, ThreatType.Malware, ["T1027.002"],
                $"Entropie de section PE élevée ({evt.Attr(AttributeKeys.PeMaxEntropy)} bits/octet)"));
        }
    }

    private static void EvaluateThreatIntel(EnrichedEvent e, List<RuleMatch> matches)
    {
        var evt = e.Event;
        var source = evt.Attr(AttributeKeys.ThreatIntelSource) ?? "ThreatIntel";
        var indicator = evt.Attr(AttributeKeys.ThreatIntelIndicator) ?? evt.Subject;
        var threat = evt.Attr(AttributeKeys.ThreatIntelThreat) ?? "indicateur malveillant";
        var firstSeen = evt.Attr(AttributeKeys.ThreatIntelFirstSeen);
        var indType = evt.Attr(AttributeKeys.ThreatIntelIndicatorType) ?? "ioc";

        var threatType = threat.Contains("phish", StringComparison.OrdinalIgnoreCase)
            ? ThreatType.Phishing
            : ThreatType.Malware;

        var dateSuffix = string.IsNullOrWhiteSpace(firstSeen) ? string.Empty : $" le {firstSeen}";
        matches.Add(new RuleMatch(
            $"TI-{source.ToUpperInvariant()}",
            92,
            threatType,
            threatType == ThreatType.Phishing ? ["T1566.002", "T1071"] : ["T1071", "T1105"],
            $"Indicateur ({indType}) « {indicator} » listé par {source}{dateSuffix} ({threat})"));
    }
}
