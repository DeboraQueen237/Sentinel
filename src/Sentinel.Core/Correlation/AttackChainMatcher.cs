using Sentinel.Core.Enrichment;
using Sentinel.Shared.Models;

namespace Sentinel.Core.Correlation;

/// <summary>Représentation interne d'un nœud événementiel dans un cluster de corrélation.</summary>
internal sealed class CorrelatedNode
{
    public required EnrichedEvent Enriched { get; init; }
    public required ThreatAssessment Assessment { get; init; }
    public required IReadOnlyList<ContextKeyInfo> Keys { get; init; }
    public Guid? ClusterId { get; set; }

    public SecurityEvent Event => Enriched.Event;
    public Guid Id => Enriched.Event.Id;
    public DateTimeOffset Timestamp => Enriched.Event.Timestamp;
}

internal readonly record struct ContextKeyInfo(
    string Key,
    GraphEdgeType DefaultEdgeType,
    bool IsEntityKey,
    ContextWindowKind Window);

internal enum ContextWindowKind
{
    Short = 0,
    Medium = 1,
    Long = 2
}

/// <summary>
/// Détecte les 7 chaînes d'attaque modélisées (doc §8.3) sur un cluster d'événements triés chronologiquement,
/// avec support de la progression partielle et calcul du bonus de séquence (+15 à +30, doc §8.2).
/// </summary>
internal static class AttackChainMatcher
{
    public static AttackChainMatch? MatchBest(IReadOnlyList<CorrelatedNode> orderedNodes)
    {
        if (orderedNodes.Count < 2) return null;

        var candidates = new List<AttackChainMatch>(4);

        TryAdd(candidates, MatchPhishing(orderedNodes));
        TryAdd(candidates, MatchBadUsb(orderedNodes));
        TryAdd(candidates, MatchRansomware(orderedNodes));
        TryAdd(candidates, MatchExfiltration(orderedNodes));
        TryAdd(candidates, MatchBruteForce(orderedNodes));
        TryAdd(candidates, MatchPersistence(orderedNodes));
        TryAdd(candidates, MatchSocialEngineering(orderedNodes));

        if (candidates.Count == 0) return null;

        // Si Phishing atteint l'étape d'exécution ou C2 (>= 4 étapes), il prime sur Ingénierie sociale (3 étapes)
        var advancedPhishing = candidates.FirstOrDefault(c => c.ChainId == "CHAIN-PHISHING" && c.StepsMatched >= 4);
        if (advancedPhishing is not null)
        {
            return advancedPhishing;
        }

        return candidates
            .OrderByDescending(c => c.Bonus)
            .ThenByDescending(c => c.IsComplete)
            .ThenByDescending(c => c.Progress)
            .ThenByDescending(c => c.StepsMatched)
            .First();
    }

    /// <summary>
    /// 1. Phishing → exécution : Presse-papiers/lien → navigation → téléchargement → exécution → connexion sortante.
    /// </summary>
    private static AttackChainMatch? MatchPhishing(IReadOnlyList<CorrelatedNode> nodes)
    {
        Func<CorrelatedNode, bool>[] stages =
        [
            n => (n.Event.Category == EventCategory.Clipboard && n.Event.EventType == EventTypes.ClipboardUrl) ||
                 (n.Event.Category == EventCategory.Browser && n.Event.EventType == EventTypes.LinkClicked),
            n => n.Event.Category == EventCategory.Browser &&
                 n.Event.EventType is EventTypes.UrlVisited or EventTypes.LinkClicked or EventTypes.Redirect,
            n => (n.Event.Category == EventCategory.Browser && n.Event.EventType == EventTypes.DownloadStarted) ||
                 (n.Event.Category == EventCategory.File &&
                  (n.Enriched.HasDoubleExtension || n.Event.AttrIsTrue(AttributeKeys.IsExecutable) ||
                   ThreatIndicators.IsExecutableExtension(n.Enriched.Extension ?? n.Enriched.FilePath) ||
                   n.Enriched.IsDownloadsDirectory)),
            n => n.Event.Category == EventCategory.Process && n.Event.EventType == EventTypes.ProcessStart,
            n => n.Event.Category == EventCategory.Network &&
                 n.Event.EventType is EventTypes.NetworkConnection or EventTypes.DnsQuery or EventTypes.NetworkVolume
        ];

        var matched = CountOrderedDistinctStages(nodes, stages);
        if (matched < 2) return null;

        return BuildMatch(
            "CHAIN-PHISHING",
            "Phishing → exécution",
            matched,
            stages.Length,
            ThreatType.Phishing,
            ["T1566", "T1566.002", "T1204.002", "T1071"]);
    }

    /// <summary>
    /// 2. BadUSB : USB HID inséré → saisie ultra-rapide/injectée → lancement PowerShell/cmd.
    /// </summary>
    private static AttackChainMatch? MatchBadUsb(IReadOnlyList<CorrelatedNode> nodes)
    {
        Func<CorrelatedNode, bool>[] stages =
        [
            n => n.Event.Category == EventCategory.Device &&
                 n.Event.EventType is EventTypes.UsbInserted or EventTypes.DeviceAdded &&
                 (n.Event.AttrIsTrue(AttributeKeys.IsKeyboard) ||
                  (n.Event.Attr(AttributeKeys.DeviceClass)?.Contains("HID", StringComparison.OrdinalIgnoreCase) ?? false) ||
                  (n.Event.Attr(AttributeKeys.DeviceClass)?.Contains("Keyboard", StringComparison.OrdinalIgnoreCase) ?? false) ||
                  n.Assessment.Type == ThreatType.BadUsb),
            n => n.Event.Category == EventCategory.Typing,
            n => n.Event.Category == EventCategory.Process &&
                 n.Event.EventType == EventTypes.ProcessStart &&
                 (n.Enriched.IsLolBin || n.Enriched.HasEncodedCommand)
        ];

        var matched = CountOrderedDistinctStages(nodes, stages);
        if (matched < 2) return null;

        return BuildMatch(
            "CHAIN-BADUSB",
            "Attaque BadUSB (HID → frappe scriptée → shell)",
            matched,
            stages.Length,
            ThreatType.BadUsb,
            ["T1200", "T1056", "T1059.001"]);
    }

    /// <summary>
    /// 3. Ransomware : Rafale de modifications + hausse d'entropie + extensions modifiées / renommages.
    /// </summary>
    private static AttackChainMatch? MatchRansomware(IReadOnlyList<CorrelatedNode> nodes)
    {
        var fileNodes = nodes.Where(n => n.Event.Category == EventCategory.File).ToList();
        if (fileNodes.Count < 2) return null;

        var hasBurst = fileNodes.Any(n => n.Event.EventType == EventTypes.FileBurst) ||
                       fileNodes.Count(n => n.Event.EventType is EventTypes.FileModified or EventTypes.FileCreated or EventTypes.FileRenamed) >= 3;

        var hasHighEntropy = fileNodes.Any(n =>
            (n.Event.AttrDouble(AttributeKeys.Entropy) is >= 7.0) ||
            (n.Event.AttrDouble(AttributeKeys.BurstAvgEntropy) is >= 7.0));

        var hasExtensionChange = fileNodes.Any(n =>
            (n.Event.EventType == EventTypes.FileRenamed &&
             (ThreatIndicators.IsRansomwareExtension(n.Enriched.Extension) ||
              !string.Equals(
                  n.Event.Attr(AttributeKeys.OldExtension) ?? ThreatIndicators.ExtractExtension(n.Event.Attr(AttributeKeys.OldFilePath)),
                  n.Enriched.Extension,
                  StringComparison.OrdinalIgnoreCase))) ||
            (n.Event.AttrLong(AttributeKeys.BurstDistinctExtensions) is >= 2));

        var matched = (hasBurst ? 1 : 0) + (hasHighEntropy ? 1 : 0) + (hasExtensionChange ? 1 : 0);
        if (matched < 2) return null;

        return BuildMatch(
            "CHAIN-RANSOMWARE",
            "Activité Ransomware (rafale + entropie + renommages)",
            matched,
            3,
            ThreatType.Ransomware,
            ["T1486"]);
    }

    /// <summary>
    /// 4. Exfiltration : Archive créée + domaine rare / gros volume sortant ou USB stockage.
    /// </summary>
    private static AttackChainMatch? MatchExfiltration(IReadOnlyList<CorrelatedNode> nodes)
    {
        var archiveNode = nodes.FirstOrDefault(n =>
            n.Event.Category == EventCategory.File &&
            (n.Event.AttrIsTrue(AttributeKeys.IsArchive) || ThreatIndicators.IsArchiveExtension(n.Enriched.Extension ?? n.Enriched.FilePath)));
        if (archiveNode is null) return null;

        var hasRareOrUsb = nodes.Any(n =>
            n != archiveNode &&
            ((n.Event.Category == EventCategory.Network &&
              (n.Enriched.HasRiskyTld || n.Event.AttrDouble(AttributeKeys.DomainAgeDays) is <= 30 ||
               n.Enriched.IsKnownBadDomain || ThreatIndicators.IsSuspiciousDnsName(n.Enriched.Domain) ||
               ThreatIndicators.IsPublicIp(n.Enriched.RemoteIp))) ||
             (n.Event.Category == EventCategory.Device &&
              (n.Event.AttrIsTrue(AttributeKeys.IsStorage) ||
               (n.Event.Attr(AttributeKeys.DeviceClass)?.Contains("USBSTOR", StringComparison.OrdinalIgnoreCase) ?? false)))));

        var hasLargeOutboundOrUsbCopy = nodes.Any(n =>
            n != archiveNode &&
            ((n.Event.Category == EventCategory.Network &&
              ((n.Event.AttrLong(AttributeKeys.BytesSent) ?? 0) >= 10_000_000 || n.Event.EventType == EventTypes.NetworkVolume)) ||
             (n.Event.Category == EventCategory.Device && n.Event.AttrIsTrue(AttributeKeys.IsStorage) &&
              nodes.Any(other => other != archiveNode && other != n && other.Event.Category is EventCategory.File or EventCategory.Network))));

        var matched = 1 + (hasRareOrUsb ? 1 : 0) + (hasLargeOutboundOrUsbCopy ? 1 : 0);
        if (matched < 2) return null;

        var mitre = nodes.Any(n => n.Event.Category == EventCategory.Device)
            ? new[] { "T1560", "T1052" }
            : new[] { "T1560", "T1041" };

        return BuildMatch(
            "CHAIN-EXFILTRATION",
            "Exfiltration de données (archive + transfert externe)",
            matched,
            3,
            ThreatType.Exfiltration,
            mitre);
    }

    /// <summary>
    /// 5. Brute force / intrusion : N échecs de connexion → succès → processus inhabituel.
    /// </summary>
    private static AttackChainMatch? MatchBruteForce(IReadOnlyList<CorrelatedNode> nodes)
    {
        var failureNodes = nodes
            .Where(n => n.Event.Category == EventCategory.Session && n.Event.EventType == EventTypes.LogonFailure)
            .ToList();
        if (failureNodes.Count == 0) return null;

        var hasMultipleFailures = failureNodes.Count >= 2 ||
                                  failureNodes.Any(n => (n.Event.AttrLong(AttributeKeys.FailureCount) ?? 0) >= 2);
        var firstFailureTs = failureNodes[0].Timestamp;

        var successNode = nodes.FirstOrDefault(n =>
            n.Event.Category == EventCategory.Session &&
            n.Event.EventType == EventTypes.LogonSuccess &&
            n.Timestamp >= firstFailureTs);

        var unusualProc = successNode is not null
            ? nodes.FirstOrDefault(n =>
                n.Event.Category == EventCategory.Process &&
                n.Event.EventType == EventTypes.ProcessStart &&
                n.Timestamp >= successNode.Timestamp)
            : null;

        var matched = 0;
        if (hasMultipleFailures || successNode is not null) matched++;
        if (successNode is not null) matched++;
        if (unusualProc is not null) matched++;

        if (matched < 2) return null;

        return BuildMatch(
            "CHAIN-BRUTEFORCE",
            "Brute force / intrusion (échecs → connexion → exécution)",
            matched,
            3,
            ThreatType.Intrusion,
            ["T1110", "T1078", "T1059"]);
    }

    /// <summary>
    /// 6. Persistance : Nouvelle installation / exécutable + clé de démarrage + tâche planifiée.
    /// </summary>
    private static AttackChainMatch? MatchPersistence(IReadOnlyList<CorrelatedNode> nodes)
    {
        var hasInstallOrDrop = nodes.Any(n =>
            (n.Event.Category == EventCategory.Installation && n.Event.EventType == EventTypes.AppInstalled) ||
            (n.Event.Category == EventCategory.Process && n.Event.EventType == EventTypes.ProcessStart) ||
            (n.Event.Category == EventCategory.File &&
             (n.Event.AttrIsTrue(AttributeKeys.IsExecutable) || ThreatIndicators.IsExecutableExtension(n.Enriched.Extension ?? n.Enriched.FilePath))));

        var hasStartup = nodes.Any(n => n.Event.EventType == EventTypes.StartupEntryAdded);
        var hasTask = nodes.Any(n => n.Event.EventType == EventTypes.ScheduledTaskCreated);

        // Exiger au moins un mécanisme explicite de persistance (clé de démarrage ou tâche planifiée)
        if (!hasStartup && !hasTask) return null;

        var matched = (hasInstallOrDrop ? 1 : 0) + (hasStartup ? 1 : 0) + (hasTask ? 1 : 0);
        if (matched < 2) return null;

        return BuildMatch(
            "CHAIN-PERSISTENCE",
            "Établissement de persistance (installation + démarrage + tâche)",
            matched,
            3,
            ThreatType.Persistence,
            ["T1204", "T1547.001", "T1053.005"]);
    }

    /// <summary>
    /// 7. Ingénierie sociale : Lien raccourci + domaine récent + exécutable téléchargé aussitôt.
    /// </summary>
    private static AttackChainMatch? MatchSocialEngineering(IReadOnlyList<CorrelatedNode> nodes)
    {
        Func<CorrelatedNode, bool>[] stages =
        [
            n => n.Event.Category is EventCategory.Clipboard or EventCategory.Browser && n.Enriched.IsShortener,
            n => n.Event.Category == EventCategory.Browser &&
                 (n.Event.AttrDouble(AttributeKeys.DomainAgeDays) is <= 30 ||
                  n.Enriched.HasRiskyTld ||
                  (n.Event.AttrLong(AttributeKeys.RedirectCount) ?? 0) >= 2),
            n => (n.Event.Category == EventCategory.Browser && n.Event.EventType == EventTypes.DownloadStarted &&
                  (n.Event.AttrIsTrue(AttributeKeys.IsExecutable) || n.Enriched.HasDoubleExtension ||
                   ThreatIndicators.IsExecutableExtension(n.Enriched.FileName ?? n.Event.Subject))) ||
                 (n.Event.Category == EventCategory.File &&
                  (n.Event.AttrIsTrue(AttributeKeys.IsExecutable) || n.Enriched.HasDoubleExtension ||
                   ThreatIndicators.IsExecutableExtension(n.Enriched.Extension ?? n.Enriched.FilePath)))
        ];

        var matched = CountOrderedDistinctStages(nodes, stages);
        if (matched < 2) return null;

        return BuildMatch(
            "CHAIN-SOCIAL-ENG",
            "Ingénierie sociale (lien raccourci → domaine récent → exécutable)",
            matched,
            stages.Length,
            ThreatType.SocialEngineering,
            ["T1566.002", "T1105", "T1204.002"]);
    }

    /// <summary>
    /// Compte le nombre maximal d'étapes distinctes respectant l'ordre chronologique
    /// (un événement donné ne fait progresser qu'une seule étape).
    /// </summary>
    private static int CountOrderedDistinctStages(
        IReadOnlyList<CorrelatedNode> orderedNodes,
        Func<CorrelatedNode, bool>[] stages)
    {
        var stageCount = stages.Length;
        // DP : best[s] = longueur max d'une sous-séquence strictement croissante d'étapes se terminant à l'étape s
        var best = new int[stageCount];

        for (var i = 0; i < orderedNodes.Count; i++)
        {
            var node = orderedNodes[i];
            // Parcours en ordre inverse pour qu'un même événement n'avance pas deux étapes à la fois
            for (var s = stageCount - 1; s >= 0; s--)
            {
                if (!stages[s](node)) continue;

                var prevBest = 0;
                for (var p = 0; p < s; p++)
                {
                    if (best[p] > prevBest) prevBest = best[p];
                }

                var candidate = prevBest + 1;
                if (candidate > best[s])
                {
                    best[s] = candidate;
                }
            }
        }

        var max = 0;
        for (var s = 0; s < stageCount; s++)
        {
            if (best[s] > max) max = best[s];
        }
        return max;
    }

    private static AttackChainMatch BuildMatch(
        string chainId,
        string name,
        int stepsMatched,
        int totalSteps,
        ThreatType type,
        IReadOnlyList<string> mitre)
    {
        // Bonus progressif strictement dans [15, 30] (doc §8.2)
        var denom = Math.Max(1, totalSteps - 2);
        var ratio = Math.Clamp((double)(stepsMatched - 2) / denom, 0.0, 1.0);
        var bonus = (int)Math.Round(15.0 + 15.0 * ratio);

        return new AttackChainMatch(
            chainId,
            name,
            stepsMatched,
            totalSteps,
            Math.Clamp(bonus, 15, 30),
            type,
            mitre);
    }

    private static void TryAdd(List<AttackChainMatch> list, AttackChainMatch? match)
    {
        if (match is not null) list.Add(match);
    }
}
