using Sentinel.Shared.Models;

namespace Sentinel.Core.Enrichment;

/// <summary>Vue enrichie d'un <see cref="SecurityEvent"/> produite par le pré-filtre déterministe (doc §7.1-1).</summary>
public sealed class EnrichedEvent
{
    public required SecurityEvent Event { get; init; }
    public string? Domain { get; init; }
    public string? Url { get; init; }
    public string? ProcessName { get; init; }
    public string? ProcessPath { get; init; }
    public string? ParentProcessName { get; init; }
    public string? CommandLine { get; init; }
    public string? FilePath { get; init; }
    public string? FileName { get; init; }
    public string? Extension { get; init; }
    public string? Sha256 { get; init; }
    public string? RemoteIp { get; init; }
    public string? Publisher { get; init; }

    public bool? IsSigned { get; init; }
    public bool IsTrustedPublisher { get; init; }
    public bool IsShortener { get; init; }
    public bool HasRiskyTld { get; init; }
    public bool IsLolBin { get; init; }
    public bool HasEncodedCommand { get; init; }
    public bool IsObfuscatedCommand { get; init; }
    public bool HasDoubleExtension { get; init; }
    public bool IsSuspiciousDirectory { get; init; }
    public bool IsDownloadsDirectory { get; init; }
    public bool IsKnownBadHash { get; init; }
    public bool IsKnownBadDomain { get; init; }
    public bool IsKnownBadIp { get; init; }

    public bool IsExcluded { get; init; }
    public bool IsTrustedSignedBypass { get; init; }
    public string? ExclusionReason { get; init; }
}

/// <summary>
/// Pré-filtre déterministe et enrichissement local (doc §7.1-1).
/// Applique les exclusions de <see cref="SentinelSettings"/>, la liste blanche d'éditeurs signés
/// et la réputation locale avant le moteur de règles et le LLM.
/// </summary>
public sealed class EventPreFilter
{
    private readonly LocalReputationStore _reputation;

    public EventPreFilter(LocalReputationStore reputation)
    {
        _reputation = reputation ?? throw new ArgumentNullException(nameof(reputation));
    }

    public EnrichedEvent Evaluate(SecurityEvent evt, SentinelSettings settings)
    {
        ArgumentNullException.ThrowIfNull(evt);
        ArgumentNullException.ThrowIfNull(settings);

        var url = evt.Attr(AttributeKeys.Url)
                  ?? (evt.Subject.Contains("://", StringComparison.Ordinal) ? evt.Subject : null);

        var domain = evt.Attr(AttributeKeys.Domain)
                     ?? ThreatIndicators.ExtractDomain(url)
                     ?? (evt.Category is EventCategory.Network or EventCategory.Browser or EventCategory.Clipboard
                         ? ThreatIndicators.ExtractDomain(evt.Subject)
                         : null);
        domain = domain?.Trim().TrimEnd('.').ToLowerInvariant();

        var processPath = evt.Attr(AttributeKeys.ProcessPath)
                          ?? (evt.Category == EventCategory.Process ? evt.Subject : null);
        var rawProcessName = evt.Attr(AttributeKeys.ProcessName) ?? processPath;
        var processName = ThreatIndicators.NormalizeProcessName(rawProcessName);
        if (string.IsNullOrEmpty(processName)) processName = null;

        var parentProcessName = ThreatIndicators.NormalizeProcessName(
            evt.Attr(AttributeKeys.ParentProcessName) ?? evt.Attr(AttributeKeys.ParentProcessPath));
        if (string.IsNullOrEmpty(parentProcessName)) parentProcessName = null;

        var cmdline = evt.Attr(AttributeKeys.CommandLine);

        var filePath = evt.Attr(AttributeKeys.FilePath)
                       ?? (evt.Category == EventCategory.File ? evt.Subject : null);
        var fileName = evt.Attr(AttributeKeys.FileName)
                       ?? (!string.IsNullOrWhiteSpace(filePath) ? ThreatIndicators.ExtractFileName(filePath) : null)
                       ?? (!string.IsNullOrWhiteSpace(processPath) ? ThreatIndicators.ExtractFileName(processPath) : null);

        var ext = evt.Attr(AttributeKeys.Extension)
                  ?? ThreatIndicators.ExtractExtension(filePath ?? fileName ?? processPath);
        if (string.IsNullOrEmpty(ext)) ext = null;

        var sha256 = evt.Attr(AttributeKeys.Sha256) ?? evt.Attr(AttributeKeys.ContentHash);
        var remoteIp = evt.Attr(AttributeKeys.RemoteIp) ?? evt.Attr(AttributeKeys.SourceIp);
        var publisher = evt.Attr(AttributeKeys.Publisher) ?? evt.Attr(AttributeKeys.AppPublisher);

        bool? isSigned = evt.Attributes.TryGetValue(AttributeKeys.Signed, out var signedRaw)
            ? signedRaw == "1" || signedRaw.Equals("true", StringComparison.OrdinalIgnoreCase)
            : null;

        var isTrustedPublisher = ThreatIndicators.IsTrustedPublisher(publisher);
        var isShortener = evt.AttrIsTrue(AttributeKeys.IsShortener) || ThreatIndicators.IsUrlShortener(domain);
        var hasRiskyTld = ThreatIndicators.HasRiskyTld(domain);
        var isLolBin = ThreatIndicators.IsLolBin(processName);
        var hasEncodedCmd = ThreatIndicators.HasEncodedOrSuspiciousCommand(cmdline);
        var isObfuscatedCmd = ThreatIndicators.IsObfuscatedCommand(cmdline);

        var hasDoubleExt = evt.AttrIsTrue(AttributeKeys.DoubleExtension)
                           || ThreatIndicators.HasDoubleExtension(filePath)
                           || ThreatIndicators.HasDoubleExtension(fileName)
                           || ThreatIndicators.HasDoubleExtension(processPath);

        var inspectedPath = filePath ?? processPath ?? evt.Subject;
        var watchedFolder = evt.Attr(AttributeKeys.WatchedFolder);
        var isSuspiciousDir = ThreatIndicators.IsSuspiciousDirectory(inspectedPath)
                              || string.Equals(watchedFolder, WatchedFolders.Temp, StringComparison.OrdinalIgnoreCase)
                              || string.Equals(watchedFolder, WatchedFolders.Downloads, StringComparison.OrdinalIgnoreCase);
        var isDownloadsDir = ThreatIndicators.IsDownloadsDirectory(inspectedPath)
                             || string.Equals(watchedFolder, WatchedFolders.Downloads, StringComparison.OrdinalIgnoreCase);

        var isKnownBadHash = _reputation.IsBadHash(sha256);
        var isKnownBadDomain = _reputation.IsBadDomain(domain);
        var isKnownBadIp = _reputation.IsBadIp(remoteIp);

        var (isExcluded, exclusionReason) = CheckExclusions(
            evt, settings, processName, processPath, domain, filePath, sha256);

        // Liste blanche d'éditeurs signés connus (jamais pour les LOLBins ni les comportements suspects)
        var isTrustedSignedBypass = !isExcluded
                                    && evt.Category is EventCategory.Process or EventCategory.Installation
                                    && evt.EventType is EventTypes.ProcessStart or EventTypes.ProcessStop or EventTypes.AppInstalled
                                    && isSigned == true
                                    && isTrustedPublisher
                                    && !isLolBin
                                    && !hasEncodedCmd
                                    && !isObfuscatedCmd
                                    && !hasDoubleExt
                                    && !isSuspiciousDir
                                    && !isKnownBadHash;

        return new EnrichedEvent
        {
            Event = evt,
            Domain = domain,
            Url = url,
            ProcessName = processName,
            ProcessPath = processPath,
            ParentProcessName = parentProcessName,
            CommandLine = cmdline,
            FilePath = filePath,
            FileName = fileName,
            Extension = ext,
            Sha256 = sha256,
            RemoteIp = remoteIp,
            Publisher = publisher,
            IsSigned = isSigned,
            IsTrustedPublisher = isTrustedPublisher,
            IsShortener = isShortener,
            HasRiskyTld = hasRiskyTld,
            IsLolBin = isLolBin,
            HasEncodedCommand = hasEncodedCmd,
            IsObfuscatedCommand = isObfuscatedCmd,
            HasDoubleExtension = hasDoubleExt,
            IsSuspiciousDirectory = isSuspiciousDir,
            IsDownloadsDirectory = isDownloadsDir,
            IsKnownBadHash = isKnownBadHash,
            IsKnownBadDomain = isKnownBadDomain,
            IsKnownBadIp = isKnownBadIp,
            IsExcluded = isExcluded,
            IsTrustedSignedBypass = isTrustedSignedBypass,
            ExclusionReason = exclusionReason
        };
    }

    private (bool Excluded, string? Reason) CheckExclusions(
        SecurityEvent evt,
        SentinelSettings settings,
        string? processName,
        string? processPath,
        string? domain,
        string? filePath,
        string? sha256)
    {
        // Les événements d'auto-protection ne sont jamais exclus
        if (evt.Category == EventCategory.System)
        {
            return (false, null);
        }

        // 1. Exclusions par empreinte SHA-256
        if (!string.IsNullOrWhiteSpace(sha256))
        {
            foreach (var h in settings.ExcludedHashes)
            {
                if (!string.IsNullOrWhiteSpace(h) &&
                    sha256.Equals(h.Trim(), StringComparison.OrdinalIgnoreCase))
                {
                    return (true, $"Exclu par politique (empreinte SHA-256 autorisée : {sha256[..Math.Min(12, sha256.Length)]}…)");
                }
            }

            if (_reputation.IsBenignHash(sha256))
            {
                return (true, "Exclu par apprentissage analyste (empreinte marquée comme faux positif)");
            }
        }

        // 2. Exclusions par nom de processus
        if (!string.IsNullOrWhiteSpace(processName))
        {
            foreach (var p in settings.ExcludedProcesses)
            {
                if (string.IsNullOrWhiteSpace(p)) continue;
                if (ThreatIndicators.NormalizeProcessName(p).Equals(processName, StringComparison.OrdinalIgnoreCase))
                {
                    return (true, $"Exclu par politique (processus autorisé : {p})");
                }
            }
        }

        // 3. Exclusions par domaine (exact ou sous-domaine)
        if (!string.IsNullOrWhiteSpace(domain))
        {
            foreach (var d in settings.ExcludedDomains)
            {
                if (ThreatIndicators.MatchesDomainExclusion(domain, d))
                {
                    return (true, $"Exclu par politique (domaine autorisé : {d})");
                }
            }

            if (_reputation.IsBenignDomain(domain))
            {
                return (true, $"Exclu par apprentissage analyste (domaine faux positif : {domain})");
            }
        }

        // 4. Exclusions par chemin
        if (settings.ExcludedPaths.Count > 0)
        {
            var candidatePath = NormalizePath(filePath ?? processPath ?? evt.Subject);
            if (!string.IsNullOrEmpty(candidatePath))
            {
                foreach (var rawPrefix in settings.ExcludedPaths)
                {
                    if (string.IsNullOrWhiteSpace(rawPrefix)) continue;
                    var prefix = NormalizePath(Environment.ExpandEnvironmentVariables(rawPrefix));
                    if (!string.IsNullOrEmpty(prefix) &&
                        candidatePath.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    {
                        return (true, $"Exclu par politique (chemin autorisé : {rawPrefix})");
                    }
                }
            }
        }

        // 5. Processus marqué bénin par retour analyste (hors LOLBins à commande encodée)
        if (!string.IsNullOrWhiteSpace(processName) &&
            evt.Category == EventCategory.Process &&
            _reputation.IsBenignProcess(processName))
        {
            return (true, $"Exclu par apprentissage analyste (processus faux positif : {processName})");
        }

        return (false, null);
    }

    private static string NormalizePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return string.Empty;
        return path.Trim().Trim('"').Replace('/', '\\');
    }
}
