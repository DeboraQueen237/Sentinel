using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Sentinel.Detection.Static;

/// <summary>
/// Utilitaire de scan statique planifie ou a la demande, strictement restreint aux dossiers
/// surveilles configures (ne scanne JAMAIS la racine d'un disque entier).
/// </summary>
public sealed class ScheduledStaticScanner
{
    private readonly IStaticFileScanner _scanner;
    private readonly ILogger<ScheduledStaticScanner> _logger;

    public ScheduledStaticScanner(
        IStaticFileScanner scanner,
        ILogger<ScheduledStaticScanner>? logger = null)
    {
        _scanner = scanner ?? throw new ArgumentNullException(nameof(scanner));
        _logger = logger ?? NullLogger<ScheduledStaticScanner>.Instance;
    }

    /// <summary>
    /// Verifie qu'un chemin de dossier surveille n'est pas une racine de disque ou un repertoire systeme global.
    /// </summary>
    public static bool IsSafeWatchedFolder(string folderPath, out string resolvedPath, out string? rejectionReason)
    {
        resolvedPath = string.Empty;
        rejectionReason = null;

        if (string.IsNullOrWhiteSpace(folderPath))
        {
            rejectionReason = "Chemin de dossier vide.";
            return false;
        }

        string expanded;
        try
        {
            expanded = Environment.ExpandEnvironmentVariables(folderPath.Trim());
            resolvedPath = Path.GetFullPath(expanded).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        }
        catch (Exception ex)
        {
            rejectionReason = $"Chemin invalide '{folderPath}' : {ex.Message}";
            return false;
        }

        var root = Path.GetPathRoot(resolvedPath)?.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (string.IsNullOrEmpty(resolvedPath) ||
            (!string.IsNullOrEmpty(root) && resolvedPath.Equals(root, StringComparison.OrdinalIgnoreCase)))
        {
            rejectionReason = $"Scan de la racine du disque refuse par securite : '{folderPath}'.";
            return false;
        }

        var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (!string.IsNullOrEmpty(winDir) && resolvedPath.Equals(winDir, StringComparison.OrdinalIgnoreCase))
        {
            rejectionReason = $"Scan integral du repertoire Windows refuse : '{folderPath}'.";
            return false;
        }

        return true;
    }

    /// <summary>
    /// Scanne a la demande uniquement les dossiers surveilles configures, avec profondeur
    /// et nombre maximal de fichiers bornes.
    /// </summary>
    public async Task<ScheduledScanSummary> ScanWatchedFoldersAsync(
        IEnumerable<string> configuredFolders,
        IEnumerable<string>? excludedPaths = null,
        IEnumerable<string>? excludedHashes = null,
        int maxDepth = 2,
        int maxFilesPerFolder = 500,
        int minFindingScore = 30,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(configuredFolders);

        var sw = Stopwatch.StartNew();
        var folderList = configuredFolders.ToList();
        var rejected = new List<string>();
        var findings = new List<StaticScanOutcome>();

        var excludedPrefixes = (excludedPaths ?? Array.Empty<string>())
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Select(p => Path.GetFullPath(Environment.ExpandEnvironmentVariables(p.Trim())))
            .ToArray();

        var excludedHashSet = new HashSet<string>(
            (excludedHashes ?? Array.Empty<string>()).Where(h => !string.IsNullOrWhiteSpace(h)),
            StringComparer.OrdinalIgnoreCase);

        var foldersScanned = 0;
        var filesEvaluated = 0;
        var filesScanned = 0;
        var filesSkipped = 0;

        foreach (var rawFolder in folderList)
        {
            ct.ThrowIfCancellationRequested();

            if (!IsSafeWatchedFolder(rawFolder, out var folderPath, out var rejectReason))
            {
                rejected.Add($"{rawFolder} ({rejectReason})");
                _logger.LogWarning("Dossier ignore lors du scan planifie : {Reason}", rejectReason);
                continue;
            }

            if (!Directory.Exists(folderPath))
                continue;

            foldersScanned++;
            var folderFilesScanned = 0;

            foreach (var file in EnumerateFilesBounded(folderPath, Math.Max(0, maxDepth), ct))
            {
                ct.ThrowIfCancellationRequested();
                filesEvaluated++;

                if (folderFilesScanned >= Math.Max(1, maxFilesPerFolder))
                    break;

                if (IsExcludedPath(file, excludedPrefixes))
                {
                    filesSkipped++;
                    continue;
                }

                if (!_scanner.IsEligibleExtension(file))
                {
                    filesSkipped++;
                    continue;
                }

                var outcome = await _scanner.ScanFileDetailedAsync(file, ct).ConfigureAwait(false);
                if (outcome.Skipped)
                {
                    filesSkipped++;
                    continue;
                }

                filesScanned++;
                folderFilesScanned++;

                if (!string.IsNullOrEmpty(outcome.Result.Sha256) &&
                    excludedHashSet.Contains(outcome.Result.Sha256))
                {
                    continue;
                }

                if (outcome.Result.YaraMatches.Count > 0 || outcome.Result.CombinedScore >= minFindingScore)
                {
                    findings.Add(outcome);
                }
            }
        }

        sw.Stop();
        var summary = new ScheduledScanSummary(
            FoldersRequested: folderList.Count,
            FoldersScanned: foldersScanned,
            RejectedFolders: rejected,
            FilesEvaluated: filesEvaluated,
            FilesScanned: filesScanned,
            FilesSkipped: filesSkipped,
            FindingsCount: findings.Count,
            Findings: findings,
            ElapsedMs: Math.Round(sw.Elapsed.TotalMilliseconds, 2),
            CompletedAt: DateTimeOffset.UtcNow);

        _logger.LogInformation(
            "Scan statique planifie termine : {Folders} dossier(s), {Scanned} fichier(s) analyses, {Findings} detection(s) en {ElapsedMs} ms.",
            summary.FoldersScanned, summary.FilesScanned, summary.FindingsCount, summary.ElapsedMs);

        return summary;
    }

    /// <summary>
    /// Execute periodiquement <see cref="ScanWatchedFoldersAsync"/> jusqu'a annulation.
    /// </summary>
    public async Task RunPeriodicAsync(
        Func<IEnumerable<string>> foldersProvider,
        TimeSpan interval,
        Action<ScheduledScanSummary>? onCompleted = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(foldersProvider);
        var effectiveInterval = interval < TimeSpan.FromMinutes(1) ? TimeSpan.FromMinutes(1) : interval;

        using var timer = new PeriodicTimer(effectiveInterval);
        while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
        {
            try
            {
                var summary = await ScanWatchedFoldersAsync(foldersProvider(), ct: ct).ConfigureAwait(false);
                onCompleted?.Invoke(summary);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Erreur lors du cycle de scan statique periodique.");
            }
        }
    }

    private static IEnumerable<string> EnumerateFilesBounded(string rootDir, int maxDepth, CancellationToken ct)
    {
        var stack = new Stack<(string Dir, int Depth)>();
        stack.Push((rootDir, 0));

        while (stack.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var (current, depth) = stack.Pop();

            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(current); }
            catch { continue; }

            foreach (var f in files)
                yield return f;

            if (depth >= maxDepth)
                continue;

            IEnumerable<string> subDirs;
            try { subDirs = Directory.EnumerateDirectories(current); }
            catch { continue; }

            foreach (var sub in subDirs)
            {
                try
                {
                    var attrs = File.GetAttributes(sub);
                    if ((attrs & FileAttributes.ReparsePoint) != 0)
                        continue; // Ne jamais suivre les liens symboliques / jonctions
                }
                catch
                {
                    continue;
                }
                stack.Push((sub, depth + 1));
            }
        }
    }

    private static bool IsExcludedPath(string filePath, string[] excludedPrefixes)
    {
        foreach (var prefix in excludedPrefixes)
        {
            if (filePath.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }
}
