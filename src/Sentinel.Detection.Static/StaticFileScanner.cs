using System.Diagnostics;
using System.Globalization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Shared.Api;
using Sentinel.Shared.Models;

namespace Sentinel.Detection.Static;

/// <summary>
/// Orchestrateur de scan statique (analyse PE + YARA) avec garde-fous stricts de ressources
/// (taille max, timeout par fichier, parallelisme borne, execution a priorite basse).
/// </summary>
public interface IStaticFileScanner : IDisposable
{
    StaticScanSettings Settings { get; }
    IYaraScanner YaraScanner { get; }
    PeStaticAnalyzer PeAnalyzer { get; }

    /// <summary>Indique si l'extension du fichier est eligible au scan declenche par evenement.</summary>
    bool IsEligibleExtension(string filePath);

    /// <summary>Scanne un fichier (y compris a la demande) en appliquant les limites de ressources.</summary>
    Task<StaticScanResultDto> ScanFileAsync(string filePath, CancellationToken ct = default);

    /// <summary>Scanne un fichier et retourne le detail complet (PE, YARA, contributions de score).</summary>
    Task<StaticScanOutcome> ScanFileDetailedAsync(string filePath, CancellationToken ct = default);

    /// <summary>Scanne un fichier uniquement si son extension est eligible au scan automatique.</summary>
    Task<StaticScanOutcome?> ScanIfEligibleAsync(string filePath, CancellationToken ct = default);

    /// <summary>Convertit les detections d'un scan statique en <see cref="SecurityEvent"/> normalises.</summary>
    IReadOnlyList<SecurityEvent> ToSecurityEvents(StaticScanOutcome outcome, string hostId, string userId);

    /// <summary>Produit les <see cref="ScoreContribution"/> explicables pour le pipeline de scoring v2.</summary>
    IReadOnlyList<ScoreContribution> ToScoreContributions(StaticScanOutcome outcome);
}

/// <summary>
/// Implementation par defaut de <see cref="IStaticFileScanner"/>.
/// Execute l'analyse sur une tache dediee a priorite <see cref="ThreadPriority.BelowNormal"/>
/// afin de ne pas degrader la reactivite du poste utilisateur.
/// </summary>
public sealed class StaticFileScanner : IStaticFileScanner
{
    public static readonly IReadOnlySet<string> EligibleExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys", ".scr", ".msi", ".com",
        ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta",
        ".zip", ".7z", ".rar", ".iso",
        ".docm", ".xlsm", ".pptm", ".doc", ".xls",
        ".txt"
    };

    private readonly SemaphoreSlim _concurrencyGate;
    private readonly ILogger<StaticFileScanner> _logger;
    private readonly bool _ownsYaraScanner;
    private bool _disposed;

    public StaticFileScanner(
        IYaraScanner? yaraScanner = null,
        PeStaticAnalyzer? peAnalyzer = null,
        StaticScanSettings? settings = null,
        ILogger<StaticFileScanner>? logger = null)
    {
        _ownsYaraScanner = yaraScanner is null;
        YaraScanner = yaraScanner ?? new YaraScannerService();
        PeAnalyzer = peAnalyzer ?? new PeStaticAnalyzer();
        Settings = settings ?? new StaticScanSettings();
        _logger = logger ?? NullLogger<StaticFileScanner>.Instance;
        _concurrencyGate = new SemaphoreSlim(Math.Max(1, Settings.MaxConcurrency), Math.Max(1, Settings.MaxConcurrency));
    }

    /// <inheritdoc />
    public StaticScanSettings Settings { get; }

    /// <inheritdoc />
    public IYaraScanner YaraScanner { get; }

    /// <inheritdoc />
    public PeStaticAnalyzer PeAnalyzer { get; }

    /// <inheritdoc />
    public bool IsEligibleExtension(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
            return false;

        var ext = Path.GetExtension(filePath);
        return !string.IsNullOrEmpty(ext) && EligibleExtensions.Contains(ext);
    }

    /// <inheritdoc />
    public async Task<StaticScanResultDto> ScanFileAsync(string filePath, CancellationToken ct = default)
    {
        var outcome = await ScanFileDetailedAsync(filePath, ct).ConfigureAwait(false);
        return outcome.Result;
    }

    /// <inheritdoc />
    public async Task<StaticScanOutcome?> ScanIfEligibleAsync(string filePath, CancellationToken ct = default)
    {
        if (!Settings.Enabled || !IsEligibleExtension(filePath))
            return null;

        return await ScanFileDetailedAsync(filePath, ct).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<StaticScanOutcome> ScanFileDetailedAsync(string filePath, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        ObjectDisposedException.ThrowIf(_disposed, this);

        var sw = Stopwatch.StartNew();

        // 1. Verification rapide d'existence et de taille avant d'acquerir un slot ou de lire le fichier
        FileInfo info;
        try
        {
            info = new FileInfo(filePath);
            if (!info.Exists)
            {
                return CreateSkippedOutcome(filePath, 0, sw.Elapsed.TotalMilliseconds, $"Fichier introuvable : '{filePath}'.", timedOut: false);
            }
        }
        catch (Exception ex)
        {
            return CreateSkippedOutcome(filePath, 0, sw.Elapsed.TotalMilliseconds, $"Acces impossible au fichier : {ex.Message}", timedOut: false);
        }

        var maxSize = Settings.MaxFileSizeBytes > 0 ? Settings.MaxFileSizeBytes : 25L * 1024 * 1024;
        if (info.Length > maxSize)
        {
            var reason = $"Fichier refuse : taille ({info.Length} octets) superieure a la limite autorisee ({maxSize} octets).";
            _logger.LogDebug("Scan statique ignore pour {File} : {Reason}", filePath, reason);
            return CreateSkippedOutcome(filePath, info.Length, sw.Elapsed.TotalMilliseconds, reason, timedOut: false);
        }

        // 2. Timeout strict par fichier + controle de parallelisme borne
        var timeoutMs = Settings.TimeoutMs > 0 ? Settings.TimeoutMs : 4000;
        using var timeoutCts = new CancellationTokenSource(timeoutMs);
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);

        var acquired = false;
        try
        {
            await _concurrencyGate.WaitAsync(linkedCts.Token).ConfigureAwait(false);
            acquired = true;

            var workerTask = RunOnBelowNormalThreadAsync(
                workerToken => ExecuteStaticAnalysisCore(filePath, workerToken),
                linkedCts.Token);

            // Permet de retourner immediatement si le timeout expire meme pendant un appel natif bloquant
            var delayTask = Task.Delay(Timeout.Infinite, linkedCts.Token);
            var completed = await Task.WhenAny(workerTask, delayTask).ConfigureAwait(false);

            if (completed != workerTask)
            {
                if (ct.IsCancellationRequested)
                    ct.ThrowIfCancellationRequested();

                var timeoutMsg = $"Timeout d'analyse statique depasse ({timeoutMs} ms) pour '{filePath}'.";
                _logger.LogWarning("Timeout d'analyse statique ({TimeoutMs} ms) sur {File}", timeoutMs, filePath);
                return CreateSkippedOutcome(filePath, info.Length, sw.Elapsed.TotalMilliseconds, timeoutMsg, timedOut: true);
            }

            var (peResult, yaraReport) = await workerTask.ConfigureAwait(false);
            sw.Stop();

            return BuildOutcome(filePath, peResult, yaraReport, sw.Elapsed.TotalMilliseconds);
        }
        catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested && !ct.IsCancellationRequested)
        {
            sw.Stop();
            var timeoutMsg = $"Timeout d'analyse statique depasse ({timeoutMs} ms) pour '{filePath}'.";
            _logger.LogWarning("Timeout d'analyse statique ({TimeoutMs} ms) sur {File}", timeoutMs, filePath);
            return CreateSkippedOutcome(filePath, info.Length, sw.Elapsed.TotalMilliseconds, timeoutMsg, timedOut: true);
        }
        finally
        {
            if (acquired)
                _concurrencyGate.Release();
        }
    }

    /// <inheritdoc />
    public IReadOnlyList<SecurityEvent> ToSecurityEvents(StaticScanOutcome outcome, string hostId, string userId)
    {
        ArgumentNullException.ThrowIfNull(outcome);
        var events = new List<SecurityEvent>();
        var res = outcome.Result;
        var fileName = Path.GetFileName(res.FilePath);
        var ext = Path.GetExtension(res.FilePath);

        if (outcome.YaraReport is { Matches.Count: > 0 } yara)
        {
            var attrs = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                [AttributeKeys.FilePath] = res.FilePath,
                [AttributeKeys.FileName] = fileName,
                [AttributeKeys.Extension] = ext,
                [AttributeKeys.FileSize] = res.SizeBytes.ToString(CultureInfo.InvariantCulture),
                [AttributeKeys.Sha256] = res.Sha256,
                [AttributeKeys.Entropy] = res.MaxEntropy.ToString("0.000", CultureInfo.InvariantCulture),
                [AttributeKeys.YaraRule] = string.Join(",", yara.Matches.Select(m => m.RuleId)),
                [AttributeKeys.YaraNamespace] = string.Join(",", yara.Matches.Select(m => m.Namespace).Distinct(StringComparer.OrdinalIgnoreCase)),
                [AttributeKeys.YaraEngine] = yara.EngineName,
                [AttributeKeys.PeSigned] = res.Signed ? "true" : "false"
            };
            if (!string.IsNullOrWhiteSpace(res.Publisher))
                attrs[AttributeKeys.Publisher] = res.Publisher;

            events.Add(SecurityEvent.Create(
                hostId: hostId,
                userId: userId,
                category: EventCategory.StaticAnalysis,
                eventType: EventTypes.YaraMatch,
                subject: res.FilePath,
                attributes: attrs,
                correlationHints: res.Sha256));
        }

        if (outcome.PeAnalysis is { IsPe: true } pe && HasSignificantPeAnomaly(pe))
        {
            var attrs = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                [AttributeKeys.FilePath] = res.FilePath,
                [AttributeKeys.FileName] = fileName,
                [AttributeKeys.Extension] = ext,
                [AttributeKeys.FileSize] = res.SizeBytes.ToString(CultureInfo.InvariantCulture),
                [AttributeKeys.Sha256] = res.Sha256,
                [AttributeKeys.Entropy] = pe.FileEntropy.ToString("0.000", CultureInfo.InvariantCulture),
                [AttributeKeys.PeSigned] = pe.HasValidSignature ? "true" : "false",
                [AttributeKeys.PeSectionCount] = pe.Sections.Count.ToString(CultureInfo.InvariantCulture),
                [AttributeKeys.PeMaxEntropy] = pe.MaxEntropy.ToString("0.000", CultureInfo.InvariantCulture)
            };
            if (!string.IsNullOrWhiteSpace(pe.Publisher))
                attrs[AttributeKeys.Publisher] = pe.Publisher;
            if (!string.IsNullOrWhiteSpace(pe.ProbablePacker))
                attrs[AttributeKeys.PePacker] = pe.ProbablePacker;
            if (pe.CompileTime.HasValue)
                attrs[AttributeKeys.PeCompileTime] = pe.CompileTime.Value.ToString("O", CultureInfo.InvariantCulture);
            else if (pe.TimestampAnomaly)
                attrs[AttributeKeys.PeCompileTime] = "0";
            if (pe.SuspiciousImports.Count > 0)
                attrs[AttributeKeys.PeSuspiciousImports] = string.Join(",", pe.SuspiciousImports);

            events.Add(SecurityEvent.Create(
                hostId: hostId,
                userId: userId,
                category: EventCategory.StaticAnalysis,
                eventType: EventTypes.PeStaticAnomaly,
                subject: res.FilePath,
                attributes: attrs,
                correlationHints: res.Sha256));
        }

        return events;
    }

    /// <inheritdoc />
    public IReadOnlyList<ScoreContribution> ToScoreContributions(StaticScanOutcome outcome)
    {
        ArgumentNullException.ThrowIfNull(outcome);
        return outcome.Contributions;
    }

    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;
        _concurrencyGate.Dispose();
        if (_ownsYaraScanner)
            YaraScanner.Dispose();
    }

    private (PeAnalysisResult PeResult, YaraScanReport YaraReport) ExecuteStaticAnalysisCore(string filePath, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        byte[] bytes;
        using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
        {
            bytes = new byte[fs.Length];
            var total = 0;
            while (total < bytes.Length)
            {
                ct.ThrowIfCancellationRequested();
                var n = fs.Read(bytes, total, bytes.Length - total);
                if (n <= 0) break;
                total += n;
            }
            if (total != bytes.Length)
                Array.Resize(ref bytes, total);
        }

        ct.ThrowIfCancellationRequested();
        var peResult = PeAnalyzer.AnalyzeBytes(bytes, filePath, ct);

        ct.ThrowIfCancellationRequested();
        var yaraReport = YaraScanner.ScanBytes(bytes, ct);

        return (peResult, yaraReport);
    }

    private StaticScanOutcome BuildOutcome(
        string filePath,
        PeAnalysisResult peResult,
        YaraScanReport yaraReport,
        double elapsedMs)
    {
        var contributions = new List<ScoreContribution>();
        var yaraScore = 0;

        if (yaraReport.Matches.Count > 0)
        {
            var peakYara = yaraReport.Matches.Max(m => m.Score);
            var multiBonus = Math.Min(15, (yaraReport.Matches.Count - 1) * 5);
            yaraScore = Math.Clamp(peakYara + multiBonus, 0, 100);

            var signals = yaraReport.Matches
                .Select(m => $"{m.RuleId} ({m.Level})")
                .ToArray();

            contributions.Add(new ScoreContribution(
                Engine: "YARA",
                Score: yaraScore,
                Weight: 1.0,
                Summary: $"{yaraReport.Matches.Count} regle(s) YARA declenchee(s) via {yaraReport.EngineName} : {string.Join(", ", yaraReport.Matches.Select(m => m.RuleId))}",
                Signals: signals));
        }

        if (peResult.IsPe && peResult.RiskScore > 0)
        {
            contributions.Add(new ScoreContribution(
                Engine: "PeStatic",
                Score: peResult.RiskScore,
                Weight: 0.7,
                Summary: peResult.Signals.Count > 0
                    ? string.Join(" ; ", peResult.Signals)
                    : $"Anomalie statique PE (entropie max {peResult.MaxEntropy:0.00})",
                Signals: peResult.Signals));
        }

        var combinedScore = ComputeCombinedScore(yaraScore, peResult.RiskScore);
        var error = peResult.Error ?? yaraReport.Error;

        var dto = new StaticScanResultDto(
            FilePath: filePath,
            Sha256: peResult.Sha256,
            SizeBytes: peResult.SizeBytes,
            IsPe: peResult.IsPe,
            Signed: peResult.IsSigned && peResult.HasValidSignature,
            Publisher: peResult.Publisher,
            MaxEntropy: peResult.MaxEntropy,
            ProbablePacker: peResult.ProbablePacker,
            TimestampAnomaly: peResult.TimestampAnomaly,
            SuspiciousImports: peResult.SuspiciousImports,
            YaraMatches: yaraReport.Matches.Select(m => m.RuleId).ToArray(),
            YaraEngine: yaraReport.EngineName,
            MlMaliciousProbability: null,
            MlTopFeatures: Array.Empty<string>(),
            CombinedScore: combinedScore,
            ElapsedMs: Math.Round(elapsedMs, 2),
            Error: error);

        return new StaticScanOutcome(dto, peResult, yaraReport, contributions);
    }

    private StaticScanOutcome CreateSkippedOutcome(
        string filePath,
        long sizeBytes,
        double elapsedMs,
        string reason,
        bool timedOut)
    {
        var dto = new StaticScanResultDto(
            FilePath: filePath,
            Sha256: string.Empty,
            SizeBytes: sizeBytes,
            IsPe: false,
            Signed: false,
            Publisher: null,
            MaxEntropy: 0.0,
            ProbablePacker: null,
            TimestampAnomaly: false,
            SuspiciousImports: Array.Empty<string>(),
            YaraMatches: Array.Empty<string>(),
            YaraEngine: YaraScanner.EngineName,
            MlMaliciousProbability: null,
            MlTopFeatures: Array.Empty<string>(),
            CombinedScore: 0,
            ElapsedMs: Math.Round(elapsedMs, 2),
            Error: reason);

        return new StaticScanOutcome(
            dto,
            PeAnalysis: null,
            YaraReport: null,
            Contributions: Array.Empty<ScoreContribution>(),
            Skipped: true,
            SkipReason: reason,
            TimedOut: timedOut);
    }

    private static int ComputeCombinedScore(int yaraScore, int peScore)
    {
        if (yaraScore <= 0)
            return Math.Clamp(peScore, 0, 100);
        if (peScore <= 0)
            return Math.Clamp(yaraScore, 0, 100);

        return Math.Clamp(Math.Max(yaraScore, peScore) + (int)Math.Round(Math.Min(yaraScore, peScore) * 0.25), 0, 100);
    }

    private static bool HasSignificantPeAnomaly(PeAnalysisResult pe) =>
        pe.ProbablePacker is not null ||
        pe.TimestampAnomaly ||
        pe.SuspiciousImports.Count > 0 ||
        pe.MaxEntropy > 7.2 ||
        pe.RiskScore >= 30;

    private static Task<T> RunOnBelowNormalThreadAsync<T>(Func<CancellationToken, T> work, CancellationToken ct)
    {
        var tcs = new TaskCompletionSource<T>(TaskCreationOptions.RunContinuationsAsynchronously);

        var thread = new Thread(() =>
        {
            try
            {
                ct.ThrowIfCancellationRequested();
                var result = work(ct);
                tcs.TrySetResult(result);
            }
            catch (OperationCanceledException oce)
            {
                tcs.TrySetCanceled(oce.CancellationToken);
            }
            catch (Exception ex)
            {
                tcs.TrySetException(ex);
            }
        })
        {
            Name = "Sentinel.StaticScan.Worker",
            IsBackground = true
        };

        try
        {
            thread.Priority = ThreadPriority.BelowNormal;
        }
        catch
        {
            // Certains environnements restreints peuvent refuser la modification de priorite
        }

        thread.Start();
        return tcs.Task;
    }
}
