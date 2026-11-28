using System.Diagnostics;
using Microsoft.EntityFrameworkCore;
using Microsoft.Win32;
using Sentinel.AI;
using Sentinel.Core.Abstractions;
using Sentinel.Detection.Sigma;
using Sentinel.Detection.Static;
using Sentinel.ML;
using Sentinel.Shared.Api;
using Sentinel.Shared.Infrastructure;
using Sentinel.Shared.Json;
using Sentinel.Shared.Models;
using Sentinel.Storage;
using Sentinel.Storage.Entities;
using Sentinel.Storage.Services;
using Sentinel.ThreatIntel;
using System.Net.NetworkInformation;

namespace Sentinel.Server.Services;

/// <summary>
/// Moteur unifié de Scan Système Général (détection proactive d'anomalies sur processus, connexions réseau,
/// clés de persistance, dossiers sensibles et canaris), d'Audit de Posture &amp; d'Intégrité Système,
/// et de Simulation Interactive de Présentation (scénarios inoffensifs multi-étapes en temps réel).
/// </summary>
public sealed class SystemScanAndAuditService : BackgroundService
{
    private static readonly HashSet<int> SuspiciousPorts = [4444, 1337, 5555, 6667, 6697, 9001, 9050, 31337];
    private static readonly HashSet<string> ScanExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".scr", ".ps1", ".vbs", ".js", ".hta", ".bat", ".cmd"
    };

    private readonly IThreatPipeline _pipeline;
    private readonly EventIngestionService _ingestion;
    private readonly IntegrityVerifier _integrityVerifier;
    private readonly HashChainWriter _auditWriter;
    private readonly IDbContextFactory<SentinelDbContext> _dbFactory;
    private readonly ILlmAssessor _llm;
    private readonly IAlertNotificationDispatcher _notifications;
    private readonly ISigmaEngine? _sigma;
    private readonly IYaraScanner? _yara;
    private readonly IStaticFileScanner? _staticScanner;
    private readonly IPeMlClassifier? _mlClassifier;
    private readonly IReputationService? _threatIntel;
    private readonly IHostEnvironment _environment;
    private readonly ILogger<SystemScanAndAuditService> _logger;

    private readonly object _cacheGate = new();
    private SystemScanReportDto? _lastScan;
    private SecurityAuditReportDto? _lastAudit;

    public SystemScanAndAuditService(
        IThreatPipeline pipeline,
        EventIngestionService ingestion,
        IntegrityVerifier integrityVerifier,
        HashChainWriter auditWriter,
        IDbContextFactory<SentinelDbContext> dbFactory,
        ILlmAssessor llm,
        IAlertNotificationDispatcher notifications,
        IHostEnvironment environment,
        ILogger<SystemScanAndAuditService> logger,
        ISigmaEngine? sigma = null,
        IYaraScanner? yara = null,
        IStaticFileScanner? staticScanner = null,
        IPeMlClassifier? mlClassifier = null,
        IReputationService? threatIntel = null)
    {
        _pipeline = pipeline;
        _ingestion = ingestion;
        _integrityVerifier = integrityVerifier;
        _auditWriter = auditWriter;
        _dbFactory = dbFactory;
        _llm = llm;
        _notifications = notifications;
        _environment = environment;
        _logger = logger;
        _sigma = sigma;
        _yara = yara;
        _staticScanner = staticScanner;
        _mlClassifier = mlClassifier;
        _threatIntel = threatIntel;
    }

    public SystemScanReportDto? LastScanReport
    {
        get { lock (_cacheGate) return _lastScan; }
    }

    public SecurityAuditReportDto? LastAuditReport
    {
        get { lock (_cacheGate) return _lastAudit; }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (_environment.IsEnvironment("Testing"))
        {
            return;
        }

        // Scan général périodique automatique toutes les 6 heures
        using var timer = new PeriodicTimer(TimeSpan.FromHours(6));
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
            {
                try
                {
                    await RunGeneralSystemScanAsync(ingestAnomalies: true, includeAiSummary: false, actor: "AutoScheduler", ct: stoppingToken)
                        .ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Échec du scan système périodique automatique.");
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
    }

    /// <summary>Lance un scan général complet du poste (processus, réseau, persistance, fichiers récents, canaris).</summary>
    public async Task<SystemScanReportDto> RunGeneralSystemScanAsync(
        bool ingestAnomalies = true,
        bool includeAiSummary = true,
        string actor = "Admin",
        CancellationToken ct = default)
    {
        var startedAt = DateTimeOffset.UtcNow;
        var sw = Stopwatch.StartNew();
        var hostName = Environment.MachineName.ToLowerInvariant();
        var findings = new List<SystemScanFindingDto>();
        var eventsToIngest = new List<SecurityEvent>();

        var tempDir = Path.GetTempPath().TrimEnd(Path.DirectorySeparatorChar);
        var downloadsDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");

        // 1. Inspection rapide des processus en cours d'exécution (en ignorant les processus noyau Session 0 inaccessibles)
        var procCount = 0;
        var currentSessionId = Process.GetCurrentProcess().SessionId;
        var inspectedPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        static bool IsKnownKernelProcess(string name) =>
            name is "Idle" or "System" or "Registry" or "Memory Compression" or "smss" or "csrss" or "wininit" or "services" or "lsass" or "svchost" or "fontdrvhost" or "dwm";

        foreach (var proc in Process.GetProcesses())
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                procCount++;
                var pName = proc.ProcessName;
                if (IsKnownKernelProcess(pName)) continue;
                try { if (proc.SessionId == 0 && currentSessionId != 0) continue; } catch { continue; }

                string? exePath = null;
                try { exePath = proc.MainModule?.FileName; } catch { /* processus protégé */ }
                if (string.IsNullOrWhiteSpace(exePath)) continue;

                var inSuspiciousFolder =
                    exePath.StartsWith(tempDir, StringComparison.OrdinalIgnoreCase) ||
                    exePath.StartsWith(downloadsDir, StringComparison.OrdinalIgnoreCase) ||
                    exePath.Contains(@"\Users\Public\", StringComparison.OrdinalIgnoreCase);

                if (inSuspiciousFolder && inspectedPaths.Add(exePath))
                {
                    var score = 72;
                    var details = $"Exécutable actif lancé depuis un répertoire temporaire/téléchargement : {exePath} (PID {proc.Id}).";
                    if (_staticScanner is not null && File.Exists(exePath))
                    {
                        try
                        {
                            var scanRes = await _staticScanner.ScanFileAsync(exePath, ct).ConfigureAwait(false);
                            if (scanRes.CombinedScore > score) score = scanRes.CombinedScore;
                            if (scanRes.YaraMatches.Count > 0)
                                details += $" Règles YARA : {string.Join(", ", scanRes.YaraMatches)}.";
                        }
                        catch { }
                    }

                    var level = ThreatLevels.FromScore(score);
                    findings.Add(new SystemScanFindingDto(
                        Area: "Processus actifs",
                        Severity: level,
                        Score: score,
                        Title: $"Processus en exécution depuis un dossier à risque ({proc.ProcessName})",
                        Subject: exePath,
                        Details: details,
                        Recommendation: "Vérifier la légitimité du binaire et le mettre en quarantaine réversible s'il n'est pas signé.",
                        MitreTechniques: ["T1204.002"],
                        IngestedAsEvent: ingestAnomalies));

                    if (ingestAnomalies)
                    {
                        eventsToIngest.Add(SecurityEvent.Create(
                            hostName,
                            Environment.UserName,
                            EventCategory.Process,
                            EventTypes.ProcessStart,
                            exePath,
                            new Dictionary<string, string>
                            {
                                [AttributeKeys.ProcessName] = proc.ProcessName + ".exe",
                                [AttributeKeys.ProcessPath] = exePath,
                                [AttributeKeys.ProcessId] = proc.Id.ToString()
                            },
                            "scan:general"));
                    }
                }
            }
            finally
            {
                proc.Dispose();
            }
        }

        // 2. Inspection des connexions TCP actives & réputation ThreatIntel
        var connCount = 0;
        try
        {
            var ipProps = IPGlobalProperties.GetIPGlobalProperties();
            var tcpConns = ipProps.GetActiveTcpConnections();
            var seenRemote = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var c in tcpConns)
            {
                connCount++;
                if (c.State != TcpState.Established) continue;
                var remoteIp = c.RemoteEndPoint.Address.ToString();
                var remotePort = c.RemoteEndPoint.Port;
                if (c.RemoteEndPoint.Address.Equals(System.Net.IPAddress.Loopback) ||
                    c.RemoteEndPoint.Address.Equals(System.Net.IPAddress.IPv6Loopback))
                {
                    continue;
                }

                var key = $"{remoteIp}:{remotePort}";
                if (!seenRemote.Add(key)) continue;

                var tiHit = _threatIntel?.LookupIp(remoteIp);
                if (tiHit is not null)
                {
                    findings.Add(new SystemScanFindingDto(
                        Area: "Réseau actif",
                        Severity: ThreatLevel.Critical,
                        Score: 92,
                        Title: $"Connexion établie vers une IP malveillante connue ({remoteIp})",
                        Subject: key,
                        Details: tiHit.Justification,
                        Recommendation: "Bloquer immédiatement l'IP distante via le pare-feu SENTINEL et identifier le processus émetteur.",
                        MitreTechniques: ["T1071"],
                        IngestedAsEvent: ingestAnomalies));

                    if (ingestAnomalies)
                    {
                        eventsToIngest.Add(SecurityEvent.Create(
                            hostName, Environment.UserName, EventCategory.Network, EventTypes.NetworkConnection, key,
                            new Dictionary<string, string>
                            {
                                [AttributeKeys.RemoteIp] = remoteIp,
                                [AttributeKeys.RemotePort] = remotePort.ToString()
                            },
                            "scan:general"));
                    }
                }
                else if (SuspiciousPorts.Contains(remotePort))
                {
                    findings.Add(new SystemScanFindingDto(
                        Area: "Réseau actif",
                        Severity: ThreatLevel.High,
                        Score: 76,
                        Title: $"Connexion sortante sur port C2/inhabituel ({remotePort})",
                        Subject: key,
                        Details: $"Connexion TCP établie vers {remoteIp}:{remotePort}.",
                        Recommendation: "Vérifier le service distant et bloquer le port s'il ne correspond pas à un outil administrateur connu.",
                        MitreTechniques: ["T1571"],
                        IngestedAsEvent: ingestAnomalies));
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Inspection réseau partielle lors du scan général.");
        }

        // 3. Inspection des entrées de persistance (Registre Run / RunOnce)
        var persistenceCount = 0;
        if (OperatingSystem.IsWindows())
        {
            var runKeys = new (RegistryKey Root, string Path, string Scope)[]
            {
                (Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU\\Run"),
                (Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\RunOnce"),
                (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run"),
                (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\RunOnce")
            };

            foreach (var (root, subKeyPath, scope) in runKeys)
            {
                try
                {
                    using var key = root.OpenSubKey(subKeyPath);
                    if (key is null) continue;
                    foreach (var valName in key.GetValueNames())
                    {
                        persistenceCount++;
                        var cmd = Convert.ToString(key.GetValue(valName)) ?? string.Empty;
                        if (string.IsNullOrWhiteSpace(cmd)) continue;

                        var lowerCmd = cmd.ToLowerInvariant();
                        var suspiciousAutorun =
                            lowerCmd.Contains("-enc", StringComparison.Ordinal) ||
                            lowerCmd.Contains("frombase64string", StringComparison.Ordinal) ||
                            lowerCmd.Contains("mshta", StringComparison.Ordinal) ||
                            lowerCmd.Contains("wscript", StringComparison.Ordinal) ||
                            lowerCmd.Contains(@"\appdata\local\temp\", StringComparison.Ordinal) ||
                            lowerCmd.Contains(@"\downloads\", StringComparison.Ordinal);

                        if (suspiciousAutorun)
                        {
                            findings.Add(new SystemScanFindingDto(
                                Area: "Persistance",
                                Severity: ThreatLevel.High,
                                Score: 82,
                                Title: $"Entrée de démarrage suspecte dans {scope} ({valName})",
                                Subject: $"{scope}\\{valName}",
                                Details: $"Commande enregistrée au démarrage : {Truncate(cmd, 180)}",
                                Recommendation: "Supprimer la clé de registre non légitime et analyser le script/binaire référencé.",
                                MitreTechniques: ["T1547.001"],
                                IngestedAsEvent: ingestAnomalies));

                            if (ingestAnomalies)
                            {
                                eventsToIngest.Add(SecurityEvent.Create(
                                    hostName, Environment.UserName, EventCategory.Installation, EventTypes.StartupEntryAdded, $"{scope}\\{valName}",
                                    new Dictionary<string, string>
                                    {
                                        [AttributeKeys.CommandLine] = Truncate(cmd, 240),
                                        [AttributeKeys.RegistryKey] = scope,
                                        [AttributeKeys.RegistryValue] = valName
                                    },
                                    "scan:general"));
                            }
                        }
                    }
                }
                catch { /* clé inaccessible sans élévation */ }
            }
        }

        // 4. Balayage borné des exécutables/scripts récents dans les dossiers surveillés (YARA + PeNet + ML)
        var filesScanned = 0;
        if (_staticScanner is not null)
        {
            var settings = _pipeline.Settings;
            var recentCutoff = DateTime.UtcNow.AddDays(-3);
            foreach (var rawFolder in settings.WatchedFolders.Take(4))
            {
                var expanded = Environment.ExpandEnvironmentVariables(rawFolder);
                if (!Directory.Exists(expanded)) continue;

                IEnumerable<string> candidates;
                try
                {
                    candidates = Directory.EnumerateFiles(expanded, "*.*", SearchOption.TopDirectoryOnly)
                        .Where(f => ScanExtensions.Contains(Path.GetExtension(f)))
                        .Take(25);
                }
                catch { continue; }

                foreach (var file in candidates)
                {
                    ct.ThrowIfCancellationRequested();
                    if (filesScanned >= 40) break;
                    try
                    {
                        var info = new FileInfo(file);
                        if (!info.Exists || info.Length == 0 || info.Length > settings.StaticScan.MaxFileSizeBytes) continue;
                        if (info.LastWriteTimeUtc < recentCutoff) continue;

                        filesScanned++;
                        var res = await _staticScanner.ScanFileAsync(file, ct).ConfigureAwait(false);
                        if (res.CombinedScore >= 55 || res.YaraMatches.Count > 0)
                        {
                            var score = Math.Max(res.CombinedScore, res.YaraMatches.Count > 0 ? 80 : 55);
                            findings.Add(new SystemScanFindingDto(
                                Area: "Analyse statique fichiers",
                                Severity: ThreatLevels.FromScore(score),
                                Score: score,
                                Title: $"Fichier suspect détecté ({Path.GetFileName(file)})",
                                Subject: file,
                                Details: res.YaraMatches.Count > 0
                                    ? $"Correspondance YARA : {string.Join(", ", res.YaraMatches)} (entropie max {res.MaxEntropy:F2})."
                                    : $"Anomalies statiques PE (score {score}/100, signé={res.Signed}).",
                                Recommendation: "Mettre le fichier en quarantaine réversible et vérifier sa provenance.",
                                MitreTechniques: ["T1027"],
                                IngestedAsEvent: false));
                        }
                    }
                    catch { }
                }
            }
        }

        // 5. Contrôle d'intégrité des fichiers canaris anti-ransomware
        var canariesChecked = 0;
        if (File.Exists(SentinelPaths.CanariesRegistryFile))
        {
            try
            {
                var json = await File.ReadAllTextAsync(SentinelPaths.CanariesRegistryFile, ct).ConfigureAwait(false);
                var canaries = SentinelJson.Deserialize<List<CanaryStatusDto>>(json) ?? [];
                foreach (var canary in canaries)
                {
                    canariesChecked++;
                    if (!File.Exists(canary.FilePath))
                    {
                        findings.Add(new SystemScanFindingDto(
                            Area: "Canaris anti-ransomware",
                            Severity: ThreatLevel.High,
                            Score: 85,
                            Title: "Fichier canari manquant ou supprimé",
                            Subject: canary.FilePath,
                            Details: $"Le fichier leurre attendu dans {canary.Folder} est introuvable.",
                            Recommendation: "Vérifier l'activité récente dans ce dossier ou redéployer les canaris depuis l'écran Canaris.",
                            MitreTechniques: ["T1486"],
                            IngestedAsEvent: false));
                    }
                }
            }
            catch { }
        }

        // Ingestion éventuelle dans le pipeline temps réel
        var ingestedCount = 0;
        if (ingestAnomalies && eventsToIngest.Count > 0)
        {
            await _ingestion.IngestBatchAsync(eventsToIngest, ct).ConfigureAwait(false);
            ingestedCount = eventsToIngest.Count;
        }

        // Synthèse IA optionnelle si des anomalies ont été relevées (ou confirmation d'état sain)
        string? aiSummary = null;
        if (includeAiSummary)
        {
            if (findings.Count == 0)
            {
                aiSummary = $"Aucune anomalie critique détectée sur {hostName} ({procCount} processus, {connCount} connexions TCP, {persistenceCount} clés de démarrage et {filesScanned} binaires récents inspectés).";
            }
            else
            {
                var top = findings.OrderByDescending(f => f.Score).First();
                try
                {
                    using var aiCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    aiCts.CancelAfter(TimeSpan.FromSeconds(14));
                    var analysis = await _llm.AnalyzeIncidentAsync(
                        targetId: "system-scan",
                        title: $"Scan système général : {findings.Count} anomalie(s) détectée(s)",
                        score: top.Score,
                        level: top.Severity,
                        threatType: ThreatType.Anomaly,
                        contextSummary: string.Join(" | ", findings.Take(4).Select(f => $"{f.Area}: {f.Title}")),
                        mitreTechniques: findings.SelectMany(f => f.MitreTechniques).Distinct().ToArray(),
                        ct: aiCts.Token).ConfigureAwait(false);
                    aiSummary = $"{analysis.ExecutiveSummary} — Cause probable : {analysis.RootCauseHypothesis}";
                }
                catch
                {
                    aiSummary = $"{findings.Count} anomalie(s) relevée(s) sur {hostName} (sévérité max : {ThreatLevels.Label(top.Severity)}, {top.Score}/100 — {top.Title}). Recommandation prioritaire : {top.Recommendation}";
                }
            }
        }

        sw.Stop();
        var completedAt = DateTimeOffset.UtcNow;
        var report = new SystemScanReportDto(
            ScanId: Guid.NewGuid(),
            StartedAt: startedAt,
            CompletedAt: completedAt,
            DurationMs: Math.Round(sw.Elapsed.TotalMilliseconds, 1),
            HostName: hostName,
            ProcessesInspected: procCount,
            ConnectionsInspected: connCount,
            PersistenceEntriesInspected: persistenceCount,
            FilesScanned: filesScanned,
            CanariesChecked: canariesChecked,
            AnomaliesFound: findings.Count,
            EventsIngested: ingestedCount,
            AiExecutiveSummary: aiSummary,
            Findings: findings.OrderByDescending(f => f.Score).ToArray());

        lock (_cacheGate)
        {
            _lastScan = report;
        }

        await _auditWriter.WriteAuditAsync(
            actor,
            "GeneralSystemScanExecuted",
            $"host:{hostName}",
            $"Processus={procCount}, Connexions={connCount}, Persistance={persistenceCount}, Fichiers={filesScanned}, Anomalies={findings.Count}, Durée={report.DurationMs}ms.",
            "127.0.0.1",
            ct).ConfigureAwait(false);

        return report;
    }

    /// <summary>Exécute un audit complet de sécurité, de conformité et d'intégrité cryptographique du poste et de SENTINEL.</summary>
    public async Task<SecurityAuditReportDto> RunSystemSecurityAuditAsync(
        bool includeAiPlan = true,
        string actor = "Admin",
        CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var hostName = Environment.MachineName.ToLowerInvariant();
        var checks = new List<SecurityAuditCheckDto>(12);

        // 1. Microsoft Defender
        var (defStatus, defState, defRec) = CheckDefenderPosture();
        checks.Add(new SecurityAuditCheckDto("DEF-01", "Posture Windows", "Protection temps réel Microsoft Defender", defStatus, 15, defState, defRec));

        // 2. Pare-feu Windows
        var (fwStatus, fwState, fwRec) = CheckFirewallPosture();
        checks.Add(new SecurityAuditCheckDto("FW-01", "Posture Windows", "Pare-feu Windows (Profils Domaine / Privé / Public)", fwStatus, 12, fwState, fwRec));

        // 3. Contrôle de compte utilisateur (UAC)
        var (uacStatus, uacState, uacRec) = CheckUacPosture();
        checks.Add(new SecurityAuditCheckDto("OS-UAC", "Posture Windows", "Contrôle de compte d'utilisateur (UAC / EnableLUA)", uacStatus, 10, uacState, uacRec));

        // 4. Journalisation PowerShell 4104
        var (psStatus, psState, psRec) = CheckPowerShellLogging();
        checks.Add(new SecurityAuditCheckDto("VIS-PS4104", "Visibilité Système", "PowerShell Script Block Logging (Event ID 4104)", psStatus, 8, psState, psRec));

        // 5. Sysmon optionnel
        var sysmonInstalled = CheckSysmonInstalled();
        checks.Add(new SecurityAuditCheckDto(
            "VIS-SYSMON",
            "Visibilité Système",
            "Journal télémétrique Sysmon (optionnel)",
            sysmonInstalled ? "Pass" : "Warning",
            5,
            sysmonInstalled ? "Service Sysmon détecté et exploitable" : "Non installé (les collecteurs natifs ETW/WMI/Defender prennent le relais)",
            "Optionnel : installez Sysinternals Sysmon avec une configuration SwiftOnSecurity pour enrichir la télémétrie."));

        // 6. Intégrité cryptographique SHA-256 des journaux SQLite
        bool hashChainValid = true;
        string chainState;
        try
        {
            var reports = await _integrityVerifier.VerifyAllAsync(ct).ConfigureAwait(false);
            hashChainValid = reports.All(r => r.Valid);
            var totalEntries = reports.Sum(r => r.CheckedEntries);
            chainState = hashChainValid
                ? $"Chaîne SHA-256 intacte ({totalEntries} entrées vérifiées sur Events & AuditEntries)"
                : "ALERTE : rupture de chaîne SHA-256 détectée !";
        }
        catch (Exception ex)
        {
            hashChainValid = false;
            chainState = $"Erreur de vérification : {ex.Message}";
        }
        checks.Add(new SecurityAuditCheckDto(
            "INT-CHAIN",
            "Intégrité SENTINEL",
            "Chaînage cryptographique anti-altération (SHA-256)",
            hashChainValid ? "Pass" : "Critical",
            15,
            chainState,
            hashChainValid ? "Aucune action requise." : "Investiguer immédiatement toute tentative de modification directe du fichier sentinel.db."));

        // 7. Certificats PKI mTLS
        var certsPresent = Directory.Exists(SentinelPaths.Certificates) &&
                           Directory.EnumerateFiles(SentinelPaths.Certificates, "*.pfx").Any();
        checks.Add(new SecurityAuditCheckDto(
            "PKI-MTLS",
            "Intégrité SENTINEL",
            "Certificats mTLS Agent ↔ Serveur",
            certsPresent ? "Pass" : "Warning",
            8,
            certsPresent ? $"PKI présente dans {SentinelPaths.Certificates}" : "Mode local sans certificats mTLS pré-générés",
            "En déploiement de production, maintenir UseMtls=true avec certificats générés par l'installeur."));

        // 8. Moteurs Sigma & YARA
        var sigmaCount = _sigma?.EnabledRuleCount ?? 0;
        var yaraCount = _yara?.RuleCount ?? 0;
        checks.Add(new SecurityAuditCheckDto(
            "DET-RULES",
            "Moteurs de Détection",
            "Règles Sigma & YARA chargées en mémoire",
            (sigmaCount > 0 && yaraCount > 0) ? "Pass" : "Warning",
            10,
            $"{sigmaCount} règle(s) Sigma active(s), {yaraCount} règle(s) YARA active(s)",
            "Exécuter scripts/update-sigma-rules.ps1 et scripts/update-yara-rules.ps1 pour enrichir la couverture."));

        // 9. Classifieur ML PE & Threat Intel
        var mlLoaded = _mlClassifier?.GetStatus().Loaded ?? false;
        var tiStats = _threatIntel?.GetStatus();
        var tiCount = tiStats?.TotalIndicators ?? 0;
        checks.Add(new SecurityAuditCheckDto(
            "DET-INTEL-ML",
            "Moteurs de Détection",
            "Threat Intelligence locale & Classifieur ML PE",
            (tiCount > 0 || mlLoaded) ? "Pass" : "Warning",
            7,
            $"IOC en cache : {tiCount} · Modèle ML PE : {(mlLoaded ? "chargé" : "mode heuristique")}",
            "Actualiser les flux publics abuse.ch depuis l'écran Renseignement (/intel)."));

        // 10. Mode de réponse SENTINEL & IA Locale Qwen
        var settings = _pipeline.Settings;
        var llmAvail = _llm.IsAvailable;
        var activeModel = !string.IsNullOrWhiteSpace(_llm.ActiveModel) ? _llm.ActiveModel : settings.Llm.Model;
        checks.Add(new SecurityAuditCheckDto(
            "AI-QWEN",
            "IA Locale & Réponse",
            "Disponibilité de l'analyste IA local Ollama (Qwen)",
            llmAvail ? "Pass" : "Warning",
            5,
            llmAvail ? $"En ligne — modèle actif : {activeModel}" : "Hors ligne (repli déterministe actif)",
            "Démarrer Ollama localement avec qwen2.5-coder:3b pour bénéficier du scoring hybride et des diagnostics SOC IA."));

        // 11. Canaux de notification administrateur
        var notifStatus = _notifications.GetStatus();
        var anyExternal = notifStatus.GlobalEnabled && (notifStatus.EmailEnabled || notifStatus.WhatsAppEnabled || notifStatus.WebhookEnabled || notifStatus.SmsEnabled);
        checks.Add(new SecurityAuditCheckDto(
            "NOTIF-01",
            "IA Locale & Réponse",
            "Canaux d'alerte temps réel (In-App + Email/SMS/WhatsApp/Webhook)",
            notifStatus.InAppEnabled ? "Pass" : "Warning",
            5,
            $"Centre In-App : {(notifStatus.InAppEnabled ? "Actif" : "Inactif")} · Canaux externes : {(anyExternal ? "Configurés" : "Opt-in non activé")}",
            "Configurer Email SMTP, SMS, WhatsApp ou Webhook dans Paramètres (/settings) pour recevoir les alertes critiques hors console."));

        // Calcul du score global pondéré sur 100
        var totalWeight = checks.Sum(c => c.Weight);
        var earned = checks.Sum(c => c.Status switch
        {
            "Pass" => c.Weight,
            "Warning" => c.Weight * 0.55,
            _ => 0.0
        });
        var postureScore = totalWeight > 0 ? Math.Clamp((int)Math.Round(100.0 * earned / totalWeight), 0, 100) : 100;

        string? aiPlan = null;
        if (includeAiPlan)
        {
            var nonPassing = checks.Where(c => c.Status != "Pass").ToList();
            if (nonPassing.Count == 0)
            {
                aiPlan = "Posture excellente : tous les contrôles de sécurité Windows et d'intégrité SENTINEL sont conformes.";
            }
            else
            {
                var deterministicPlan = $"Score de posture {postureScore}/100 ({nonPassing.Count} point(s) d'attention sur {checks.Count} contrôles). Priorités : " +
                                        string.Join(" · ", nonPassing.Take(3).Select(c => $"{c.Title} → {c.Recommendation}"));
                try
                {
                    using var aiCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    aiCts.CancelAfter(TimeSpan.FromSeconds(14));
                    var summaryText = string.Join(" ; ", nonPassing.Select(c => $"{c.Title}: {c.CurrentState}"));
                    var aiRes = await _llm.AnalyzeIncidentAsync(
                        targetId: "security-audit",
                        title: $"Audit de posture sécurité ({postureScore}/100)",
                        score: Math.Max(30, 100 - postureScore),
                        level: nonPassing.Any(c => c.Status == "Critical") ? ThreatLevel.Critical : ThreatLevel.Moderate,
                        threatType: ThreatType.Tampering,
                        contextSummary: summaryText,
                        mitreTechniques: ["T1562"],
                        ct: aiCts.Token).ConfigureAwait(false);
                    aiPlan = $"{aiRes.ExecutiveSummary}\nPriorités : {string.Join(" · ", aiRes.ImmediateActions.Take(3))}";
                }
                catch
                {
                    aiPlan = deterministicPlan;
                }
            }
        }

        sw.Stop();
        var report = new SecurityAuditReportDto(
            AuditId: Guid.NewGuid(),
            GeneratedAt: DateTimeOffset.UtcNow,
            DurationMs: Math.Round(sw.Elapsed.TotalMilliseconds, 1),
            HostName: hostName,
            PostureScore: postureScore,
            PassedCount: checks.Count(c => c.Status == "Pass"),
            WarningCount: checks.Count(c => c.Status == "Warning"),
            CriticalCount: checks.Count(c => c.Status == "Critical"),
            HashChainValid: hashChainValid,
            AiActionPlan: aiPlan,
            Checks: checks);

        lock (_cacheGate)
        {
            _lastAudit = report;
        }

        await _auditWriter.WriteAuditAsync(
            actor,
            "SystemSecurityAuditCompleted",
            $"host:{hostName}",
            $"ScorePosture={postureScore}/100, Pass={report.PassedCount}, Warning={report.WarningCount}, Critical={report.CriticalCount}, HashChain={hashChainValid}.",
            "127.0.0.1",
            ct).ConfigureAwait(false);

        return report;
    }

    /// <summary>
    /// Exécute un scénario de démonstration inoffensif et réaliste en temps réel pour présenter SENTINEL
    /// (arbre causal dans le graphe, corrélation multi-étapes, alerte, analyse IA Qwen et notifications).
    /// </summary>
    public async Task<DemoScenarioResultDto> RunDemoScenarioAsync(
        string scenarioId,
        string actor = "Admin",
        CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var key = (scenarioId ?? string.Empty).Trim().ToLowerInvariant();

        if (key == "clear-noise")
        {
            var purged = await PurgeDuplicateNoiseAlertsAsync(actor, ct).ConfigureAwait(false);
            sw.Stop();
            return new DemoScenarioResultDto(
                ScenarioId: "clear-noise",
                Title: "Nettoyage du bruit historique (doublons AgentTampering)",
                EventsInjected: 0,
                AlertsGenerated: 0,
                PrimaryClusterId: null,
                PrimaryAlertId: null,
                Summary: $"{purged.AlertsResolved} alerte(s) redondante(s) résolue(s). Il reste {purged.RemainingOpenAlerts} alerte(s) ouverte(s).",
                ElapsedMs: Math.Round(sw.Elapsed.TotalMilliseconds, 1));
        }

        var now = DateTimeOffset.UtcNow;
        var (title, demoHost, demoUser, events) = BuildDemoEvents(key, now.AddSeconds(-8));

        var results = new List<PipelineResult>(events.Count);
        foreach (var ev in events)
        {
            var res = await _ingestion.IngestAsync(ev, ct).ConfigureAwait(false);
            results.Add(res);
            await Task.Delay(120, ct).ConfigureAwait(false);
        }

        var clusterId = results.Select(r => r.Cluster?.Id).LastOrDefault(id => id.HasValue);
        Guid? alertId = null;
        var alertsCount = 0;

        await using (var db = await _dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false))
        {
            var recentCutoff = now.AddSeconds(-15).ToUnixTimeMilliseconds();
            var matchingAlerts = await db.Alerts
                .AsNoTracking()
                .Where(a => a.HostId == demoHost && a.UpdatedAtUnixMs >= recentCutoff)
                .OrderByDescending(a => a.Score)
                .ToListAsync(ct)
                .ConfigureAwait(false);
            alertsCount = matchingAlerts.Count;
            alertId = matchingAlerts.FirstOrDefault()?.Id;
        }

        sw.Stop();
        var summary = $"Scénario « {title} » injecté en temps réel sur {demoHost} ({events.Count} événements corrélés, {alertsCount} alerte(s) générée(s)). Ouvrez le Graphe ou la cloche de notifications pour inspecter la chaîne.";

        await _auditWriter.WriteAuditAsync(
            actor,
            "DemoScenarioExecuted",
            $"demo:{key}",
            summary,
            "127.0.0.1",
            ct).ConfigureAwait(false);

        return new DemoScenarioResultDto(
            ScenarioId: key,
            Title: title,
            EventsInjected: events.Count,
            AlertsGenerated: alertsCount,
            PrimaryClusterId: clusterId,
            PrimaryAlertId: alertId,
            Summary: summary,
            ElapsedMs: Math.Round(sw.Elapsed.TotalMilliseconds, 1));
    }

    /// <summary>Résout en masse les alertes redondantes (ex. rafales historiques AgentTampering) en ne gardant que la plus récente par couple (Poste, Titre).</summary>
    public async Task<PurgeDuplicatesResultDto> PurgeDuplicateNoiseAlertsAsync(string actor = "Admin", CancellationToken ct = default)
    {
        var now = DateTimeOffset.UtcNow;
        int resolvedCount = 0;
        int remainingOpen = 0;

        await using (var db = await _dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false))
        {
            var openAlerts = await db.Alerts
                .Where(a => a.Status == AlertStatus.Open || a.Status == AlertStatus.Acknowledged)
                .OrderByDescending(a => a.UpdatedAtUnixMs)
                .ToListAsync(ct)
                .ConfigureAwait(false);

            var seenSignature = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var alert in openAlerts)
            {
                var sig = $"{alert.HostId}|{alert.ThreatType}|{alert.Title}";
                if (!seenSignature.Add(sig))
                {
                    alert.Status = AlertStatus.Resolved;
                    alert.RequiresDecision = false;
                    alert.UpdatedAt = now;
                    alert.UpdatedAtUnixMs = now.ToUnixTimeMilliseconds();
                    resolvedCount++;
                }
                else
                {
                    remainingOpen++;
                }
            }

            if (resolvedCount > 0)
            {
                await db.SaveChangesAsync(ct).ConfigureAwait(false);
            }
        }

        if (resolvedCount > 0)
        {
            await _auditWriter.WriteAuditAsync(
                actor,
                "DuplicateAlertsPurged",
                "alerts:deduplicate",
                $"{resolvedCount} alerte(s) ouverte(s) en doublon archivée(s) comme résolues ({remainingOpen} alerte(s) distincte(s) conservée(s)).",
                "127.0.0.1",
                ct).ConfigureAwait(false);
        }

        return new PurgeDuplicatesResultDto(resolvedCount, remainingOpen);
    }

    private static (string Title, string Host, string User, List<SecurityEvent> Events) BuildDemoEvents(string key, DateTimeOffset t0)
    {
        switch (key)
        {
            case "ransomware-canary":
            {
                const string host = "pc-direction-01";
                const string user = "c.mbarga";
                var list = new List<SecurityEvent>
                {
                    SecurityEvent.Create(
                        host, user, EventCategory.Process, EventTypes.ProcessStart,
                        @"C:\Users\c.mbarga\Downloads\facture_2026_urgent.exe",
                        new Dictionary<string, string>
                        {
                            [AttributeKeys.ProcessName] = "facture_2026_urgent.exe",
                            [AttributeKeys.ProcessPath] = @"C:\Users\c.mbarga\Downloads\facture_2026_urgent.exe",
                            [AttributeKeys.ParentProcessName] = "explorer.exe",
                            [AttributeKeys.Signed] = "false",
                            [AttributeKeys.DoubleExtension] = "true"
                        },
                        "demo:ransomware",
                        t0),
                    SecurityEvent.Create(
                        host, user, EventCategory.Canary, EventTypes.CanaryModified,
                        @"C:\Users\c.mbarga\Documents\~Budget_Previsionnel_2026.xlsx",
                        new Dictionary<string, string>
                        {
                            [AttributeKeys.FilePath] = @"C:\Users\c.mbarga\Documents\~Budget_Previsionnel_2026.xlsx",
                            [AttributeKeys.ProcessName] = "facture_2026_urgent.exe",
                            [AttributeKeys.ProcessPath] = @"C:\Users\c.mbarga\Downloads\facture_2026_urgent.exe",
                            [AttributeKeys.Entropy] = "7.96"
                        },
                        "demo:ransomware",
                        t0.AddSeconds(2)),
                    SecurityEvent.Create(
                        host, user, EventCategory.File, EventTypes.FileBurst,
                        @"C:\Users\c.mbarga\Documents\*.locked",
                        new Dictionary<string, string>
                        {
                            [AttributeKeys.FilePath] = @"C:\Users\c.mbarga\Documents\Contrat_Client.pdf.locked",
                            [AttributeKeys.ProcessName] = "facture_2026_urgent.exe",
                            [AttributeKeys.Entropy] = "7.98",
                            ["file.rate_per_min"] = "85"
                        },
                        "demo:ransomware",
                        t0.AddSeconds(4))
                };
                return ("Attaque Rançongiciel stoppée par Fichier Canari", host, user, list);
            }

            case "badusb-intrusion":
            {
                const string host = "pc-accueil-02";
                const string user = "j.nkono";
                var list = new List<SecurityEvent>
                {
                    SecurityEvent.Create(
                        host, user, EventCategory.Device, EventTypes.UsbInserted,
                        @"USB\VID_16C0&PID_0486 (Composite HID Keyboard)",
                        new Dictionary<string, string>
                        {
                            [AttributeKeys.DeviceId] = @"USB\VID_16C0&PID_0486",
                            [AttributeKeys.DeviceName] = "Teensy USB Composite HID",
                            [AttributeKeys.DeviceClass] = "HID"
                        },
                        "demo:badusb",
                        t0),
                    SecurityEvent.Create(
                        host, user, EventCategory.Typing, EventTypes.TypingStats,
                        "Cadence HID injectée : 68 touches/s (intervalle 11 ms)",
                        new Dictionary<string, string>
                        {
                            [AttributeKeys.KeysPerSecond] = "68.5",
                            ["typing.mean_interval_ms"] = "11.2",
                            ["typing.stddev_ms"] = "0.8",
                            ["typing.injected"] = "true"
                        },
                        "demo:badusb",
                        t0.AddSeconds(2)),
                    SecurityEvent.Create(
                        host, user, EventCategory.Installation, EventTypes.StartupEntryAdded,
                        @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WinUpdater",
                        new Dictionary<string, string>
                        {
                            [AttributeKeys.ProcessName] = "powershell.exe",
                            [AttributeKeys.CommandLine] = "powershell.exe -w hidden -ep bypass -enc SQBFAFgA",
                            [AttributeKeys.RegistryKey] = @"HKCU\Run",
                            [AttributeKeys.RegistryValue] = "WinUpdater"
                        },
                        "demo:badusb",
                        t0.AddSeconds(4))
                };
                return ("Intrusion physique BadUSB & Persistance Registre", host, user, list);
            }

            case "phishing-chain":
            default:
            {
                const string host = "pc-compta-01";
                const string user = "a.kamga";
                var list = new List<SecurityEvent>
                {
                    SecurityEvent.Create(
                        host, user, EventCategory.Clipboard, EventTypes.ClipboardUrl,
                        "https://bit.ly/portail-paie-verification",
                        new Dictionary<string, string>
                        {
                            [AttributeKeys.Domain] = "portail-paie-secure-login.top",
                            [AttributeKeys.Url] = "https://portail-paie-secure-login.top/auth",
                            ["url.shortener"] = "true"
                        },
                        "demo:phishing",
                        t0),
                    SecurityEvent.Create(
                        host, user, EventCategory.Browser, EventTypes.DownloadStarted,
                        @"C:\Users\a.kamga\Downloads\Bulletin_Paie_Nov.pdf.exe",
                        new Dictionary<string, string>
                        {
                            [AttributeKeys.Domain] = "portail-paie-secure-login.top",
                            [AttributeKeys.FilePath] = @"C:\Users\a.kamga\Downloads\Bulletin_Paie_Nov.pdf.exe",
                            [AttributeKeys.DoubleExtension] = "true"
                        },
                        "demo:phishing",
                        t0.AddSeconds(2)),
                    SecurityEvent.Create(
                        host, user, EventCategory.Process, EventTypes.ProcessStart,
                        "powershell.exe -NoP -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
                        new Dictionary<string, string>
                        {
                            [AttributeKeys.ProcessName] = "powershell.exe",
                            [AttributeKeys.ProcessPath] = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                            [AttributeKeys.ParentProcessName] = "Bulletin_Paie_Nov.pdf.exe",
                            [AttributeKeys.ParentProcessPath] = @"C:\Users\a.kamga\Downloads\Bulletin_Paie_Nov.pdf.exe",
                            [AttributeKeys.CommandLine] = "powershell.exe -NoP -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"
                        },
                        "demo:phishing",
                        t0.AddSeconds(4)),
                    SecurityEvent.Create(
                        host, user, EventCategory.Network, EventTypes.NetworkConnection,
                        "185.220.101.45:4444",
                        new Dictionary<string, string>
                        {
                            [AttributeKeys.ProcessName] = "powershell.exe",
                            [AttributeKeys.RemoteIp] = "185.220.101.45",
                            [AttributeKeys.RemotePort] = "4444",
                            [AttributeKeys.Domain] = "c2-update-telemetry.xyz"
                        },
                        "demo:phishing",
                        t0.AddSeconds(6))
                };
                return ("Chaîne d'attaque Phishing → PowerShell encodé → C2", host, user, list);
            }
        }
    }

    private static (string Status, string CurrentState, string Recommendation) CheckDefenderPosture()
    {
        if (!OperatingSystem.IsWindows())
            return ("Warning", "Environnement non-Windows", "Vérifier l'antivirus système.");

        try
        {
            using var svc = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\WinDefend");
            using var rt = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection");
            var disabled = rt?.GetValue("DisableRealtimeMonitoring") is int d && d == 1;

            if (svc is null)
                return ("Warning", "Service WinDefend absent (solution tierce probable)", "Vérifier qu'un moteur antivirus actif protège le poste.");
            if (disabled)
                return ("Critical", "Protection temps réel Microsoft Defender DÉSACTIVÉE", "Réactiver immédiatement la protection en temps réel dans Sécurité Windows.");
            return ("Pass", "Service WinDefend présent et protection temps réel active", "Conserver la protection contre les falsifications activée.");
        }
        catch
        {
            return ("Pass", "Service Microsoft Defender détecté", "Aucune action requise.");
        }
    }

    private static (string Status, string CurrentState, string Recommendation) CheckFirewallPosture()
    {
        if (!OperatingSystem.IsWindows())
            return ("Warning", "Non vérifiable hors Windows", "Activer le pare-feu hôte.");

        try
        {
            string[] profiles =
            [
                @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile",
                @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
                @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile"
            ];

            var enabledCount = 0;
            foreach (var p in profiles)
            {
                using var k = Registry.LocalMachine.OpenSubKey(p);
                var val = k?.GetValue("EnableFirewall");
                if (val is null || (val is int i && i != 0)) enabledCount++;
            }

            return enabledCount == 3
                ? ("Pass", "3/3 profils pare-feu actifs (Domaine, Privé, Public)", "Aucune action requise.")
                : ("Warning", $"{enabledCount}/3 profils pare-feu actifs", "Activer tous les profils du pare-feu Windows Defender (netsh advfirewall set allprofiles state on).");
        }
        catch
        {
            return ("Pass", "Pare-feu Windows géré par le système", "Aucune action requise.");
        }
    }

    private static (string Status, string CurrentState, string Recommendation) CheckUacPosture()
    {
        if (!OperatingSystem.IsWindows())
            return ("Pass", "N/A", "Aucune action requise.");

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
            var lua = key?.GetValue("EnableLUA");
            if (lua is int i && i == 0)
                return ("Critical", "UAC (EnableLUA) désactivé", "Réactiver UAC pour bloquer les élévations silencieuses de privilèges.");
            return ("Pass", "Contrôle UAC (EnableLUA=1) actif", "Aucune action requise.");
        }
        catch
        {
            return ("Pass", "UAC standard actif", "Aucune action requise.");
        }
    }

    private static (string Status, string CurrentState, string Recommendation) CheckPowerShellLogging()
    {
        if (!OperatingSystem.IsWindows())
            return ("Warning", "N/A", "Aucune action requise.");

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging");
            var enabled = key?.GetValue("EnableScriptBlockLogging") is int i && i == 1;
            return enabled
                ? ("Pass", "ScriptBlockLogging (Event 4104) explicitement activé par stratégie", "Aucune action requise.")
                : ("Warning", "ScriptBlockLogging en mode automatique Windows par défaut (blocs suspects uniquement)", "Exécuter scripts/enable-script-logging.ps1 en Administrateur pour une visibilité complète.");
        }
        catch
        {
            return ("Warning", "Stratégie ScriptBlockLogging par défaut", "Exécuter scripts/enable-script-logging.ps1 en Administrateur.");
        }
    }

    private static bool CheckSysmonInstalled()
    {
        if (!OperatingSystem.IsWindows()) return false;
        try
        {
            using var s64 = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Sysmon64");
            using var s32 = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Sysmon");
            return s64 is not null || s32 is not null;
        }
        catch
        {
            return false;
        }
    }

    private static string Truncate(string? s, int max) =>
        string.IsNullOrEmpty(s) ? string.Empty : (s.Length <= max ? s : s[..(max - 1)] + "…");
}
