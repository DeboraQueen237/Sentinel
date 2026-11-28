using System.Diagnostics;
using System.IO.Compression;
using System.Net.Http;
using System.Reflection;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;
using Sentinel.AI;
using Sentinel.Shared.Infrastructure;
using Sentinel.Shared.Json;
using Sentinel.Shared.Models;
using Sentinel.Shared.Security;

namespace Sentinel.Installer;

/// <summary>Consentement explicite signé et horodaté conformément au §2.3 de la documentation.</summary>
public sealed record ConsentRecord(
    DateTimeOffset AcceptedAtUtc,
    string AcceptedByUser,
    string MachineName,
    string Version,
    IReadOnlyList<string> MonitoredChannels,
    IReadOnlyList<string> ExplicitExclusions,
    string SignatureSha256);

/// <summary>Diagnostic pré-installation de l'environnement Windows (Defender, Sysmon, Ollama, RAM).</summary>
public sealed record EnvironmentDiagnostic(
    double TotalRamGb,
    bool DefenderRealtimeActive,
    string DefenderStatus,
    bool SysmonInstalled,
    bool OllamaReachable,
    IReadOnlyList<string> OllamaModels,
    string RecommendedOllamaModel,
    string? SelectedOllamaModel = null,
    string? OllamaSelectionReason = null);

public sealed record InstallOptions(
    string InstallDirectory,
    bool GenerateCertificates,
    bool InstallServices,
    bool InstallServerService,
    bool RegisterBrowserNativeHost,
    string BrowserExtensionId,
    bool RegisterTrayAutoStart,
    bool InstallAdminService = false,
    bool StartAfterInstall = false,
    string? SourceDirectory = null,
    bool EnableCanaries = true,
    bool ConfigureFirewall = true,
    bool CreateDashboardShortcut = true);

/// <summary>
/// Moteur d'installation et de désinstallation SENTINEL v2 réutilisé par l'assistant graphique WinForms
/// et par le mode ligne de commande (CLI).
/// </summary>
public static class InstallerCore
{
    public const string ProductVersion = "2.2.0";
    public const string NativeHostName = "com.sentinel.browserhost";
    public const string EmbeddedPayloadResourceName = "Sentinel.Installer.payload.zip";

    public static readonly IReadOnlyList<string> ClosedChannelList =
    [
        "Processus : lancement, arrêt, chemin, hash SHA-256, parent, signature Authenticode (sans contenu mémoire).",
        "Réseau : connexions actives, IP/port/domaine résolu, volumes émis/reçus (sans contenu des paquets).",
        "Presse-papiers : détection en mémoire d'URLs ou motifs de commande (seuls type, domaine et hash SHA-256 sont conservés).",
        "Fichiers & Canaris : création/modification/renommage dans les dossiers surveillés et fichiers leurres anti-ransomware (sans lecture du contenu des documents).",
        "Microsoft Defender & Sysmon optionnel : détections Defender, affaiblissement de la protection, journal Sysmon s'il est déjà installé (Sysmon jamais embarqué).",
        "Visibilité scripts PowerShell 4104 : métadonnées, hash SHA-256 et indicateurs d'obfuscation (extrait tronqué avec caviardage désactivé par défaut).",
        "Analyse statique YARA / PE / ML & Threat Intel locale : métadonnées PE, correspondances règles locales et indicateurs publics (hors-ligne).",
        "Sessions, Périphériques USB, Navigation (extension) et Statistiques de cadence de saisie (JAMAIS les touches frappées)."
    ];

    public static readonly IReadOnlyList<string> ExplicitExclusions =
    [
        "Aucun enregistrement des touches frappées (aucun keylogger).",
        "Aucun stockage du texte brut du presse-papiers ni des mots de passe.",
        "Aucune lecture ni conservation du contenu des documents utilisateur.",
        "Aucun accès au contenu des messageries chiffrées (WhatsApp, Signal, Teams, etc.).",
        "Aucun transfert de données utilisateur vers le cloud : analyse, ML et IA locale (Ollama/Qwen) 100 % locaux ; les notifications administrateur externes (Email, WhatsApp, Webhook) sont strictement opt-in et n'envoient que des métadonnées d'alerte.",
        "Aucune suppression définitive automatique : toute action automatique est réversible en un clic."
    ];

    public static bool IsElevated()
    {
        if (!OperatingSystem.IsWindows()) return false;
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    public static bool HasBundledPayload()
    {
        var asm = Assembly.GetExecutingAssembly();
        if (asm.GetManifestResourceInfo(EmbeddedPayloadResourceName) is not null)
            return true;

        var baseDir = AppContext.BaseDirectory;
        return File.Exists(Path.Combine(baseDir, "payload.zip"))
               || Directory.Exists(Path.Combine(baseDir, "payload"));
    }

    /// <summary>
    /// Analyse l'environnement local avant installation : RAM, Microsoft Defender, Sysmon (optionnel) et Ollama local.
    /// Ne télécharge jamais aucun modèle ni composant externe sans action explicite de l'utilisateur.
    /// </summary>
    public static EnvironmentDiagnostic DetectEnvironment()
    {
        var ramGb = OllamaModelSelector.GetHostRamGb();
        var recommendedModel = OllamaModelSelector.RecommendQwenForRam(ramGb);

        // 1. Microsoft Defender
        var defenderActive = false;
        var defenderStatus = "Statut inconnu";
        try
        {
            using var rtKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection");
            var disabled = rtKey?.GetValue("DisableRealtimeMonitoring");
            var isDisabled = disabled is int i && i == 1;

            using var svcKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\WinDefend");
            var svcExists = svcKey is not null;

            defenderActive = svcExists && !isDisabled;
            defenderStatus = !svcExists
                ? "Service WinDefend introuvable — vérifiez votre antivirus"
                : isDisabled
                    ? "ATTENTION : protection temps réel désactivée !"
                    : "Actif (protection temps réel détectée)";
        }
        catch
        {
            defenderStatus = "Vérification impossible sans privilèges complets";
        }

        // 2. Sysmon optionnel (jamais embarqué)
        var sysmonInstalled = false;
        try
        {
            using var s64 = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Sysmon64");
            using var s32 = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Sysmon");
            sysmonInstalled = s64 is not null || s32 is not null;
        }
        catch { /* ignoré */ }

        // 3. Ollama local (http://localhost:11434/api/tags — sélection intelligente du meilleur Qwen local)
        var ollamaReachable = false;
        IReadOnlyList<OllamaInstalledModel> parsedModels = Array.Empty<OllamaInstalledModel>();
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(2) };
            var resp = http.GetAsync("http://localhost:11434/api/tags").GetAwaiter().GetResult();
            if (resp.IsSuccessStatusCode)
            {
                ollamaReachable = true;
                var json = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                using var doc = JsonDocument.Parse(json);
                parsedModels = OllamaModelSelector.ParseTagsResponse(doc.RootElement);
            }
        }
        catch { /* Ollama optionnel */ }

        var models = parsedModels.Select(m => m.Name).ToArray();
        string? selectedModel = null;
        string? selectionReason = null;

        if (parsedModels.Count > 0)
        {
            var selection = OllamaModelSelector.SelectBestModel(parsedModels, recommendedModel, autoSelectBestQwen: true, ramGb);
            selectedModel = selection.SelectedModel;
            selectionReason = selection.Reason;
            if (!string.IsNullOrWhiteSpace(selectedModel))
            {
                recommendedModel = selectedModel;
            }
        }

        return new EnvironmentDiagnostic(
            ramGb,
            defenderActive,
            defenderStatus,
            sysmonInstalled,
            ollamaReachable,
            models,
            recommendedModel,
            selectedModel,
            selectionReason);
    }

    public static ConsentRecord WriteSignedConsent(Action<string>? log = null)
    {
        var now = DateTimeOffset.UtcNow;
        var user = $"{Environment.UserDomainName}\\{Environment.UserName}";
        var machine = Environment.MachineName;

        var payload = $"{now:O}|{user}|{machine}|{ProductVersion}|{string.Join(";", ClosedChannelList)}";
        var signature = HashChain.Sha256Hex(payload);

        var record = new ConsentRecord(
            now, user, machine, ProductVersion, ClosedChannelList, ExplicitExclusions, signature);

        File.WriteAllText(SentinelPaths.ConsentFile, SentinelJson.Serialize(record), new UTF8Encoding(false));
        log?.Invoke($"Consentement signé enregistré dans {SentinelPaths.ConsentFile}.");
        return record;
    }

    public static void Install(InstallOptions opts, Action<string>? log = null)
    {
        Directory.CreateDirectory(opts.InstallDirectory);
        log?.Invoke($"Répertoire d'installation préparé : {opts.InstallDirectory}");

        var diag = DetectEnvironment();
        log?.Invoke($"Diagnostic poste : RAM={diag.TotalRamGb:F1} Go | Defender={diag.DefenderStatus} | Sysmon={(diag.SysmonInstalled ? "Installé" : "Absent (optionnel)")} | Ollama={(diag.OllamaReachable ? string.Join(", ", diag.OllamaModels) : "Hors ligne")}");
        if (!diag.DefenderRealtimeActive)
        {
            log?.Invoke("AVERTISSEMENT : Microsoft Defender semble inactif. SENTINEL complète Defender mais ne le remplace pas.");
        }

        WriteSignedConsent(log);

        var deployedFiles = DeployBinaries(opts, log);
        if (deployedFiles > 0)
        {
            log?.Invoke($"{deployedFiles} fichier(s) applicatif(s) déployé(s) dans {opts.InstallDirectory}.");
        }

        DeployDefaultRules(opts.InstallDirectory, log);
        CopySelfForUninstall(opts.InstallDirectory, log);

        if (opts.GenerateCertificates)
        {
            SentinelPki.EnsureCertificates();
            log?.Invoke($"Certificats PKI mTLS générés dans {SentinelPaths.Certificates}.");
        }

        var acl = DirectorySecurityHardener.HardenDirectory(SentinelPaths.Root);
        log?.Invoke($"Durcissement ACL NTFS ({SentinelPaths.Root}) : {acl.Message}");

        GenerateIntegrityManifest(opts.InstallDirectory, log);

        if (opts.ConfigureFirewall)
        {
            ConfigureLocalFirewallRules(log);
        }

        if (opts.InstallServices)
        {
            if (opts.InstallServerService)
            {
                InstallWindowsService(
                    SentinelEndpoints.ServerServiceName,
                    "SENTINEL — Serveur d'analyse et corrélation",
                    Path.Combine(opts.InstallDirectory, "Sentinel.Server.exe"),
                    log);
            }

            if (opts.InstallAdminService)
            {
                InstallWindowsService(
                    SentinelEndpoints.AdminServiceName,
                    "SENTINEL — Console d'administration Blazor",
                    Path.Combine(opts.InstallDirectory, "Sentinel.Admin.exe"),
                    log);
            }

            InstallWindowsService(
                SentinelEndpoints.AgentServiceName,
                "SENTINEL — Agent de détection et réponse",
                Path.Combine(opts.InstallDirectory, "Sentinel.Agent.exe"),
                log);

            InstallWindowsService(
                SentinelEndpoints.WatchdogServiceName,
                "SENTINEL — Watchdog d'auto-protection",
                Path.Combine(opts.InstallDirectory, "Sentinel.Watchdog.exe"),
                log);
        }

        if (opts.RegisterBrowserNativeHost)
        {
            RegisterNativeMessagingHost(opts.InstallDirectory, opts.BrowserExtensionId, log);
        }

        if (opts.RegisterTrayAutoStart)
        {
            RegisterTrayAutoStart(opts.InstallDirectory, log);
        }

        if (opts.CreateDashboardShortcut)
        {
            CreateStartMenuDashboardShortcut(log);
        }

        RegisterUninstallEntry(opts.InstallDirectory, log);

        log?.Invoke($"Mode initial par défaut : Learning (7 jours), Canaris={(opts.EnableCanaries ? "activés" : "désactivés")}.");

        if (opts.StartAfterInstall)
        {
            StartInstalledComponents(opts, log);
        }

        log?.Invoke($"Installation SENTINEL v{ProductVersion} terminée avec succès.");
    }

    private static void DeployDefaultRules(string installDir, Action<string>? log)
    {
        var candidates = new[]
        {
            Path.Combine(installDir, "rules"),
            Path.Combine(AppContext.BaseDirectory, "rules")
        };

        var rulesRoot = candidates.FirstOrDefault(Directory.Exists);
        if (rulesRoot is null)
            return;

        var sigmaSrc = Path.Combine(rulesRoot, "sigma");
        if (Directory.Exists(sigmaSrc))
        {
            var count = CopyDirectoryRecursive(sigmaSrc, SentinelPaths.SigmaRules);
            log?.Invoke($"{count} règle(s) Sigma déployée(s) dans {SentinelPaths.SigmaRules}.");
        }

        var yaraSrc = Path.Combine(rulesRoot, "yara");
        if (Directory.Exists(yaraSrc))
        {
            var count = CopyDirectoryRecursive(yaraSrc, SentinelPaths.YaraRules);
            log?.Invoke($"{count} règle(s) YARA déployée(s) dans {SentinelPaths.YaraRules}.");
        }
    }

    private static void ConfigureLocalFirewallRules(Action<string>? log)
    {
        if (!IsElevated())
        {
            log?.Invoke("Règles pare-feu ignorées (élévation Administrateur requise).");
            return;
        }

        RunNetsh(["advfirewall", "firewall", "delete", "rule", "name=\"Sentinel-API-Loopback\""], log);
        RunNetsh(["advfirewall", "firewall", "add", "rule", "name=\"Sentinel-API-Loopback\"", "dir=in", "action=allow", "protocol=TCP", "localport=5180,5200", "remoteip=127.0.0.1"], log);

        RunNetsh(["advfirewall", "firewall", "delete", "rule", "name=\"Sentinel-gRPC-Local\""], log);
        RunNetsh(["advfirewall", "firewall", "add", "rule", "name=\"Sentinel-gRPC-Local\"", "dir=in", "action=allow", "protocol=TCP", "localport=5181", "remoteip=127.0.0.1"], log);

        log?.Invoke("Règles pare-feu Windows configurées (boucle locale 5180/5200 et gRPC 5181).");
    }

    private static void CreateStartMenuDashboardShortcut(Action<string>? log)
    {
        try
        {
            var programs = IsElevated()
                ? Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms)
                : Environment.GetFolderPath(Environment.SpecialFolder.Programs);
            var folder = Path.Combine(programs, "SENTINEL");
            Directory.CreateDirectory(folder);
            var urlFile = Path.Combine(folder, "SENTINEL Dashboard.url");
            File.WriteAllText(urlFile, $"[InternetShortcut]\r\nURL={SentinelEndpoints.AdminUrl}\r\n", Encoding.ASCII);
            log?.Invoke($"Raccourci Menu Démarrer créé : {urlFile}");
        }
        catch (Exception ex)
        {
            log?.Invoke($"Avertissement création raccourci dashboard : {ex.Message}");
        }
    }

    private static int DeployBinaries(InstallOptions opts, Action<string>? log)
    {
        if (!string.IsNullOrWhiteSpace(opts.SourceDirectory) && Directory.Exists(opts.SourceDirectory))
        {
            log?.Invoke($"Copie des binaires depuis {opts.SourceDirectory}…");
            return CopyDirectoryRecursive(opts.SourceDirectory, opts.InstallDirectory);
        }

        var asm = Assembly.GetExecutingAssembly();
        using (var resourceStream = asm.GetManifestResourceStream(EmbeddedPayloadResourceName))
        {
            if (resourceStream is not null)
            {
                log?.Invoke("Extraction du package intégré SENTINEL…");
                return ExtractZipStream(resourceStream, opts.InstallDirectory);
            }
        }

        var siblingZip = Path.Combine(AppContext.BaseDirectory, "payload.zip");
        if (File.Exists(siblingZip))
        {
            log?.Invoke($"Extraction de l'archive {siblingZip}…");
            using var fs = File.OpenRead(siblingZip);
            return ExtractZipStream(fs, opts.InstallDirectory);
        }

        var siblingDir = Path.Combine(AppContext.BaseDirectory, "payload");
        if (Directory.Exists(siblingDir))
        {
            log?.Invoke($"Copie des binaires depuis {siblingDir}…");
            return CopyDirectoryRecursive(siblingDir, opts.InstallDirectory);
        }

        log?.Invoke("Aucun package binaire groupé détecté : seuls le consentement, la PKI et les entrées système sont configurés.");
        return 0;
    }

    private static int ExtractZipStream(Stream stream, string targetDir)
    {
        using var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
        var count = 0;
        var fullTarget = Path.GetFullPath(targetDir);
        if (!fullTarget.EndsWith(Path.DirectorySeparatorChar))
            fullTarget += Path.DirectorySeparatorChar;

        foreach (var entry in archive.Entries)
        {
            var destPath = Path.GetFullPath(Path.Combine(fullTarget, entry.FullName));
            if (!destPath.StartsWith(fullTarget, StringComparison.OrdinalIgnoreCase))
                continue;

            if (string.IsNullOrEmpty(entry.Name))
            {
                Directory.CreateDirectory(destPath);
                continue;
            }

            Directory.CreateDirectory(Path.GetDirectoryName(destPath)!);
            entry.ExtractToFile(destPath, overwrite: true);
            count++;
        }

        return count;
    }

    private static int CopyDirectoryRecursive(string sourceDir, string destDir)
    {
        var count = 0;
        var srcFull = Path.GetFullPath(sourceDir).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var dstFull = Path.GetFullPath(destDir).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (string.Equals(srcFull, dstFull, StringComparison.OrdinalIgnoreCase))
            return 0;

        Directory.CreateDirectory(dstFull);

        foreach (var dir in Directory.EnumerateDirectories(srcFull, "*", SearchOption.AllDirectories))
        {
            var rel = Path.GetRelativePath(srcFull, dir);
            Directory.CreateDirectory(Path.Combine(dstFull, rel));
        }

        foreach (var file in Directory.EnumerateFiles(srcFull, "*", SearchOption.AllDirectories))
        {
            var rel = Path.GetRelativePath(srcFull, file);
            var target = Path.Combine(dstFull, rel);
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(file, target, overwrite: true);
            count++;
        }

        return count;
    }

    private static void CopySelfForUninstall(string installDir, Action<string>? log)
    {
        try
        {
            var currentExe = Environment.ProcessPath;
            if (string.IsNullOrWhiteSpace(currentExe) || !File.Exists(currentExe))
                return;

            var targetExe = Path.Combine(installDir, "Sentinel.Installer.exe");
            if (!string.Equals(Path.GetFullPath(currentExe), Path.GetFullPath(targetExe), StringComparison.OrdinalIgnoreCase))
            {
                File.Copy(currentExe, targetExe, overwrite: true);
                var baseName = Path.GetFileNameWithoutExtension(currentExe);
                var sourceDir = Path.GetDirectoryName(currentExe)!;
                foreach (var ext in new[] { ".dll", ".deps.json", ".runtimeconfig.json" })
                {
                    var sidecar = Path.Combine(sourceDir, baseName + ext);
                    if (File.Exists(sidecar))
                        File.Copy(sidecar, Path.Combine(installDir, "Sentinel.Installer" + ext), overwrite: true);
                }
            }
        }
        catch (Exception ex)
        {
            log?.Invoke($"Avertissement copie désinstalleur : {ex.Message}");
        }
    }

    public static void GenerateIntegrityManifest(string installDir, Action<string>? log = null)
    {
        var hashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (Directory.Exists(installDir))
        {
            foreach (var file in Directory.EnumerateFiles(installDir, "Sentinel.*", SearchOption.TopDirectoryOnly))
            {
                var ext = Path.GetExtension(file);
                if (!ext.Equals(".exe", StringComparison.OrdinalIgnoreCase) &&
                    !ext.Equals(".dll", StringComparison.OrdinalIgnoreCase))
                    continue;

                try { hashes[Path.GetFileName(file)] = HashChain.Sha256File(file); }
                catch { /* Ignoré si verrouillé */ }
            }
        }

        var manifest = new
        {
            generatedAtUtc = DateTimeOffset.UtcNow,
            version = ProductVersion,
            installDirectory = installDir,
            fileHashes = hashes
        };

        var manifestPath = Path.Combine(SentinelPaths.Data, "integrity-manifest.json");
        File.WriteAllText(manifestPath, SentinelJson.Serialize(manifest), new UTF8Encoding(false));
        log?.Invoke($"Manifeste d'intégrité SHA-256 généré ({hashes.Count} binaire(s)) : {manifestPath}.");
    }

    public static void RegisterNativeMessagingHost(string installDir, string extensionId, Action<string>? log = null)
    {
        var hostExe = Path.Combine(installDir, "Sentinel.BrowserHost.exe");
        var manifestFile = Path.Combine(installDir, NativeHostName + ".json");
        var cleanExtId = string.IsNullOrWhiteSpace(extensionId) ? "REPLACE_WITH_SENTINEL_EXTENSION_ID" : extensionId.Trim();

        var manifestObj = new
        {
            name = NativeHostName,
            description = "Hôte Native Messaging SENTINEL reliant l'extension navigateur à Sentinel.Agent.",
            path = hostExe,
            type = "stdio",
            allowed_origins = new[] { $"chrome-extension://{cleanExtId}/" }
        };

        File.WriteAllText(manifestFile, SentinelJson.Serialize(manifestObj), new UTF8Encoding(false));

        string[] regPaths =
        [
            $@"SOFTWARE\Google\Chrome\NativeMessagingHosts\{NativeHostName}",
            $@"SOFTWARE\Microsoft\Edge\NativeMessagingHosts\{NativeHostName}"
        ];

        foreach (var path in regPaths)
        {
            try
            {
                using var key = Registry.CurrentUser.CreateSubKey(path);
                key?.SetValue(null, manifestFile, RegistryValueKind.String);
                log?.Invoke($"Native Messaging enregistré : HKCU\\{path}");
            }
            catch (Exception ex)
            {
                log?.Invoke($"Avertissement registre HKCU\\{path} : {ex.Message}");
            }

            try
            {
                using var lmKey = Registry.LocalMachine.CreateSubKey(path);
                lmKey?.SetValue(null, manifestFile, RegistryValueKind.String);
                log?.Invoke($"Native Messaging enregistré : HKLM\\{path}");
            }
            catch { /* HKLM exige élévation */ }
        }
    }

    public static void RegisterTrayAutoStart(string installDir, Action<string>? log = null)
    {
        var trayExe = Path.Combine(installDir, "Sentinel.Tray.exe");
        try
        {
            using var runKey = Registry.CurrentUser.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run");
            runKey?.SetValue("SentinelTray", $"\"{trayExe}\"", RegistryValueKind.String);
            log?.Invoke($"Démarrage automatique configuré pour Sentinel.Tray ({trayExe}).");
        }
        catch (Exception ex)
        {
            log?.Invoke($"Impossible d'enregistrer le démarrage auto de Sentinel.Tray : {ex.Message}");
        }
    }

    private static void RegisterUninstallEntry(string installDir, Action<string>? log)
    {
        const string uninstallKeyPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Sentinel";
        var uninstallerExe = Path.Combine(installDir, "Sentinel.Installer.exe");

        foreach (var root in new[] { Registry.LocalMachine, Registry.CurrentUser })
        {
            try
            {
                using var key = root.CreateSubKey(uninstallKeyPath);
                if (key is null) continue;

                key.SetValue("DisplayName", $"SENTINEL EDR ({ProductVersion})", RegistryValueKind.String);
                key.SetValue("DisplayVersion", ProductVersion, RegistryValueKind.String);
                key.SetValue("Publisher", "Sentinel Contributors", RegistryValueKind.String);
                key.SetValue("InstallLocation", installDir, RegistryValueKind.String);
                key.SetValue("UninstallString", $"\"{uninstallerExe}\" --uninstall", RegistryValueKind.String);
                key.SetValue("NoModify", 1, RegistryValueKind.DWord);
                key.SetValue("NoRepair", 1, RegistryValueKind.DWord);
                log?.Invoke($"Entrée Ajout/Suppression de programmes enregistrée ({root.Name}\\{uninstallKeyPath}).");
                return;
            }
            catch { /* repli HKCU */ }
        }
    }

    private static void StartInstalledComponents(InstallOptions opts, Action<string>? log)
    {
        if (opts.InstallServices)
        {
            if (opts.InstallServerService) RunSc(["start", SentinelEndpoints.ServerServiceName], log);
            if (opts.InstallAdminService) RunSc(["start", SentinelEndpoints.AdminServiceName], log);
            RunSc(["start", SentinelEndpoints.AgentServiceName], log);
            RunSc(["start", SentinelEndpoints.WatchdogServiceName], log);
        }

        if (opts.RegisterTrayAutoStart)
        {
            var trayExe = Path.Combine(opts.InstallDirectory, "Sentinel.Tray.exe");
            if (File.Exists(trayExe))
            {
                try
                {
                    Process.Start(new ProcessStartInfo(trayExe) { UseShellExecute = true });
                    log?.Invoke("Sentinel.Tray démarré dans la session utilisateur.");
                }
                catch (Exception ex)
                {
                    log?.Invoke($"Impossible de démarrer Sentinel.Tray : {ex.Message}");
                }
            }
        }
    }

    public static void Uninstall(Action<string>? log = null, bool deleteData = false)
    {
        foreach (var svc in new[]
        {
            SentinelEndpoints.WatchdogServiceName,
            SentinelEndpoints.AgentServiceName,
            SentinelEndpoints.AdminServiceName,
            SentinelEndpoints.ServerServiceName
        })
        {
            RunSc(["stop", svc], log);
            RunSc(["delete", svc], log);
        }

        if (IsElevated())
        {
            RunNetsh(["advfirewall", "firewall", "delete", "rule", "name=\"Sentinel-API-Loopback\""], log);
            RunNetsh(["advfirewall", "firewall", "delete", "rule", "name=\"Sentinel-gRPC-Local\""], log);
        }

        try
        {
            using var runKey = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", writable: true);
            runKey?.DeleteValue("SentinelTray", throwOnMissingValue: false);
            log?.Invoke("Entrée de démarrage automatique SentinelTray retirée.");
        }
        catch (Exception ex)
        {
            log?.Invoke($"Avertissement retrait démarrage auto : {ex.Message}");
        }

        foreach (var sp in new[] { Environment.SpecialFolder.CommonPrograms, Environment.SpecialFolder.Programs })
        {
            try
            {
                var dir = Path.Combine(Environment.GetFolderPath(sp), "SENTINEL");
                if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true);
            }
            catch { /* ignoré */ }
        }

        string[] regPaths =
        [
            $@"SOFTWARE\Google\Chrome\NativeMessagingHosts\{NativeHostName}",
            $@"SOFTWARE\Microsoft\Edge\NativeMessagingHosts\{NativeHostName}"
        ];

        foreach (var path in regPaths)
        {
            try { Registry.CurrentUser.DeleteSubKeyTree(path, throwOnMissingSubKey: false); } catch { /* ignoré */ }
            try { Registry.LocalMachine.DeleteSubKeyTree(path, throwOnMissingSubKey: false); } catch { /* ignoré */ }
        }

        const string uninstallKeyPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Sentinel";
        try { Registry.LocalMachine.DeleteSubKeyTree(uninstallKeyPath, throwOnMissingSubKey: false); } catch { /* ignoré */ }
        try { Registry.CurrentUser.DeleteSubKeyTree(uninstallKeyPath, throwOnMissingSubKey: false); } catch { /* ignoré */ }

        if (deleteData)
        {
            try
            {
                var dataRoot = SentinelPaths.Root;
                if (Directory.Exists(dataRoot))
                {
                    Directory.Delete(dataRoot, recursive: true);
                    log?.Invoke($"Données locales supprimées : {dataRoot}");
                }
            }
            catch (Exception ex)
            {
                log?.Invoke($"Avertissement suppression des données : {ex.Message}");
            }
        }
        else
        {
            log?.Invoke($"Données locales conservées dans {SentinelPaths.Root} (passez --delete-data pour les purger).");
        }

        log?.Invoke("Désinstallation SENTINEL v2 terminée.");
    }

    private static void InstallWindowsService(string serviceName, string displayName, string binaryPath, Action<string>? log)
    {
        if (!File.Exists(binaryPath))
        {
            log?.Invoke($"Service {serviceName} ignoré : binaire introuvable ({binaryPath}).");
            return;
        }

        RunSc(["create", serviceName, $"binPath= \"{binaryPath}\"", "start= auto", $"DisplayName= \"{displayName}\""], log);
        RunSc(["failure", serviceName, "reset= 86400", "actions= restart/5000/restart/15000/restart/30000"], log);
        log?.Invoke($"Service Windows {serviceName} configuré (redémarrage automatique sur panne).");
    }

    private static void RunSc(string[] args, Action<string>? log) => RunSystemTool("sc.exe", args, log);
    private static void RunNetsh(string[] args, Action<string>? log) => RunSystemTool("netsh.exe", args, log);

    private static void RunSystemTool(string exeName, string[] args, Action<string>? log)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), exeName),
                Arguments = string.Join(" ", args),
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using var proc = Process.Start(psi);
            if (proc is null) return;
            var output = proc.StandardOutput.ReadToEnd().Trim();
            proc.WaitForExit(10_000);
            if (!string.IsNullOrWhiteSpace(output))
                log?.Invoke($"[{exeName}] {output.Replace(Environment.NewLine, " ")}");
        }
        catch (Exception ex)
        {
            log?.Invoke($"[{exeName}] Erreur : {ex.Message}");
        }
    }
}
