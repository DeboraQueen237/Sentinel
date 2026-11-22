using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace Sentinel.Core.Enrichment;

/// <summary>
/// Tables déterministes d'indicateurs de menace et détecteurs utilitaires (doc §7.1-1).
/// Aucune dépendance réseau : 100 % local et instantané.
/// </summary>
public static partial class ThreatIndicators
{
    /// <summary>Empreinte SHA-256 officielle du fichier de test antivirus inoffensif EICAR (doc §14.1).</summary>
    public const string EicarSha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    public static readonly IReadOnlySet<string> TrustedPublishers = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft Corporation",
        "Microsoft Windows",
        "Microsoft Windows Publisher",
        "Google LLC",
        "Mozilla Corporation",
        "Apple Inc.",
        "Adobe Inc.",
        "Adobe Systems, Incorporated",
        "Intel Corporation",
        "NVIDIA Corporation",
        "Advanced Micro Devices, Inc.",
        "GitHub, Inc.",
        "JetBrains s.r.o.",
        "Valve Corp.",
        "Sentinel"
    };

    public static readonly IReadOnlySet<string> UrlShorteners = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "rebrand.ly", "rb.gy",
        "shorturl.at", "ow.ly", "goo.gl", "tiny.cc", "buff.ly", "s.id", "v.gd",
        "clck.ru", "short.io", "adf.ly", "bc.vc", "lnkd.in", "bit.do", "mcaf.ee",
        "su.pr", "qr.ae", "t.ly", "kutt.it", "dub.sh", "soo.gd"
    };

    public static readonly IReadOnlySet<string> RiskyTlds = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        ".xyz", ".top", ".click", ".zip", ".mov", ".tk", ".ml", ".gq", ".cf", ".ga",
        ".ru", ".pw", ".su", ".cc", ".buzz", ".work", ".cam", ".rest", ".icu",
        ".monster", ".loan", ".xin", ".country", ".kim", ".men", ".stream", ".bid",
        ".download", ".racing", ".party", ".win"
    };

    public static readonly IReadOnlySet<string> LolBins = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "powershell", "pwsh", "cmd", "mshta", "rundll32", "regsvr32", "certutil",
        "bitsadmin", "wscript", "cscript", "wmic", "msiexec", "curl", "installutil",
        "regasm", "regsvcs", "odbcconf", "forfiles", "pcalua", "cmstp",
        "syncappvpublishingserver", "msbuild", "csc", "hh"
    };

    public static readonly IReadOnlySet<string> OfficeApplications = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "winword", "excel", "powerpnt", "outlook", "msaccess", "mspub", "visio",
        "acrord32", "acrobat", "soffice", "wps"
    };

    public static readonly IReadOnlySet<string> BrowserProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "chrome", "msedge", "firefox", "brave", "opera", "iexplore", "vivaldi", "arc", "waterfox"
    };

    public static readonly IReadOnlySet<string> ExecutableExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".scr", ".pif", ".com", ".bat", ".cmd", ".ps1", ".psm1",
        ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".msi", ".msp",
        ".cpl", ".jar", ".lnk", ".iso", ".img", ".vba"
    };

    public static readonly IReadOnlySet<string> BaitDocumentExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf",
        ".jpg", ".jpeg", ".png", ".gif", ".csv", ".odt", ".ods", ".zip", ".rar", ".html"
    };

    public static readonly IReadOnlySet<string> ArchiveExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        ".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".cab", ".iso"
    };

    public static readonly IReadOnlySet<string> CompressedOrMediaExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        ".zip", ".rar", ".7z", ".gz", ".tgz", ".bz2", ".xz", ".jpg", ".jpeg", ".png",
        ".webp", ".gif", ".mp4", ".mkv", ".avi", ".mp3", ".flac", ".ogg", ".woff2", ".pdf"
    };

    public static readonly IReadOnlySet<string> RansomwareExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        ".locked", ".enc", ".encrypted", ".crypt", ".crypted", ".crypto", ".ransom",
        ".locky", ".cerber", ".wnry", ".wncry", ".ryuk", ".conti", ".lockbit",
        ".blackcat", ".akira", ".play", ".zepto", ".odin", ".aesir", ".cobalt"
    };

    public static readonly IReadOnlySet<int> UnusualC2Ports = new HashSet<int>
    {
        1337, 2222, 3333, 4444, 4445, 5555, 6666, 6667, 6697,
        7777, 8443, 8888, 9001, 9050, 9999, 12345, 31337, 54321
    };

    /// <summary>Identifiants vendeurs USB (VID) fréquents pour les microcontrôleurs détournés en BadUSB.</summary>
    public static readonly IReadOnlySet<string> SuspiciousUsbVendorIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "16C0", // Digispark / V-USB
        "2341", // Arduino
        "2E8A", // Raspberry Pi Pico
        "1B4F", // SparkFun
        "03EB", // Atmel (ATmega32U4)
        "F055", // Flipper / custom HID
        "1209", // pid.codes (DIY HID)
        "239A", // Adafruit
        "0483"  // STMicroelectronics dev board
    };

    private static readonly string[] SuspiciousDirMarkers =
    [
        "\\temp\\",
        "\\tmp\\",
        "\\downloads\\",
        "\\téléchargements\\",
        "\\appdata\\local\\temp\\",
        "\\appdata\\roaming\\",
        "\\appdata\\local\\",
        "\\users\\public\\",
        "\\programdata\\"
    ];

    private static readonly string[] EncodedCommandMarkers =
    [
        "-enc ", "-enc\t", "-encodedcommand", "frombase64string",
        "invoke-expression", "downloadstring", "downloadfile",
        "net.webclient", "invoke-webrequest", "start-bitstransfer",
        "-w hidden", "-windowstyle hidden", "-window hidden",
        "-ep bypass", "-executionpolicy bypass", "-nop ", "-noprofile",
        "certutil -urlcache", "certutil.exe -urlcache",
        "mshta http", "rundll32 javascript", "[convert]::"
    ];

    public static bool IsTrustedPublisher(string? publisher)
    {
        if (string.IsNullOrWhiteSpace(publisher)) return false;
        var trimmed = publisher.Trim();
        if (TrustedPublishers.Contains(trimmed)) return true;
        foreach (var trusted in TrustedPublishers)
        {
            if (trimmed.StartsWith(trusted, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    public static string NormalizeProcessName(string? nameOrPath)
    {
        if (string.IsNullOrWhiteSpace(nameOrPath)) return string.Empty;
        var clean = nameOrPath.Trim().Trim('"');
        var slash = Math.Max(clean.LastIndexOf('\\'), clean.LastIndexOf('/'));
        var fileName = slash >= 0 ? clean[(slash + 1)..] : clean;
        return fileName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            ? fileName[..^4].ToLowerInvariant()
            : fileName.ToLowerInvariant();
    }

    public static string ExtractFileName(string? pathOrName)
    {
        if (string.IsNullOrWhiteSpace(pathOrName)) return string.Empty;
        var clean = pathOrName.Trim().Trim('"');
        var q = clean.IndexOfAny(['?', '#']);
        if (q > 0 && clean.Contains("://", StringComparison.Ordinal)) clean = clean[..q];
        var slash = Math.Max(clean.LastIndexOf('\\'), clean.LastIndexOf('/'));
        return slash >= 0 ? clean[(slash + 1)..] : clean;
    }

    public static string ExtractExtension(string? pathOrExt)
    {
        if (string.IsNullOrWhiteSpace(pathOrExt)) return string.Empty;
        var trimmed = pathOrExt.Trim();
        if (trimmed.StartsWith('.') && !trimmed.Contains('\\') && !trimmed.Contains('/'))
        {
            return trimmed.ToLowerInvariant();
        }
        var fileName = ExtractFileName(trimmed);
        var dot = fileName.LastIndexOf('.');
        return dot >= 0 && dot < fileName.Length - 1
            ? fileName[dot..].ToLowerInvariant()
            : string.Empty;
    }

    public static string? ExtractDomain(string? urlOrHost)
    {
        if (string.IsNullOrWhiteSpace(urlOrHost)) return null;
        var trimmed = urlOrHost.Trim();

        // Ignorer les chemins de fichiers Windows (C:\...) ou UNC (\\serveur\...)
        if (trimmed.Length >= 2 && (trimmed[1] == ':' || trimmed.StartsWith(@"\\", StringComparison.Ordinal)))
        {
            return null;
        }

        if (Uri.TryCreate(trimmed, UriKind.Absolute, out var uri) &&
            !string.IsNullOrWhiteSpace(uri.Host) &&
            (uri.Scheme is "http" or "https" or "ftp" or "ws" or "wss"))
        {
            return uri.Host.TrimEnd('.').ToLowerInvariant();
        }

        // Hôte nu (avec ou sans port)
        var candidate = trimmed;
        var slash = candidate.IndexOf('/');
        if (slash > 0) candidate = candidate[..slash];
        var colon = candidate.LastIndexOf(':');
        if (colon > 0 && !candidate.Contains(']')) candidate = candidate[..colon];
        candidate = candidate.Trim().TrimEnd('.').ToLowerInvariant();

        if (candidate.Length is < 3 or > 253) return null;
        if (IPAddress.TryParse(candidate, out _)) return null;
        if (!candidate.Contains('.') || candidate.Contains(' ') || candidate.Contains('\\')) return null;

        // Éviter de confondre un nom de fichier (ex. "facture.pdf.exe") avec un domaine
        var ext = ExtractExtension(candidate);
        if (ExecutableExtensions.Contains(ext) || BaitDocumentExtensions.Contains(ext))
        {
            // Attention : .zip et .mov sont aussi des TLD à risque s'ils proviennent d'une URL,
            // mais sur un nom nu sans schéma, ne garder que si ce n'est pas un fichier courant (ex. .exe/.dll/.pdf/.docx).
            if (ext is not ".zip" and not ".mov") return null;
        }

        return candidate;
    }

    public static bool IsUrlShortener(string? domain)
    {
        if (string.IsNullOrWhiteSpace(domain)) return false;
        var d = domain.Trim().TrimEnd('.').ToLowerInvariant();
        if (UrlShorteners.Contains(d)) return true;
        foreach (var shortener in UrlShorteners)
        {
            if (d.EndsWith("." + shortener, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    public static bool HasRiskyTld(string? domain)
    {
        if (string.IsNullOrWhiteSpace(domain)) return false;
        var dot = domain.LastIndexOf('.');
        if (dot < 0 || dot == domain.Length - 1) return false;
        return RiskyTlds.Contains(domain[dot..]);
    }

    public static bool MatchesDomainExclusion(string? domain, string excludedDomain)
    {
        if (string.IsNullOrWhiteSpace(domain) || string.IsNullOrWhiteSpace(excludedDomain)) return false;
        var d = domain.Trim().TrimEnd('.').ToLowerInvariant();
        var ex = excludedDomain.Trim().TrimStart('.').TrimEnd('.').ToLowerInvariant();
        return d.Equals(ex, StringComparison.OrdinalIgnoreCase) ||
               d.EndsWith("." + ex, StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsLolBin(string? processNameOrPath) =>
        LolBins.Contains(NormalizeProcessName(processNameOrPath));

    public static bool IsOfficeApp(string? processNameOrPath) =>
        OfficeApplications.Contains(NormalizeProcessName(processNameOrPath));

    public static bool IsBrowser(string? processNameOrPath) =>
        BrowserProcesses.Contains(NormalizeProcessName(processNameOrPath));

    public static bool IsExecutableExtension(string? extOrPath) =>
        ExecutableExtensions.Contains(ExtractExtension(extOrPath));

    public static bool IsArchiveExtension(string? extOrPath) =>
        ArchiveExtensions.Contains(ExtractExtension(extOrPath));

    public static bool IsRansomwareExtension(string? extOrPath) =>
        RansomwareExtensions.Contains(ExtractExtension(extOrPath));

    public static bool IsCompressedOrMedia(string? extOrPath) =>
        CompressedOrMediaExtensions.Contains(ExtractExtension(extOrPath));

    public static bool HasDoubleExtension(string? pathOrFileName)
    {
        var fileName = ExtractFileName(pathOrFileName);
        if (string.IsNullOrWhiteSpace(fileName)) return false;

        var lastDot = fileName.LastIndexOf('.');
        if (lastDot <= 0 || lastDot >= fileName.Length - 1) return false;

        var finalExt = fileName[lastDot..];
        if (!ExecutableExtensions.Contains(finalExt)) return false;

        var prefix = fileName[..lastDot].TrimEnd();
        var prevDot = prefix.LastIndexOf('.');
        if (prevDot < 0 || prevDot >= prefix.Length - 1) return false;

        var prevExt = prefix[prevDot..];
        return BaitDocumentExtensions.Contains(prevExt);
    }

    public static bool IsSuspiciousDirectory(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        var norm = path.Replace('/', '\\');
        foreach (var marker in SuspiciousDirMarkers)
        {
            if (norm.Contains(marker, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    public static bool IsDownloadsDirectory(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        var norm = path.Replace('/', '\\');
        return norm.Contains("\\downloads\\", StringComparison.OrdinalIgnoreCase) ||
               norm.Contains("\\téléchargements\\", StringComparison.OrdinalIgnoreCase);
    }

    public static bool HasEncodedOrSuspiciousCommand(string? cmdline)
    {
        if (string.IsNullOrWhiteSpace(cmdline)) return false;
        foreach (var marker in EncodedCommandMarkers)
        {
            if (cmdline.Contains(marker, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return IexTokenRegex().IsMatch(cmdline) || ShortEncodedFlagRegex().IsMatch(cmdline);
    }

    public static bool IsObfuscatedCommand(string? cmdline)
    {
        if (string.IsNullOrWhiteSpace(cmdline) || cmdline.Length < 20) return false;

        // Abus de caractères d'échappement (^ en cmd, ` en PowerShell)
        var carets = 0;
        var backticks = 0;
        var plusQuotes = 0;
        for (var i = 0; i < cmdline.Length; i++)
        {
            var c = cmdline[i];
            if (c == '^') carets++;
            else if (c == '`') backticks++;
            else if (c == '+' && i > 0 && (cmdline[i - 1] == '\'' || cmdline[i - 1] == '"')) plusQuotes++;
        }

        if (carets >= 5 || backticks >= 4 || plusQuotes >= 4) return true;
        if (LongBase64Regex().IsMatch(cmdline)) return true;
        if (cmdline.Contains("[char]", StringComparison.OrdinalIgnoreCase) && cmdline.Contains("-join", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return false;
    }

    public static bool IsPrivateIp(string? ipText)
    {
        if (string.IsNullOrWhiteSpace(ipText) || !IPAddress.TryParse(ipText.Trim(), out var ip))
        {
            return false;
        }

        if (IPAddress.IsLoopback(ip)) return true;

        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            return b[0] == 10 ||
                   (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
                   (b[0] == 192 && b[1] == 168) ||
                   (b[0] == 169 && b[1] == 254) ||
                   b[0] == 0;
        }

        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal) return true;
            var b = ip.GetAddressBytes();
            return (b[0] & 0xFE) == 0xFC; // fc00::/7 ULA
        }

        return false;
    }

    public static bool IsPublicIp(string? ipText) =>
        !string.IsNullOrWhiteSpace(ipText) &&
        IPAddress.TryParse(ipText.Trim(), out _) &&
        !IsPrivateIp(ipText);

    public static bool IsSuspiciousDnsName(string? domain)
    {
        if (string.IsNullOrWhiteSpace(domain)) return false;
        if (domain.Length > 55) return true;

        var firstDot = domain.IndexOf('.');
        if (firstDot < 18) return false;
        var label = domain[..firstDot];
        if (label.Length > 30) return true;

        // Sous-domaine à forte entropie (DGA / exfiltration DNS)
        return ComputeShannonEntropy(label) >= 3.9;
    }

    public static double ComputeShannonEntropy(string text)
    {
        if (string.IsNullOrEmpty(text)) return 0;
        Span<int> counts = stackalloc int[256];
        var total = 0;
        foreach (var ch in text)
        {
            if (ch < 256)
            {
                counts[ch]++;
                total++;
            }
        }
        if (total == 0) return 0;

        var entropy = 0.0;
        for (var i = 0; i < 256; i++)
        {
            if (counts[i] == 0) continue;
            var p = (double)counts[i] / total;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }

    [GeneratedRegex(@"(?:^|[\s;|(])iex(?:[\s(|]|$)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex IexTokenRegex();

    [GeneratedRegex(@"(?:^|\s)-(?:e|en|enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ShortEncodedFlagRegex();

    [GeneratedRegex(@"(?:^|[\s""'=])[A-Za-z0-9+/]{48,}={0,2}(?:$|[\s""'])", RegexOptions.CultureInvariant)]
    private static partial Regex LongBase64Regex();
}
