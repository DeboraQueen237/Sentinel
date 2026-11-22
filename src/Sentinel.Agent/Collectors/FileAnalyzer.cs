using System.Security.Cryptography;
using Sentinel.Shared.Models;

namespace Sentinel.Agent.Collectors;

/// <summary>
/// Utilitaires d'analyse statique des fichiers (doc §6.4) : entropie de Shannon sur échantillon borné,
/// détection de double extension masquée (MITRE T1036.007), classification exécutable/archive et empreinte SHA-256.
/// Respect strict de la vie privée : aucun contenu de document n'est conservé ni journalisé.
/// </summary>
public static class FileAnalyzer
{
    public const int DefaultEntropySampleBytes = 64 * 1024;
    public const long DefaultMaxHashBytes = 25L * 1024 * 1024;

    private static readonly HashSet<string> ExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".psm1", ".psd1",
        ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".msi", ".msp",
        ".hta", ".com", ".pif", ".cpl", ".lnk", ".jar", ".reg", ".msc", ".inf"
    };

    private static readonly HashSet<string> ArchiveExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".xz",
        ".cab", ".iso", ".img", ".vhd", ".vhdx", ".lzma"
    };

    private static readonly HashSet<string> DecoyDocumentExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".pdf", ".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm",
        ".ppt", ".pptx", ".txt", ".rtf", ".csv", ".odt", ".ods",
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".svg",
        ".mp3", ".mp4", ".wav", ".avi", ".mov", ".zip", ".rar", ".7z",
        ".html", ".htm", ".xml", ".eml", ".msg"
    };

    /// <summary>
    /// Calcule l'entropie de Shannon d'un tampon d'octets dans l'intervalle [0, 8] bits/octet.
    /// Un texte clair se situe généralement entre 3,0 et 5,0 ; un fichier chiffré/compressé avoisine 7,8–8,0.
    /// </summary>
    public static double ComputeShannonEntropy(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
        {
            return 0.0;
        }

        Span<int> counts = stackalloc int[256];
        foreach (var b in data)
        {
            counts[b]++;
        }

        double entropy = 0.0;
        double len = data.Length;
        for (int i = 0; i < 256; i++)
        {
            var c = counts[i];
            if (c == 0)
            {
                continue;
            }
            var p = c / len;
            entropy -= p * Math.Log2(p);
        }

        return Math.Clamp(entropy, 0.0, 8.0);
    }

    /// <summary>
    /// Calcule l'entropie de Shannon en lisant au maximum <paramref name="maxSampleBytes"/> octets (64 Ko par défaut).
    /// Ne stocke ni ne transmet jamais le contenu lu.
    /// </summary>
    public static double ComputeFileEntropy(string path, int maxSampleBytes = DefaultEntropySampleBytes)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return 0.0;
        }

        var buffer = new byte[Math.Clamp(maxSampleBytes, 1024, 512 * 1024)];
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 8192);
        int totalRead = 0;
        while (totalRead < buffer.Length)
        {
            var read = fs.Read(buffer, totalRead, buffer.Length - totalRead);
            if (read <= 0)
            {
                break;
            }
            totalRead += read;
        }

        return ComputeShannonEntropy(buffer.AsSpan(0, totalRead));
    }

    /// <summary>
    /// Détecte une double extension suspecte masquant un exécutable ou script derrière une extension documentaire
    /// (ex. <c>facture.pdf.exe</c>, <c>devis.docx.scr</c>), sans faux positif sur <c>rapport.v2.pdf</c>.
    /// </summary>
    public static bool HasDoubleExtension(string fileNameOrPath)
    {
        if (string.IsNullOrWhiteSpace(fileNameOrPath))
        {
            return false;
        }

        var name = Path.GetFileName(fileNameOrPath).Trim();
        if (string.IsNullOrEmpty(name))
        {
            return false;
        }

        var lastExt = Path.GetExtension(name);
        if (string.IsNullOrEmpty(lastExt) || !ExecutableExtensions.Contains(lastExt))
        {
            return false;
        }

        var withoutLast = name[..^lastExt.Length].TrimEnd();
        var prevExt = Path.GetExtension(withoutLast);
        if (string.IsNullOrEmpty(prevExt))
        {
            return false;
        }

        return DecoyDocumentExtensions.Contains(prevExt);
    }

    public static bool IsExecutableExtension(string fileNameOrPath)
    {
        var ext = Path.GetExtension(fileNameOrPath);
        return !string.IsNullOrEmpty(ext) && ExecutableExtensions.Contains(ext);
    }

    public static bool IsArchiveExtension(string fileNameOrPath)
    {
        var ext = Path.GetExtension(fileNameOrPath);
        return !string.IsNullOrEmpty(ext) && ArchiveExtensions.Contains(ext);
    }

    public static string? ComputeSha256Bounded(string path, long maxBytes = DefaultMaxHashBytes)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return null;
        }

        var info = new FileInfo(path);
        if (!info.Exists || info.Length == 0 || info.Length > maxBytes)
        {
            return null;
        }

        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16);
        return Convert.ToHexString(SHA256.HashData(fs)).ToLowerInvariant();
    }

    public static string ClassifyWatchedFolder(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return WatchedFolders.Custom;
        }

        var normalized = path.Replace('/', '\\');
        if (normalized.Contains(@"\Downloads\", StringComparison.OrdinalIgnoreCase) ||
            normalized.Contains(@"\Téléchargements\", StringComparison.OrdinalIgnoreCase))
        {
            return WatchedFolders.Downloads;
        }

        if (normalized.Contains(@"\Desktop\", StringComparison.OrdinalIgnoreCase) ||
            normalized.Contains(@"\Bureau\", StringComparison.OrdinalIgnoreCase))
        {
            return WatchedFolders.Desktop;
        }

        if (normalized.Contains(@"\Documents\", StringComparison.OrdinalIgnoreCase))
        {
            return WatchedFolders.Documents;
        }

        var tempPath = Path.GetTempPath().TrimEnd('\\');
        if ((!string.IsNullOrEmpty(tempPath) && normalized.StartsWith(tempPath, StringComparison.OrdinalIgnoreCase)) ||
            normalized.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase))
        {
            return WatchedFolders.Temp;
        }

        return WatchedFolders.Custom;
    }
}
