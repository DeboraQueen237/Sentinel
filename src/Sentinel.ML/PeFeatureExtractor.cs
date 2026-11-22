using System.Globalization;
using System.Text;
using PeNet;

namespace Sentinel.ML;

/// <summary>
/// Extracteur de caractéristiques statiques PE inspiré d'EMBER (Anderson &amp; Roth, 2018),
/// utilisant PeNet et une analyse bornée des octets bruts.
/// Ne conserve ni ne journalise jamais le contenu textuel des chaînes extraites.
/// </summary>
public sealed class PeFeatureExtractor
{
    /// <summary>Taille maximale lue par défaut pour borner l'empreinte mémoire et CPU (16 Mio).</summary>
    public const int DefaultMaxReadBytes = 16 * 1024 * 1024;

    private const uint ImageScnMemExecute = 0x20000000u;
    private const uint ImageScnMemWrite = 0x80000000u;
    private const int MinPrintableRunLength = 5;
    private const int MaxStringRunCap = 256;

    /// <summary>Noms ordonnés et stables des 51 caractéristiques du vecteur PE.</summary>
    public static IReadOnlyList<string> FeatureNames { get; } =
    [
        "LogFileSize",
        "Is64Bit",
        "IsDll",
        "IsSigned",
        "HasDebugInfo",
        "HasResources",
        "HasTls",
        "HasRelocations",
        "Subsystem",
        "TimestampAnomaly",
        "TimestampYearNorm",
        "SectionCount",
        "ExecutableSectionCount",
        "WritableExecutableSectionCount",
        "MaxSectionEntropy",
        "MeanSectionEntropy",
        "MinSectionEntropy",
        "VirtualToRawSizeRatio",
        "HasPackerSectionName",
        "ImportDllCount",
        "ImportFunctionCount",
        "ExportCount",
        "SuspiciousImportCount",
        "CryptoApiCount",
        "NetworkApiCount",
        "InjectionApiCount",
        "AntiDebugApiCount",
        "ByteHistBin00",
        "ByteHistBin01",
        "ByteHistBin02",
        "ByteHistBin03",
        "ByteHistBin04",
        "ByteHistBin05",
        "ByteHistBin06",
        "ByteHistBin07",
        "ByteHistBin08",
        "ByteHistBin09",
        "ByteHistBin10",
        "ByteHistBin11",
        "ByteHistBin12",
        "ByteHistBin13",
        "ByteHistBin14",
        "ByteHistBin15",
        "GlobalByteEntropy",
        "NullByteRatio",
        "PrintableAsciiRatio",
        "PrintableStringCount",
        "AvgStringLength",
        "UrlLikeStringCount",
        "PathLikeStringCount",
        "RegistryStringCount"
    ];

    private static readonly Dictionary<string, int> FeatureNameToIndex = BuildIndexMap();

    private static readonly HashSet<string> IntegerFormattedFeatures = new(StringComparer.Ordinal)
    {
        "Is64Bit", "IsDll", "IsSigned", "HasDebugInfo", "HasResources", "HasTls", "HasRelocations",
        "Subsystem", "TimestampAnomaly", "SectionCount", "ExecutableSectionCount",
        "WritableExecutableSectionCount", "HasPackerSectionName", "ImportDllCount",
        "ImportFunctionCount", "ExportCount", "SuspiciousImportCount", "CryptoApiCount",
        "NetworkApiCount", "InjectionApiCount", "AntiDebugApiCount", "PrintableStringCount",
        "UrlLikeStringCount", "PathLikeStringCount", "RegistryStringCount"
    };

    private static readonly string[] PackerSectionTokens =
    [
        "upx", "aspack", "adata", "themida", "vmp", "mpress", "petite",
        "nsp0", "nsp1", "packed", "enigma", "mew", "fsg", "pecompact",
        "pec1", "pec2", "yp", "perplex", "boom", "obsidium", "armadillo", "kkrunchy"
    ];

    internal static readonly HashSet<string> CryptoApis = new(StringComparer.OrdinalIgnoreCase)
    {
        "CryptAcquireContextA", "CryptAcquireContextW", "CryptEncrypt", "CryptDecrypt",
        "CryptGenKey", "CryptDeriveKey", "CryptImportKey", "CryptExportKey",
        "CryptCreateHash", "CryptHashData", "CryptGenRandom", "CryptProtectData",
        "CryptUnprotectData", "BCryptOpenAlgorithmProvider", "BCryptEncrypt", "BCryptDecrypt",
        "BCryptGenerateSymmetricKey", "BCryptImportKey", "BCryptDeriveKey",
        "NCryptEncrypt", "NCryptDecrypt", "SystemFunction036"
    };

    internal static readonly HashSet<string> NetworkApis = new(StringComparer.OrdinalIgnoreCase)
    {
        "InternetOpenA", "InternetOpenW", "InternetOpenUrlA", "InternetOpenUrlW",
        "InternetConnectA", "InternetConnectW", "InternetReadFile", "InternetWriteFile",
        "HttpOpenRequestA", "HttpOpenRequestW", "HttpSendRequestA", "HttpSendRequestW",
        "URLDownloadToFileA", "URLDownloadToFileW", "URLDownloadToCacheFileA", "URLDownloadToCacheFileW",
        "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest", "WinHttpSendRequest",
        "WinHttpReceiveResponse", "WinHttpReadData", "WSAStartup", "WSASocketA", "WSASocketW",
        "socket", "connect", "send", "recv", "sendto", "recvfrom", "bind", "listen", "accept",
        "getaddrinfo", "GetAddrInfoW", "DnsQuery_A", "DnsQuery_W"
    };

    internal static readonly HashSet<string> InjectionApis = new(StringComparer.OrdinalIgnoreCase)
    {
        "VirtualAllocEx", "VirtualProtectEx", "WriteProcessMemory", "ReadProcessMemory",
        "CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx", "RtlCreateUserThread",
        "NtUnmapViewOfSection", "ZwUnmapViewOfSection", "NtMapViewOfSection", "ZwMapViewOfSection",
        "QueueUserAPC", "NtQueueApcThread", "SetThreadContext", "GetThreadContext",
        "ResumeThread", "SuspendThread", "OpenProcess", "NtWriteVirtualMemory",
        "ZwWriteVirtualMemory", "NtAllocateVirtualMemory", "ZwAllocateVirtualMemory",
        "SetWindowsHookExA", "SetWindowsHookExW", "CreateProcessInternalW"
    };

    internal static readonly HashSet<string> AntiDebugApis = new(StringComparer.OrdinalIgnoreCase)
    {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "ZwQueryInformationProcess", "NtSetInformationThread", "ZwSetInformationThread",
        "NtQuerySystemInformation", "ZwQuerySystemInformation", "DebugActiveProcess",
        "OutputDebugStringA", "OutputDebugStringW", "SetUnhandledExceptionFilter",
        "AddVectoredExceptionHandler", "EnumSystemFirmwareTables", "NtQueryObject"
    };

    internal static readonly HashSet<string> AdditionalSuspiciousApis = new(StringComparer.OrdinalIgnoreCase)
    {
        "VirtualAlloc", "VirtualProtect", "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
        "GetProcAddress", "LdrLoadDll", "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW",
        "WinExec", "CreateProcessA", "CreateProcessW", "CreateProcessAsUserA", "CreateProcessAsUserW",
        "CreateServiceA", "CreateServiceW", "StartServiceA", "StartServiceW", "OpenSCManagerA", "OpenSCManagerW",
        "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW",
        "AdjustTokenPrivileges", "OpenProcessToken", "ImpersonateLoggedOnUser", "DuplicateTokenEx",
        "MiniDumpWriteDump", "CredEnumerateA", "CredEnumerateW", "GetAsyncKeyState", "GetKeyState",
        "BitBlt", "CreateToolhelp32Snapshot", "Process32First", "Process32Next", "AmsiScanBuffer", "EtwEventWrite"
    };

    private readonly int _maxReadBytes;

    public PeFeatureExtractor(int maxReadBytes = DefaultMaxReadBytes)
    {
        _maxReadBytes = Math.Clamp(maxReadBytes, 64 * 1024, 64 * 1024 * 1024);
    }

    /// <summary>Retourne l'indice d'une caractéristique par nom, ou -1 si inconnue.</summary>
    public static int IndexOf(string featureName) =>
        FeatureNameToIndex.TryGetValue(featureName, out var index) ? index : -1;

    /// <summary>Formate une paire nom=valeur de manière lisible pour l'explicabilité.</summary>
    public static string FormatFeatureValue(int featureIndex, float value)
    {
        if (featureIndex < 0 || featureIndex >= FeatureNames.Count)
        {
            return string.Create(CultureInfo.InvariantCulture, $"Feature{featureIndex}={value:0.##}");
        }

        var name = FeatureNames[featureIndex];
        return IntegerFormattedFeatures.Contains(name)
            ? string.Create(CultureInfo.InvariantCulture, $"{name}={(long)Math.Round(value)}")
            : string.Create(CultureInfo.InvariantCulture, $"{name}={value:0.00}");
    }

    /// <summary>Tente d'extraire le vecteur de caractéristiques PE depuis un fichier sur disque.</summary>
    public bool TryExtract(string filePath, out PeFeatureVector? vector, out string? error)
    {
        vector = null;
        error = null;

        if (string.IsNullOrWhiteSpace(filePath))
        {
            error = "Chemin de fichier vide.";
            return false;
        }

        if (!File.Exists(filePath))
        {
            error = $"Fichier introuvable : '{filePath}'.";
            return false;
        }

        try
        {
            long totalFileSize;
            byte[] buffer;

            using (var stream = new FileStream(
                filePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete))
            {
                totalFileSize = stream.Length;
                if (totalFileSize < 64)
                {
                    error = "Fichier trop petit pour être un exécutable PE valide.";
                    return false;
                }

                var toRead = (int)Math.Min(totalFileSize, _maxReadBytes);
                buffer = new byte[toRead];
                var offset = 0;
                while (offset < toRead)
                {
                    var read = stream.Read(buffer, offset, toRead - offset);
                    if (read <= 0)
                    {
                        break;
                    }
                    offset += read;
                }

                if (offset < toRead)
                {
                    Array.Resize(ref buffer, offset);
                }
            }

            return TryExtractFromBytes(buffer, totalFileSize, out vector, out error);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            error = $"Impossible de lire le fichier PE : {ex.Message}";
            return false;
        }
    }

    /// <summary>Extrait le vecteur de caractéristiques PE depuis un fichier, ou lève une exception si invalide.</summary>
    public PeFeatureVector ExtractFromFile(string filePath)
    {
        if (!TryExtract(filePath, out var vector, out var error) || vector is null)
        {
            throw new InvalidOperationException(error ?? "Échec d'extraction des caractéristiques PE.");
        }
        return vector;
    }

    /// <summary>Extrait le vecteur de caractéristiques PE depuis un tampon d'octets borné.</summary>
    public bool TryExtractFromBytes(byte[] rawBytes, long? actualFileSize, out PeFeatureVector? vector, out string? error)
    {
        vector = null;
        error = null;

        if (rawBytes is null || rawBytes.Length < 64)
        {
            error = "Tampon trop petit pour contenir un en-tête PE.";
            return false;
        }

        // Vérification rapide de la signature MZ avant de solliciter PeNet
        if (rawBytes[0] != (byte)'M' || rawBytes[1] != (byte)'Z')
        {
            error = "Le fichier n'a pas d'en-tête DOS/PE valide (signature MZ absente).";
            return false;
        }

        PeFile pe;
        try
        {
            if (!PeFile.IsPeFile(rawBytes))
            {
                error = "Le fichier n'est pas un binaire Portable Executable (PE) valide.";
                return false;
            }
            pe = new PeFile(rawBytes);
        }
        catch (Exception ex)
        {
            error = $"Échec d'analyse PE via PeNet : {ex.Message}";
            return false;
        }

        var features = new float[PeFeatureVector.FeatureCount];
        var effectiveFileSize = Math.Max(actualFileSize ?? rawBytes.Length, rawBytes.Length);

        ExtractGeneralFeatures(pe, effectiveFileSize, features);
        ExtractSectionFeatures(pe, rawBytes, features);
        ExtractImportExportFeatures(pe, features);
        ExtractByteHistogramAndEntropy(rawBytes, features);
        ExtractStringStatistics(rawBytes, features);

        vector = new PeFeatureVector(features);
        return true;
    }

    private static void ExtractGeneralFeatures(PeFile pe, long fileSizeBytes, float[] features)
    {
        features[PeFeatureIndex.LogFileSize] = MathF.Log10(1f + Math.Max(0L, fileSizeBytes));
        features[PeFeatureIndex.Is64Bit] = pe.Is64Bit ? 1f : 0f;
        features[PeFeatureIndex.IsDll] = pe.IsDll ? 1f : 0f;

        var dataDirs = pe.ImageNtHeaders?.OptionalHeader?.DataDirectory;
        var hasSecurityDir = dataDirs is not null && dataDirs.Length > 4 &&
                             dataDirs[4].VirtualAddress > 0 && dataDirs[4].Size > 0;
        var hasDebugDir = dataDirs is not null && dataDirs.Length > 6 && dataDirs[6].Size > 0;
        var hasResourceDir = dataDirs is not null && dataDirs.Length > 2 && dataDirs[2].Size > 0;
        var hasTlsDir = dataDirs is not null && dataDirs.Length > 9 && dataDirs[9].Size > 0;
        var hasRelocDir = dataDirs is not null && dataDirs.Length > 5 && dataDirs[5].Size > 0;

        bool isSigned;
        try
        {
            isSigned = hasSecurityDir || (pe.AuthenticodeInfo?.SigningCertificate is not null);
        }
        catch
        {
            isSigned = hasSecurityDir;
        }

        features[PeFeatureIndex.IsSigned] = isSigned ? 1f : 0f;
        features[PeFeatureIndex.HasDebugInfo] = (hasDebugDir || (pe.ImageDebugDirectory?.Length > 0)) ? 1f : 0f;
        features[PeFeatureIndex.HasResources] = (hasResourceDir || pe.ImageResourceDirectory is not null) ? 1f : 0f;
        features[PeFeatureIndex.HasTls] = (hasTlsDir || pe.ImageTlsDirectory is not null) ? 1f : 0f;
        features[PeFeatureIndex.HasRelocations] = (hasRelocDir || (pe.ImageRelocationDirectory?.Length > 0)) ? 1f : 0f;

        var subsystem = pe.ImageNtHeaders?.OptionalHeader is not null
            ? (int)pe.ImageNtHeaders.OptionalHeader.Subsystem
            : 0;
        features[PeFeatureIndex.Subsystem] = Math.Clamp(subsystem, 0, 32);

        var timestamp = pe.ImageNtHeaders?.FileHeader?.TimeDateStamp ?? 0u;
        var (anomaly, yearNorm) = EvaluateTimestamp(timestamp);
        features[PeFeatureIndex.TimestampAnomaly] = anomaly ? 1f : 0f;
        features[PeFeatureIndex.TimestampYearNorm] = yearNorm;
    }

    internal static (bool Anomaly, float YearNorm) EvaluateTimestamp(uint unixTimestamp)
    {
        if (unixTimestamp == 0)
        {
            return (true, 0f);
        }

        try
        {
            var dt = DateTimeOffset.FromUnixTimeSeconds(unixTimestamp);
            var now = DateTimeOffset.UtcNow;
            var isAnomaly = dt.Year < 1995 || dt > now.AddDays(1);
            var yearNorm = Math.Clamp((dt.Year - 2000f) / 30f, -1f, 2f);
            return (isAnomaly, isAnomaly ? 0f : yearNorm);
        }
        catch
        {
            return (true, 0f);
        }
    }

    private static void ExtractSectionFeatures(PeFile pe, byte[] rawBytes, float[] features)
    {
        var sections = pe.ImageSectionHeaders;
        if (sections is null || sections.Length == 0)
        {
            return;
        }

        var sectionCount = sections.Length;
        var execCount = 0;
        var rwxCount = 0;
        var hasPackerName = false;
        double maxEntropy = 0.0;
        double minEntropy = 8.0;
        double sumEntropy = 0.0;
        var measuredSections = 0;
        ulong totalVirtual = 0;
        ulong totalRaw = 0;

        foreach (var sec in sections)
        {
            if (sec is null)
            {
                continue;
            }

            var chars = (uint)sec.Characteristics;
            var isExec = (chars & ImageScnMemExecute) != 0;
            var isWrite = (chars & ImageScnMemWrite) != 0;
            if (isExec)
            {
                execCount++;
                if (isWrite)
                {
                    rwxCount++;
                }
            }

            if (!hasPackerName && IsPackerSectionName(sec.Name))
            {
                hasPackerName = true;
            }

            totalVirtual += sec.VirtualSize;
            totalRaw += sec.SizeOfRawData;

            var ptr = (long)sec.PointerToRawData;
            var rawSize = (long)sec.SizeOfRawData;
            if (ptr >= 0 && rawSize > 0 && ptr < rawBytes.Length)
            {
                var available = (int)Math.Min(rawSize, rawBytes.Length - ptr);
                if (available > 0)
                {
                    var entropy = ComputeShannonEntropy(rawBytes.AsSpan((int)ptr, available));
                    if (entropy > maxEntropy) maxEntropy = entropy;
                    if (entropy < minEntropy) minEntropy = entropy;
                    sumEntropy += entropy;
                    measuredSections++;
                }
            }
        }

        features[PeFeatureIndex.SectionCount] = sectionCount;
        features[PeFeatureIndex.ExecutableSectionCount] = execCount;
        features[PeFeatureIndex.WritableExecutableSectionCount] = rwxCount;
        features[PeFeatureIndex.MaxSectionEntropy] = measuredSections > 0 ? (float)maxEntropy : 0f;
        features[PeFeatureIndex.MeanSectionEntropy] = measuredSections > 0 ? (float)(sumEntropy / measuredSections) : 0f;
        features[PeFeatureIndex.MinSectionEntropy] = measuredSections > 0 ? (float)minEntropy : 0f;
        features[PeFeatureIndex.VirtualToRawSizeRatio] = totalRaw > 0
            ? Math.Clamp((float)((double)totalVirtual / totalRaw), 0f, 100f)
            : (totalVirtual > 0 ? 100f : 0f);
        features[PeFeatureIndex.HasPackerSectionName] = hasPackerName ? 1f : 0f;
    }

    internal static bool IsPackerSectionName(string? sectionName)
    {
        if (string.IsNullOrWhiteSpace(sectionName))
        {
            return false;
        }

        var normalized = sectionName.Trim('\0', ' ', '.').ToLowerInvariant();
        if (normalized.Length == 0)
        {
            return false;
        }

        foreach (var token in PackerSectionTokens)
        {
            if (normalized.StartsWith(token, StringComparison.Ordinal) ||
                normalized.Equals(token, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static void ExtractImportExportFeatures(PeFile pe, float[] features)
    {
        var dlls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var uniqueFunctions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var suspiciousCount = 0;
        var cryptoCount = 0;
        var networkCount = 0;
        var injectionCount = 0;
        var antiDebugCount = 0;

        try
        {
            var imports = pe.ImportedFunctions;
            if (imports is not null)
            {
                foreach (var imp in imports)
                {
                    if (imp is null)
                    {
                        continue;
                    }

                    if (!string.IsNullOrWhiteSpace(imp.DLL))
                    {
                        dlls.Add(imp.DLL);
                    }

                    var fn = imp.Name;
                    if (string.IsNullOrWhiteSpace(fn))
                    {
                        continue;
                    }

                    if (!uniqueFunctions.Add(fn))
                    {
                        continue;
                    }

                    var isSuspicious = false;
                    if (CryptoApis.Contains(fn)) { cryptoCount++; isSuspicious = true; }
                    if (NetworkApis.Contains(fn)) { networkCount++; isSuspicious = true; }
                    if (InjectionApis.Contains(fn)) { injectionCount++; isSuspicious = true; }
                    if (AntiDebugApis.Contains(fn)) { antiDebugCount++; isSuspicious = true; }
                    if (!isSuspicious && AdditionalSuspiciousApis.Contains(fn)) { isSuspicious = true; }

                    if (isSuspicious)
                    {
                        suspiciousCount++;
                    }
                }
            }
        }
        catch
        {
            // Table d'imports corrompue ou obfusquée : on conserve les compteurs partiels sans lever d'exception
        }

        var exportCount = 0;
        try
        {
            exportCount = pe.ExportedFunctions?.Length ?? 0;
        }
        catch
        {
            exportCount = 0;
        }

        features[PeFeatureIndex.ImportDllCount] = dlls.Count;
        features[PeFeatureIndex.ImportFunctionCount] = uniqueFunctions.Count;
        features[PeFeatureIndex.ExportCount] = exportCount;
        features[PeFeatureIndex.SuspiciousImportCount] = suspiciousCount;
        features[PeFeatureIndex.CryptoApiCount] = cryptoCount;
        features[PeFeatureIndex.NetworkApiCount] = networkCount;
        features[PeFeatureIndex.InjectionApiCount] = injectionCount;
        features[PeFeatureIndex.AntiDebugApiCount] = antiDebugCount;
    }

    internal static void PopulateImportCategories(
        IEnumerable<string> functionNames,
        out int suspiciousCount,
        out int cryptoCount,
        out int networkCount,
        out int injectionCount,
        out int antiDebugCount)
    {
        suspiciousCount = 0;
        cryptoCount = 0;
        networkCount = 0;
        injectionCount = 0;
        antiDebugCount = 0;

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var fn in functionNames)
        {
            if (string.IsNullOrWhiteSpace(fn) || !seen.Add(fn))
            {
                continue;
            }

            var isSuspicious = false;
            if (CryptoApis.Contains(fn)) { cryptoCount++; isSuspicious = true; }
            if (NetworkApis.Contains(fn)) { networkCount++; isSuspicious = true; }
            if (InjectionApis.Contains(fn)) { injectionCount++; isSuspicious = true; }
            if (AntiDebugApis.Contains(fn)) { antiDebugCount++; isSuspicious = true; }
            if (!isSuspicious && AdditionalSuspiciousApis.Contains(fn)) { isSuspicious = true; }

            if (isSuspicious)
            {
                suspiciousCount++;
            }
        }
    }

    private static void ExtractByteHistogramAndEntropy(ReadOnlySpan<byte> data, float[] features)
    {
        if (data.Length == 0)
        {
            return;
        }

        Span<int> counts = stackalloc int[256];
        var printableCount = 0;
        for (var i = 0; i < data.Length; i++)
        {
            var b = data[i];
            counts[b]++;
            if ((b >= 0x20 && b <= 0x7E) || b is 0x09 or 0x0A or 0x0D)
            {
                printableCount++;
            }
        }

        var total = (double)data.Length;

        // 16 bins de 16 valeurs d'octets chacun (0x00..0x0F, ..., 0xF0..0xFF)
        for (var bin = 0; bin < PeFeatureIndex.ByteHistBinCount; bin++)
        {
            var binSum = 0;
            var start = bin * 16;
            for (var j = 0; j < 16; j++)
            {
                binSum += counts[start + j];
            }
            features[PeFeatureIndex.ByteHistBinStart + bin] = (float)(binSum / total);
        }

        // Entropie de Shannon globale sur les 256 valeurs
        double entropy = 0.0;
        for (var i = 0; i < 256; i++)
        {
            var c = counts[i];
            if (c <= 0)
            {
                continue;
            }
            var p = c / total;
            entropy -= p * Math.Log2(p);
        }

        features[PeFeatureIndex.GlobalByteEntropy] = (float)Math.Clamp(entropy, 0.0, 8.0);
        features[PeFeatureIndex.NullByteRatio] = (float)(counts[0] / total);
        features[PeFeatureIndex.PrintableAsciiRatio] = (float)(printableCount / total);
    }

    /// <summary>
    /// Analyse purement statistique des séquences ASCII et UTF-16LE imprimables.
    /// Aucune chaîne extraite n'est conservée en mémoire après la fin de l'analyse.
    /// </summary>
    private static void ExtractStringStatistics(ReadOnlySpan<byte> data, float[] features)
    {
        var stringCount = 0;
        long totalStringLength = 0;
        var urlCount = 0;
        var pathCount = 0;
        var registryCount = 0;

        Span<char> scratch = stackalloc char[MaxStringRunCap];

        // 1) Parcours ASCII imprimable
        var i = 0;
        while (i < data.Length)
        {
            if (IsAsciiPrintable(data[i]))
            {
                var start = i;
                var copied = 0;
                while (i < data.Length && IsAsciiPrintable(data[i]))
                {
                    if (copied < MaxStringRunCap)
                    {
                        scratch[copied++] = (char)data[i];
                    }
                    i++;
                }

                var runLen = i - start;
                if (runLen >= MinPrintableRunLength)
                {
                    stringCount++;
                    totalStringLength += runLen;
                    ClassifyStringSpan(scratch[..copied], ref urlCount, ref pathCount, ref registryCount);
                }
            }
            else
            {
                i++;
            }
        }

        // 2) Parcours UTF-16LE imprimable (fréquent dans les binaires Windows / .NET)
        i = 0;
        while (i + 1 < data.Length)
        {
            if (IsAsciiPrintable(data[i]) && data[i + 1] == 0x00)
            {
                var runLen = 0;
                var copied = 0;
                while (i + 1 < data.Length && IsAsciiPrintable(data[i]) && data[i + 1] == 0x00)
                {
                    if (copied < MaxStringRunCap)
                    {
                        scratch[copied++] = (char)data[i];
                    }
                    runLen++;
                    i += 2;
                }

                if (runLen >= MinPrintableRunLength)
                {
                    stringCount++;
                    totalStringLength += runLen;
                    ClassifyStringSpan(scratch[..copied], ref urlCount, ref pathCount, ref registryCount);
                }
            }
            else
            {
                i++;
            }
        }

        // Nettoyage explicite du tampon temporaire sur pile
        scratch.Clear();

        features[PeFeatureIndex.PrintableStringCount] = stringCount;
        features[PeFeatureIndex.AvgStringLength] = stringCount > 0
            ? (float)((double)totalStringLength / stringCount)
            : 0f;
        features[PeFeatureIndex.UrlLikeStringCount] = urlCount;
        features[PeFeatureIndex.PathLikeStringCount] = pathCount;
        features[PeFeatureIndex.RegistryStringCount] = registryCount;
    }

    private static void ClassifyStringSpan(
        ReadOnlySpan<char> span,
        ref int urlCount,
        ref int pathCount,
        ref int registryCount)
    {
        if (ContainsIgnoreCase(span, "http://") ||
            ContainsIgnoreCase(span, "https://") ||
            ContainsIgnoreCase(span, "ftp://") ||
            ContainsIgnoreCase(span, "ws://") ||
            ContainsIgnoreCase(span, "wss://"))
        {
            urlCount++;
        }

        if (ContainsIgnoreCase(span, ":\\") ||
            ContainsIgnoreCase(span, "\\windows\\") ||
            ContainsIgnoreCase(span, "\\system32\\") ||
            ContainsIgnoreCase(span, "%appdata%") ||
            ContainsIgnoreCase(span, "%temp%") ||
            ContainsIgnoreCase(span, "%userprofile%") ||
            ContainsIgnoreCase(span, ".exe") ||
            ContainsIgnoreCase(span, ".dll") ||
            ContainsIgnoreCase(span, ".ps1") ||
            ContainsIgnoreCase(span, ".bat") ||
            ContainsIgnoreCase(span, ".vbs"))
        {
            pathCount++;
        }

        if (ContainsIgnoreCase(span, "hkey_") ||
            ContainsIgnoreCase(span, "hklm\\") ||
            ContainsIgnoreCase(span, "hkcu\\") ||
            ContainsIgnoreCase(span, "currentversion\\run") ||
            ContainsIgnoreCase(span, "currentcontrolset") ||
            ContainsIgnoreCase(span, "software\\microsoft\\windows"))
        {
            registryCount++;
        }
    }

    private static bool ContainsIgnoreCase(ReadOnlySpan<char> haystack, ReadOnlySpan<char> needle) =>
        haystack.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0;

    private static bool IsAsciiPrintable(byte b) => b >= 0x20 && b <= 0x7E;

    internal static double ComputeShannonEntropy(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0)
        {
            return 0.0;
        }

        Span<int> counts = stackalloc int[256];
        for (var i = 0; i < data.Length; i++)
        {
            counts[data[i]]++;
        }

        var total = (double)data.Length;
        double entropy = 0.0;
        for (var i = 0; i < 256; i++)
        {
            var c = counts[i];
            if (c <= 0)
            {
                continue;
            }
            var p = c / total;
            entropy -= p * Math.Log2(p);
        }

        return Math.Clamp(entropy, 0.0, 8.0);
    }

    private static Dictionary<string, int> BuildIndexMap()
    {
        var map = new Dictionary<string, int>(FeatureNames.Count, StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < FeatureNames.Count; i++)
        {
            map[FeatureNames[i]] = i;
        }
        return map;
    }
}
