using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using PeNet;
using PeNet.Header.Pe;

namespace Sentinel.Detection.Static;

/// <summary>
/// Analyseur statique d'executables Windows PE (MZ/PE) base sur <c>PeNet 6.1.2</c>.
/// Extrait : signature Authenticode et editeur, sections et entropie de Shannon,
/// detection de packer probable, imports suspects, anomalie d'horodatage de compilation et SHA-256.
/// </summary>
public sealed class PeStaticAnalyzer
{
    private static readonly DateTimeOffset MinPlausibleCompileTime = new(1995, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private static readonly (string Prefix, string PackerName)[] KnownPackerSections =
    [
        ("UPX0", "UPX"),
        ("UPX1", "UPX"),
        ("UPX2", "UPX"),
        (".UPX", "UPX"),
        (".aspack", "ASPack"),
        (".adata", "ASPack"),
        (".themida", "Themida"),
        (".winlice", "Themida/WinLicense"),
        (".vmp0", "VMProtect"),
        (".vmp1", "VMProtect"),
        (".vmp2", "VMProtect"),
        (".vmp", "VMProtect"),
        (".mpress1", "MPRESS"),
        (".mpress2", "MPRESS"),
        (".mpress", "MPRESS"),
        (".enigma1", "Enigma"),
        (".enigma2", "Enigma"),
        (".petite", "Petite"),
        ("PEC2", "PECompact"),
        (".nsp0", "NsPack"),
        (".nsp1", "NsPack")
    ];

    /// <summary>
    /// APIs Windows a haut signal malveillant (injection de processus, hooking/keylogging,
    /// chiffrement, anti-debug, telechargement et execution).
    /// </summary>
    private static readonly HashSet<string> SuspiciousApiExactNames = new(StringComparer.OrdinalIgnoreCase)
    {
        // Injection & manipulation de processus
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "CreateRemoteThreadEx",
        "NtUnmapViewOfSection",
        "ZwUnmapViewOfSection",
        "VirtualProtectEx",
        "QueueUserAPC",
        "NtQueueApcThread",
        "RtlCreateUserThread",
        "ResumeThread",
        "SetThreadContext",
        "OpenProcess",
        // Hooking / capture
        "SetWindowsHookEx",
        "SetWindowsHookExA",
        "SetWindowsHookExW",
        "GetAsyncKeyState",
        "GetKeyState",
        // Chiffrement (ransomware)
        "CryptEncrypt",
        "CryptGenKey",
        "CryptImportKey",
        "BCryptEncrypt",
        // Anti-debug / evasion
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
        "OutputDebugStringA",
        "OutputDebugStringW",
        // Chargement dynamique / telechargement / execution
        "LoadLibraryA",
        "LoadLibraryW",
        "LoadLibraryExA",
        "LoadLibraryExW",
        "URLDownloadToFileA",
        "URLDownloadToFileW",
        "WinExec",
        "ShellExecuteA",
        "ShellExecuteW",
        "ShellExecuteExA",
        "ShellExecuteExW",
        // Acces identifiants / privileges
        "MiniDumpWriteDump",
        "AdjustTokenPrivileges",
        "CreateProcessWithTokenW"
    };

    private static readonly HashSet<string> HighRiskInjectionApis = new(StringComparer.OrdinalIgnoreCase)
    {
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "CreateRemoteThreadEx",
        "NtUnmapViewOfSection",
        "ZwUnmapViewOfSection",
        "QueueUserAPC",
        "RtlCreateUserThread"
    };

    /// <summary>Calcule l'entropie de Shannon d'une sequence d'octets (en bits par octet, dans [0, 8]).</summary>
    public static double ComputeShannonEntropy(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
            return 0.0;

        Span<int> counts = stackalloc int[256];
        counts.Clear();

        for (var i = 0; i < data.Length; i++)
            counts[data[i]]++;

        var len = (double)data.Length;
        var entropy = 0.0;

        for (var b = 0; b < 256; b++)
        {
            var c = counts[b];
            if (c == 0)
                continue;
            var p = c / len;
            entropy -= p * Math.Log2(p);
        }

        return Math.Round(Math.Clamp(entropy, 0.0, 8.0), 4);
    }

    /// <summary>Calcule l'empreinte SHA-256 (hexadecimal minuscules) d'un tampon.</summary>
    public static string ComputeSha256(ReadOnlySpan<byte> data)
    {
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(data, hash);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// <summary>Calcule l'empreinte SHA-256 (hexadecimal minuscules) d'un fichier.</summary>
    public static string ComputeSha256File(string filePath)
    {
        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        var hash = SHA256.HashData(fs);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// <summary>Indique rapidement si un tampon debute par un en-tete MZ/PE valide.</summary>
    public static bool HasValidPeMagic(ReadOnlySpan<byte> data)
    {
        if (data.Length < 64)
            return false;

        // "MZ" (0x4D 0x5A)
        if (data[0] != 0x4D || data[1] != 0x5A)
            return false;

        var peOffset = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(0x3C, 4));
        if (peOffset > (uint)(data.Length - 4))
            return false;

        // "PE\0\0" (0x50 0x45 0x00 0x00)
        var off = (int)peOffset;
        return data[off] == 0x50 && data[off + 1] == 0x45 && data[off + 2] == 0x00 && data[off + 3] == 0x00;
    }

    /// <summary>Analyse un fichier sur disque.</summary>
    public PeAnalysisResult AnalyzeFile(string filePath, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        ct.ThrowIfCancellationRequested();

        if (!File.Exists(filePath))
        {
            return CreateErrorResult(filePath, $"Fichier introuvable : '{filePath}'.");
        }

        byte[] bytes;
        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
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
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return CreateErrorResult(filePath, $"Impossible de lire le fichier : {ex.Message}");
        }

        return AnalyzeBytes(bytes, filePath, ct);
    }

    /// <summary>Analyse un tampon binaire en memoire (PE ou non-PE).</summary>
    public PeAnalysisResult AnalyzeBytes(byte[] bytes, string filePath = "<memory>", CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        ct.ThrowIfCancellationRequested();

        var sha256 = ComputeSha256(bytes);
        var fileEntropy = ComputeShannonEntropy(bytes);
        var sizeBytes = (long)bytes.Length;

        if (!HasValidPeMagic(bytes) || !PeFile.TryParse(bytes, out var peFile) || peFile is null)
        {
            return new PeAnalysisResult(
                FilePath: filePath,
                Sha256: sha256,
                SizeBytes: sizeBytes,
                IsPe: false,
                Is64Bit: false,
                IsDll: false,
                IsDotNet: false,
                IsSigned: false,
                HasValidSignature: false,
                HasValidCertChain: false,
                Publisher: null,
                CompileTime: null,
                RawTimeDateStamp: 0,
                TimestampAnomaly: false,
                TimestampAnomalyReason: null,
                Sections: Array.Empty<PeSectionInfo>(),
                MaxEntropy: fileEntropy,
                FileEntropy: fileEntropy,
                ProbablePacker: null,
                TotalImportCount: 0,
                SuspiciousImports: Array.Empty<string>(),
                RiskScore: 0,
                Signals: Array.Empty<string>(),
                MitreTechniques: Array.Empty<string>());
        }

        ct.ThrowIfCancellationRequested();

        var signals = new List<string>();
        var mitre = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // 1. Authenticode & editeur
        var isSigned = SafeTry(() => peFile.IsAuthenticodeSigned, false);
        var hasValidSig = isSigned && SafeTry(() => peFile.HasValidAuthenticodeSignature, false);
        var hasValidChain = isSigned && SafeTry(() => peFile.HasValidAuthenticodeCertChain(useOnlineCrl: false), false);
        var publisher = ExtractPublisher(peFile);

        // 2. Sections & entropie de Shannon
        var sections = new List<PeSectionInfo>();
        double maxEntropy = 0.0;
        string? knownPacker = null;
        var hasExecHighEntropy = false;
        var hasRwxSection = false;

        var rawSections = SafeTry(() => peFile.ImageSectionHeaders, null);
        if (rawSections is not null)
        {
            foreach (var sec in rawSections)
            {
                ct.ThrowIfCancellationRequested();
                var name = (sec.Name ?? string.Empty).TrimEnd('\0').Trim();
                var isExec = (sec.Characteristics & (ScnCharacteristicsType.MemExecute | ScnCharacteristicsType.CntCode)) != 0;
                var isWrite = (sec.Characteristics & ScnCharacteristicsType.MemWrite) != 0;

                var secEntropy = ComputeSectionEntropy(bytes, sec.PointerToRawData, sec.SizeOfRawData);
                if (secEntropy > maxEntropy)
                    maxEntropy = secEntropy;

                sections.Add(new PeSectionInfo(
                    Name: name,
                    VirtualSize: sec.VirtualSize,
                    RawSize: sec.SizeOfRawData,
                    RawOffset: sec.PointerToRawData,
                    Entropy: secEntropy,
                    IsExecutable: isExec,
                    IsWritable: isWrite));

                if (knownPacker is null)
                    knownPacker = DetectKnownPackerSection(name);

                if (isExec && secEntropy > 7.2)
                    hasExecHighEntropy = true;

                if (isExec && isWrite)
                    hasRwxSection = true;
            }
        }

        if (sections.Count == 0)
            maxEntropy = fileEntropy;

        // 3. Imports & imports suspects
        var (totalImports, suspiciousImports) = AnalyzeImports(peFile);

        // 4. Packer probable (nom de section connu OU heuristique entropie > 7.2 + faibles imports)
        var probablePacker = knownPacker;
        if (probablePacker is null && hasExecHighEntropy && totalImports <= 15)
        {
            probablePacker = "HeuristicPacker (HighEntropy+LowImports)";
        }

        if (probablePacker is not null)
        {
            signals.Add($"Packer probable detecte : {probablePacker} (entropie max {maxEntropy:0.00}, imports={totalImports})");
            mitre.Add("T1027.002");
        }
        else if (maxEntropy > 7.2)
        {
            signals.Add($"Section PE a tres forte entropie ({maxEntropy:0.00} bits/octet)");
            mitre.Add("T1027");
        }

        if (hasRwxSection)
        {
            signals.Add("Section PE simultanement executable et inscriptible (RWX)");
            mitre.Add("T1027");
        }

        if (suspiciousImports.Count > 0)
        {
            signals.Add($"Imports suspects ({suspiciousImports.Count}) : {string.Join(", ", suspiciousImports.Take(8))}");
            if (suspiciousImports.Any(i => HighRiskInjectionApis.Contains(i)))
                mitre.Add("T1055");
            if (suspiciousImports.Any(i => i.StartsWith("URLDownloadToFile", StringComparison.OrdinalIgnoreCase)))
                mitre.Add("T1105");
            if (suspiciousImports.Any(i => i.Contains("CryptEncrypt", StringComparison.OrdinalIgnoreCase)))
                mitre.Add("T1486");
        }

        // 5. Horodatage de compilation
        var rawStamp = SafeTry(() => peFile.ImageNtHeaders?.FileHeader?.TimeDateStamp ?? 0u, 0u);
        var (compileTime, tsAnomaly, tsReason) = EvaluateTimestamp(rawStamp, DateTimeOffset.UtcNow);
        if (tsAnomaly && tsReason is not null)
        {
            signals.Add(tsReason);
            mitre.Add("T1070.006");
        }

        // 6. Score heuristique statique PE (0..100)
        var riskScore = ComputePeRiskScore(
            probablePacker is not null,
            maxEntropy,
            hasRwxSection,
            suspiciousImports,
            tsAnomaly,
            isSigned,
            hasValidSig);

        return new PeAnalysisResult(
            FilePath: filePath,
            Sha256: sha256,
            SizeBytes: sizeBytes,
            IsPe: true,
            Is64Bit: SafeTry(() => peFile.Is64Bit, false),
            IsDll: SafeTry(() => peFile.IsDll, false),
            IsDotNet: SafeTry(() => peFile.IsDotNet, false),
            IsSigned: isSigned,
            HasValidSignature: hasValidSig,
            HasValidCertChain: hasValidChain,
            Publisher: publisher,
            CompileTime: compileTime,
            RawTimeDateStamp: rawStamp,
            TimestampAnomaly: tsAnomaly,
            TimestampAnomalyReason: tsReason,
            Sections: sections,
            MaxEntropy: maxEntropy,
            FileEntropy: fileEntropy,
            ProbablePacker: probablePacker,
            TotalImportCount: totalImports,
            SuspiciousImports: suspiciousImports,
            RiskScore: riskScore,
            Signals: signals,
            MitreTechniques: mitre.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray());
    }

    private static double ComputeSectionEntropy(byte[] fileBytes, uint rawOffset, uint rawSize)
    {
        if (rawSize == 0 || rawOffset >= (uint)fileBytes.Length)
            return 0.0;

        var available = fileBytes.Length - (int)rawOffset;
        var len = (int)Math.Min(rawSize, (uint)available);
        if (len <= 0)
            return 0.0;

        return ComputeShannonEntropy(fileBytes.AsSpan((int)rawOffset, len));
    }

    private static string? DetectKnownPackerSection(string sectionName)
    {
        if (string.IsNullOrWhiteSpace(sectionName))
            return null;

        foreach (var (prefix, packer) in KnownPackerSections)
        {
            if (sectionName.Equals(prefix, StringComparison.OrdinalIgnoreCase) ||
                sectionName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                return packer;
            }
        }
        return null;
    }

    private static (int TotalCount, IReadOnlyList<string> Suspicious) AnalyzeImports(PeFile peFile)
    {
        var allNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var suspicious = new List<string>();
        var suspiciousSeen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Collect(ImportFunction[]? funcs)
        {
            if (funcs is null)
                return;

            foreach (var fn in funcs)
            {
                var name = fn.Name;
                if (string.IsNullOrWhiteSpace(name))
                    continue;

                allNames.Add(name);
                if (SuspiciousApiExactNames.Contains(name) && suspiciousSeen.Add(name))
                    suspicious.Add(name);
            }
        }

        Collect(SafeTry(() => peFile.ImportedFunctions, null));
        Collect(SafeTry(() => peFile.DelayImportedFunctions, null));

        return (allNames.Count, suspicious);
    }

    internal static (DateTimeOffset? CompileTime, bool IsAnomaly, string? Reason) EvaluateTimestamp(
        uint rawTimeDateStamp,
        DateTimeOffset nowUtc)
    {
        if (rawTimeDateStamp == 0)
            return (null, true, "Horodatage de compilation PE nul (TimeDateStamp = 0).");

        var compileTime = DateTimeOffset.FromUnixTimeSeconds(rawTimeDateStamp);
        if (compileTime > nowUtc.AddDays(1))
        {
            return (compileTime, true,
                $"Horodatage de compilation PE incoherant dans le futur ({compileTime:yyyy-MM-dd}).");
        }

        if (compileTime < MinPlausibleCompileTime)
        {
            return (compileTime, true,
                $"Horodatage de compilation PE anormalement ancien (< 1995 : {compileTime:yyyy-MM-dd}).");
        }

        return (compileTime, false, null);
    }

    private static int ComputePeRiskScore(
        bool hasPacker,
        double maxEntropy,
        bool hasRwxSection,
        IReadOnlyList<string> suspiciousImports,
        bool timestampAnomaly,
        bool isSigned,
        bool hasValidSig)
    {
        var score = 0;

        if (hasPacker)
            score += 35;
        else if (maxEntropy > 7.2)
            score += 22;
        else if (maxEntropy > 6.8)
            score += 10;

        if (hasRwxSection)
            score += 15;

        if (suspiciousImports.Count > 0)
        {
            var injectionCount = suspiciousImports.Count(i => HighRiskInjectionApis.Contains(i));
            score += Math.Min(35, suspiciousImports.Count * 8 + (injectionCount >= 2 ? 15 : 0));
        }

        if (timestampAnomaly)
            score += 10;

        if (isSigned && hasValidSig)
            score = (int)Math.Round(score * 0.6);
        else if (!isSigned && score >= 25)
            score += 10;

        return Math.Clamp(score, 0, 100);
    }

    private static string? ExtractPublisher(PeFile peFile)
    {
        var cert = SafeTry(() => peFile.SigningAuthenticodeCertificate, null)
                   ?? SafeTry(() => peFile.AuthenticodeInfo?.SigningCertificate, null);

        if (cert is null)
            return null;

        try
        {
            var simple = cert.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
            if (!string.IsNullOrWhiteSpace(simple))
                return simple.Trim();

            return string.IsNullOrWhiteSpace(cert.Subject) ? null : cert.Subject.Trim();
        }
        catch
        {
            return null;
        }
    }

    private static PeAnalysisResult CreateErrorResult(string filePath, string error) =>
        new(
            FilePath: filePath,
            Sha256: string.Empty,
            SizeBytes: 0,
            IsPe: false,
            Is64Bit: false,
            IsDll: false,
            IsDotNet: false,
            IsSigned: false,
            HasValidSignature: false,
            HasValidCertChain: false,
            Publisher: null,
            CompileTime: null,
            RawTimeDateStamp: 0,
            TimestampAnomaly: false,
            TimestampAnomalyReason: null,
            Sections: Array.Empty<PeSectionInfo>(),
            MaxEntropy: 0.0,
            FileEntropy: 0.0,
            ProbablePacker: null,
            TotalImportCount: 0,
            SuspiciousImports: Array.Empty<string>(),
            RiskScore: 0,
            Signals: Array.Empty<string>(),
            MitreTechniques: Array.Empty<string>(),
            Error: error);

    private static T SafeTry<T>(Func<T> action, T fallback)
    {
        try { return action(); }
        catch { return fallback; }
    }
}
