using System.Collections.Concurrent;
using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Sentinel.Shared.Security;

namespace Sentinel.Agent.Collectors;

/// <summary>Métadonnées binaires mises en cache par (chemin, horodatage de dernière modification).</summary>
public sealed record BinarySignatureInfo(string? Sha256, bool IsSigned, string? Publisher);

/// <summary>
/// Enrichissement des processus (doc §6.1) avec cache LRU borné (SHA-256 + vérification Authenticode via
/// <c>WinVerifyTrust</c> P/Invoke hors-ligne) afin de maintenir la consommation CPU &lt; 3 %.
/// </summary>
public sealed class ProcessEnricher
{
    private const int MaxCacheEntries = 2048;
    private const long MaxHashFileBytes = 100L * 1024 * 1024;

    private readonly object _lruGate = new();
    private readonly Dictionary<string, LinkedListNode<(string Key, BinarySignatureInfo Value)>> _cacheMap = new(StringComparer.OrdinalIgnoreCase);
    private readonly LinkedList<(string Key, BinarySignatureInfo Value)> _lruList = new();
    private readonly ConcurrentDictionary<int, (string Name, string? Path)> _knownProcesses = new();

    public void RememberProcess(int pid, string name, string? path)
    {
        if (pid <= 0 || string.IsNullOrWhiteSpace(name))
        {
            return;
        }
        _knownProcesses[pid] = (name, path);
        if (_knownProcesses.Count > 4096)
        {
            foreach (var key in _knownProcesses.Keys.Take(512))
            {
                _knownProcesses.TryRemove(key, out _);
            }
        }
    }

    public void ForgetProcess(int pid) => _knownProcesses.TryRemove(pid, out _);

    public (string? Name, string? Path) ResolveParent(int parentPid)
    {
        if (parentPid <= 0)
        {
            return (null, null);
        }

        if (_knownProcesses.TryGetValue(parentPid, out var cached))
        {
            return cached;
        }

        try
        {
            using var proc = Process.GetProcessById(parentPid);
            var path = TryGetProcessPath(parentPid) ?? TryGetMainModulePath(proc);
            var name = proc.ProcessName + ".exe";
            RememberProcess(parentPid, name, path);
            return (name, path);
        }
        catch
        {
            return (null, null);
        }
    }

    public BinarySignatureInfo InspectBinary(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return new BinarySignatureInfo(null, false, null);
        }

        long mtimeTicks;
        long length;
        try
        {
            var info = new FileInfo(path);
            mtimeTicks = info.LastWriteTimeUtc.Ticks;
            length = info.Length;
        }
        catch
        {
            return new BinarySignatureInfo(null, false, null);
        }

        var key = $"{path}|{mtimeTicks}";
        lock (_lruGate)
        {
            if (_cacheMap.TryGetValue(key, out var existing))
            {
                _lruList.Remove(existing);
                _lruList.AddFirst(existing);
                return existing.Value.Value;
            }
        }

        string? sha256 = null;
        if (length > 0 && length <= MaxHashFileBytes)
        {
            try
            {
                sha256 = HashChain.Sha256File(path);
            }
            catch
            {
                // Fichier inaccessible ou temporaire.
            }
        }

        var (signed, publisher) = VerifyAuthenticode(path);
        var result = new BinarySignatureInfo(sha256, signed, publisher);

        lock (_lruGate)
        {
            if (!_cacheMap.ContainsKey(key))
            {
                var node = new LinkedListNode<(string Key, BinarySignatureInfo Value)>((key, result));
                _lruList.AddFirst(node);
                _cacheMap[key] = node;

                while (_cacheMap.Count > MaxCacheEntries && _lruList.Last is { } tail)
                {
                    _cacheMap.Remove(tail.Value.Key);
                    _lruList.RemoveLast();
                }
            }
        }

        return result;
    }

    public static string? TryGetProcessPath(int pid)
    {
        IntPtr handle = IntPtr.Zero;
        try
        {
            handle = OpenProcess(ProcessQueryLimitedInformation, false, pid);
            if (handle == IntPtr.Zero)
            {
                return null;
            }

            var sb = new StringBuilder(1024);
            int size = sb.Capacity;
            return QueryFullProcessImageName(handle, 0, sb, ref size) ? sb.ToString() : null;
        }
        catch
        {
            return null;
        }
        finally
        {
            if (handle != IntPtr.Zero)
            {
                CloseHandle(handle);
            }
        }
    }

    public static (string? CommandLine, int ParentPid) TryQueryWmiProcessDetails(int pid)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT CommandLine, ParentProcessId FROM Win32_Process WHERE ProcessId = {pid}");
            using var results = searcher.Get();
            foreach (ManagementObject obj in results)
            {
                var cmdLine = obj["CommandLine"]?.ToString();
                if (cmdLine is { Length: > 2048 })
                {
                    cmdLine = cmdLine[..2048];
                }
                var ppid = obj["ParentProcessId"] is not null ? Convert.ToInt32(obj["ParentProcessId"]) : 0;
                return (cmdLine, ppid);
            }
        }
        catch
        {
            // Processus déjà terminé ou accès refusé.
        }

        return (null, 0);
    }

    public static bool? TryIsProcessElevated(int pid)
    {
        IntPtr hProc = IntPtr.Zero;
        IntPtr hToken = IntPtr.Zero;
        try
        {
            hProc = OpenProcess(ProcessQueryLimitedInformation, false, pid);
            if (hProc == IntPtr.Zero)
            {
                return null;
            }

            if (!OpenProcessToken(hProc, TokenQuery, out hToken))
            {
                return null;
            }

            int elevation = 0;
            if (GetTokenInformation(hToken, TokenElevationInfoClass, ref elevation, sizeof(int), out _))
            {
                return elevation != 0;
            }
        }
        catch
        {
            // Non déterminable.
        }
        finally
        {
            if (hToken != IntPtr.Zero) CloseHandle(hToken);
            if (hProc != IntPtr.Zero) CloseHandle(hProc);
        }

        return null;
    }

    public static (bool IsSigned, string? Publisher) VerifyAuthenticode(string filePath)
    {
        string? publisher = null;
        try
        {
#pragma warning disable SYSLIB0057 // Extraction de signature Authenticode d'un PE Windows
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(filePath));
#pragma warning restore SYSLIB0057
            publisher = ExtractPublisherName(cert.Subject);
        }
        catch
        {
            return (false, null);
        }

        try
        {
            var fileInfo = new WinTrustFileInfo(filePath);
            var trustData = new WinTrustData(fileInfo);
            try
            {
                var action = WintrustActionGenericVerifyV2;
                var result = WinVerifyTrust(IntPtr.Zero, ref action, ref trustData);
                return (result == 0, publisher);
            }
            finally
            {
                trustData.StateAction = WtdStateActionClose;
                var closeAction = WintrustActionGenericVerifyV2;
                WinVerifyTrust(IntPtr.Zero, ref closeAction, ref trustData);
                trustData.Dispose();
            }
        }
        catch
        {
            return (false, publisher);
        }
    }

    private static string ExtractPublisherName(string subject)
    {
        if (string.IsNullOrWhiteSpace(subject))
        {
            return string.Empty;
        }

        foreach (var part in subject.Split(','))
        {
            var trimmed = part.Trim();
            if (trimmed.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
            {
                return trimmed[3..].Trim('"');
            }
        }

        return subject;
    }

    private static string? TryGetMainModulePath(Process proc)
    {
        try
        {
            return proc.MainModule?.FileName;
        }
        catch
        {
            return null;
        }
    }

    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint TokenQuery = 0x0008;
    private const int TokenElevationInfoClass = 20;

    private static readonly Guid WintrustActionGenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
    private const uint WtdUiNone = 2;
    private const uint WtdRevokeNone = 0;
    private const uint WtdChoiceFile = 1;
    private const uint WtdStateActionVerify = 1;
    private const uint WtdStateActionClose = 2;
    private const uint WtdCacheOnlyUrlRetrieval = 0x00000004;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(IntPtr hProcess, int dwFlags, StringBuilder lpExeName, ref int lpdwSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr tokenHandle, int tokenInformationClass, ref int tokenInformation, int tokenInformationLength, out int returnLength);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
    private static extern uint WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WinTrustData pWVTData);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustFileInfo(string filePath)
    {
        public uint cbStruct = (uint)Marshal.SizeOf<WinTrustFileInfo>();
        public IntPtr pcwszFilePath = Marshal.StringToCoTaskMemUni(filePath);
        public IntPtr hFile = IntPtr.Zero;
        public IntPtr pgKnownSubject = IntPtr.Zero;

        public void Dispose()
        {
            if (pcwszFilePath != IntPtr.Zero)
            {
                Marshal.FreeCoTaskMem(pcwszFilePath);
                pcwszFilePath = IntPtr.Zero;
            }
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustData : IDisposable
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint StateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;

        public WinTrustData(WinTrustFileInfo fileInfo)
        {
            cbStruct = (uint)Marshal.SizeOf<WinTrustData>();
            pPolicyCallbackData = IntPtr.Zero;
            pSIPClientData = IntPtr.Zero;
            dwUIChoice = WtdUiNone;
            fdwRevocationChecks = WtdRevokeNone;
            dwUnionChoice = WtdChoiceFile;
            StateAction = WtdStateActionVerify;
            hWVTStateData = IntPtr.Zero;
            pwszURLReference = IntPtr.Zero;
            dwProvFlags = WtdCacheOnlyUrlRetrieval;
            dwUIContext = 0;
            pSignatureSettings = IntPtr.Zero;

            pFile = Marshal.AllocCoTaskMem(Marshal.SizeOf<WinTrustFileInfo>());
            Marshal.StructureToPtr(fileInfo, pFile, false);
        }

        public void Dispose()
        {
            if (pFile != IntPtr.Zero)
            {
                var info = Marshal.PtrToStructure<WinTrustFileInfo>(pFile);
                info.Dispose();
                Marshal.FreeCoTaskMem(pFile);
                pFile = IntPtr.Zero;
            }
        }
    }
}
