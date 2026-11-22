using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Sentinel.Agent.Response;

/// <summary>
/// Contrôle réversible des processus (suspension/reprise via <c>NtSuspendProcess</c>/<c>NtResumeProcess</c>
/// et arrêt via <see cref="Process.Kill(bool)"/>) avec garde-fou protégeant les processus système critiques
/// ainsi que SENTINEL lui-même (doc §9.2, §9.4).
/// </summary>
public sealed class ProcessController
{
    private static readonly HashSet<string> ProtectedProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "System", "Idle", "Registry", "smss", "csrss", "wininit", "winlogon",
        "services", "lsass", "svchost", "dwm", "fontdrvhost", "MsMpEng",
        "Sentinel.Agent", "Sentinel.Server", "Sentinel.Watchdog", "Sentinel.Tray", "Sentinel.Admin"
    };

    public static bool IsProtected(Process process)
    {
        if (process.Id <= 4 || process.Id == Environment.ProcessId)
        {
            return true;
        }

        return ProtectedProcessNames.Contains(process.ProcessName);
    }

    public int? ResolvePid(string? target, IDictionary<string, string>? parameters = null)
    {
        if (parameters is not null &&
            parameters.TryGetValue("pid", out var pidStr) &&
            int.TryParse(pidStr, out var fromParam) &&
            fromParam > 0)
        {
            return fromParam;
        }

        if (int.TryParse(target?.Trim(), out var directPid) && directPid > 0)
        {
            return directPid;
        }

        if (string.IsNullOrWhiteSpace(target))
        {
            return null;
        }

        var name = Path.GetFileNameWithoutExtension(target);
        if (string.IsNullOrWhiteSpace(name))
        {
            return null;
        }

        foreach (var proc in Process.GetProcessesByName(name))
        {
            try
            {
                if (!IsProtected(proc))
                {
                    return proc.Id;
                }
            }
            finally
            {
                proc.Dispose();
            }
        }

        return null;
    }

    public (bool Success, string Message) SuspendProcess(int pid)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);
            if (IsProtected(proc))
            {
                return (false, $"Processus protégé ({proc.ProcessName}, PID {pid}) : suspension refusée.");
            }

            var handle = OpenProcess(ProcessSuspendResume, false, pid);
            if (handle == IntPtr.Zero)
            {
                return (false, $"Impossible d'ouvrir le processus PID {pid} (erreur Win32 {Marshal.GetLastWin32Error()}).");
            }

            try
            {
                var status = NtSuspendProcess(handle);
                return status == 0
                    ? (true, $"Processus {proc.ProcessName} (PID {pid}) suspendu.")
                    : (false, $"NtSuspendProcess a échoué (NTSTATUS 0x{status:X8}).");
            }
            finally
            {
                CloseHandle(handle);
            }
        }
        catch (Exception ex)
        {
            return (false, $"Échec de suspension du PID {pid} : {ex.Message}");
        }
    }

    public (bool Success, string Message) ResumeProcess(int pid)
    {
        IntPtr handle = IntPtr.Zero;
        try
        {
            handle = OpenProcess(ProcessSuspendResume, false, pid);
            if (handle == IntPtr.Zero)
            {
                return (false, $"Impossible d'ouvrir le processus PID {pid} pour reprise (erreur Win32 {Marshal.GetLastWin32Error()}).");
            }

            var status = NtResumeProcess(handle);
            return status == 0
                ? (true, $"Processus PID {pid} repris.")
                : (false, $"NtResumeProcess a échoué (NTSTATUS 0x{status:X8}).");
        }
        catch (Exception ex)
        {
            return (false, $"Échec de reprise du PID {pid} : {ex.Message}");
        }
        finally
        {
            if (handle != IntPtr.Zero)
            {
                CloseHandle(handle);
            }
        }
    }

    public (bool Success, string Message) KillProcess(int pid)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);
            if (IsProtected(proc))
            {
                return (false, $"Processus protégé ({proc.ProcessName}, PID {pid}) : arrêt refusé.");
            }

            var name = proc.ProcessName;
            proc.Kill(entireProcessTree: true);
            return (true, $"Processus {name} (PID {pid}) terminé.");
        }
        catch (Exception ex)
        {
            return (false, $"Échec d'arrêt du PID {pid} : {ex.Message}");
        }
    }

    private const uint ProcessSuspendResume = 0x0800;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("ntdll.dll")]
    private static extern int NtSuspendProcess(IntPtr processHandle);

    [DllImport("ntdll.dll")]
    private static extern int NtResumeProcess(IntPtr processHandle);
}
