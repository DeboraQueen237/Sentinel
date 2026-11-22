using System.Diagnostics;
using System.Runtime.InteropServices;
using Sentinel.Shared.Models;

namespace Sentinel.Tray.Collectors;

/// <summary>
/// Collecteur de dynamique de saisie via hook clavier bas niveau (<c>WH_KEYBOARD_LL</c>).
/// GARANTIE VIE PRIVÉE ABSOLUE (doc §2.1, §2.2, §6.6) : le callback ne lit JAMAIS <c>vkCode</c>
/// ni aucun caractère ; il relève uniquement l'horodatage haute précision (<see cref="Stopwatch"/>)
/// et le drapeau d'injection <c>LLKHF_INJECTED</c> (bit 0x10).
/// </summary>
public sealed class TypingRhythmCollector : IDisposable
{
    private const int WhKeyboardLl = 13;
    private const int WmKeyDown = 0x0100;
    private const int WmSysKeyDown = 0x0104;
    private const uint LlkhfInjected = 0x10;
    private const uint LlkhfLowerIlInjected = 0x02;

    private readonly Action<SecurityEvent> _onEvent;
    private readonly string _userId;
    private readonly TypingRhythmAnalyzer _analyzer = new();
    private readonly LowLevelKeyboardProc _hookCallback;
    private readonly double _ticksToMs = 1000.0 / Stopwatch.Frequency;

    private IntPtr _hookHandle;
    private bool _enabled = true;
    private bool _disposed;

    public bool IsHookInstalled => _hookHandle != IntPtr.Zero;

    public bool IsEnabled
    {
        get => _enabled;
        set => _enabled = value;
    }

    public TypingRhythmCollector(Action<SecurityEvent> onEvent, string? userId = null)
    {
        _onEvent = onEvent ?? throw new ArgumentNullException(nameof(onEvent));
        _userId = string.IsNullOrWhiteSpace(userId) ? Environment.UserName : userId;
        _hookCallback = HookCallback;

        InstallHook();
    }

    private void InstallHook()
    {
        try
        {
            using var curProcess = Process.GetCurrentProcess();
            using var curModule = curProcess.MainModule;
            var modHandle = curModule is not null ? GetModuleHandle(curModule.ModuleName) : IntPtr.Zero;
            _hookHandle = SetWindowsHookEx(WhKeyboardLl, _hookCallback, modHandle, 0);
        }
        catch
        {
            _hookHandle = IntPtr.Zero;
        }
    }

    private IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
    {
        if (nCode >= 0 && _enabled && !_disposed)
        {
            var msg = wParam.ToInt32();
            if (msg == WmKeyDown || msg == WmSysKeyDown)
            {
                // Lecture EXCLUSIVE du champ flags à l'offset 8 de KBDLLHOOKSTRUCT (aucune lecture de vkCode/scanCode !).
                var flags = (uint)Marshal.ReadInt32(lParam, 8);
                var isInjected = (flags & (LlkhfInjected | LlkhfLowerIlInjected)) != 0;
                var nowMs = Stopwatch.GetTimestamp() * _ticksToMs;

                var stats = _analyzer.RecordKeystroke(nowMs, isInjected);
                if (stats is not null)
                {
                    var evt = TypingRhythmAnalyzer.ToSecurityEvent(stats, hostId: string.Empty, userId: _userId);
                    ThreadPool.QueueUserWorkItem(_ => _onEvent(evt));
                }
            }
        }

        return CallNextHookEx(_hookHandle, nCode, wParam, lParam);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_hookHandle != IntPtr.Zero)
        {
            UnhookWindowsHookEx(_hookHandle);
            _hookHandle = IntPtr.Zero;
        }
    }

    private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UnhookWindowsHookEx(IntPtr hhk);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr GetModuleHandle(string? lpModuleName);
}
