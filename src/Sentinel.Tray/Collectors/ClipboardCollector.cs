using System.Runtime.InteropServices;
using Sentinel.Shared.Models;

namespace Sentinel.Tray.Collectors;

/// <summary>
/// Collecteur presse-papiers en session utilisateur via <c>AddClipboardFormatListener</c> (P/Invoke)
/// sur une <see cref="NativeWindow"/> cachée (doc §6.3).
/// Analyse en mémoire uniquement ; aucun contenu brut n'est jamais stocké ni transmis.
/// </summary>
public sealed class ClipboardCollector : NativeWindow, IDisposable
{
    private const int WmClipboardUpdate = 0x031D;

    private readonly Action<SecurityEvent> _onEvent;
    private readonly string _userId;
    private bool _listening;
    private bool _enabled = true;
    private string? _lastHash;
    private DateTimeOffset _lastHashTime = DateTimeOffset.MinValue;
    private bool _disposed;

    public bool IsEnabled
    {
        get => _enabled;
        set => _enabled = value;
    }

    public ClipboardCollector(Action<SecurityEvent> onEvent, string? userId = null)
    {
        _onEvent = onEvent ?? throw new ArgumentNullException(nameof(onEvent));
        _userId = string.IsNullOrWhiteSpace(userId) ? Environment.UserName : userId;

        var cp = new CreateParams
        {
            Caption = "SentinelClipboardListener",
            Style = 0
        };
        CreateHandle(cp);
        _listening = AddClipboardFormatListener(Handle);
    }

    protected override void WndProc(ref Message m)
    {
        if (m.Msg == WmClipboardUpdate && _enabled && !_disposed)
        {
            HandleClipboardUpdate();
        }

        base.WndProc(ref m);
    }

    private void HandleClipboardUpdate()
    {
        try
        {
            if (!Clipboard.ContainsText())
            {
                return;
            }

            var text = Clipboard.GetText();
            var evt = ClipboardAnalyzer.AnalyzeToEvent(text, hostId: string.Empty, userId: _userId);
            text = null; // libération immédiate de la référence en mémoire

            if (evt is null)
            {
                return;
            }

            var hash = evt.Attr(AttributeKeys.ContentHash);
            var now = DateTimeOffset.UtcNow;
            if (!string.IsNullOrEmpty(hash) &&
                string.Equals(hash, _lastHash, StringComparison.Ordinal) &&
                (now - _lastHashTime).TotalSeconds < 5)
            {
                return;
            }

            _lastHash = hash;
            _lastHashTime = now;
            _onEvent(evt);
        }
        catch
        {
            // Le presse-papiers peut être temporairement verrouillé par une autre application.
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_listening && Handle != IntPtr.Zero)
        {
            RemoveClipboardFormatListener(Handle);
            _listening = false;
        }
        if (Handle != IntPtr.Zero)
        {
            DestroyHandle();
        }
    }

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AddClipboardFormatListener(IntPtr hwnd);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool RemoveClipboardFormatListener(IntPtr hwnd);
}
