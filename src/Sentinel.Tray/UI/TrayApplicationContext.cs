using System.Diagnostics;
using Sentinel.Shared.Infrastructure;
using Sentinel.Shared.Ipc;
using Sentinel.Shared.Models;
using Sentinel.Tray.Collectors;
using Sentinel.Tray.Ipc;

namespace Sentinel.Tray.UI;

/// <summary>
/// Contexte WinForms en zone de notification gérant l'icône SENTINEL, le menu contextuel,
/// les collecteurs utilisateur (presse-papiers &amp; rythme de frappe) et le lien IPC vers <c>Sentinel.Agent</c>.
/// </summary>
public sealed class TrayApplicationContext : ApplicationContext
{
    private readonly SynchronizationContext _uiContext;
    private readonly NotifyIcon _notifyIcon;
    private readonly ToolStripMenuItem _statusMenuItem;
    private readonly TrayIpcClient _ipcClient;
    private readonly ClipboardCollector _clipboardCollector;
    private readonly TypingRhythmCollector _typingCollector;

    private IpcClientSettings _currentSettings = new(true, true, true, OperatingMode.Learning, Array.Empty<string>());
    private Icon _currentIcon;
    private bool _disposed;

    public TrayApplicationContext()
    {
        _uiContext = SynchronizationContext.Current ?? new WindowsFormsSynchronizationContext();
        _currentIcon = TrayIconRenderer.CreateShieldIcon(TrayVisualState.Disconnected);

        _statusMenuItem = new ToolStripMenuItem("Statut SENTINEL : connexion à l'agent…") { Enabled = false };
        var openConsoleItem = new ToolStripMenuItem("Ouvrir la console d'administration", null, OnOpenConsole);
        var privacyItem = new ToolStripMenuItem("Voir le consentement & canaux actifs", null, OnShowPrivacy);
        var exitItem = new ToolStripMenuItem("Quitter", null, OnExit);

        var menu = new ContextMenuStrip();
        menu.Items.Add(_statusMenuItem);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(openConsoleItem);
        menu.Items.Add(privacyItem);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(exitItem);

        _notifyIcon = new NotifyIcon
        {
            Icon = _currentIcon,
            Text = "SENTINEL — Agent en attente de connexion",
            ContextMenuStrip = menu,
            Visible = true
        };
        _notifyIcon.DoubleClick += OnShowPrivacy;

        _ipcClient = new TrayIpcClient();
        _ipcClient.ConnectionChanged += connected => PostUi(() => UpdateVisualStatus(connected));
        _ipcClient.SettingsReceived += settings => PostUi(() => ApplySettings(settings));
        _ipcClient.NotificationReceived += notif => PostUi(() => ShowNotification(notif));

        _clipboardCollector = new ClipboardCollector(evt => _ipcClient.SendEvent(evt));
        _typingCollector = new TypingRhythmCollector(evt => _ipcClient.SendEvent(evt));
    }

    private void ApplySettings(IpcClientSettings settings)
    {
        _currentSettings = settings;
        _clipboardCollector.IsEnabled = settings.ClipboardEnabled;
        _typingCollector.IsEnabled = settings.TypingRhythmEnabled;
        UpdateVisualStatus(_ipcClient.IsConnected);
    }

    private void UpdateVisualStatus(bool connected, bool critical = false)
    {
        var visual = critical
            ? TrayVisualState.Critical
            : !connected
                ? TrayVisualState.Disconnected
                : _currentSettings.Mode == OperatingMode.Active
                    ? TrayVisualState.Active
                    : TrayVisualState.LearningOrWarning;

        var nextIcon = TrayIconRenderer.CreateShieldIcon(visual);
        _notifyIcon.Icon = nextIcon;
        _currentIcon.Dispose();
        _currentIcon = nextIcon;

        var modeLabel = _currentSettings.Mode switch
        {
            OperatingMode.Active => "Actif",
            OperatingMode.Simulation => "Simulation",
            _ => "Apprentissage"
        };

        _statusMenuItem.Text = connected
            ? $"Statut SENTINEL : Connecté ({modeLabel})"
            : "Statut SENTINEL : Agent déconnecté";

        var tip = connected
            ? $"SENTINEL — Actif ({modeLabel})"
            : "SENTINEL — En attente du service SentinelAgent";
        _notifyIcon.Text = tip[..Math.Min(tip.Length, 63)];
    }

    private void ShowNotification(UserNotification notif)
    {
        var icon = notif.Severity switch
        {
            NotificationSeverity.Critical => ToolTipIcon.Error,
            NotificationSeverity.Warning => ToolTipIcon.Warning,
            _ => ToolTipIcon.Info
        };

        if (notif.Severity == NotificationSeverity.Critical)
        {
            UpdateVisualStatus(_ipcClient.IsConnected, critical: true);
        }

        _notifyIcon.ShowBalloonTip(7000, notif.Title, notif.Message, icon);
    }

    private void OnOpenConsole(object? sender, EventArgs e)
    {
        try
        {
            Process.Start(new ProcessStartInfo(SentinelEndpoints.AdminUrl) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Impossible d'ouvrir {SentinelEndpoints.AdminUrl} : {ex.Message}",
                "SENTINEL", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    private void OnShowPrivacy(object? sender, EventArgs e)
    {
        using var dialog = new PrivacyDialog(_ipcClient.IsConnected, _currentSettings);
        dialog.ShowDialog();
    }

    private void OnExit(object? sender, EventArgs e)
    {
        ExitThread();
    }

    private void PostUi(Action action)
    {
        if (_disposed) return;
        _uiContext.Post(_ =>
        {
            if (!_disposed)
            {
                action();
            }
        }, null);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing && !_disposed)
        {
            _disposed = true;
            _typingCollector.Dispose();
            _clipboardCollector.Dispose();
            _ipcClient.Dispose();
            _notifyIcon.Visible = false;
            _notifyIcon.Dispose();
            _currentIcon.Dispose();
        }
        base.Dispose(disposing);
    }
}
