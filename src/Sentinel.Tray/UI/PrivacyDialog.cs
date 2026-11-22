using Sentinel.Shared.Infrastructure;
using Sentinel.Shared.Ipc;
using Sentinel.Shared.Models;

namespace Sentinel.Tray.UI;

/// <summary>Fenêtre de transparence vie privée affichant le consentement et l'état des canaux (doc §2.1–§2.3).</summary>
public sealed class PrivacyDialog : Form
{
    public PrivacyDialog(bool connected, IpcClientSettings settings)
    {
        Text = "SENTINEL — Transparence, consentement et canaux actifs";
        StartPosition = FormStartPosition.CenterScreen;
        Size = new Size(640, 520);
        MinimumSize = new Size(560, 440);
        BackColor = Color.FromArgb(15, 23, 42);
        ForeColor = Color.FromArgb(241, 245, 249);
        Font = new Font("Segoe UI", 9.5f);

        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(18),
            RowCount = 4,
            ColumnCount = 1
        };
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        var title = new Label
        {
            Text = "SENTINEL — Protection active & respect de la vie privée",
            Font = new Font("Segoe UI", 13f, FontStyle.Bold),
            ForeColor = Color.FromArgb(52, 211, 153),
            AutoSize = true,
            Margin = new Padding(0, 0, 0, 6)
        };

        var consentExists = File.Exists(SentinelPaths.ConsentFile);
        var status = new Label
        {
            Text = $"Agent local : {(connected ? "Connecté" : "Déconnecté")}   |   Mode : {FormatMode(settings.Mode)}   |   Consentement enregistré : {(consentExists ? "Oui" : "Non détecté")}",
            ForeColor = Color.FromArgb(203, 213, 225),
            AutoSize = true,
            Margin = new Padding(0, 0, 0, 12)
        };

        var details = new TextBox
        {
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Vertical,
            Dock = DockStyle.Fill,
            BackColor = Color.FromArgb(30, 41, 59),
            ForeColor = Color.FromArgb(226, 232, 240),
            BorderStyle = BorderStyle.FixedSingle,
            Text = BuildPrivacyReport(settings)
        };

        var closeBtn = new Button
        {
            Text = "Fermer",
            Width = 110,
            Height = 34,
            Anchor = AnchorStyles.Right,
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.FromArgb(16, 185, 129),
            ForeColor = Color.White,
            Margin = new Padding(0, 12, 0, 0)
        };
        closeBtn.FlatAppearance.BorderSize = 0;
        closeBtn.Click += (_, _) => Close();

        layout.Controls.Add(title, 0, 0);
        layout.Controls.Add(status, 0, 1);
        layout.Controls.Add(details, 0, 2);
        layout.Controls.Add(closeBtn, 0, 3);
        Controls.Add(layout);
    }

    private static string FormatMode(OperatingMode mode) => mode switch
    {
        OperatingMode.Learning => "Apprentissage (aucun blocage automatique)",
        OperatingMode.Simulation => "Simulation (actions journalisées uniquement)",
        OperatingMode.Active => "Actif (réponse graduée réversible)",
        _ => mode.ToString()
    };

    private static string BuildPrivacyReport(IpcClientSettings s) => $"""
        CANAUX COLLECTÉS (LISTE FERMÉE — DOC §2.1)
        ──────────────────────────────────────────────────────────
        • Processus : lancement, chemin, hash SHA-256, signature Authenticode (sans contenu mémoire).
        • Réseau : connexions actives, IP/port/domaine, volumes (sans contenu des paquets).
        • Fichiers : métadonnées, entropie et double extension dans les dossiers surveillés (sans lecture de contenu).
        • Sessions & Périphériques : ouvertures/verrouillages et identifiants USB VID/PID.
        • Presse-papiers [{(s.ClipboardEnabled ? "ACTIF" : "INACTIF")}] : analyse en mémoire uniquement ; seuls le type, le domaine et le hash SHA-256 sont conservés.
        • Dynamique de saisie [{(s.TypingRhythmEnabled ? "ACTIF" : "INACTIF")}] : statistiques d'intervalles temporels uniquement (vitesse, écart-type, flag d'injection BadUSB).
        • Navigation [{(s.BrowserEnabled ? "ACTIF" : "INACTIF")}] : domaines/URLs sans paramètres sensibles via extension dédiée.

        EXCLUSIONS ABSOLUES (DOC §2.2)
        ──────────────────────────────────────────────────────────
        ✕ Aucun enregistrement des touches frappées (pas de keylogger).
        ✕ Aucun stockage du texte brut du presse-papiers ni des mots de passe.
        ✕ Aucun accès au contenu des documents utilisateur ni des messageries chiffrées (WhatsApp, Signal…).
        ✕ Aucun envoi de données sur Internet (analyse et IA 100 % locales).

        Domaines bloqués actuellement synchronisés : {s.BlockedDomains.Count}
        """;
}
