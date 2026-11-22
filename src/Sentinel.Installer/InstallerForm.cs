using System.Diagnostics;

namespace Sentinel.Installer;

/// <summary>
/// Assistant d'installation graphique WinForms multi-étapes incluant l'écran de consentement explicite
/// obligatoire (§2.3) avant le déploiement des binaires, des services, des certificats mTLS et de l'hôte navigateur.
/// </summary>
public sealed class InstallerForm : Form
{
    private readonly Panel _contentPanel = new() { Dock = DockStyle.Fill, Padding = new Padding(24) };
    private readonly Label _stepHeader = new()
    {
        Dock = DockStyle.Top,
        Height = 56,
        Padding = new Padding(24, 14, 24, 0),
        Font = new Font("Segoe UI", 14f, FontStyle.Bold),
        ForeColor = Color.FromArgb(52, 211, 153),
        BackColor = Color.FromArgb(15, 23, 42)
    };

    private readonly Button _btnBack = CreateButton("Précédent", primary: false);
    private readonly Button _btnNext = CreateButton("Suivant", primary: true);
    private readonly Button _btnCancel = CreateButton("Annuler", primary: false);

    // Contrôles étape 2 (Consentement)
    private readonly CheckBox _chkConsent = new()
    {
        Text = "J'ai lu, compris et j'accepte explicitement la collecte des métadonnées techniques listées ci-dessus.",
        AutoSize = true,
        ForeColor = Color.FromArgb(241, 245, 249),
        Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
        Margin = new Padding(0, 12, 0, 0)
    };

    // Contrôles étape 3 (Configuration)
    private readonly TextBox _txtInstallDir = new()
    {
        Text = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Sentinel"),
        Width = 430,
        BackColor = Color.FromArgb(30, 41, 59),
        ForeColor = Color.White,
        BorderStyle = BorderStyle.FixedSingle
    };
    private readonly CheckBox _chkCerts = new() { Text = "Générer les certificats locaux mTLS (PKI SENTINEL)", Checked = true, AutoSize = true };
    private readonly CheckBox _chkServices = new() { Text = "Installer les services Windows (SentinelAgent + SentinelWatchdog)", Checked = true, AutoSize = true };
    private readonly CheckBox _chkServerSvc = new() { Text = "Installer également le service SentinelServer (cœur d'analyse)", Checked = true, AutoSize = true };
    private readonly CheckBox _chkAdminSvc = new() { Text = "Installer également le service SentinelAdmin (console web :5200)", Checked = true, AutoSize = true };
    private readonly CheckBox _chkBrowser = new() { Text = "Enregistrer l'hôte Native Messaging (Chrome & Edge)", Checked = true, AutoSize = true };
    private readonly TextBox _txtExtId = new()
    {
        PlaceholderText = "Identifiant de l'extension Chrome/Edge (facultatif)",
        Width = 360,
        BackColor = Color.FromArgb(30, 41, 59),
        ForeColor = Color.White,
        BorderStyle = BorderStyle.FixedSingle
    };
    private readonly CheckBox _chkTray = new() { Text = "Démarrer automatiquement Sentinel.Tray à l'ouverture de session", Checked = true, AutoSize = true };
    private readonly CheckBox _chkStartNow = new() { Text = "Démarrer immédiatement les services et Sentinel.Tray après installation", Checked = true, AutoSize = true };

    // Contrôles étape 4 (Progression)
    private readonly ProgressBar _progressBar = new() { Dock = DockStyle.Top, Height = 18, Style = ProgressBarStyle.Marquee };
    private readonly TextBox _logBox = new()
    {
        Multiline = true,
        ReadOnly = true,
        ScrollBars = ScrollBars.Vertical,
        Dock = DockStyle.Fill,
        BackColor = Color.FromArgb(15, 23, 42),
        ForeColor = Color.FromArgb(203, 213, 225),
        Font = new Font("Consolas", 9f),
        BorderStyle = BorderStyle.FixedSingle
    };

    private int _step;
    private bool _installed;

    public InstallerForm()
    {
        Text = $"SENTINEL v{InstallerCore.ProductVersion} — Assistant d'installation";
        StartPosition = FormStartPosition.CenterScreen;
        Size = new Size(760, 650);
        MinimumSize = new Size(700, 580);
        BackColor = Color.FromArgb(15, 23, 42);
        ForeColor = Color.FromArgb(241, 245, 249);
        Font = new Font("Segoe UI", 9.5f);

        var footer = new FlowLayoutPanel
        {
            Dock = DockStyle.Bottom,
            Height = 60,
            FlowDirection = FlowDirection.RightToLeft,
            Padding = new Padding(20, 12, 20, 12),
            BackColor = Color.FromArgb(30, 41, 59)
        };

        _btnCancel.Click += (_, _) => Close();
        _btnBack.Click += (_, _) => GoToStep(_step - 1);
        _btnNext.Click += OnNextClicked;
        _chkConsent.CheckedChanged += (_, _) => UpdateNavigationButtons();

        footer.Controls.Add(_btnNext);
        footer.Controls.Add(_btnBack);
        footer.Controls.Add(_btnCancel);

        Controls.Add(_contentPanel);
        Controls.Add(_stepHeader);
        Controls.Add(footer);

        GoToStep(0);
    }

    private void GoToStep(int step)
    {
        _step = Math.Clamp(step, 0, 3);
        _contentPanel.Controls.Clear();

        switch (_step)
        {
            case 0:
                _stepHeader.Text = "Étape 1/4 — Bienvenue dans SENTINEL";
                _contentPanel.Controls.Add(BuildWelcomeView());
                break;
            case 1:
                _stepHeader.Text = "Étape 2/4 — Consentement explicite et vie privée (§2.3)";
                _contentPanel.Controls.Add(BuildConsentView());
                break;
            case 2:
                _stepHeader.Text = "Étape 3/4 — Configuration de l'installation";
                _contentPanel.Controls.Add(BuildConfigView());
                break;
            case 3:
                _stepHeader.Text = "Étape 4/4 — Installation en cours";
                _contentPanel.Controls.Add(BuildProgressView());
                _ = RunInstallationAsync();
                break;
        }

        UpdateNavigationButtons();
    }

    private Control BuildWelcomeView()
    {
        var panel = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false
        };

        panel.Controls.Add(new Label
        {
            Text = "SENTINEL — Agent de détection et de prévention des menaces avec corrélation locale",
            Font = new Font("Segoe UI", 12f, FontStyle.Bold),
            AutoSize = true,
            MaximumSize = new Size(680, 0),
            Margin = new Padding(0, 6, 0, 14)
        });

        var bundleNotice = InstallerCore.HasBundledPayload()
            ? "Package complet prêt : tous les binaires SENTINEL seront déployés automatiquement."
            : "Mode configuration : prépare consentement, certificats mTLS, services et enregistrements.";

        panel.Controls.Add(new Label
        {
            Text = $"""
                Cet assistant va installer et configurer les composants locaux de SENTINEL sur votre poste :

                  • Déploiement des binaires (Serveur, Console Admin, Agent, Watchdog, Tray, BrowserHost, Extension).
                  • Enregistrement de votre consentement explicite horodaté (consent.json).
                  • Certificats locaux mTLS (PKI privée) sécurisant les échanges agent ↔ serveur.
                  • Services Windows avec redémarrage automatique et contrôle d'intégrité SHA-256.
                  • Liaison Native Messaging Chrome/Edge et icône de notification Sentinel.Tray.

                {bundleNotice}
                Toutes les analyses et l'IA locale (Ollama) s'exécutent intégralement sur votre machine.
                """,
            AutoSize = true,
            MaximumSize = new Size(680, 0),
            ForeColor = Color.FromArgb(203, 213, 225)
        });

        if (!InstallerCore.IsElevated())
        {
            var adminHint = new FlowLayoutPanel
            {
                AutoSize = true,
                Margin = new Padding(0, 16, 0, 0),
                FlowDirection = FlowDirection.LeftToRight
            };
            adminHint.Controls.Add(new Label
            {
                Text = "Note : les droits Administrateur sont requis pour écrire dans Program Files et créer les services Windows.",
                AutoSize = true,
                MaximumSize = new Size(490, 0),
                ForeColor = Color.FromArgb(251, 191, 36),
                Margin = new Padding(0, 6, 12, 0)
            });
            var btnElevate = CreateButton("Mode Admin (UAC)", primary: false);
            btnElevate.Width = 140;
            btnElevate.Height = 30;
            btnElevate.Click += (_, _) => ElevateSelf();
            adminHint.Controls.Add(btnElevate);
            panel.Controls.Add(adminHint);
        }

        return panel;
    }

    private Control BuildConsentView()
    {
        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            RowCount = 3,
            ColumnCount = 1
        };
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        layout.Controls.Add(new Label
        {
            Text = "Conformément aux principes d'éthique et de transparence (§2.1–§2.3), veuillez prendre connaissance de la liste fermée des données techniques collectées et des exclusions absolues :",
            AutoSize = true,
            MaximumSize = new Size(680, 0),
            ForeColor = Color.FromArgb(203, 213, 225),
            Margin = new Padding(0, 0, 0, 10)
        }, 0, 0);

        var sb = new System.Text.StringBuilder();
        sb.AppendLine("CANAUX COLLECTÉS (LISTE FERMÉE)");
        sb.AppendLine("────────────────────────────────────────────────────────────");
        foreach (var ch in InstallerCore.ClosedChannelList)
        {
            sb.AppendLine("• " + ch);
        }
        sb.AppendLine();
        sb.AppendLine("EXCLUSIONS ABSOLUES");
        sb.AppendLine("────────────────────────────────────────────────────────────");
        foreach (var ex in InstallerCore.ExplicitExclusions)
        {
            sb.AppendLine("✕ " + ex);
        }

        var textBox = new TextBox
        {
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Vertical,
            Dock = DockStyle.Fill,
            BackColor = Color.FromArgb(30, 41, 59),
            ForeColor = Color.FromArgb(226, 232, 240),
            BorderStyle = BorderStyle.FixedSingle,
            Text = sb.ToString()
        };

        layout.Controls.Add(textBox, 0, 1);
        layout.Controls.Add(_chkConsent, 0, 2);
        return layout;
    }

    private Control BuildConfigView()
    {
        var panel = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            AutoScroll = true
        };

        panel.Controls.Add(new Label { Text = "Répertoire d'installation des binaires :", AutoSize = true, Margin = new Padding(0, 2, 0, 6) });

        var dirRow = new FlowLayoutPanel { AutoSize = true, Margin = new Padding(0, 0, 0, 10) };
        var browseBtn = CreateButton("Parcourir…", primary: false);
        browseBtn.Width = 100;
        browseBtn.Height = 28;
        browseBtn.Click += (_, _) =>
        {
            using var dlg = new FolderBrowserDialog { SelectedPath = _txtInstallDir.Text };
            if (dlg.ShowDialog() == DialogResult.OK)
            {
                _txtInstallDir.Text = dlg.SelectedPath;
            }
        };
        dirRow.Controls.Add(_txtInstallDir);
        dirRow.Controls.Add(browseBtn);
        panel.Controls.Add(dirRow);

        foreach (var cb in new[] { _chkCerts, _chkServices, _chkServerSvc, _chkAdminSvc, _chkBrowser, _chkTray, _chkStartNow })
        {
            cb.ForeColor = Color.FromArgb(226, 232, 240);
            cb.Margin = new Padding(0, 4, 0, 4);
        }

        panel.Controls.Add(_chkCerts);
        panel.Controls.Add(_chkServices);
        panel.Controls.Add(_chkServerSvc);
        panel.Controls.Add(_chkAdminSvc);
        panel.Controls.Add(_chkBrowser);
        panel.Controls.Add(new Label { Text = "ID de l'extension Chrome/Edge (facultatif) :", AutoSize = true, Margin = new Padding(22, 2, 0, 4), ForeColor = Color.FromArgb(148, 163, 184) });
        _txtExtId.Margin = new Padding(22, 0, 0, 6);
        panel.Controls.Add(_txtExtId);
        panel.Controls.Add(_chkTray);
        panel.Controls.Add(_chkStartNow);

        return panel;
    }

    private Control BuildProgressView()
    {
        var container = new Panel { Dock = DockStyle.Fill };
        var spacer = new Panel { Dock = DockStyle.Top, Height = 12 };
        container.Controls.Add(_logBox);
        container.Controls.Add(spacer);
        container.Controls.Add(_progressBar);
        return container;
    }

    private async Task RunInstallationAsync()
    {
        _btnBack.Enabled = false;
        _btnNext.Enabled = false;
        _btnCancel.Enabled = false;
        _logBox.Clear();

        var opts = new InstallOptions(
            _txtInstallDir.Text.Trim(),
            _chkCerts.Checked,
            _chkServices.Checked,
            _chkServerSvc.Checked,
            _chkBrowser.Checked,
            _txtExtId.Text.Trim(),
            _chkTray.Checked,
            _chkAdminSvc.Checked,
            _chkStartNow.Checked);

        try
        {
            await Task.Run(() => InstallerCore.Install(opts, AppendLog));
            _installed = true;
            _stepHeader.Text = "Étape 4/4 — Installation terminée";
            _progressBar.Style = ProgressBarStyle.Continuous;
            _progressBar.Value = 100;
        }
        catch (Exception ex)
        {
            AppendLog($"ERREUR FATALE : {ex.Message}");
            _stepHeader.Text = "Étape 4/4 — Erreur lors de l'installation";
            _progressBar.Style = ProgressBarStyle.Continuous;
            _progressBar.Value = 0;
        }
        finally
        {
            _btnNext.Text = "Terminer";
            _btnNext.Enabled = true;
            _btnCancel.Enabled = false;
        }
    }

    private void AppendLog(string message)
    {
        if (InvokeRequired)
        {
            BeginInvoke(() => AppendLog(message));
            return;
        }

        _logBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}{Environment.NewLine}");
    }

    private void OnNextClicked(object? sender, EventArgs e)
    {
        if (_step == 3)
        {
            Close();
            return;
        }

        if (_step == 1 && !_chkConsent.Checked)
        {
            MessageBox.Show(
                "Vous devez accepter explicitement le consentement avant de poursuivre l'installation.",
                "Consentement requis",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return;
        }

        if (_step == 2 && (_chkServices.Checked || _chkServerSvc.Checked || _chkAdminSvc.Checked) && !InstallerCore.IsElevated())
        {
            var answer = MessageBox.Show(
                "L'installation des services Windows et l'écriture dans Program Files requièrent les privilèges Administrateur.\n\nSouhaitez-vous relancer l'installeur en mode Administrateur (UAC) ?",
                "Élévation requise",
                MessageBoxButtons.YesNoCancel,
                MessageBoxIcon.Question);

            if (answer == DialogResult.Cancel) return;
            if (answer == DialogResult.Yes)
            {
                ElevateSelf();
                return;
            }
        }

        GoToStep(_step + 1);
    }

    private void ElevateSelf()
    {
        var exe = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(exe)) return;
        try
        {
            Process.Start(new ProcessStartInfo(exe) { UseShellExecute = true, Verb = "runas" });
            Close();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Impossible de passer en mode Administrateur : {ex.Message}", "SENTINEL", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    private void UpdateNavigationButtons()
    {
        _btnBack.Enabled = _step is 1 or 2;
        _btnNext.Text = _step switch
        {
            2 => "Installer",
            3 => _installed ? "Terminer" : "Installation…",
            _ => "Suivant"
        };
        _btnNext.Enabled = _step switch
        {
            1 => _chkConsent.Checked,
            3 => _installed,
            _ => true
        };
    }

    private static Button CreateButton(string text, bool primary)
    {
        var btn = new Button
        {
            Text = text,
            Width = 115,
            Height = 34,
            FlatStyle = FlatStyle.Flat,
            BackColor = primary ? Color.FromArgb(16, 185, 129) : Color.FromArgb(51, 65, 85),
            ForeColor = Color.White,
            Margin = new Padding(8, 0, 0, 0)
        };
        btn.FlatAppearance.BorderSize = 0;
        return btn;
    }
}
