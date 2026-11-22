using System.Runtime.InteropServices;

namespace Sentinel.Installer;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length > 0)
        {
            AttachParentConsole();
            return RunCli(args);
        }

        ApplicationConfiguration.Initialize();
        Application.Run(new InstallerForm());
        return 0;
    }

    private static int RunCli(string[] args)
    {
        var flags = new HashSet<string>(args, StringComparer.OrdinalIgnoreCase);

        if (flags.Contains("--help") || flags.Contains("-h"))
        {
            Console.WriteLine("""
                SENTINEL Installer — Mode ligne de commande (CLI)
                Options :
                  --accept-consent          Enregistre le consentement explicite signé (obligatoire pour installer)
                  --install-certs           Génère les certificats PKI locaux mTLS
                  --install-dir <chemin>    Répertoire des binaires (défaut : %ProgramFiles%\Sentinel)
                  --source <chemin>         Dossier source contenant les binaires à déployer (défaut : package intégré)
                  --install-services        Installe les services Windows SentinelAgent et SentinelWatchdog
                  --install-server-service  Installe également SentinelServer
                  --install-admin-service   Installe également SentinelAdmin
                  --register-browser        Enregistre le manifeste Native Messaging (Chrome & Edge)
                  --extension-id <id>       Identifiant de l'extension Chrome/Edge
                  --register-tray           Active le démarrage automatique de Sentinel.Tray
                  --start-services          Démarre immédiatement les services et Sentinel.Tray après installation
                  --uninstall               Désinstalle services, démarrage auto, entrée Windows et hôte navigateur
                """);
            return 0;
        }

        if (flags.Contains("--uninstall"))
        {
            try
            {
                InstallerCore.Uninstall(Console.WriteLine);
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Erreur de désinstallation : {ex.Message}");
                return 1;
            }
        }

        if (!flags.Contains("--accept-consent"))
        {
            Console.Error.WriteLine("Consentement explicite requis (§2.3) : passez --accept-consent pour autoriser l'installation automatisée.");
            return 2;
        }

        var installDir = GetOptionValue(args, "--install-dir")
                         ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Sentinel");
        var sourceDir = GetOptionValue(args, "--source");
        var extensionId = GetOptionValue(args, "--extension-id") ?? string.Empty;

        var options = new InstallOptions(
            InstallDirectory: installDir,
            GenerateCertificates: flags.Contains("--install-certs"),
            InstallServices: flags.Contains("--install-services"),
            InstallServerService: flags.Contains("--install-server-service"),
            RegisterBrowserNativeHost: flags.Contains("--register-browser"),
            BrowserExtensionId: extensionId,
            RegisterTrayAutoStart: flags.Contains("--register-tray"),
            InstallAdminService: flags.Contains("--install-admin-service"),
            StartAfterInstall: flags.Contains("--start-services"),
            SourceDirectory: sourceDir);

        try
        {
            InstallerCore.Install(options, Console.WriteLine);
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Erreur d'installation : {ex.Message}");
            return 1;
        }
    }

    private static string? GetOptionValue(string[] args, string optionName)
    {
        for (int i = 0; i < args.Length - 1; i++)
        {
            if (args[i].Equals(optionName, StringComparison.OrdinalIgnoreCase))
            {
                return args[i + 1];
            }
        }
        return null;
    }

    private static void AttachParentConsole()
    {
        try
        {
            AttachConsole(AttachParentProcess);
        }
        catch
        {
            // Ignoré si déjà attaché ou sans console parente.
        }
    }

    private const int AttachParentProcess = -1;

    [DllImport("kernel32.dll")]
    private static extern bool AttachConsole(int dwProcessId);
}
