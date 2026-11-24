namespace Sentinel.Shared.Infrastructure;

/// <summary>
/// Emplacements de données de SENTINEL. Racine : variable d'environnement <c>SENTINEL_DATA_DIR</c>
/// si définie (développement / tests), sinon <c>%ProgramData%\Sentinel</c>.
/// </summary>
public static class SentinelPaths
{
    public const string DataDirEnvVar = "SENTINEL_DATA_DIR";

    public static string Root
    {
        get
        {
            var env = Environment.GetEnvironmentVariable(DataDirEnvVar);
            var root = !string.IsNullOrWhiteSpace(env)
                ? Environment.ExpandEnvironmentVariables(env)
                : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Sentinel");
            try
            {
                Directory.CreateDirectory(root);
                return root;
            }
            catch (UnauthorizedAccessException)
            {
                var fallback = Path.Combine(Path.GetTempPath(), "Sentinel");
                Directory.CreateDirectory(fallback);
                return fallback;
            }
        }
    }

    public static string Data => Ensure("Data");
    public static string Logs => Ensure("Logs");
    public static string Quarantine => Ensure("Quarantine");
    public static string Certificates => Ensure("Certs");
    public static string Outbox => Ensure("Outbox");
    public static string Reports => Ensure("Reports");
    public static string Secrets => Ensure("Secrets");
    public static string Rules => Ensure("rules");
    public static string SigmaRules => Ensure(Path.Combine("rules", "sigma"));
    public static string YaraRules => Ensure(Path.Combine("rules", "yara"));
    public static string Models => Ensure("models");

    public static string ServerDatabase => Path.Combine(Data, "sentinel.db");
    public static string ThreatIntelDatabase => Path.Combine(Data, "threat-intel.db");
    public static string AgentOutboxDatabase => Path.Combine(Outbox, "agent-outbox.db");
    public static string AgentStateFile => Path.Combine(Data, "agent-state.json");
    public static string ConsentFile => Path.Combine(Data, "consent.json");
    public static string CanariesRegistryFile => Path.Combine(Data, "canaries.json");
    public static string MlModelFile => Path.Combine(Models, "pe-classifier.zip");
    public static string MlModelMetadataFile => Path.Combine(Models, "pe-classifier.meta.json");

    private static string Ensure(string sub)
    {
        var p = Path.Combine(Root, sub);
        try
        {
            Directory.CreateDirectory(p);
            return p;
        }
        catch (UnauthorizedAccessException)
        {
            var fallback = Path.Combine(Path.GetTempPath(), "Sentinel", sub);
            Directory.CreateDirectory(fallback);
            return fallback;
        }
    }
}

/// <summary>Points de terminaison par défaut (surchargeables via appsettings.json).</summary>
public static class SentinelEndpoints
{
    /// <summary>API REST + SignalR du serveur (boucle locale uniquement).</summary>
    public const string ServerApiUrl = "http://127.0.0.1:5180";
    /// <summary>Canal gRPC agents (HTTP/2 + TLS, certificat client exigé).</summary>
    public const string ServerGrpcUrl = "https://localhost:5181";
    public const int ServerGrpcPort = 5181;
    public const int ServerApiPort = 5180;
    /// <summary>Console d'administration Blazor.</summary>
    public const string AdminUrl = "http://127.0.0.1:5200";

    public const string AgentServiceName = "SentinelAgent";
    public const string ServerServiceName = "SentinelServer";
    public const string WatchdogServiceName = "SentinelWatchdog";
    public const string AdminServiceName = "SentinelAdmin";

    public const string EventLogSource = "Sentinel";
}
