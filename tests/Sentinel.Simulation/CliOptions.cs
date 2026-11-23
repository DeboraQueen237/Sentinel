namespace Sentinel.Simulation;

/// <summary>
/// Options de ligne de commande du banc de simulation et d'évaluation SENTINEL.
/// </summary>
public sealed record CliOptions
{
    public bool ShowHelp { get; init; }
    public string? OutputJsonPath { get; init; }
    public string? OutputMdPath { get; init; }
    public string? PushGrpcUrl { get; init; }
    public bool NoMtls { get; init; }
    public string? CertDirectory { get; init; }
    public string? PushEvalUrl { get; init; }
    public string? BearerToken { get; init; }
    public bool UseOllama { get; init; }
    public string OllamaUrl { get; init; } = "http://localhost:11434";
    public string OllamaModel { get; init; } = "qwen2.5-coder:3b";
    public string? HostId { get; init; }
    public int DelayMs { get; init; }

    public bool IsGrpcReplayMode => !string.IsNullOrWhiteSpace(PushGrpcUrl);

    public static CliOptions Parse(string[] args, out string? error)
    {
        error = null;
        var showHelp = false;
        string? outputJson = null;
        string? outputMd = null;
        string? pushGrpc = null;
        var noMtls = false;
        string? certDir = null;
        string? pushEval = null;
        string? token = null;
        var useOllama = false;
        var ollamaUrl = "http://localhost:11434";
        var ollamaModel = "qwen2.5-coder:3b";
        string? hostId = null;
        var delayMs = 0;

        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            switch (arg.ToLowerInvariant())
            {
                case "-h":
                case "--help":
                case "/?":
                    showHelp = true;
                    break;

                case "--output-json":
                    if (!TryReadValue(args, ref i, arg, out outputJson, out error)) return new CliOptions();
                    break;

                case "--output-md":
                    if (!TryReadValue(args, ref i, arg, out outputMd, out error)) return new CliOptions();
                    break;

                case "--push-grpc":
                    if (!TryReadValue(args, ref i, arg, out pushGrpc, out error)) return new CliOptions();
                    break;

                case "--no-mtls":
                    noMtls = true;
                    break;

                case "--cert-dir":
                    if (!TryReadValue(args, ref i, arg, out certDir, out error)) return new CliOptions();
                    break;

                case "--push-eval":
                    if (!TryReadValue(args, ref i, arg, out pushEval, out error)) return new CliOptions();
                    break;

                case "--token":
                    if (!TryReadValue(args, ref i, arg, out token, out error)) return new CliOptions();
                    break;

                case "--ollama":
                    useOllama = true;
                    break;

                case "--ollama-url":
                    if (!TryReadValue(args, ref i, arg, out var urlVal, out error)) return new CliOptions();
                    ollamaUrl = urlVal!;
                    break;

                case "--ollama-model":
                    if (!TryReadValue(args, ref i, arg, out var modelVal, out error)) return new CliOptions();
                    ollamaModel = modelVal!;
                    break;

                case "--host":
                    if (!TryReadValue(args, ref i, arg, out hostId, out error)) return new CliOptions();
                    break;

                case "--delay-ms":
                    if (!TryReadValue(args, ref i, arg, out var delayStr, out error)) return new CliOptions();
                    if (!int.TryParse(delayStr, out delayMs) || delayMs < 0)
                    {
                        error = $"Valeur invalide pour --delay-ms : '{delayStr}' (entier >= 0 attendu).";
                        return new CliOptions();
                    }
                    break;

                default:
                    error = $"Option inconnue : '{arg}'. Utilisez --help pour afficher l'aide.";
                    return new CliOptions();
            }
        }

        return new CliOptions
        {
            ShowHelp = showHelp,
            OutputJsonPath = outputJson,
            OutputMdPath = outputMd,
            PushGrpcUrl = pushGrpc,
            NoMtls = noMtls,
            CertDirectory = certDir,
            PushEvalUrl = pushEval,
            BearerToken = token,
            UseOllama = useOllama,
            OllamaUrl = ollamaUrl,
            OllamaModel = ollamaModel,
            HostId = hostId,
            DelayMs = delayMs
        };
    }

    private static bool TryReadValue(string[] args, ref int index, string flag, out string? value, out string? error)
    {
        if (index + 1 >= args.Length)
        {
            value = null;
            error = $"L'option '{flag}' attend une valeur.";
            return false;
        }

        value = args[++index];
        error = null;
        return true;
    }

    public static void PrintUsage()
    {
        Console.WriteLine("""
            SENTINEL — Banc de simulation et d'évaluation scientifique (doc §8.4, §14)

            Utilisation :
              dotnet run --project tests/Sentinel.Simulation -- [options]

            Modes :
              (par défaut)               Exécute le benchmark complet A vs B vs C sur les 11 scénarios
                                         d'attaque (v1 + v2) et le corpus bénin 24 h (480+ événements).
              --push-grpc <url>          S'enregistre auprès de Sentinel.Server via gRPC AgentGateway
                                         (ex. https://localhost:5181) et rejoue un scénario réaliste
                                         multi-postes (WS-FINANCE-01, WS-RH-02, SRV-COMPTA-03).
              --push-eval <apiUrl>       Exporte les métriques ScenarioMetricDto[] vers
                                         POST <apiUrl>/api/reports/evaluation après le benchmark.

            Options :
              --output-json <chemin>     Écrit les résultats ScenarioMetricDto[] en JSON.
              --output-md <chemin>       Écrit le rapport scientifique complet en Markdown.
              --token <bearer>           Jeton Bearer administrateur pour --push-eval.
              --no-mtls                  Désactive le certificat client mTLS (mode --push-grpc).
              --cert-dir <dossier>       Dossier PKI alternatif pour SentinelPki (mode --push-grpc).
              --ollama                   Tente d'utiliser Ollama local avant repli sur l'analyste simulé.
              --ollama-url <url>         Endpoint Ollama (défaut : http://localhost:11434).
              --ollama-model <modèle>    Modèle Ollama (défaut : qwen2.5-coder:3b).
              --host <id>                Identifiant de poste unique (mode --push-grpc ou benchmark).
              --delay-ms <ms>            Délai en millisecondes entre événements (démo temps réel).
              -h, --help                 Affiche cette aide.
            """);
    }
}
