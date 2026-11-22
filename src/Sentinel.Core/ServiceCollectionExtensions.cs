using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Sentinel.AI;
using Sentinel.Core.Abstractions;
using Sentinel.Detection.Sigma;
using Sentinel.Detection.Static;
using Sentinel.ML;
using Sentinel.Shared.Infrastructure;
using Sentinel.Shared.Models;
using Sentinel.ThreatIntel;

namespace Sentinel.Core;

/// <summary>Enregistrement DI du cœur d'analyse SENTINEL (<c>Sentinel.Core</c> + <c>Sentinel.AI</c> + moteurs v2).</summary>
public static class ServiceCollectionExtensions
{
    public const string OllamaHttpClientName = "SentinelOllama";

    public static IServiceCollection AddSentinelCore(
        this IServiceCollection services,
        SentinelSettings? initialSettings = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        var settingsSnapshot = ThreatPipeline.CloneSettings(initialSettings ?? new SentinelSettings());

        services.AddHttpClient(OllamaHttpClientName, client =>
        {
            // Le timeout fin par requête est géré par OllamaAssessor via CancellationTokenSource
            client.Timeout = Timeout.InfiniteTimeSpan;
        });

        services.AddSingleton(settingsSnapshot);

        // Moteur Sigma natif (M2) : charge %ProgramData%\Sentinel\rules\sigma + règles de démo embarquées si présentes
        services.AddSingleton<ISigmaEngine>(sp =>
        {
            var logger = sp.GetService<ILogger<SigmaEngine>>();
            var engine = new SigmaEngine(logger);
            var dirs = CollectExistingDirectories(
                SentinelPaths.SigmaRules,
                Path.Combine(AppContext.BaseDirectory, "rules", "sigma"),
                Path.Combine(Directory.GetCurrentDirectory(), "rules", "sigma"));
            if (dirs.Count > 0)
            {
                engine.LoadFromDirectories(dirs);
            }
            if (settingsSnapshot.Rules.HotReload && Directory.Exists(SentinelPaths.SigmaRules))
            {
                engine.EnableHotReload(SentinelPaths.SigmaRules);
            }
            return engine;
        });

        // Moteur YARA + Analyse statique PE (M3)
        services.AddSingleton<IYaraScanner>(sp =>
        {
            var logger = sp.GetService<ILogger<YaraScannerService>>();
            var scanner = new YaraScannerService(logger: logger);
            var dirs = CollectExistingDirectories(
                SentinelPaths.YaraRules,
                Path.Combine(AppContext.BaseDirectory, "rules", "yara"),
                Path.Combine(Directory.GetCurrentDirectory(), "rules", "yara"));
            if (dirs.Count > 0)
            {
                scanner.LoadFromDirectories(dirs);
            }
            if (settingsSnapshot.Rules.HotReload && Directory.Exists(SentinelPaths.YaraRules))
            {
                scanner.EnableHotReload(SentinelPaths.YaraRules);
            }
            return scanner;
        });
        services.AddSingleton<PeStaticAnalyzer>();
        services.AddSingleton<IStaticFileScanner>(sp => new StaticFileScanner(
            sp.GetRequiredService<IYaraScanner>(),
            sp.GetRequiredService<PeStaticAnalyzer>(),
            settingsSnapshot.StaticScan,
            sp.GetService<ILogger<StaticFileScanner>>()));

        // Threat Intelligence locale (M4 — SQLite + filtre de Bloom + clients résilients Polly)
        services.AddSentinelThreatIntel(opts =>
        {
            opts.DatabasePath = SentinelPaths.ThreatIntelDatabase;
            opts.Settings = settingsSnapshot.ThreatIntel;
        }, registerBackgroundWorker: false);

        // Classifieur ML PE (M5 — charge le modèle versionné s'il existe)
        services.AddSingleton<IPeMlClassifier>(sp => new PeMlClassifierService(
            modelPath: SentinelPaths.MlModelFile,
            metadataPath: SentinelPaths.MlModelMetadataFile,
            settings: settingsSnapshot.MachineLearning,
            logger: sp.GetService<ILogger<PeMlClassifierService>>()));

        services.AddSingleton<ILlmAssessor>(sp =>
        {
            var factory = sp.GetRequiredService<IHttpClientFactory>();
            var http = factory.CreateClient(OllamaHttpClientName);
            var logger = sp.GetService<ILogger<OllamaAssessor>>();
            var clock = sp.GetService<TimeProvider>();
            return new OllamaAssessor(http, settingsSnapshot.Llm, logger, clock);
        });

        services.AddSingleton<IThreatPipeline>(sp =>
        {
            var llm = sp.GetRequiredService<ILlmAssessor>();
            var loggerFactory = sp.GetService<ILoggerFactory>();
            var clock = sp.GetService<TimeProvider>();
            var sigma = sp.GetService<ISigmaEngine>();
            var threatIntel = sp.GetService<IReputationService>();
            var ml = sp.GetService<IPeMlClassifier>();
            return new ThreatPipeline(settingsSnapshot, llm, loggerFactory, clock, sigma, threatIntel, ml);
        });

        services.AddHostedService<OllamaHealthMonitorService>();

        return services;
    }

    private static List<string> CollectExistingDirectories(params string[] candidates)
    {
        var result = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var c in candidates)
        {
            if (string.IsNullOrWhiteSpace(c) || !Directory.Exists(c)) continue;
            var full = Path.GetFullPath(c);
            if (seen.Add(full)) result.Add(full);
        }
        return result;
    }
}

/// <summary>
/// Service d'arrière-plan vérifiant périodiquement la disponibilité d'Ollama
/// sans jamais bloquer le flux d'ingestion d'événements.
/// </summary>
internal sealed class OllamaHealthMonitorService : BackgroundService
{
    private readonly ILlmAssessor _llm;
    private readonly ILogger<OllamaHealthMonitorService> _logger;

    public OllamaHealthMonitorService(ILlmAssessor llm, ILogger<OllamaHealthMonitorService> logger)
    {
        _llm = llm;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await _llm.CheckHealthAsync(stoppingToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            return;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Vérification initiale d'Ollama échouée.");
        }

        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(30));
        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
        {
            try
            {
                await _llm.CheckHealthAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Vérification périodique d'Ollama échouée.");
            }
        }
    }
}
