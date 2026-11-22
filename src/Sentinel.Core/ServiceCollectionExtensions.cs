using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Sentinel.AI;
using Sentinel.Core.Abstractions;
using Sentinel.Shared.Models;

namespace Sentinel.Core;

/// <summary>Enregistrement DI du cœur d'analyse SENTINEL (<c>Sentinel.Core</c> + <c>Sentinel.AI</c>).</summary>
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
            return new ThreatPipeline(settingsSnapshot, llm, loggerFactory, clock);
        });

        services.AddHostedService<OllamaHealthMonitorService>();

        return services;
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
