using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;

namespace Sentinel.ThreatIntel;

/// <summary>Extensions d'enregistrement DI pour le module <c>Sentinel.ThreatIntel</c>.</summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Enregistre le magasin SQLite + filtre de Bloom, les clients HTTP résilients Polly v8,
    /// <see cref="IReputationService"/> et le service d'arrière-plan <see cref="ThreatIntelRefreshWorker"/>.
    /// </summary>
    public static IServiceCollection AddSentinelThreatIntel(
        this IServiceCollection services,
        Action<ThreatIntelOptions>? configure = null,
        bool registerBackgroundWorker = true)
    {
        ArgumentNullException.ThrowIfNull(services);

        var options = new ThreatIntelOptions();
        configure?.Invoke(options);

        services.TryAddSingleton(TimeProvider.System);
        services.AddSingleton(options);

        services.AddHttpClient(ThreatIntelHttpClientNames.Feeds, client =>
        {
            client.Timeout = Timeout.InfiniteTimeSpan;
            client.DefaultRequestHeaders.UserAgent.ParseAdd("Sentinel-ThreatIntel/2.0");
        });

        services.AddHttpClient(ThreatIntelHttpClientNames.VirusTotal, client =>
        {
            client.Timeout = Timeout.InfiniteTimeSpan;
            client.DefaultRequestHeaders.UserAgent.ParseAdd("Sentinel-ThreatIntel/2.0");
        });

        services.TryAddSingleton<IThreatIntelSecretProvider>(sp => new ThreatIntelSecretProvider(
            configuration: sp.GetService<IConfiguration>(),
            secretsDirectory: options.SecretsDirectory,
            logger: sp.GetService<ILogger<ThreatIntelSecretProvider>>()));

        services.TryAddSingleton(sp => new ThreatIntelStore(
            databasePath: options.DatabasePath,
            bloomExpectedCapacity: options.BloomExpectedCapacity,
            bloomFalsePositiveRate: options.BloomFalsePositiveRate,
            initialNowUtc: sp.GetRequiredService<TimeProvider>().GetUtcNow()));

        services.TryAddSingleton(sp => new ThreatIntelFeedClients(
            httpClientFactory: sp.GetRequiredService<IHttpClientFactory>(),
            secretProvider: sp.GetRequiredService<IThreatIntelSecretProvider>(),
            options: options,
            clock: sp.GetRequiredService<TimeProvider>(),
            logger: sp.GetService<ILogger<ThreatIntelFeedClients>>()));

        services.TryAddSingleton(sp => new ReputationService(
            store: sp.GetRequiredService<ThreatIntelStore>(),
            clients: sp.GetRequiredService<ThreatIntelFeedClients>(),
            options: options,
            secretProvider: sp.GetRequiredService<IThreatIntelSecretProvider>(),
            clock: sp.GetRequiredService<TimeProvider>(),
            logger: sp.GetService<ILogger<ReputationService>>(),
            ownsStore: false));

        services.TryAddSingleton<IReputationService>(sp => sp.GetRequiredService<ReputationService>());

        if (registerBackgroundWorker)
        {
            services.AddHostedService<ThreatIntelRefreshWorker>();
        }

        return services;
    }
}
