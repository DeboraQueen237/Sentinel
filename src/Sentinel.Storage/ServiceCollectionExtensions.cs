using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Shared.Infrastructure;
using Sentinel.Storage.Services;

namespace Sentinel.Storage;

/// <summary>Méthodes d'extension DI pour enregistrer la couche de persistance SENTINEL.</summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Enregistre <see cref="IDbContextFactory{SentinelDbContext}"/> (singleton),
    /// <see cref="SentinelDbContext"/> (scoped), ainsi que <see cref="SentinelDbInitializer"/>,
    /// <see cref="HashChainWriter"/>, <see cref="IntegrityVerifier"/> et <see cref="RetentionCleaner"/>.
    /// Par défaut, utilise SQLite sur <see cref="SentinelPaths.ServerDatabase"/>.
    /// </summary>
    public static IServiceCollection AddSentinelStorage(
        this IServiceCollection services,
        string? connectionString = null)
    {
        var cs = string.IsNullOrWhiteSpace(connectionString)
            ? $"Data Source={SentinelPaths.ServerDatabase}"
            : connectionString;

        var pragmaInterceptor = new SqlitePragmaConnectionInterceptor();

        return services.AddSentinelStorage(options =>
        {
            options.UseSqlite(cs, sqlite =>
            {
                sqlite.CommandTimeout(30);
            });
            options.AddInterceptors(pragmaInterceptor);
        });
    }

    /// <summary>
    /// Variante permettant de brancher un autre fournisseur EF Core (ex. PostgreSQL / Npgsql).
    /// </summary>
    public static IServiceCollection AddSentinelStorage(
        this IServiceCollection services,
        Action<DbContextOptionsBuilder> configureOptions)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configureOptions);

        services.AddDbContextFactory<SentinelDbContext>(configureOptions);
        services.AddScoped(sp => sp.GetRequiredService<IDbContextFactory<SentinelDbContext>>().CreateDbContext());

        services.AddSingleton<SentinelDbInitializer>();
        services.AddSingleton<HashChainWriter>();
        services.AddSingleton<IntegrityVerifier>();
        services.AddSingleton<RetentionCleaner>();

        return services;
    }
}
