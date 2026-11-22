using System.Data;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Sentinel.Storage;

/// <summary>
/// Initialise la base SENTINEL au démarrage : création du répertoire, schéma (compatible migrations)
/// et configuration SQLite WAL (journalisation performante et concurrence lectures/écritures).
/// </summary>
public sealed class SentinelDbInitializer
{
    private const string InitPragmas =
        "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;";

    private readonly IDbContextFactory<SentinelDbContext> _dbFactory;
    private readonly ILogger<SentinelDbInitializer>? _logger;

    public SentinelDbInitializer(
        IDbContextFactory<SentinelDbContext> dbFactory,
        ILogger<SentinelDbInitializer>? logger = null)
    {
        _dbFactory = dbFactory;
        _logger = logger;
    }

    /// <summary>
    /// Crée/migre le schéma et active les PRAGMA SQLite de production.
    /// Idempotent : peut être appelé à chaque démarrage du serveur.
    /// </summary>
    public async Task InitializeAsync(CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        await InitializeAsync(db, ct).ConfigureAwait(false);
    }

    /// <summary>Initialise un contexte déjà instancié (utile pour les tests avec SQLite en mémoire).</summary>
    public async Task InitializeAsync(SentinelDbContext db, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(db);

        if (db.Database.IsSqlite())
        {
            EnsureSqliteDirectory(db.Database.GetConnectionString());
        }

        var hasMigrations = db.Database.GetMigrations().Any();
        if (hasMigrations)
        {
            await db.Database.MigrateAsync(ct).ConfigureAwait(false);
        }
        else
        {
            await db.Database.EnsureCreatedAsync(ct).ConfigureAwait(false);
        }

        if (db.Database.IsSqlite())
        {
            var connection = db.Database.GetDbConnection();
            var wasOpen = connection.State == ConnectionState.Open;
            if (!wasOpen)
            {
                await db.Database.OpenConnectionAsync(ct).ConfigureAwait(false);
            }

            try
            {
                await using var cmd = connection.CreateCommand();
                cmd.CommandText = InitPragmas;
                await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
            }
            finally
            {
                if (!wasOpen)
                {
                    await db.Database.CloseConnectionAsync().ConfigureAwait(false);
                }
            }

            _logger?.LogInformation("Base SQLite SENTINEL initialisée (mode WAL, foreign_keys=ON, busy_timeout=5000).");
        }
        else
        {
            _logger?.LogInformation("Base de données SENTINEL initialisée ({Provider}).", db.Database.ProviderName);
        }
    }

    private static void EnsureSqliteDirectory(string? connectionString)
    {
        if (string.IsNullOrWhiteSpace(connectionString))
            return;

        try
        {
            var builder = new SqliteConnectionStringBuilder(connectionString);
            var dataSource = builder.DataSource;
            if (string.IsNullOrWhiteSpace(dataSource)
                || string.Equals(dataSource, ":memory:", StringComparison.OrdinalIgnoreCase)
                || dataSource.StartsWith("file::memory:", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            var directory = Path.GetDirectoryName(Path.GetFullPath(dataSource));
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }
        }
        catch
        {
            // Si la chaîne de connexion utilise un format URI particulier, SQLite la gérera directement.
        }
    }
}
