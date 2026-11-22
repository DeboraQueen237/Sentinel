using System.Data.Common;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace Sentinel.Storage;

/// <summary>
/// Intercepteur EF Core appliquant les PRAGMA de connexion SQLite (intégrité référentielle,
/// délai d'attente sur contention et synchronisation) à chaque ouverture de connexion.
/// </summary>
internal sealed class SqlitePragmaConnectionInterceptor : DbConnectionInterceptor
{
    private const string ConnectionPragmas =
        "PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; PRAGMA synchronous=NORMAL;";

    public override void ConnectionOpened(DbConnection connection, ConnectionEndEventData eventData)
    {
        if (connection is SqliteConnection sqliteConnection)
        {
            using var cmd = sqliteConnection.CreateCommand();
            cmd.CommandText = ConnectionPragmas;
            cmd.ExecuteNonQuery();
        }

        base.ConnectionOpened(connection, eventData);
    }

    public override async Task ConnectionOpenedAsync(
        DbConnection connection,
        ConnectionEndEventData eventData,
        CancellationToken cancellationToken = default)
    {
        if (connection is SqliteConnection sqliteConnection)
        {
            await using var cmd = sqliteConnection.CreateCommand();
            cmd.CommandText = ConnectionPragmas;
            await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }

        await base.ConnectionOpenedAsync(connection, eventData, cancellationToken).ConfigureAwait(false);
    }
}
