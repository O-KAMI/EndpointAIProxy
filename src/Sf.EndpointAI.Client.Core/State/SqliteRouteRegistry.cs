using System.Globalization;
using Microsoft.Data.Sqlite;
using Sf.EndpointAI.Client.Core.Routing;
using Sf.EndpointAI.Client.Core.Security;
using Sf.EndpointAI.Contracts;

namespace Sf.EndpointAI.Client.Core.State;

public sealed class SqliteRouteRegistry(string databasePath, ITextProtector protector) : IRouteRegistry
{
    private readonly string _databasePath = Path.GetFullPath(databasePath);

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        var directory = Path.GetDirectoryName(_databasePath)
            ?? throw new InvalidOperationException("The state database path has no parent directory.");
        Directory.CreateDirectory(directory);

        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS routes (
                route_id TEXT PRIMARY KEY,
                user_sid TEXT NOT NULL,
                agent_type INTEGER NOT NULL,
                provider_id TEXT NOT NULL,
                protected_original_base_uri BLOB NOT NULL,
                injected_base_uri TEXT NOT NULL,
                status INTEGER NOT NULL,
                created_at_utc TEXT NOT NULL,
                updated_at_utc TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS ux_routes_identity
                ON routes(user_sid, agent_type, provider_id);
            """;
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<RouteRecord?> FindAsync(string routeId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(routeId);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT route_id, user_sid, agent_type, provider_id,
                   protected_original_base_uri, injected_base_uri, status,
                   created_at_utc, updated_at_utc
            FROM routes
            WHERE route_id = $routeId;
            """;
        command.Parameters.AddWithValue("$routeId", routeId);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? Read(reader) : null;
    }

    public async Task<RouteRecord?> FindByIdentityAsync(
        string userSid,
        AgentType agentType,
        string providerId,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userSid);
        ArgumentException.ThrowIfNullOrWhiteSpace(providerId);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT route_id, user_sid, agent_type, provider_id,
                   protected_original_base_uri, injected_base_uri, status,
                   created_at_utc, updated_at_utc
            FROM routes
            WHERE user_sid = $userSid
              AND agent_type = $agentType
              AND provider_id = $providerId
            LIMIT 1;
            """;
        command.Parameters.AddWithValue("$userSid", userSid);
        command.Parameters.AddWithValue("$agentType", (int)agentType);
        command.Parameters.AddWithValue("$providerId", providerId);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? Read(reader) : null;
    }

    public async Task<IReadOnlyList<RouteRecord>> ListAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken);
        return await ReadAllAsync(connection, cancellationToken);
    }

    public async Task<IReadOnlyList<RouteRecord>> ListReadOnlyAsync(CancellationToken cancellationToken = default)
    {
        var builder = new SqliteConnectionStringBuilder
        {
            DataSource = _databasePath,
            Mode = SqliteOpenMode.ReadOnly,
            Cache = SqliteCacheMode.Private,
            Pooling = false,
        };
        await using var connection = new SqliteConnection(builder.ConnectionString);
        await connection.OpenAsync(cancellationToken);
        await using var timeout = connection.CreateCommand();
        timeout.CommandText = "PRAGMA busy_timeout=5000;";
        await timeout.ExecuteNonQueryAsync(cancellationToken);
        return await ReadAllAsync(connection, cancellationToken);
    }

    private async Task<IReadOnlyList<RouteRecord>> ReadAllAsync(
        SqliteConnection connection,
        CancellationToken cancellationToken)
    {
        var routes = new List<RouteRecord>();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT route_id, user_sid, agent_type, provider_id,
                   protected_original_base_uri, injected_base_uri, status,
                   created_at_utc, updated_at_utc
            FROM routes
            ORDER BY created_at_utc;
            """;

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            routes.Add(Read(reader));
        }

        return routes;
    }

    public async Task UpsertAsync(RouteRecord route, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(route);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO routes (
                route_id, user_sid, agent_type, provider_id,
                protected_original_base_uri, injected_base_uri, status,
                created_at_utc, updated_at_utc)
            VALUES (
                $routeId, $userSid, $agentType, $providerId,
                $originalBaseUri, $injectedBaseUri, $status,
                $createdAtUtc, $updatedAtUtc)
            ON CONFLICT(route_id) DO UPDATE SET
                user_sid = excluded.user_sid,
                agent_type = excluded.agent_type,
                provider_id = excluded.provider_id,
                protected_original_base_uri = excluded.protected_original_base_uri,
                injected_base_uri = excluded.injected_base_uri,
                status = excluded.status,
                updated_at_utc = excluded.updated_at_utc;
            """;
        command.Parameters.AddWithValue("$routeId", route.RouteId);
        command.Parameters.AddWithValue("$userSid", route.UserSid);
        command.Parameters.AddWithValue("$agentType", (int)route.AgentType);
        command.Parameters.AddWithValue("$providerId", route.ProviderId);
        command.Parameters.Add("$originalBaseUri", SqliteType.Blob).Value = protector.Protect(route.OriginalBaseUri.AbsoluteUri);
        command.Parameters.AddWithValue("$injectedBaseUri", route.InjectedBaseUri.AbsoluteUri);
        command.Parameters.AddWithValue("$status", (int)route.Status);
        command.Parameters.AddWithValue("$createdAtUtc", route.CreatedAtUtc.ToString("O", CultureInfo.InvariantCulture));
        command.Parameters.AddWithValue("$updatedAtUtc", route.UpdatedAtUtc.ToString("O", CultureInfo.InvariantCulture));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task DeleteByIdentityAsync(
        string userSid,
        AgentType agentType,
        string providerId,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userSid);
        ArgumentException.ThrowIfNullOrWhiteSpace(providerId);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            DELETE FROM routes
            WHERE user_sid = $userSid
              AND agent_type = $agentType
              AND provider_id = $providerId;
            """;
        command.Parameters.AddWithValue("$userSid", userSid);
        command.Parameters.AddWithValue("$agentType", (int)agentType);
        command.Parameters.AddWithValue("$providerId", providerId);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private async Task<SqliteConnection> OpenAsync(CancellationToken cancellationToken)
    {
        var builder = new SqliteConnectionStringBuilder
        {
            DataSource = _databasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared,
            Pooling = true,
        };
        var connection = new SqliteConnection(builder.ConnectionString);
        await connection.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;";
        await command.ExecuteNonQueryAsync(cancellationToken);
        return connection;
    }

    private RouteRecord Read(SqliteDataReader reader)
    {
        var original = protector.Unprotect((byte[])reader[4]);
        return new RouteRecord(
            reader.GetString(0),
            reader.GetString(1),
            (AgentType)reader.GetInt32(2),
            reader.GetString(3),
            new Uri(original, UriKind.Absolute),
            new Uri(reader.GetString(5), UriKind.Absolute),
            (RouteStatus)reader.GetInt32(6),
            DateTimeOffset.Parse(reader.GetString(7), CultureInfo.InvariantCulture),
            DateTimeOffset.Parse(reader.GetString(8), CultureInfo.InvariantCulture));
    }
}
