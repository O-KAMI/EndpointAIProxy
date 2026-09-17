using Microsoft.Data.Sqlite;

namespace Sf.EndpointAI.Client.Core.Configuration;

public sealed record CcSwitchProviderInspection(
    string ProviderId,
    string AppType,
    string Name,
    string SettingsConfig,
    bool IsCurrent,
    Uri? OriginalBaseUri,
    string? ErrorCode);

public sealed record CcSwitchProviderEndpointInspection(
    long EndpointId,
    string ProviderId,
    string AppType,
    string Url,
    Uri? OriginalBaseUri,
    string? ErrorCode);

public sealed record CcSwitchProxyConfigInspection(
    string AppType,
    bool ProxyEnabled,
    bool Enabled,
    string ListenAddress,
    int ListenPort,
    bool LiveTakeoverActive,
    bool HasLiveBackup);

public sealed record CcSwitchDatabaseInspection(
    int UserVersion,
    IReadOnlySet<string> ProviderColumns,
    IReadOnlyList<CcSwitchProviderInspection> Providers,
    IReadOnlyList<CcSwitchProviderEndpointInspection> Endpoints,
    IReadOnlyDictionary<string, CcSwitchProxyConfigInspection> ProxyConfigs,
    bool ProxySchemaSupported,
    bool EndpointSchemaSupported,
    bool ProviderSchemaSupported = true);

public sealed record CcSwitchProviderMutation(
    string ProviderId,
    string AppType,
    string ExpectedSettingsConfig,
    string UpdatedSettingsConfig);

public sealed record CcSwitchEndpointMutation(
    long EndpointId,
    string ProviderId,
    string AppType,
    string ExpectedUrl,
    string UpdatedUrl);

public sealed record CcSwitchDatabaseUpdateResult(
    string DatabasePath,
    string BackupPath,
    int UpdatedProviders,
    int UpdatedEndpoints);

public sealed class CcSwitchDatabaseAdapter
{
    private static readonly string[] RequiredProviderColumns =
    [
        "id",
        "app_type",
        "name",
        "settings_config",
        "is_current",
    ];

    private static readonly string[] RequiredProxyColumns =
    [
        "app_type",
        "proxy_enabled",
        "listen_address",
        "listen_port",
        "enabled",
        "live_takeover_active",
    ];

    private static readonly string[] RequiredEndpointColumns =
    [
        "id",
        "provider_id",
        "app_type",
        "url",
    ];

    private static readonly Uri InspectionUri = new("http://127.0.0.1:18080/r/ccswitch-inspection");

    public static async Task<CcSwitchDatabaseInspection> InspectAsync(
        string databasePath,
        CancellationToken cancellationToken = default)
    {
        var fullPath = ValidateExistingDatabasePath(databasePath);
        await using var connection = await OpenAsync(fullPath, SqliteOpenMode.ReadOnly, cancellationToken);
        var version = await ReadUserVersionAsync(connection, cancellationToken);
        var providerColumns = await ReadTableColumnsAsync(connection, "providers", cancellationToken);
        var providerSchemaSupported = RequiredProviderColumns.All(providerColumns.Contains);
        var providers = providerSchemaSupported
            ? await ReadProvidersAsync(connection, cancellationToken)
            : [];
        var proxyColumns = await ReadTableColumnsAsync(connection, "proxy_config", cancellationToken);
        var proxySchemaSupported = proxyColumns.Count == 0 || RequiredProxyColumns.All(proxyColumns.Contains);
        var endpointColumns = await ReadTableColumnsAsync(connection, "provider_endpoints", cancellationToken);
        var endpointSchemaSupported = endpointColumns.Count == 0 || RequiredEndpointColumns.All(endpointColumns.Contains);

        var backups = await ReadLiveBackupAppsAsync(connection, cancellationToken);
        var proxyConfigs = proxySchemaSupported
            ? await ReadProxyConfigsAsync(connection, proxyColumns.Count > 0, backups, cancellationToken)
            : new Dictionary<string, CcSwitchProxyConfigInspection>(StringComparer.Ordinal);
        var endpoints = endpointSchemaSupported
            ? await ReadEndpointsAsync(connection, endpointColumns.Count > 0, cancellationToken)
            : [];

        return new CcSwitchDatabaseInspection(
            version,
            providerColumns,
            providers,
            endpoints,
            proxyConfigs,
            proxySchemaSupported,
            endpointSchemaSupported,
            providerSchemaSupported);
    }

    public static Task<CcSwitchDatabaseUpdateResult> ApplyAsync(
        string databasePath,
        IReadOnlyList<CcSwitchProviderMutation> providerMutations,
        string backupDirectory,
        CancellationToken cancellationToken = default) =>
        ApplyAsync(databasePath, providerMutations, [], backupDirectory, cancellationToken);

    public static async Task<CcSwitchDatabaseUpdateResult> ApplyAsync(
        string databasePath,
        IReadOnlyList<CcSwitchProviderMutation> providerMutations,
        IReadOnlyList<CcSwitchEndpointMutation> endpointMutations,
        string backupDirectory,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(providerMutations);
        ArgumentNullException.ThrowIfNull(endpointMutations);
        ArgumentException.ThrowIfNullOrWhiteSpace(backupDirectory);
        if (providerMutations.Count == 0 && endpointMutations.Count == 0)
        {
            throw new ArgumentException("At least one CC Switch mutation is required.", nameof(providerMutations));
        }

        var fullPath = ValidateExistingDatabasePath(databasePath);
        var fullBackupDirectory = Path.GetFullPath(backupDirectory);
        Directory.CreateDirectory(fullBackupDirectory);
        var backupPath = Path.Combine(
            fullBackupDirectory,
            $"cc-switch.sf-endpoint-ai.{DateTimeOffset.UtcNow:yyyyMMddTHHmmssfffffffZ}.{Guid.NewGuid():N}.db");

        await using var connection = await OpenAsync(fullPath, SqliteOpenMode.ReadWrite, cancellationToken);
        var providerColumns = await ReadTableColumnsAsync(connection, "providers", cancellationToken);
        EnsureCompatibleSchema("providers", providerColumns, RequiredProviderColumns);
        if (endpointMutations.Count > 0)
        {
            var endpointColumns = await ReadTableColumnsAsync(connection, "provider_endpoints", cancellationToken);
            EnsureCompatibleSchema("provider_endpoints", endpointColumns, RequiredEndpointColumns);
        }

        var backupBuilder = new SqliteConnectionStringBuilder
        {
            DataSource = backupPath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Pooling = false,
        };
        await using (var backup = new SqliteConnection(backupBuilder.ConnectionString))
        {
            await backup.OpenAsync(cancellationToken);
            connection.BackupDatabase(backup);
        }

        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        try
        {
            foreach (var mutation in providerMutations)
            {
                await using var command = connection.CreateCommand();
                command.Transaction = (SqliteTransaction)transaction;
                command.CommandText = """
                    UPDATE providers
                    SET settings_config = $updated
                    WHERE id = $providerId
                      AND app_type = $appType
                      AND settings_config = $expected;
                    """;
                command.Parameters.AddWithValue("$updated", mutation.UpdatedSettingsConfig);
                command.Parameters.AddWithValue("$providerId", mutation.ProviderId);
                command.Parameters.AddWithValue("$appType", mutation.AppType);
                command.Parameters.AddWithValue("$expected", mutation.ExpectedSettingsConfig);
                await EnsureSingleConcurrentUpdateAsync(command, mutation.AppType, mutation.ProviderId, cancellationToken);
            }

            foreach (var mutation in endpointMutations)
            {
                await using var command = connection.CreateCommand();
                command.Transaction = (SqliteTransaction)transaction;
                command.CommandText = """
                    UPDATE provider_endpoints
                    SET url = $updated
                    WHERE id = $endpointId
                      AND provider_id = $providerId
                      AND app_type = $appType
                      AND url = $expected;
                    """;
                command.Parameters.AddWithValue("$updated", mutation.UpdatedUrl);
                command.Parameters.AddWithValue("$endpointId", mutation.EndpointId);
                command.Parameters.AddWithValue("$providerId", mutation.ProviderId);
                command.Parameters.AddWithValue("$appType", mutation.AppType);
                command.Parameters.AddWithValue("$expected", mutation.ExpectedUrl);
                await EnsureSingleConcurrentUpdateAsync(
                    command,
                    mutation.AppType,
                    $"{mutation.ProviderId}/endpoint/{mutation.EndpointId}",
                    cancellationToken);
            }

            await transaction.CommitAsync(cancellationToken);
        }
        catch
        {
            await transaction.RollbackAsync(CancellationToken.None);
            throw;
        }

        return new CcSwitchDatabaseUpdateResult(
            fullPath,
            backupPath,
            providerMutations.Count,
            endpointMutations.Count);
    }

    public static async Task RestoreAsync(
        string databasePath,
        string backupPath,
        CancellationToken cancellationToken = default)
    {
        var fullPath = ValidateExistingDatabasePath(databasePath);
        var fullBackupPath = ValidateExistingDatabasePath(backupPath);
        await using var destination = await OpenAsync(fullPath, SqliteOpenMode.ReadWrite, cancellationToken);
        await using var source = await OpenAsync(fullBackupPath, SqliteOpenMode.ReadOnly, cancellationToken);
        source.BackupDatabase(destination);
    }

    private static async Task<IReadOnlyList<CcSwitchProviderInspection>> ReadProvidersAsync(
        SqliteConnection connection,
        CancellationToken cancellationToken)
    {
        var providers = new List<CcSwitchProviderInspection>();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT id, app_type, name, settings_config, is_current
            FROM providers
            WHERE app_type IN ('claude', 'codex')
            ORDER BY app_type, id;
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var providerId = reader.GetString(0);
            var appType = reader.GetString(1);
            var name = reader.GetString(2);
            var settingsConfig = reader.GetString(3);
            Uri? originalBaseUri = null;
            string? errorCode = null;
            try
            {
                originalBaseUri = CcSwitchSettingsTransformer
                    .InjectBaseUrl(appType, settingsConfig, InspectionUri)
                    .OriginalBaseUri;
            }
            catch (ConfigMutationException exception)
            {
                errorCode = exception.Code;
            }

            providers.Add(new CcSwitchProviderInspection(
                providerId,
                appType,
                name,
                settingsConfig,
                reader.GetBoolean(4),
                originalBaseUri,
                errorCode));
        }

        return providers;
    }

    private static async Task<IReadOnlyList<CcSwitchProviderEndpointInspection>> ReadEndpointsAsync(
        SqliteConnection connection,
        bool tableExists,
        CancellationToken cancellationToken)
    {
        if (!tableExists)
        {
            return [];
        }

        var endpoints = new List<CcSwitchProviderEndpointInspection>();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT id, provider_id, app_type, url
            FROM provider_endpoints
            WHERE app_type IN ('claude', 'codex')
            ORDER BY app_type, provider_id, id;
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var url = reader.GetString(3);
            var valid = Uri.TryCreate(url, UriKind.Absolute, out var uri)
                && (string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
                    || string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase));
            endpoints.Add(new CcSwitchProviderEndpointInspection(
                reader.GetInt64(0),
                reader.GetString(1),
                reader.GetString(2),
                url,
                valid ? uri : null,
                valid ? null : "CCSWITCH_ENDPOINT_URL_INVALID"));
        }

        return endpoints;
    }

    private static async Task<IReadOnlyDictionary<string, CcSwitchProxyConfigInspection>> ReadProxyConfigsAsync(
        SqliteConnection connection,
        bool tableExists,
        IReadOnlySet<string> liveBackupApps,
        CancellationToken cancellationToken)
    {
        var configs = new Dictionary<string, CcSwitchProxyConfigInspection>(StringComparer.Ordinal);
        if (!tableExists)
        {
            return configs;
        }

        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT app_type, proxy_enabled, enabled, listen_address, listen_port, live_takeover_active
            FROM proxy_config
            WHERE app_type IN ('claude', 'codex')
            ORDER BY app_type;
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var appType = reader.GetString(0);
            configs[appType] = new CcSwitchProxyConfigInspection(
                appType,
                reader.GetBoolean(1),
                reader.GetBoolean(2),
                reader.GetString(3),
                reader.GetInt32(4),
                reader.GetBoolean(5),
                liveBackupApps.Contains(appType));
        }

        return configs;
    }

    private static async Task<IReadOnlySet<string>> ReadLiveBackupAppsAsync(
        SqliteConnection connection,
        CancellationToken cancellationToken)
    {
        var columns = await ReadTableColumnsAsync(connection, "proxy_live_backup", cancellationToken);
        if (!columns.Contains("app_type"))
        {
            return new HashSet<string>(StringComparer.Ordinal);
        }

        var apps = new HashSet<string>(StringComparer.Ordinal);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT app_type FROM proxy_live_backup WHERE app_type IN ('claude', 'codex');";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            apps.Add(reader.GetString(0));
        }

        return apps;
    }

    private static async Task EnsureSingleConcurrentUpdateAsync(
        SqliteCommand command,
        string appType,
        string identity,
        CancellationToken cancellationToken)
    {
        var updated = await command.ExecuteNonQueryAsync(cancellationToken);
        if (updated != 1)
        {
            throw new ConfigMutationException(
                "CCSWITCH_DB_CHANGED_CONCURRENTLY",
                $"CC Switch entry '{appType}/{identity}' changed after inspection.");
        }
    }

    private static async Task<SqliteConnection> OpenAsync(
        string databasePath,
        SqliteOpenMode mode,
        CancellationToken cancellationToken)
    {
        var builder = new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = mode,
            Cache = SqliteCacheMode.Shared,
            Pooling = false,
        };
        var connection = new SqliteConnection(builder.ConnectionString);
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA busy_timeout=5000;";
        await command.ExecuteNonQueryAsync(cancellationToken);
        return connection;
    }

    private static async Task<int> ReadUserVersionAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA user_version;";
        return Convert.ToInt32(await command.ExecuteScalarAsync(cancellationToken), System.Globalization.CultureInfo.InvariantCulture);
    }

    private static async Task<IReadOnlySet<string>> ReadTableColumnsAsync(
        SqliteConnection connection,
        string table,
        CancellationToken cancellationToken)
    {
        var columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        await using var command = connection.CreateCommand();
        command.CommandText = $"PRAGMA table_info({table});";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            columns.Add(reader.GetString(1));
        }

        return columns;
    }

    private static void EnsureCompatibleSchema(
        string table,
        IReadOnlySet<string> columns,
        IReadOnlyList<string> requiredColumns)
    {
        var missing = requiredColumns.Where(column => !columns.Contains(column)).ToArray();
        if (missing.Length > 0)
        {
            throw new ConfigMutationException(
                "CCSWITCH_SCHEMA_UNSUPPORTED",
                $"CC Switch {table} schema is missing required columns: {string.Join(", ", missing)}.");
        }
    }

    private static string ValidateExistingDatabasePath(string databasePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);
        var fullPath = Path.GetFullPath(databasePath);
        if (!File.Exists(fullPath))
        {
            throw new FileNotFoundException("The CC Switch database does not exist.", fullPath);
        }

        return fullPath;
    }
}
