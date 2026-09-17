using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Data.Sqlite;
using Sf.EndpointAI.Client.Core.Security;
using Sf.EndpointAI.Contracts;

namespace Sf.EndpointAI.Client.Core.State;

public sealed record CachedPolicy(EndpointPolicy Policy, string Signature, DateTimeOffset ReceivedAtUtc);
public sealed record StoredDeviceCredential(
    string Token,
    DateTimeOffset EnrolledAtUtc,
    string? ServerOrigin,
    string? ServerCertificateSpkiSha256);
public sealed record StoredClientOperationState(
    ClientOperationState State,
    DateTimeOffset UpdatedAtUtc,
    string? LastErrorCode,
    string? LastErrorSummary);
public sealed record StoredCommandReceipt(
    Guid CommandId,
    RemoteCommandType Type,
    RemoteCommandStatus Status,
    DateTimeOffset ReceivedAtUtc,
    DateTimeOffset? CompletedAtUtc,
    string? ResultCode,
    string? ResultSummary,
    Guid? DeviceId = null,
    DateTimeOffset? IssuedAtUtc = null,
    DateTimeOffset? ExpiresAtUtc = null);

public sealed class SqliteClientStateStore(string databasePath, ITextProtector? textProtector = null)
{
    private static readonly JsonSerializerOptions JsonOptions = CreateJsonOptions();
    private readonly string _databasePath = Path.GetFullPath(databasePath);

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        var directory = Path.GetDirectoryName(_databasePath)
            ?? throw new InvalidOperationException("The client database path has no parent directory.");
        Directory.CreateDirectory(directory);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS client_identity (
                singleton_id INTEGER PRIMARY KEY CHECK(singleton_id=1),
                device_id TEXT NOT NULL,
                created_at_utc TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS cached_policy (
                singleton_id INTEGER PRIMARY KEY CHECK(singleton_id=1),
                policy_json TEXT NOT NULL,
                signature TEXT NOT NULL,
                policy_version INTEGER NOT NULL,
                server_instance_id TEXT NOT NULL,
                received_at_utc TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS device_credential (
                singleton_id INTEGER PRIMARY KEY CHECK(singleton_id=1),
                protected_token BLOB NOT NULL,
                enrolled_at_utc TEXT NOT NULL,
                server_origin TEXT NULL,
                server_certificate_spki_sha256 TEXT NULL
            );
            CREATE TABLE IF NOT EXISTS client_operation_state (
                singleton_id INTEGER PRIMARY KEY CHECK(singleton_id=1),
                operation_state INTEGER NOT NULL,
                updated_at_utc TEXT NOT NULL,
                last_error_code TEXT NULL,
                last_error_summary TEXT NULL
            );
            CREATE TABLE IF NOT EXISTS remote_command_receipts (
                command_id TEXT PRIMARY KEY,
                command_type INTEGER NOT NULL,
                status INTEGER NOT NULL,
                received_at_utc TEXT NOT NULL,
                completed_at_utc TEXT NULL,
                result_code TEXT NULL,
                result_summary TEXT NULL,
                device_id TEXT NULL,
                issued_at_utc TEXT NULL,
                expires_at_utc TEXT NULL
            );
            """;
        await command.ExecuteNonQueryAsync(cancellationToken);
        await EnsureColumnAsync(connection, "device_credential", "server_origin", "TEXT NULL", cancellationToken);
        await EnsureColumnAsync(connection, "device_credential", "server_certificate_spki_sha256", "TEXT NULL", cancellationToken);
        await EnsureColumnAsync(connection, "remote_command_receipts", "device_id", "TEXT NULL", cancellationToken);
        await EnsureColumnAsync(connection, "remote_command_receipts", "issued_at_utc", "TEXT NULL", cancellationToken);
        await EnsureColumnAsync(connection, "remote_command_receipts", "expires_at_utc", "TEXT NULL", cancellationToken);
    }

    public async Task<Guid> GetOrCreateDeviceIdAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using (var select = connection.CreateCommand())
        {
            select.CommandText = "SELECT device_id FROM client_identity WHERE singleton_id=1;";
            if (await select.ExecuteScalarAsync(cancellationToken) is string existing)
            {
                return Guid.Parse(existing);
            }
        }

        var created = Guid.NewGuid();
        await using var insert = connection.CreateCommand();
        insert.CommandText = """
            INSERT OR IGNORE INTO client_identity (singleton_id, device_id, created_at_utc)
            VALUES (1, $deviceId, $createdAt);
            SELECT device_id FROM client_identity WHERE singleton_id=1;
            """;
        insert.Parameters.AddWithValue("$deviceId", created.ToString("D"));
        insert.Parameters.AddWithValue("$createdAt", DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture));
        return Guid.Parse((string)(await insert.ExecuteScalarAsync(cancellationToken))!);
    }

    public async Task<CachedPolicy?> LoadPolicyAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT policy_json, signature, received_at_utc FROM cached_policy WHERE singleton_id=1;";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        var policy = JsonSerializer.Deserialize<EndpointPolicy>(reader.GetString(0), JsonOptions)
            ?? throw new InvalidOperationException("The cached policy is invalid.");
        return new CachedPolicy(
            policy,
            reader.GetString(1),
            DateTimeOffset.Parse(reader.GetString(2), CultureInfo.InvariantCulture));
    }

    public async Task SavePolicyAsync(
        EndpointPolicy policy,
        string signature,
        DateTimeOffset receivedAtUtc,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentException.ThrowIfNullOrWhiteSpace(signature);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO cached_policy (
                singleton_id, policy_json, signature, policy_version,
                server_instance_id, received_at_utc)
            VALUES (1, $json, $signature, $version, $serverId, $receivedAt)
            ON CONFLICT(singleton_id) DO UPDATE SET
                policy_json=excluded.policy_json,
                signature=excluded.signature,
                policy_version=excluded.policy_version,
                server_instance_id=excluded.server_instance_id,
                received_at_utc=excluded.received_at_utc;
            """;
        command.Parameters.AddWithValue("$json", JsonSerializer.Serialize(policy, JsonOptions));
        command.Parameters.AddWithValue("$signature", signature);
        command.Parameters.AddWithValue("$version", policy.PolicyVersion);
        command.Parameters.AddWithValue("$serverId", policy.ServerInstanceId.ToString("D"));
        command.Parameters.AddWithValue("$receivedAt", receivedAtUtc.ToString("O", CultureInfo.InvariantCulture));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<StoredDeviceCredential?> LoadDeviceCredentialAsync(CancellationToken cancellationToken = default)
    {
        if (textProtector is null)
        {
            return null;
        }

        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT protected_token, enrolled_at_utc, server_origin, server_certificate_spki_sha256
            FROM device_credential WHERE singleton_id=1;
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new StoredDeviceCredential(
            textProtector.Unprotect((byte[])reader[0]),
            DateTimeOffset.Parse(reader.GetString(1), CultureInfo.InvariantCulture),
            reader.IsDBNull(2) ? null : reader.GetString(2),
            reader.IsDBNull(3) ? null : reader.GetString(3));
    }

    public async Task SaveDeviceCredentialAsync(
        StoredDeviceCredential credential,
        CancellationToken cancellationToken = default)
    {
        if (textProtector is null)
        {
            throw new InvalidOperationException("A text protector is required to store device credentials.");
        }

        var protectedToken = textProtector.Protect(credential.Token);
        try
        {
            await using var connection = await OpenAsync(cancellationToken);
            await using var command = connection.CreateCommand();
            command.CommandText = """
                INSERT INTO device_credential (
                    singleton_id, protected_token, enrolled_at_utc,
                    server_origin, server_certificate_spki_sha256)
                VALUES (1, $protectedToken, $enrolledAt, $serverOrigin, $serverPin)
                ON CONFLICT(singleton_id) DO UPDATE SET
                    protected_token=excluded.protected_token,
                    enrolled_at_utc=excluded.enrolled_at_utc,
                    server_origin=excluded.server_origin,
                    server_certificate_spki_sha256=excluded.server_certificate_spki_sha256;
                """;
            command.Parameters.Add("$protectedToken", SqliteType.Blob).Value = protectedToken;
            command.Parameters.AddWithValue("$enrolledAt", credential.EnrolledAtUtc.ToString("O", CultureInfo.InvariantCulture));
            command.Parameters.AddWithValue("$serverOrigin", (object?)credential.ServerOrigin ?? DBNull.Value);
            command.Parameters.AddWithValue("$serverPin", (object?)credential.ServerCertificateSpkiSha256 ?? DBNull.Value);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(protectedToken);
        }
    }

    private static async Task EnsureColumnAsync(
        SqliteConnection connection,
        string tableName,
        string columnName,
        string declaration,
        CancellationToken cancellationToken)
    {
        await using var inspect = connection.CreateCommand();
        inspect.CommandText = $"PRAGMA table_info({tableName});";
        await using var reader = await inspect.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            if (string.Equals(reader.GetString(1), columnName, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }
        }

        await reader.DisposeAsync();
        await using var alter = connection.CreateCommand();
        alter.CommandText = $"ALTER TABLE {tableName} ADD COLUMN {columnName} {declaration};";
        await alter.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<StoredClientOperationState> LoadOperationStateAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT operation_state, updated_at_utc, last_error_code, last_error_summary
            FROM client_operation_state WHERE singleton_id=1;
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return new StoredClientOperationState(ClientOperationState.Enabled, DateTimeOffset.UtcNow, null, null);
        }

        return new StoredClientOperationState(
            (ClientOperationState)reader.GetInt32(0),
            DateTimeOffset.Parse(reader.GetString(1), CultureInfo.InvariantCulture),
            reader.IsDBNull(2) ? null : reader.GetString(2),
            reader.IsDBNull(3) ? null : reader.GetString(3));
    }

    public async Task SaveOperationStateAsync(
        StoredClientOperationState state,
        CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO client_operation_state (
                singleton_id, operation_state, updated_at_utc, last_error_code, last_error_summary)
            VALUES (1, $state, $updatedAt, $errorCode, $errorSummary)
            ON CONFLICT(singleton_id) DO UPDATE SET
                operation_state=excluded.operation_state,
                updated_at_utc=excluded.updated_at_utc,
                last_error_code=excluded.last_error_code,
                last_error_summary=excluded.last_error_summary;
            """;
        command.Parameters.AddWithValue("$state", (int)state.State);
        command.Parameters.AddWithValue("$updatedAt", state.UpdatedAtUtc.ToString("O", CultureInfo.InvariantCulture));
        command.Parameters.AddWithValue("$errorCode", (object?)state.LastErrorCode ?? DBNull.Value);
        command.Parameters.AddWithValue("$errorSummary", (object?)state.LastErrorSummary ?? DBNull.Value);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<StoredCommandReceipt?> LoadCommandReceiptAsync(
        Guid commandId,
        CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT command_type, status, received_at_utc, completed_at_utc, result_code, result_summary,
                   device_id, issued_at_utc, expires_at_utc
            FROM remote_command_receipts WHERE command_id=$commandId;
            """;
        command.Parameters.AddWithValue("$commandId", commandId.ToString("D"));
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new StoredCommandReceipt(
            commandId,
            (RemoteCommandType)reader.GetInt32(0),
            (RemoteCommandStatus)reader.GetInt32(1),
            DateTimeOffset.Parse(reader.GetString(2), CultureInfo.InvariantCulture),
            reader.IsDBNull(3) ? null : DateTimeOffset.Parse(reader.GetString(3), CultureInfo.InvariantCulture),
            reader.IsDBNull(4) ? null : reader.GetString(4),
            reader.IsDBNull(5) ? null : reader.GetString(5),
            reader.IsDBNull(6) ? null : Guid.Parse(reader.GetString(6)),
            reader.IsDBNull(7) ? null : DateTimeOffset.Parse(reader.GetString(7), CultureInfo.InvariantCulture),
            reader.IsDBNull(8) ? null : DateTimeOffset.Parse(reader.GetString(8), CultureInfo.InvariantCulture));
    }

    public async Task<IReadOnlyList<StoredCommandReceipt>> ListExecutingCommandReceiptsAsync(
        Guid deviceId,
        CancellationToken cancellationToken = default)
    {
        var result = new List<StoredCommandReceipt>();
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT command_id, command_type, status, received_at_utc, completed_at_utc,
                   result_code, result_summary, device_id, issued_at_utc, expires_at_utc
            FROM remote_command_receipts
            WHERE status=$executing AND device_id=$deviceId
            ORDER BY received_at_utc;
            """;
        command.Parameters.AddWithValue("$executing", (int)RemoteCommandStatus.Executing);
        command.Parameters.AddWithValue("$deviceId", deviceId.ToString("D"));
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            result.Add(new StoredCommandReceipt(
                Guid.Parse(reader.GetString(0)),
                (RemoteCommandType)reader.GetInt32(1),
                (RemoteCommandStatus)reader.GetInt32(2),
                DateTimeOffset.Parse(reader.GetString(3), CultureInfo.InvariantCulture),
                reader.IsDBNull(4) ? null : DateTimeOffset.Parse(reader.GetString(4), CultureInfo.InvariantCulture),
                reader.IsDBNull(5) ? null : reader.GetString(5),
                reader.IsDBNull(6) ? null : reader.GetString(6),
                Guid.Parse(reader.GetString(7)),
                reader.IsDBNull(8) ? null : DateTimeOffset.Parse(reader.GetString(8), CultureInfo.InvariantCulture),
                reader.IsDBNull(9) ? null : DateTimeOffset.Parse(reader.GetString(9), CultureInfo.InvariantCulture)));
        }

        return result;
    }

    public async Task SaveCommandReceiptAsync(
        StoredCommandReceipt receipt,
        CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO remote_command_receipts (
                command_id, command_type, status, received_at_utc, completed_at_utc,
                result_code, result_summary, device_id, issued_at_utc, expires_at_utc)
            VALUES ($commandId, $commandType, $status, $receivedAt, $completedAt,
                $resultCode, $resultSummary, $deviceId, $issuedAt, $expiresAt)
            ON CONFLICT(command_id) DO UPDATE SET
                status=excluded.status,
                completed_at_utc=excluded.completed_at_utc,
                result_code=excluded.result_code,
                result_summary=excluded.result_summary,
                device_id=COALESCE(excluded.device_id, remote_command_receipts.device_id),
                issued_at_utc=COALESCE(excluded.issued_at_utc, remote_command_receipts.issued_at_utc),
                expires_at_utc=COALESCE(excluded.expires_at_utc, remote_command_receipts.expires_at_utc);
            """;
        command.Parameters.AddWithValue("$commandId", receipt.CommandId.ToString("D"));
        command.Parameters.AddWithValue("$commandType", (int)receipt.Type);
        command.Parameters.AddWithValue("$status", (int)receipt.Status);
        command.Parameters.AddWithValue("$receivedAt", receipt.ReceivedAtUtc.ToString("O", CultureInfo.InvariantCulture));
        command.Parameters.AddWithValue("$completedAt", receipt.CompletedAtUtc is null
            ? DBNull.Value
            : receipt.CompletedAtUtc.Value.ToString("O", CultureInfo.InvariantCulture));
        command.Parameters.AddWithValue("$resultCode", (object?)receipt.ResultCode ?? DBNull.Value);
        command.Parameters.AddWithValue("$resultSummary", (object?)receipt.ResultSummary ?? DBNull.Value);
        command.Parameters.AddWithValue("$deviceId", receipt.DeviceId is null ? DBNull.Value : receipt.DeviceId.Value.ToString("D"));
        command.Parameters.AddWithValue("$issuedAt", receipt.IssuedAtUtc is null ? DBNull.Value : receipt.IssuedAtUtc.Value.ToString("O", CultureInfo.InvariantCulture));
        command.Parameters.AddWithValue("$expiresAt", receipt.ExpiresAtUtc is null ? DBNull.Value : receipt.ExpiresAtUtc.Value.ToString("O", CultureInfo.InvariantCulture));
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
        command.CommandText = "PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;";
        await command.ExecuteNonQueryAsync(cancellationToken);
        return connection;
    }

    private static JsonSerializerOptions CreateJsonOptions()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        options.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.CamelCase));
        return options;
    }
}
