using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Sf.EndpointAI.Contracts;

namespace Sf.EndpointAI.ControlServer;

public sealed record PolicyUpdateRequest(
    long ExpectedVersion,
    bool Enabled,
    RouteMode RouteMode,
    string? GatewayOrigin,
    bool AllowInsecureGateway,
    int PollIntervalSeconds,
    int HeartbeatIntervalSeconds,
    IReadOnlyList<string>? AllowlistedBaseUrls = null);

public sealed record StoredDeviceSummary(
    Guid DeviceId,
    DateTimeOffset LastSeenAtUtc,
    string Hostname,
    string OsVersion,
    int AgentCount,
    long AppliedPolicyVersion,
    ProxyState ProxyState,
    string? ServiceVersion = null,
    int EndpointCount = 0,
    ClientOperationState OperationState = ClientOperationState.Unknown,
    int HeartbeatIntervalSeconds = 60,
    int SchemaVersion = 1);

public sealed record StoredDeviceDetails(
    StoredDeviceSummary Device,
    IReadOnlyList<AgentInventoryItem> Agents,
    IReadOnlyList<AgentEndpointAsset> Endpoints,
    IReadOnlyList<ProxyActivityAsset> Activity,
    DeviceRuntimeState? Runtime);

public sealed record CreateRemoteCommandRequest(
    RemoteCommandType Type,
    string Reason,
    int ExpiresInMinutes);

public sealed record StoredRemoteCommand(
    Guid CommandId,
    Guid DeviceId,
    RemoteCommandType Type,
    RemoteCommandStatus Status,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset ExpiresAtUtc,
    string CreatedBy,
    string Reason,
    DateTimeOffset? DeliveredAtUtc,
    DateTimeOffset? StartedAtUtc,
    DateTimeOffset? CompletedAtUtc,
    string? ResultCode,
    string? ResultSummary,
    int DeliveryCount);

public sealed record EventStoreResult(int Accepted, int Duplicates);
public sealed record StoredAdminAudit(
    Guid AuditId,
    DateTimeOffset OccurredAtUtc,
    string Actor,
    string Action,
    Guid? DeviceId,
    Guid? CommandId,
    string Summary);

public sealed class ControlStore(string databasePath, JsonSerializerOptions jsonOptions)
{
    private readonly string _databasePath = Path.GetFullPath(databasePath);

    public async Task InitializeAsync(EndpointPolicy seedPolicy, CancellationToken cancellationToken = default)
    {
        var directory = Path.GetDirectoryName(_databasePath)
            ?? throw new InvalidOperationException("The control database path has no parent directory.");
        Directory.CreateDirectory(directory);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at_utc TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS control_policy (
                singleton_id INTEGER PRIMARY KEY CHECK(singleton_id = 1),
                policy_json TEXT NOT NULL,
                policy_version INTEGER NOT NULL,
                server_instance_id TEXT NOT NULL,
                updated_at_utc TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS device_heartbeats (
                device_id TEXT PRIMARY KEY,
                observed_at_utc TEXT NOT NULL,
                received_at_utc TEXT NOT NULL,
                hostname TEXT NOT NULL,
                os_version TEXT NOT NULL,
                applied_policy_version INTEGER NOT NULL,
                proxy_state INTEGER NOT NULL,
                heartbeat_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS agent_inventory (
                device_id TEXT NOT NULL,
                instance_id TEXT NOT NULL,
                user_sid TEXT NOT NULL,
                agent_type INTEGER NOT NULL,
                route_status INTEGER NOT NULL,
                last_seen_at_utc TEXT NOT NULL,
                inventory_json TEXT NOT NULL,
                PRIMARY KEY(device_id, instance_id)
            );
            CREATE INDEX IF NOT EXISTS ix_agent_inventory_type
                ON agent_inventory(agent_type, route_status);
            CREATE TABLE IF NOT EXISTS endpoint_events (
                event_id TEXT PRIMARY KEY,
                device_id TEXT NOT NULL,
                occurred_at_utc TEXT NOT NULL,
                received_at_utc TEXT NOT NULL,
                severity INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                code TEXT NOT NULL,
                event_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_endpoint_events_received
                ON endpoint_events(received_at_utc);
            CREATE TABLE IF NOT EXISTS device_runtime (
                device_id TEXT PRIMARY KEY,
                schema_version INTEGER NOT NULL,
                service_version TEXT NOT NULL,
                heartbeat_interval_seconds INTEGER NOT NULL,
                operation_state INTEGER NOT NULL,
                source_ip TEXT NULL,
                runtime_json TEXT NOT NULL,
                updated_at_utc TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS agent_endpoint_assets (
                device_id TEXT NOT NULL,
                asset_id TEXT NOT NULL,
                user_sid TEXT NOT NULL,
                agent_family TEXT NOT NULL,
                route_status INTEGER NOT NULL,
                observed_at_utc TEXT NOT NULL,
                asset_json TEXT NOT NULL,
                PRIMARY KEY(device_id, asset_id)
            );
            CREATE INDEX IF NOT EXISTS ix_agent_endpoint_assets_family
                ON agent_endpoint_assets(agent_family, route_status);
            CREATE TABLE IF NOT EXISTS proxy_activity (
                device_id TEXT NOT NULL,
                asset_id TEXT NOT NULL,
                traffic_state INTEGER NOT NULL,
                last_request_at_utc TEXT NULL,
                activity_json TEXT NOT NULL,
                PRIMARY KEY(device_id, asset_id)
            );
            CREATE TABLE IF NOT EXISTS device_credentials (
                device_id TEXT PRIMARY KEY,
                token_hash TEXT NOT NULL,
                enrolled_at_utc TEXT NOT NULL,
                last_authenticated_at_utc TEXT NULL,
                revoked INTEGER NOT NULL DEFAULT 0
            );
            CREATE UNIQUE INDEX IF NOT EXISTS ix_device_credentials_token_hash
                ON device_credentials(token_hash);
            CREATE TABLE IF NOT EXISTS remote_commands (
                command_id TEXT PRIMARY KEY,
                device_id TEXT NOT NULL,
                command_type INTEGER NOT NULL,
                status INTEGER NOT NULL,
                created_at_utc TEXT NOT NULL,
                expires_at_utc TEXT NOT NULL,
                created_by TEXT NOT NULL,
                reason TEXT NOT NULL,
                delivered_at_utc TEXT NULL,
                started_at_utc TEXT NULL,
                completed_at_utc TEXT NULL,
                result_code TEXT NULL,
                result_summary TEXT NULL,
                delivery_count INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS ix_remote_commands_device_status
                ON remote_commands(device_id, status, created_at_utc);
            CREATE TABLE IF NOT EXISTS admin_audit_log (
                audit_id TEXT PRIMARY KEY,
                occurred_at_utc TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                device_id TEXT NULL,
                command_id TEXT NULL,
                summary TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_admin_audit_occurred
                ON admin_audit_log(occurred_at_utc);
            INSERT OR IGNORE INTO schema_migrations(version, applied_at_utc)
            VALUES (2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
            """;
        await command.ExecuteNonQueryAsync(cancellationToken);

        await using var seed = connection.CreateCommand();
        seed.CommandText = """
            INSERT OR IGNORE INTO control_policy (
                singleton_id, policy_json, policy_version, server_instance_id, updated_at_utc)
            VALUES (1, $json, $version, $serverId, $updatedAt);
            """;
        seed.Parameters.AddWithValue("$json", JsonSerializer.Serialize(seedPolicy, jsonOptions));
        seed.Parameters.AddWithValue("$version", seedPolicy.PolicyVersion);
        seed.Parameters.AddWithValue("$serverId", seedPolicy.ServerInstanceId.ToString("D"));
        seed.Parameters.AddWithValue("$updatedAt", seedPolicy.IssuedAtUtc.ToString("O", CultureInfo.InvariantCulture));
        await seed.ExecuteNonQueryAsync(cancellationToken);
        await MigratePolicyAllowlistAsync(connection, cancellationToken);
    }

    public async Task<EndpointPolicy> GetPolicyAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT policy_json FROM control_policy WHERE singleton_id=1;";
        var json = (string?)await command.ExecuteScalarAsync(cancellationToken)
            ?? throw new InvalidOperationException("The control policy has not been initialized.");
        return JsonSerializer.Deserialize<EndpointPolicy>(json, jsonOptions)
            ?? throw new InvalidOperationException("The stored control policy is invalid.");
    }

    public async Task<EndpointPolicy?> TryUpdatePolicyAsync(
        PolicyUpdateRequest request,
        CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        EndpointPolicy current;
        await using (var select = connection.CreateCommand())
        {
            select.Transaction = (SqliteTransaction)transaction;
            select.CommandText = "SELECT policy_json FROM control_policy WHERE singleton_id=1;";
            var currentJson = (string?)await select.ExecuteScalarAsync(cancellationToken)
                ?? throw new InvalidOperationException("The control policy has not been initialized.");
            current = JsonSerializer.Deserialize<EndpointPolicy>(currentJson, jsonOptions)
                ?? throw new InvalidOperationException("The stored control policy is invalid.");
        }

        if (current.PolicyVersion != request.ExpectedVersion)
        {
            await transaction.RollbackAsync(cancellationToken);
            return null;
        }

        var allowlistedBaseUrls = request.AllowlistedBaseUrls is null
            ? current.AllowlistedBaseUrls ?? [BaseUrlAllowlist.LegacyCcrBaseUrl]
            : BaseUrlAllowlist.Normalize(request.AllowlistedBaseUrls);
        var updated = new EndpointPolicy(
            1,
            current.ServerInstanceId,
            checked(current.PolicyVersion + 1),
            request.Enabled,
            request.RouteMode,
            request.GatewayOrigin,
            request.AllowInsecureGateway,
            request.PollIntervalSeconds,
            request.HeartbeatIntervalSeconds,
            DateTimeOffset.UtcNow,
            allowlistedBaseUrls);
        await using var update = connection.CreateCommand();
        update.Transaction = (SqliteTransaction)transaction;
        update.CommandText = """
            UPDATE control_policy
            SET policy_json=$json,
                policy_version=$newVersion,
                updated_at_utc=$updatedAt
            WHERE singleton_id=1 AND policy_version=$expectedVersion;
            """;
        update.Parameters.AddWithValue("$json", JsonSerializer.Serialize(updated, jsonOptions));
        update.Parameters.AddWithValue("$newVersion", updated.PolicyVersion);
        update.Parameters.AddWithValue("$updatedAt", updated.IssuedAtUtc.ToString("O", CultureInfo.InvariantCulture));
        update.Parameters.AddWithValue("$expectedVersion", request.ExpectedVersion);
        if (await update.ExecuteNonQueryAsync(cancellationToken) != 1)
        {
            await transaction.RollbackAsync(cancellationToken);
            return null;
        }

        await transaction.CommitAsync(cancellationToken);
        return updated;
    }

    private async Task MigratePolicyAllowlistAsync(
        SqliteConnection connection,
        CancellationToken cancellationToken)
    {
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        await using (var applied = connection.CreateCommand())
        {
            applied.Transaction = (SqliteTransaction)transaction;
            applied.CommandText = "SELECT COUNT(*) FROM schema_migrations WHERE version=3;";
            if (Convert.ToInt32(await applied.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture) != 0)
            {
                await transaction.RollbackAsync(cancellationToken);
                return;
            }
        }

        await using (var select = connection.CreateCommand())
        {
            select.Transaction = (SqliteTransaction)transaction;
            select.CommandText = "SELECT policy_json FROM control_policy WHERE singleton_id=1;";
            var json = (string?)await select.ExecuteScalarAsync(cancellationToken)
                ?? throw new InvalidOperationException("The control policy has not been initialized.");
            var policy = JsonSerializer.Deserialize<EndpointPolicy>(json, jsonOptions)
                ?? throw new InvalidOperationException("The stored control policy is invalid.");
            if (policy.AllowlistedBaseUrls is null)
            {
                var migrated = policy with
                {
                    PolicyVersion = checked(policy.PolicyVersion + 1),
                    IssuedAtUtc = DateTimeOffset.UtcNow,
                    AllowlistedBaseUrls = [BaseUrlAllowlist.LegacyCcrBaseUrl],
                };
                await using var update = connection.CreateCommand();
                update.Transaction = (SqliteTransaction)transaction;
                update.CommandText = """
                    UPDATE control_policy
                    SET policy_json=$json,
                        policy_version=$version,
                        updated_at_utc=$updatedAt
                    WHERE singleton_id=1;
                    """;
                update.Parameters.AddWithValue("$json", JsonSerializer.Serialize(migrated, jsonOptions));
                update.Parameters.AddWithValue("$version", migrated.PolicyVersion);
                update.Parameters.AddWithValue("$updatedAt", migrated.IssuedAtUtc.ToString("O", CultureInfo.InvariantCulture));
                await update.ExecuteNonQueryAsync(cancellationToken);
            }
        }

        await using (var migration = connection.CreateCommand())
        {
            migration.Transaction = (SqliteTransaction)transaction;
            migration.CommandText = "INSERT INTO schema_migrations(version, applied_at_utc) VALUES (3, $appliedAt);";
            migration.Parameters.AddWithValue("$appliedAt", DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture));
            await migration.ExecuteNonQueryAsync(cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
    }

    public async Task RecordHeartbeatAsync(HeartbeatRequest heartbeat, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        await using (var command = connection.CreateCommand())
        {
            command.Transaction = (SqliteTransaction)transaction;
            command.CommandText = """
                INSERT INTO device_heartbeats (
                    device_id, observed_at_utc, received_at_utc, hostname, os_version,
                    applied_policy_version, proxy_state, heartbeat_json)
                VALUES ($deviceId, $observedAt, $receivedAt, $hostname, $osVersion,
                    $policyVersion, $proxyState, $json)
                ON CONFLICT(device_id) DO UPDATE SET
                    observed_at_utc=excluded.observed_at_utc,
                    received_at_utc=excluded.received_at_utc,
                    hostname=excluded.hostname,
                    os_version=excluded.os_version,
                    applied_policy_version=excluded.applied_policy_version,
                    proxy_state=excluded.proxy_state,
                    heartbeat_json=excluded.heartbeat_json;
                """;
            command.Parameters.AddWithValue("$deviceId", heartbeat.Device.DeviceId.ToString("D"));
            command.Parameters.AddWithValue("$observedAt", heartbeat.ObservedAtUtc.ToString("O", CultureInfo.InvariantCulture));
            command.Parameters.AddWithValue("$receivedAt", DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture));
            command.Parameters.AddWithValue("$hostname", heartbeat.Device.Hostname);
            command.Parameters.AddWithValue("$osVersion", heartbeat.Device.OsVersion);
            command.Parameters.AddWithValue("$policyVersion", heartbeat.Policy.AppliedVersion ?? 0);
            command.Parameters.AddWithValue("$proxyState", (int)heartbeat.Proxy.State);
            command.Parameters.AddWithValue("$json", JsonSerializer.Serialize(heartbeat, jsonOptions));
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        await using (var delete = connection.CreateCommand())
        {
            delete.Transaction = (SqliteTransaction)transaction;
            delete.CommandText = "DELETE FROM agent_inventory WHERE device_id=$deviceId;";
            delete.Parameters.AddWithValue("$deviceId", heartbeat.Device.DeviceId.ToString("D"));
            await delete.ExecuteNonQueryAsync(cancellationToken);
        }

        foreach (var agent in heartbeat.Agents)
        {
            await using var insert = connection.CreateCommand();
            insert.Transaction = (SqliteTransaction)transaction;
            insert.CommandText = """
                INSERT INTO agent_inventory (
                    device_id, instance_id, user_sid, agent_type, route_status,
                    last_seen_at_utc, inventory_json)
                VALUES ($deviceId, $instanceId, $userSid, $agentType, $routeStatus,
                    $lastSeenAt, $json);
                """;
            insert.Parameters.AddWithValue("$deviceId", heartbeat.Device.DeviceId.ToString("D"));
            insert.Parameters.AddWithValue("$instanceId", agent.InstanceId.ToString("D"));
            insert.Parameters.AddWithValue("$userSid", agent.UserSid);
            insert.Parameters.AddWithValue("$agentType", (int)agent.AgentType);
            insert.Parameters.AddWithValue("$routeStatus", (int)agent.RouteStatus);
            insert.Parameters.AddWithValue("$lastSeenAt", agent.LastSeenAtUtc.ToString("O", CultureInfo.InvariantCulture));
            insert.Parameters.AddWithValue("$json", JsonSerializer.Serialize(agent, jsonOptions));
            await insert.ExecuteNonQueryAsync(cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
    }

    public async Task RecordHeartbeatV2Async(
        HeartbeatV2Request heartbeat,
        string? sourceIp,
        int heartbeatIntervalSeconds,
        CancellationToken cancellationToken = default)
    {
        await RecordHeartbeatAsync(
            new HeartbeatRequest(
                1,
                heartbeat.HeartbeatId,
                heartbeat.ObservedAtUtc,
                heartbeat.Device,
                heartbeat.Policy,
                heartbeat.Proxy,
                heartbeat.Users,
                heartbeat.Agents),
            cancellationToken);

        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        await using (var runtime = connection.CreateCommand())
        {
            runtime.Transaction = (SqliteTransaction)transaction;
            runtime.CommandText = """
                INSERT INTO device_runtime (
                    device_id, schema_version, service_version, heartbeat_interval_seconds,
                    operation_state, source_ip, runtime_json, updated_at_utc)
                VALUES ($deviceId, 2, $serviceVersion, $heartbeatInterval,
                    $operationState, $sourceIp, $runtimeJson, $updatedAt)
                ON CONFLICT(device_id) DO UPDATE SET
                    schema_version=excluded.schema_version,
                    service_version=excluded.service_version,
                    heartbeat_interval_seconds=excluded.heartbeat_interval_seconds,
                    operation_state=excluded.operation_state,
                    source_ip=excluded.source_ip,
                    runtime_json=excluded.runtime_json,
                    updated_at_utc=excluded.updated_at_utc;
                """;
            runtime.Parameters.AddWithValue("$deviceId", heartbeat.Device.DeviceId.ToString("D"));
            runtime.Parameters.AddWithValue("$serviceVersion", heartbeat.Device.ServiceVersion);
            runtime.Parameters.AddWithValue("$heartbeatInterval", heartbeatIntervalSeconds);
            runtime.Parameters.AddWithValue("$operationState", (int)heartbeat.Runtime.OperationState);
            runtime.Parameters.AddWithValue("$sourceIp", (object?)sourceIp ?? DBNull.Value);
            runtime.Parameters.AddWithValue("$runtimeJson", JsonSerializer.Serialize(heartbeat.Runtime, jsonOptions));
            runtime.Parameters.AddWithValue("$updatedAt", DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture));
            await runtime.ExecuteNonQueryAsync(cancellationToken);
        }

        await DeleteDeviceRowsAsync(connection, (SqliteTransaction)transaction, "agent_endpoint_assets", heartbeat.Device.DeviceId, cancellationToken);
        foreach (var endpoint in heartbeat.Endpoints)
        {
            await using var insert = connection.CreateCommand();
            insert.Transaction = (SqliteTransaction)transaction;
            insert.CommandText = """
                INSERT INTO agent_endpoint_assets (
                    device_id, asset_id, user_sid, agent_family, route_status,
                    observed_at_utc, asset_json)
                VALUES ($deviceId, $assetId, $userSid, $agentFamily, $routeStatus,
                    $observedAt, $json);
                """;
            insert.Parameters.AddWithValue("$deviceId", heartbeat.Device.DeviceId.ToString("D"));
            insert.Parameters.AddWithValue("$assetId", endpoint.AssetId.ToString("D"));
            insert.Parameters.AddWithValue("$userSid", endpoint.UserSid);
            insert.Parameters.AddWithValue("$agentFamily", endpoint.AgentFamily);
            insert.Parameters.AddWithValue("$routeStatus", (int)endpoint.RouteStatus);
            insert.Parameters.AddWithValue("$observedAt", endpoint.ObservedAtUtc.ToString("O", CultureInfo.InvariantCulture));
            insert.Parameters.AddWithValue("$json", JsonSerializer.Serialize(endpoint, jsonOptions));
            await insert.ExecuteNonQueryAsync(cancellationToken);
        }

        var previousActivity = new Dictionary<Guid, ProxyActivityAsset>();
        await using (var selectActivity = connection.CreateCommand())
        {
            selectActivity.Transaction = (SqliteTransaction)transaction;
            selectActivity.CommandText = "SELECT asset_id, activity_json FROM proxy_activity WHERE device_id=$deviceId;";
            selectActivity.Parameters.AddWithValue("$deviceId", heartbeat.Device.DeviceId.ToString("D"));
            await using var reader = await selectActivity.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                var value = JsonSerializer.Deserialize<ProxyActivityAsset>(reader.GetString(1), jsonOptions);
                if (value is not null)
                {
                    previousActivity[Guid.Parse(reader.GetString(0))] = value;
                }
            }
        }

        await DeleteDeviceRowsAsync(connection, (SqliteTransaction)transaction, "proxy_activity", heartbeat.Device.DeviceId, cancellationToken);
        foreach (var activity in heartbeat.Activity)
        {
            var storedActivity = activity.State == ProxyTrafficState.NeverObserved
                && previousActivity.TryGetValue(activity.AssetId, out var previous)
                && previous.State != ProxyTrafficState.NeverObserved
                    ? activity with
                    {
                        State = previous.State,
                        LastRequestAtUtc = previous.LastRequestAtUtc,
                        LastSuccessAtUtc = previous.LastSuccessAtUtc,
                        LastFailureAtUtc = previous.LastFailureAtUtc,
                        LastHttpStatusCode = previous.LastHttpStatusCode,
                        LastOutcome = previous.LastOutcome,
                        LastErrorCode = previous.LastErrorCode,
                        LastGatewayRoundTripMilliseconds = previous.LastGatewayRoundTripMilliseconds,
                    }
                    : activity;
            await using var insert = connection.CreateCommand();
            insert.Transaction = (SqliteTransaction)transaction;
            insert.CommandText = """
                INSERT INTO proxy_activity (
                    device_id, asset_id, traffic_state, last_request_at_utc, activity_json)
                VALUES ($deviceId, $assetId, $trafficState, $lastRequestAt, $json);
                """;
            insert.Parameters.AddWithValue("$deviceId", heartbeat.Device.DeviceId.ToString("D"));
            insert.Parameters.AddWithValue("$assetId", storedActivity.AssetId.ToString("D"));
            insert.Parameters.AddWithValue("$trafficState", (int)storedActivity.State);
            insert.Parameters.AddWithValue("$lastRequestAt", storedActivity.LastRequestAtUtc is null
                ? DBNull.Value
                : storedActivity.LastRequestAtUtc.Value.ToString("O", CultureInfo.InvariantCulture));
            insert.Parameters.AddWithValue("$json", JsonSerializer.Serialize(storedActivity, jsonOptions));
            await insert.ExecuteNonQueryAsync(cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
    }

    public async Task<DeviceEnrollmentResponse> EnrollDeviceAsync(
        DeviceEnrollmentRequest request,
        CancellationToken cancellationToken = default)
    {
        var enrolledAt = DateTimeOffset.UtcNow;
        var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var tokenHash = ComputeTokenHash(token);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO device_credentials (
                device_id, token_hash, enrolled_at_utc, last_authenticated_at_utc, revoked)
            VALUES ($deviceId, $tokenHash, $enrolledAt, NULL, 0)
            ON CONFLICT(device_id) DO UPDATE SET
                token_hash=excluded.token_hash,
                enrolled_at_utc=excluded.enrolled_at_utc,
                last_authenticated_at_utc=NULL,
                revoked=0;
            """;
        command.Parameters.AddWithValue("$deviceId", request.DeviceId.ToString("D"));
        command.Parameters.AddWithValue("$tokenHash", tokenHash);
        command.Parameters.AddWithValue("$enrolledAt", enrolledAt.ToString("O", CultureInfo.InvariantCulture));
        await command.ExecuteNonQueryAsync(cancellationToken);
        return new DeviceEnrollmentResponse(request.DeviceId, token, enrolledAt);
    }

    public async Task<bool> AuthenticateDeviceAsync(
        Guid deviceId,
        string token,
        CancellationToken cancellationToken = default)
    {
        if (deviceId == Guid.Empty || string.IsNullOrWhiteSpace(token))
        {
            return false;
        }

        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            UPDATE device_credentials
            SET last_authenticated_at_utc=$authenticatedAt
            WHERE device_id=$deviceId AND token_hash=$tokenHash AND revoked=0;
            """;
        command.Parameters.AddWithValue("$authenticatedAt", DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture));
        command.Parameters.AddWithValue("$deviceId", deviceId.ToString("D"));
        command.Parameters.AddWithValue("$tokenHash", ComputeTokenHash(token));
        return await command.ExecuteNonQueryAsync(cancellationToken) == 1;
    }

    public async Task<EventStoreResult> RecordEventsAsync(
        EventBatchRequest batch,
        CancellationToken cancellationToken = default)
    {
        var accepted = 0;
        var duplicates = 0;
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        foreach (var endpointEvent in batch.Events)
        {
            await using var command = connection.CreateCommand();
            command.Transaction = (SqliteTransaction)transaction;
            command.CommandText = """
                INSERT OR IGNORE INTO endpoint_events (
                    event_id, device_id, occurred_at_utc, received_at_utc,
                    severity, event_type, code, event_json)
                VALUES ($eventId, $deviceId, $occurredAt, $receivedAt,
                    $severity, $type, $code, $json);
                """;
            command.Parameters.AddWithValue("$eventId", endpointEvent.EventId.ToString("D"));
            command.Parameters.AddWithValue("$deviceId", batch.DeviceId.ToString("D"));
            command.Parameters.AddWithValue("$occurredAt", endpointEvent.OccurredAtUtc.ToString("O", CultureInfo.InvariantCulture));
            command.Parameters.AddWithValue("$receivedAt", DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture));
            command.Parameters.AddWithValue("$severity", (int)endpointEvent.Severity);
            command.Parameters.AddWithValue("$type", endpointEvent.Type);
            command.Parameters.AddWithValue("$code", endpointEvent.Code);
            command.Parameters.AddWithValue("$json", JsonSerializer.Serialize(endpointEvent, jsonOptions));
            if (await command.ExecuteNonQueryAsync(cancellationToken) == 1)
            {
                accepted++;
            }
            else
            {
                duplicates++;
            }
        }

        await transaction.CommitAsync(cancellationToken);
        return new EventStoreResult(accepted, duplicates);
    }

    public async Task<IReadOnlyList<StoredDeviceSummary>> ListDevicesAsync(CancellationToken cancellationToken = default)
    {
        var devices = new List<StoredDeviceSummary>();
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT h.device_id, h.received_at_utc, h.hostname, h.os_version,
                   (SELECT COUNT(*) FROM agent_inventory a
                    WHERE a.device_id=h.device_id
                      AND a.agent_type NOT IN ($ccSwitchAgentType, $unknownAgentType)),
                   h.applied_policy_version, h.proxy_state,
                   r.service_version,
                   (SELECT COUNT(DISTINCT json_array(
                        e.user_sid,
                        e.agent_family,
                        json_extract(e.asset_json, '$.configurationSource'),
                        json_extract(e.asset_json, '$.providerId'),
                        COALESCE(json_extract(e.asset_json, '$.endpointId'), '')))
                    FROM agent_endpoint_assets e
                    WHERE e.device_id=h.device_id
                      AND json_extract(e.asset_json, '$.isCurrent') = 1),
                   r.operation_state,
                   r.heartbeat_interval_seconds,
                   COALESCE(r.schema_version, 1)
            FROM device_heartbeats h
            LEFT JOIN device_runtime r ON r.device_id=h.device_id
            ORDER BY h.received_at_utc DESC;
            """;
        command.Parameters.AddWithValue("$ccSwitchAgentType", (int)AgentType.CcSwitch);
        command.Parameters.AddWithValue("$unknownAgentType", (int)AgentType.UnknownCandidate);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            devices.Add(new StoredDeviceSummary(
                Guid.Parse(reader.GetString(0)),
                DateTimeOffset.Parse(reader.GetString(1), CultureInfo.InvariantCulture),
                reader.GetString(2),
                reader.GetString(3),
                reader.GetInt32(4),
                reader.GetInt64(5),
                (ProxyState)reader.GetInt32(6),
                reader.IsDBNull(7) ? null : reader.GetString(7),
                reader.GetInt32(8),
                reader.IsDBNull(9) ? ClientOperationState.Unknown : (ClientOperationState)reader.GetInt32(9),
                reader.IsDBNull(10) ? 60 : reader.GetInt32(10),
                reader.GetInt32(11)));
        }

        return devices;
    }

    public async Task<StoredDeviceDetails?> GetDeviceDetailsAsync(
        Guid deviceId,
        CancellationToken cancellationToken = default)
    {
        var device = (await ListDevicesAsync(cancellationToken)).FirstOrDefault(item => item.DeviceId == deviceId);
        if (device is null)
        {
            return null;
        }

        await using var connection = await OpenAsync(cancellationToken);
        var agents = await ReadJsonRowsAsync<AgentInventoryItem>(
            connection,
            "SELECT inventory_json FROM agent_inventory WHERE device_id=$deviceId ORDER BY agent_type, instance_id;",
            deviceId,
            cancellationToken);
        var endpoints = await ReadJsonRowsAsync<AgentEndpointAsset>(
            connection,
            "SELECT asset_json FROM agent_endpoint_assets WHERE device_id=$deviceId ORDER BY agent_family, asset_id;",
            deviceId,
            cancellationToken);
        var activity = await ReadJsonRowsAsync<ProxyActivityAsset>(
            connection,
            "SELECT activity_json FROM proxy_activity WHERE device_id=$deviceId ORDER BY asset_id;",
            deviceId,
            cancellationToken);

        DeviceRuntimeState? runtime = null;
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT runtime_json FROM device_runtime WHERE device_id=$deviceId;";
            command.Parameters.AddWithValue("$deviceId", deviceId.ToString("D"));
            if (await command.ExecuteScalarAsync(cancellationToken) is string json)
            {
                runtime = JsonSerializer.Deserialize<DeviceRuntimeState>(json, jsonOptions);
            }
        }

        return new StoredDeviceDetails(device, agents, endpoints, activity, runtime);
    }

    // Read one database snapshot in a bounded number of queries; the dashboard must
    // not issue a detail request (and a full device scan) for every terminal.
    public async Task<IReadOnlyList<StoredDeviceDetails>> ReadAnalyticsDevicesAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        var rows = new List<(HeartbeatRequest Heartbeat, DateTimeOffset Received, int Schema, int Interval, DeviceRuntimeState? Runtime)>();
        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "SELECT h.heartbeat_json,h.received_at_utc,COALESCE(r.schema_version,1),COALESCE(r.heartbeat_interval_seconds,60),r.runtime_json FROM device_heartbeats h LEFT JOIN device_runtime r ON r.device_id=h.device_id ORDER BY h.received_at_utc DESC,h.device_id;";
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                var heartbeat = JsonSerializer.Deserialize<HeartbeatRequest>(reader.GetString(0), jsonOptions)!;
                rows.Add((heartbeat, DateTimeOffset.Parse(reader.GetString(1), CultureInfo.InvariantCulture), reader.GetInt32(2), reader.GetInt32(3), reader.IsDBNull(4) ? null : JsonSerializer.Deserialize<DeviceRuntimeState>(reader.GetString(4), jsonOptions)));
            }
        }
        async Task<Dictionary<Guid, List<T>>> ReadAssets<T>(string sql)
        {
            var result = new Dictionary<Guid, List<T>>();
            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = sql;
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                var id = Guid.Parse(reader.GetString(0));
                if (!result.TryGetValue(id, out var list)) result[id] = list = [];
                if (JsonSerializer.Deserialize<T>(reader.GetString(1), jsonOptions) is { } asset) list.Add(asset);
            }
            return result;
        }
        var endpoints = await ReadAssets<AgentEndpointAsset>("SELECT device_id,asset_json FROM agent_endpoint_assets;");
        var activity = await ReadAssets<ProxyActivityAsset>("SELECT device_id,activity_json FROM proxy_activity;");
        return rows.Select(row =>
        {
            var h = row.Heartbeat;
            IReadOnlyList<AgentEndpointAsset> assets = endpoints.GetValueOrDefault(h.Device.DeviceId) ?? [];
            var summary = new StoredDeviceSummary(h.Device.DeviceId, row.Received, h.Device.Hostname, h.Device.OsVersion,
                h.Agents.Count(a => a.AgentType is not (AgentType.CcSwitch or AgentType.UnknownCandidate)), h.Policy.AppliedVersion ?? 0,
                h.Proxy.State, h.Device.ServiceVersion, assets.Where(a => a.IsCurrent)
                    .Select(a => (a.UserSid, a.AgentFamily, a.ConfigurationSource, a.ProviderId, EndpointId: a.EndpointId ?? ""))
                    .Distinct().Count(), row.Runtime?.OperationState ?? ClientOperationState.Unknown,
                row.Interval, row.Schema);
            return new StoredDeviceDetails(summary, h.Agents, assets, activity.GetValueOrDefault(h.Device.DeviceId) ?? [], row.Runtime);
        }).ToArray();
    }

    public async Task<StoredRemoteCommand?> CreateRemoteCommandAsync(
        Guid deviceId,
        CreateRemoteCommandRequest request,
        string createdBy,
        CancellationToken cancellationToken = default)
    {
        var now = DateTimeOffset.UtcNow;
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        await ExpireCommandsAsync(connection, (SqliteTransaction)transaction, deviceId, now, cancellationToken);

        await using (var exists = connection.CreateCommand())
        {
            exists.Transaction = (SqliteTransaction)transaction;
            exists.CommandText = "SELECT COUNT(*) FROM device_heartbeats WHERE device_id=$deviceId;";
            exists.Parameters.AddWithValue("$deviceId", deviceId.ToString("D"));
            if (Convert.ToInt64(await exists.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture) == 0)
            {
                await transaction.RollbackAsync(cancellationToken);
                return null;
            }
        }

        await using (var active = connection.CreateCommand())
        {
            active.Transaction = (SqliteTransaction)transaction;
            active.CommandText = """
                SELECT COUNT(*) FROM remote_commands
                WHERE device_id=$deviceId AND status IN ($pending, $delivered, $executing);
                """;
            active.Parameters.AddWithValue("$deviceId", deviceId.ToString("D"));
            active.Parameters.AddWithValue("$pending", (int)RemoteCommandStatus.Pending);
            active.Parameters.AddWithValue("$delivered", (int)RemoteCommandStatus.Delivered);
            active.Parameters.AddWithValue("$executing", (int)RemoteCommandStatus.Executing);
            if (Convert.ToInt64(await active.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture) != 0)
            {
                await transaction.RollbackAsync(cancellationToken);
                throw new InvalidOperationException("DEVICE_COMMAND_ALREADY_ACTIVE");
            }
        }

        var stored = new StoredRemoteCommand(
            Guid.NewGuid(),
            deviceId,
            request.Type,
            RemoteCommandStatus.Pending,
            now,
            now.AddMinutes(request.ExpiresInMinutes),
            createdBy,
            request.Reason,
            null,
            null,
            null,
            null,
            null,
            0);
        await InsertCommandAsync(connection, (SqliteTransaction)transaction, stored, cancellationToken);
        await InsertAuditAsync(
            connection,
            (SqliteTransaction)transaction,
            createdBy,
            "REMOTE_COMMAND_CREATED",
            deviceId,
            stored.CommandId,
            request.Type.ToString(),
            cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return stored;
    }

    public async Task<StoredRemoteCommand?> LeaseNextCommandAsync(
        Guid deviceId,
        CancellationToken cancellationToken = default)
    {
        var now = DateTimeOffset.UtcNow;
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        await ExpireCommandsAsync(connection, (SqliteTransaction)transaction, deviceId, now, cancellationToken);
        StoredRemoteCommand? selected;
        await using (var select = connection.CreateCommand())
        {
            select.Transaction = (SqliteTransaction)transaction;
            select.CommandText = """
                SELECT command_id, device_id, command_type, status, created_at_utc, expires_at_utc,
                       created_by, reason, delivered_at_utc, started_at_utc, completed_at_utc,
                       result_code, result_summary, delivery_count
                FROM remote_commands
                WHERE device_id=$deviceId AND status IN ($pending, $delivered, $executing)
                ORDER BY created_at_utc
                LIMIT 1;
                """;
            select.Parameters.AddWithValue("$deviceId", deviceId.ToString("D"));
            select.Parameters.AddWithValue("$pending", (int)RemoteCommandStatus.Pending);
            select.Parameters.AddWithValue("$delivered", (int)RemoteCommandStatus.Delivered);
            select.Parameters.AddWithValue("$executing", (int)RemoteCommandStatus.Executing);
            await using var reader = await select.ExecuteReaderAsync(cancellationToken);
            selected = await reader.ReadAsync(cancellationToken) ? ReadCommand(reader) : null;
        }

        if (selected is null)
        {
            await transaction.CommitAsync(cancellationToken);
            return null;
        }

        await using (var update = connection.CreateCommand())
        {
            update.Transaction = (SqliteTransaction)transaction;
            update.CommandText = """
                UPDATE remote_commands
                SET status=CASE WHEN status=$pending THEN $delivered ELSE status END,
                    delivered_at_utc=COALESCE(delivered_at_utc, $deliveredAt),
                    delivery_count=delivery_count+1
                WHERE command_id=$commandId AND status IN ($pending, $alreadyDelivered, $executing);
                """;
            update.Parameters.AddWithValue("$delivered", (int)RemoteCommandStatus.Delivered);
            update.Parameters.AddWithValue("$deliveredAt", now.ToString("O", CultureInfo.InvariantCulture));
            update.Parameters.AddWithValue("$commandId", selected.CommandId.ToString("D"));
            update.Parameters.AddWithValue("$pending", (int)RemoteCommandStatus.Pending);
            update.Parameters.AddWithValue("$alreadyDelivered", (int)RemoteCommandStatus.Delivered);
            update.Parameters.AddWithValue("$executing", (int)RemoteCommandStatus.Executing);
            await update.ExecuteNonQueryAsync(cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
        return selected with
        {
            Status = selected.Status == RemoteCommandStatus.Pending
                ? RemoteCommandStatus.Delivered
                : selected.Status,
            DeliveredAtUtc = selected.DeliveredAtUtc ?? now,
            DeliveryCount = selected.DeliveryCount + 1,
        };
    }

    public async Task<bool> UpdateCommandStatusAsync(
        RemoteCommandStatusUpdate update,
        CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            UPDATE remote_commands
            SET status=$status,
                started_at_utc=CASE WHEN $status=$executing THEN COALESCE(started_at_utc, $observedAt) ELSE started_at_utc END,
                completed_at_utc=CASE WHEN $status IN ($succeeded, $failed) THEN $observedAt ELSE completed_at_utc END,
                result_code=$resultCode,
                result_summary=$resultSummary
            WHERE command_id=$commandId AND device_id=$deviceId
              AND status NOT IN ($succeeded, $failed, $expired, $cancelled);
            """;
        command.Parameters.AddWithValue("$status", (int)update.Status);
        command.Parameters.AddWithValue("$executing", (int)RemoteCommandStatus.Executing);
        command.Parameters.AddWithValue("$succeeded", (int)RemoteCommandStatus.Succeeded);
        command.Parameters.AddWithValue("$failed", (int)RemoteCommandStatus.Failed);
        command.Parameters.AddWithValue("$expired", (int)RemoteCommandStatus.Expired);
        command.Parameters.AddWithValue("$cancelled", (int)RemoteCommandStatus.Cancelled);
        command.Parameters.AddWithValue("$observedAt", update.ObservedAtUtc.ToString("O", CultureInfo.InvariantCulture));
        command.Parameters.AddWithValue("$resultCode", (object?)update.ResultCode ?? DBNull.Value);
        command.Parameters.AddWithValue("$resultSummary", (object?)update.ResultSummary ?? DBNull.Value);
        command.Parameters.AddWithValue("$commandId", update.CommandId.ToString("D"));
        command.Parameters.AddWithValue("$deviceId", update.DeviceId.ToString("D"));
        return await command.ExecuteNonQueryAsync(cancellationToken) == 1;
    }

    public async Task<IReadOnlyList<StoredRemoteCommand>> ListCommandsAsync(
        Guid deviceId,
        CancellationToken cancellationToken = default)
    {
        var commands = new List<StoredRemoteCommand>();
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT command_id, device_id, command_type, status, created_at_utc, expires_at_utc,
                   created_by, reason, delivered_at_utc, started_at_utc, completed_at_utc,
                   result_code, result_summary, delivery_count
            FROM remote_commands
            WHERE device_id=$deviceId
            ORDER BY created_at_utc DESC
            LIMIT 100;
            """;
        command.Parameters.AddWithValue("$deviceId", deviceId.ToString("D"));
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            commands.Add(ReadCommand(reader));
        }

        return commands;
    }

    public async Task<bool> CancelCommandAsync(
        Guid commandId,
        string actor,
        CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        Guid? deviceId = null;
        await using (var select = connection.CreateCommand())
        {
            select.Transaction = (SqliteTransaction)transaction;
            select.CommandText = "SELECT device_id FROM remote_commands WHERE command_id=$commandId AND status=$pending;";
            select.Parameters.AddWithValue("$commandId", commandId.ToString("D"));
            select.Parameters.AddWithValue("$pending", (int)RemoteCommandStatus.Pending);
            if (await select.ExecuteScalarAsync(cancellationToken) is string value)
            {
                deviceId = Guid.Parse(value);
            }
        }

        if (deviceId is null)
        {
            await transaction.RollbackAsync(cancellationToken);
            return false;
        }

        await using (var update = connection.CreateCommand())
        {
            update.Transaction = (SqliteTransaction)transaction;
            update.CommandText = """
                UPDATE remote_commands
                SET status=$cancelled, completed_at_utc=$completedAt,
                    result_code='COMMAND_CANCELLED', result_summary='Cancelled before delivery.'
                WHERE command_id=$commandId AND status=$pending;
                """;
            update.Parameters.AddWithValue("$cancelled", (int)RemoteCommandStatus.Cancelled);
            update.Parameters.AddWithValue("$completedAt", DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture));
            update.Parameters.AddWithValue("$commandId", commandId.ToString("D"));
            update.Parameters.AddWithValue("$pending", (int)RemoteCommandStatus.Pending);
            await update.ExecuteNonQueryAsync(cancellationToken);
        }

        await InsertAuditAsync(connection, (SqliteTransaction)transaction, actor, "REMOTE_COMMAND_CANCELLED", deviceId, commandId, "Cancelled before delivery.", cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return true;
    }

    public async Task<string> BackupAsync(
        string backupDirectory,
        int retentionCount,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(backupDirectory);
        ArgumentOutOfRangeException.ThrowIfLessThan(retentionCount, 1);
        var fullDirectory = Path.GetFullPath(backupDirectory);
        Directory.CreateDirectory(fullDirectory);
        var destinationPath = Path.Combine(
            fullDirectory,
            $"control-{DateTimeOffset.UtcNow:yyyyMMddTHHmmssfffffffZ}-{Guid.NewGuid():N}.db");
        await using (var source = await OpenAsync(cancellationToken))
        {
            var builder = new SqliteConnectionStringBuilder
            {
                DataSource = destinationPath,
                Mode = SqliteOpenMode.ReadWriteCreate,
                Pooling = false,
            };
            await using var destination = new SqliteConnection(builder.ConnectionString);
            await destination.OpenAsync(cancellationToken);
            source.BackupDatabase(destination);
        }

        var backups = Directory.EnumerateFiles(fullDirectory, "control-*.db", SearchOption.TopDirectoryOnly)
            .Select(path => new FileInfo(path))
            .OrderByDescending(file => file.CreationTimeUtc)
            .ThenByDescending(file => file.Name, StringComparer.Ordinal)
            .ToArray();
        foreach (var expired in backups.Skip(retentionCount))
        {
            expired.Delete();
        }

        return destinationPath;
    }

    private static async Task DeleteDeviceRowsAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string tableName,
        Guid deviceId,
        CancellationToken cancellationToken)
    {
        if (tableName is not ("agent_endpoint_assets" or "proxy_activity"))
        {
            throw new ArgumentOutOfRangeException(nameof(tableName));
        }

        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"DELETE FROM {tableName} WHERE device_id=$deviceId;";
        command.Parameters.AddWithValue("$deviceId", deviceId.ToString("D"));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private async Task<IReadOnlyList<T>> ReadJsonRowsAsync<T>(
        SqliteConnection connection,
        string commandText,
        Guid deviceId,
        CancellationToken cancellationToken)
    {
        var result = new List<T>();
        await using var command = connection.CreateCommand();
        command.CommandText = commandText;
        command.Parameters.AddWithValue("$deviceId", deviceId.ToString("D"));
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var value = JsonSerializer.Deserialize<T>(reader.GetString(0), jsonOptions);
            if (value is not null)
            {
                result.Add(value);
            }
        }

        return result;
    }

    public async Task<IReadOnlyList<StoredAdminAudit>> ListAdminAuditAsync(
        Guid? deviceId,
        int skip,
        int take,
        CancellationToken cancellationToken = default)
    {
        var result = new List<StoredAdminAudit>();
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = deviceId is null
            ? """
                SELECT audit_id, occurred_at_utc, actor, action, device_id, command_id, summary
                FROM admin_audit_log
                ORDER BY occurred_at_utc DESC
                LIMIT $take OFFSET $skip;
                """
            : """
                SELECT audit_id, occurred_at_utc, actor, action, device_id, command_id, summary
                FROM admin_audit_log
                WHERE device_id=$deviceId
                ORDER BY occurred_at_utc DESC
                LIMIT $take OFFSET $skip;
                """;
        if (deviceId is not null)
        {
            command.Parameters.AddWithValue("$deviceId", deviceId.Value.ToString("D"));
        }
        command.Parameters.AddWithValue("$skip", Math.Max(0, skip));
        command.Parameters.AddWithValue("$take", Math.Clamp(take, 1, 500));
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            result.Add(new StoredAdminAudit(
                Guid.Parse(reader.GetString(0)),
                DateTimeOffset.Parse(reader.GetString(1), CultureInfo.InvariantCulture),
                reader.GetString(2),
                reader.GetString(3),
                reader.IsDBNull(4) ? null : Guid.Parse(reader.GetString(4)),
                reader.IsDBNull(5) ? null : Guid.Parse(reader.GetString(5)),
                reader.GetString(6)));
        }

        return result;
    }

    public async Task RecordAdminAuditAsync(
        string actor,
        string action,
        Guid? deviceId,
        Guid? commandId,
        string summary,
        CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        await InsertAuditAsync(
            connection,
            (SqliteTransaction)transaction,
            actor,
            action,
            deviceId,
            commandId,
            summary,
            cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    private static async Task ExpireCommandsAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        Guid deviceId,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            UPDATE remote_commands
            SET status=$expired, completed_at_utc=$completedAt,
                result_code='COMMAND_EXPIRED', result_summary='The command expired before completion.'
            WHERE device_id=$deviceId
              AND status IN ($pending, $delivered)
              AND expires_at_utc <= $completedAt;
            """;
        command.Parameters.AddWithValue("$expired", (int)RemoteCommandStatus.Expired);
        command.Parameters.AddWithValue("$completedAt", now.ToString("O", CultureInfo.InvariantCulture));
        command.Parameters.AddWithValue("$deviceId", deviceId.ToString("D"));
        command.Parameters.AddWithValue("$pending", (int)RemoteCommandStatus.Pending);
        command.Parameters.AddWithValue("$delivered", (int)RemoteCommandStatus.Delivered);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task InsertCommandAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        StoredRemoteCommand commandValue,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO remote_commands (
                command_id, device_id, command_type, status, created_at_utc, expires_at_utc,
                created_by, reason, delivered_at_utc, started_at_utc, completed_at_utc,
                result_code, result_summary, delivery_count)
            VALUES ($commandId, $deviceId, $commandType, $status, $createdAt, $expiresAt,
                $createdBy, $reason, NULL, NULL, NULL, NULL, NULL, 0);
            """;
        command.Parameters.AddWithValue("$commandId", commandValue.CommandId.ToString("D"));
        command.Parameters.AddWithValue("$deviceId", commandValue.DeviceId.ToString("D"));
        command.Parameters.AddWithValue("$commandType", (int)commandValue.Type);
        command.Parameters.AddWithValue("$status", (int)commandValue.Status);
        command.Parameters.AddWithValue("$createdAt", commandValue.CreatedAtUtc.ToString("O", CultureInfo.InvariantCulture));
        command.Parameters.AddWithValue("$expiresAt", commandValue.ExpiresAtUtc.ToString("O", CultureInfo.InvariantCulture));
        command.Parameters.AddWithValue("$createdBy", commandValue.CreatedBy);
        command.Parameters.AddWithValue("$reason", commandValue.Reason);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task InsertAuditAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string actor,
        string action,
        Guid? deviceId,
        Guid? commandId,
        string summary,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO admin_audit_log (
                audit_id, occurred_at_utc, actor, action, device_id, command_id, summary)
            VALUES ($auditId, $occurredAt, $actor, $action, $deviceId, $commandId, $summary);
            """;
        command.Parameters.AddWithValue("$auditId", Guid.NewGuid().ToString("D"));
        command.Parameters.AddWithValue("$occurredAt", DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture));
        command.Parameters.AddWithValue("$actor", actor);
        command.Parameters.AddWithValue("$action", action);
        command.Parameters.AddWithValue("$deviceId", deviceId is null ? DBNull.Value : deviceId.Value.ToString("D"));
        command.Parameters.AddWithValue("$commandId", commandId is null ? DBNull.Value : commandId.Value.ToString("D"));
        command.Parameters.AddWithValue("$summary", summary);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static StoredRemoteCommand ReadCommand(SqliteDataReader reader)
    {
        return new StoredRemoteCommand(
            Guid.Parse(reader.GetString(0)),
            Guid.Parse(reader.GetString(1)),
            (RemoteCommandType)reader.GetInt32(2),
            (RemoteCommandStatus)reader.GetInt32(3),
            ParseTimestamp(reader.GetString(4)),
            ParseTimestamp(reader.GetString(5)),
            reader.GetString(6),
            reader.GetString(7),
            ReadNullableTimestamp(reader, 8),
            ReadNullableTimestamp(reader, 9),
            ReadNullableTimestamp(reader, 10),
            reader.IsDBNull(11) ? null : reader.GetString(11),
            reader.IsDBNull(12) ? null : reader.GetString(12),
            reader.GetInt32(13));
    }

    private static DateTimeOffset ParseTimestamp(string value) =>
        DateTimeOffset.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);

    private static DateTimeOffset? ReadNullableTimestamp(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : ParseTimestamp(reader.GetString(ordinal));

    private static string ComputeTokenHash(string token) =>
        Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(token)));

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
        command.CommandText = "PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON;";
        await command.ExecuteNonQueryAsync(cancellationToken);
        return connection;
    }
}
