using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Data.Sqlite;
using Sf.EndpointAI.Contracts;
using Sf.EndpointAI.ControlServer;

namespace Sf.EndpointAI.UnitTests;

public sealed class ControlStoreTests : IAsyncLifetime
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), $"sf-control-{Guid.NewGuid():N}");
    private readonly JsonSerializerOptions _jsonOptions = CreateJsonOptions();
    private ControlStore Store => new(Path.Combine(_directory, "control.db"), _jsonOptions);

    public async ValueTask InitializeAsync()
    {
        Directory.CreateDirectory(_directory);
        await Store.InitializeAsync(CreatePolicy(), TestContext.Current.CancellationToken);
    }

    public ValueTask DisposeAsync()
    {
        SqliteConnection.ClearAllPools();
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }

        return ValueTask.CompletedTask;
    }

    [Fact]
    public async Task Policy_update_is_persistent_and_uses_optimistic_version()
    {
        var current = await Store.GetPolicyAsync(TestContext.Current.CancellationToken);
        var request = new PolicyUpdateRequest(
            current.PolicyVersion,
            true,
            RouteMode.FixedGateway,
            "http://10.0.0.8:8080",
            true,
            30,
            45);

        var updated = await Store.TryUpdatePolicyAsync(request, TestContext.Current.CancellationToken);
        var conflict = await Store.TryUpdatePolicyAsync(request, TestContext.Current.CancellationToken);
        var persisted = await Store.GetPolicyAsync(TestContext.Current.CancellationToken);

        Assert.NotNull(updated);
        Assert.Equal(2, updated.PolicyVersion);
        Assert.Null(conflict);
        Assert.Equal(updated with { AllowlistedBaseUrls = null }, persisted with { AllowlistedBaseUrls = null });
        Assert.Equal([BaseUrlAllowlist.LegacyCcrBaseUrl], persisted.AllowlistedBaseUrls);

        var cleared = await Store.TryUpdatePolicyAsync(
            request with { ExpectedVersion = persisted.PolicyVersion, AllowlistedBaseUrls = [] },
            TestContext.Current.CancellationToken);
        Assert.NotNull(cleared);
        Assert.Empty(cleared.AllowlistedBaseUrls!);
    }

    [Fact]
    public async Task Legacy_policy_is_migrated_to_explicit_ccr_allowlist_once()
    {
        var path = Path.Combine(_directory, "legacy-policy.db");
        var store = new ControlStore(path, _jsonOptions);
        await store.InitializeAsync(
            CreatePolicy() with { AllowlistedBaseUrls = null },
            TestContext.Current.CancellationToken);

        var migrated = await store.GetPolicyAsync(TestContext.Current.CancellationToken);
        Assert.Equal(2, migrated.PolicyVersion);
        Assert.Equal([BaseUrlAllowlist.LegacyCcrBaseUrl], migrated.AllowlistedBaseUrls);

        await store.InitializeAsync(CreatePolicy(), TestContext.Current.CancellationToken);
        var second = await store.GetPolicyAsync(TestContext.Current.CancellationToken);
        Assert.Equal(migrated with { AllowlistedBaseUrls = null }, second with { AllowlistedBaseUrls = null });
        Assert.Equal(migrated.AllowlistedBaseUrls, second.AllowlistedBaseUrls);
    }

    [Fact]
    public async Task Heartbeat_replaces_inventory_and_appears_in_device_summary()
    {
        var deviceId = Guid.NewGuid();
        var heartbeat = CreateHeartbeat(deviceId, AgentType.ClaudeCode);
        await Store.RecordHeartbeatAsync(heartbeat, TestContext.Current.CancellationToken);
        await Store.RecordHeartbeatAsync(CreateHeartbeat(deviceId, AgentType.CodexCli), TestContext.Current.CancellationToken);

        var device = Assert.Single(await Store.ListDevicesAsync(TestContext.Current.CancellationToken));

        Assert.Equal(deviceId, device.DeviceId);
        Assert.Equal(1, device.AgentCount);
        Assert.Equal(ProxyState.Listening, device.ProxyState);
    }

    [Fact]
    public async Task Event_ids_are_idempotent()
    {
        var endpointEvent = new EndpointEvent(
            Guid.NewGuid(),
            DateTimeOffset.UtcNow,
            EventSeverity.Warning,
            "policy",
            "TEST_EVENT",
            "test",
            null,
            null,
            null);
        var batch = new EventBatchRequest(1, Guid.NewGuid(), Guid.NewGuid(), [endpointEvent]);

        var first = await Store.RecordEventsAsync(batch, TestContext.Current.CancellationToken);
        var second = await Store.RecordEventsAsync(batch, TestContext.Current.CancellationToken);

        Assert.Equal(1, first.Accepted);
        Assert.Equal(0, first.Duplicates);
        Assert.Equal(0, second.Accepted);
        Assert.Equal(1, second.Duplicates);
    }

    [Fact]
    public async Task V2_heartbeat_persists_runtime_endpoints_and_activity()
    {
        var deviceId = Guid.NewGuid();
        var endpointId = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;
        var v1 = CreateHeartbeat(deviceId, AgentType.CodexCli);
        var heartbeat = new HeartbeatV2Request(
            2,
            v1.HeartbeatId,
            now,
            v1.Device with { ServiceVersion = "0.1.12" },
            new DeviceRuntimeState(
                now.AddMinutes(-5),
                300,
                ClientOperationState.Enabled,
                true,
                now,
                now,
                "SUCCESS",
                null),
            v1.Policy,
            v1.Proxy,
            v1.Users,
            v1.Agents,
            [new AgentEndpointAsset(
                endpointId,
                "S-1-5-21-test",
                "codex",
                AgentConfigurationSource.Direct,
                "direct",
                null,
                true,
                "gpt-test",
                AgentWireApi.OpenAiResponses,
                "https://api.example.com/v1",
                "http://127.0.0.1:18080/r/test",
                "http://127.0.0.1:18080/r/test",
                false,
                RouteStatus.Attached,
                now)],
            [new ProxyActivityAsset(
                endpointId,
                ProxyTrafficState.Succeeded,
                now,
                now,
                null,
                200,
                "SUCCESS",
                null,
                25.5,
                1,
                1,
                0)]);

        await Store.RecordHeartbeatV2Async(heartbeat, "10.0.0.1", 60, TestContext.Current.CancellationToken);
        var details = await Store.GetDeviceDetailsAsync(deviceId, TestContext.Current.CancellationToken);

        Assert.NotNull(details);
        Assert.Equal("0.1.12", details.Device.ServiceVersion);
        Assert.Equal(ClientOperationState.Enabled, details.Device.OperationState);
        Assert.Equal("gpt-test", Assert.Single(details.Endpoints).ConfiguredModel);
        Assert.Equal(ProxyTrafficState.Succeeded, Assert.Single(details.Activity).State);
        Assert.NotNull(details.Runtime);

        var restartedHeartbeat = heartbeat with
        {
            Device = heartbeat.Device with { BootId = Guid.NewGuid() },
            Activity = [new ProxyActivityAsset(
                endpointId,
                ProxyTrafficState.NeverObserved,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                0,
                0,
                0)],
        };
        await Store.RecordHeartbeatV2Async(
            restartedHeartbeat,
            "10.0.0.1",
            60,
            TestContext.Current.CancellationToken);
        var afterRestart = await Store.GetDeviceDetailsAsync(deviceId, TestContext.Current.CancellationToken);
        Assert.NotNull(afterRestart);
        var preservedActivity = Assert.Single(afterRestart.Activity);
        Assert.Equal(ProxyTrafficState.Succeeded, preservedActivity.State);
        Assert.Equal(0, preservedActivity.RequestCountSinceBoot);
        Assert.Equal(now, preservedActivity.LastSuccessAtUtc);
    }

    [Fact]
    public async Task Device_summary_excludes_components_and_counts_logical_configurations()
    {
        var deviceId = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;
        var v1 = CreateHeartbeat(deviceId, AgentType.CodexCli);
        var codex = Assert.Single(v1.Agents);
        var endpoints = new[]
        {
            new AgentEndpointAsset(
                Guid.NewGuid(),
                "S-1-5-21-test",
                "codex",
                AgentConfigurationSource.CcSwitchProvider,
                "moonshot",
                null,
                true,
                "kimi-k3",
                AgentWireApi.OpenAiResponses,
                "https://api.moonshot.cn/v1",
                "http://127.0.0.1:18080/r/route",
                "http://127.0.0.1:18080/r/route",
                false,
                RouteStatus.Attached,
                now),
            new AgentEndpointAsset(
                Guid.NewGuid(),
                "S-1-5-21-test",
                "codex",
                AgentConfigurationSource.CcSwitchProvider,
                "moonshot",
                null,
                true,
                "kimi-k3",
                AgentWireApi.OpenAiResponses,
                "http://127.0.0.1:18080/r/route",
                "http://127.0.0.1:18080/r/route",
                null,
                false,
                RouteStatus.Discovered,
                now),
            new AgentEndpointAsset(
                Guid.NewGuid(),
                "S-1-5-21-test",
                "codex",
                AgentConfigurationSource.CcSwitchProvider,
                "inactive-provider",
                null,
                false,
                "glm-5.3",
                AgentWireApi.OpenAiResponses,
                "https://inactive.example/v1",
                "https://inactive.example/v1",
                null,
                false,
                RouteStatus.Discovered,
                now),
        };
        var heartbeat = new HeartbeatV2Request(
            2,
            v1.HeartbeatId,
            now,
            v1.Device,
            new DeviceRuntimeState(now, 0, ClientOperationState.Enabled, true, now, now, "SUCCESS", null),
            v1.Policy,
            v1.Proxy,
            v1.Users,
            [
                codex,
                codex with { InstanceId = Guid.NewGuid(), AgentType = AgentType.CcSwitch, DisplayName = "CC Switch" },
                codex with { InstanceId = Guid.NewGuid(), AgentType = AgentType.UnknownCandidate, DisplayName = "疑似 Codex" },
            ],
            endpoints,
            []);

        await Store.RecordHeartbeatV2Async(heartbeat, "10.0.0.1", 60, TestContext.Current.CancellationToken);
        var summary = Assert.Single(await Store.ListDevicesAsync(TestContext.Current.CancellationToken));

        Assert.Equal(1, summary.AgentCount);
        Assert.Equal(1, summary.EndpointCount);
    }

    [Fact]
    public async Task Device_credentials_are_scoped_and_commands_are_idempotently_leased()
    {
        var deviceId = Guid.NewGuid();
        await Store.RecordHeartbeatAsync(CreateHeartbeat(deviceId, AgentType.ClaudeCli), TestContext.Current.CancellationToken);
        var enrollment = await Store.EnrollDeviceAsync(
            new DeviceEnrollmentRequest(2, deviceId, "test-host", "0.1.12"),
            TestContext.Current.CancellationToken);

        Assert.True(await Store.AuthenticateDeviceAsync(deviceId, enrollment.DeviceToken, TestContext.Current.CancellationToken));
        Assert.False(await Store.AuthenticateDeviceAsync(Guid.NewGuid(), enrollment.DeviceToken, TestContext.Current.CancellationToken));

        var created = await Store.CreateRemoteCommandAsync(
            deviceId,
            new CreateRemoteCommandRequest(RemoteCommandType.DisableProxy, "test", 10),
            "unit-test",
            TestContext.Current.CancellationToken);
        Assert.NotNull(created);

        var firstLease = await Store.LeaseNextCommandAsync(deviceId, TestContext.Current.CancellationToken);
        var secondLease = await Store.LeaseNextCommandAsync(deviceId, TestContext.Current.CancellationToken);
        Assert.Equal(created.CommandId, firstLease?.CommandId);
        Assert.Equal(created.CommandId, secondLease?.CommandId);
        Assert.Equal(2, secondLease?.DeliveryCount);

        Assert.True(await Store.UpdateCommandStatusAsync(
            new RemoteCommandStatusUpdate(
                1,
                deviceId,
                created.CommandId,
                RemoteCommandStatus.Executing,
                DateTimeOffset.UtcNow,
                null,
                null),
            TestContext.Current.CancellationToken));
        var executingRetry = await Store.LeaseNextCommandAsync(deviceId, TestContext.Current.CancellationToken);
        Assert.Equal(created.CommandId, executingRetry?.CommandId);
        Assert.Equal(RemoteCommandStatus.Executing, executingRetry?.Status);
        Assert.Equal(3, executingRetry?.DeliveryCount);

        await using (var connection = new SqliteConnection($"Data Source={Path.Combine(_directory, "control.db")}"))
        {
            await connection.OpenAsync(TestContext.Current.CancellationToken);
            await using var expire = connection.CreateCommand();
            expire.CommandText = "UPDATE remote_commands SET expires_at_utc=$expiresAt WHERE command_id=$commandId;";
            expire.Parameters.AddWithValue("$expiresAt", DateTimeOffset.UtcNow.AddMinutes(-1).ToString("O"));
            expire.Parameters.AddWithValue("$commandId", created.CommandId.ToString("D"));
            await expire.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
        }
        var expiredExecutingRetry = await Store.LeaseNextCommandAsync(deviceId, TestContext.Current.CancellationToken);
        Assert.Equal(created.CommandId, expiredExecutingRetry?.CommandId);
        Assert.Equal(RemoteCommandStatus.Executing, expiredExecutingRetry?.Status);

        Assert.True(await Store.UpdateCommandStatusAsync(
            new RemoteCommandStatusUpdate(
                1,
                deviceId,
                created.CommandId,
                RemoteCommandStatus.Succeeded,
                DateTimeOffset.UtcNow,
                "SUCCESS",
                "disabled"),
            TestContext.Current.CancellationToken));
        Assert.Null(await Store.LeaseNextCommandAsync(deviceId, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Admin_audit_supports_device_filter_and_pagination()
    {
        var firstDevice = Guid.NewGuid();
        var secondDevice = Guid.NewGuid();
        await Store.RecordAdminAuditAsync("operator-1", "REMOTE_COMMAND_REJECTED", firstDevice, null, "invalid", TestContext.Current.CancellationToken);
        await Store.RecordAdminAuditAsync("operator-2", "REMOTE_COMMAND_REJECTED", secondDevice, null, "missing", TestContext.Current.CancellationToken);
        await Store.RecordAdminAuditAsync("operator-3", "REMOTE_COMMAND_CANCELLED", firstDevice, Guid.NewGuid(), "cancelled", TestContext.Current.CancellationToken);

        var firstPage = await Store.ListAdminAuditAsync(firstDevice, 0, 1, TestContext.Current.CancellationToken);
        var secondPage = await Store.ListAdminAuditAsync(firstDevice, 1, 1, TestContext.Current.CancellationToken);

        Assert.Single(firstPage);
        Assert.Single(secondPage);
        Assert.All(firstPage.Concat(secondPage), item => Assert.Equal(firstDevice, item.DeviceId));
        Assert.NotEqual(firstPage[0].AuditId, secondPage[0].AuditId);
    }

    [Fact]
    public async Task Online_backup_is_consistent_and_respects_retention_count()
    {
        var deviceId = Guid.NewGuid();
        await Store.RecordHeartbeatAsync(CreateHeartbeat(deviceId, AgentType.ClaudeCli), TestContext.Current.CancellationToken);
        var backupDirectory = Path.Combine(_directory, "backups");

        var first = await Store.BackupAsync(backupDirectory, 1, TestContext.Current.CancellationToken);
        var second = await Store.BackupAsync(backupDirectory, 1, TestContext.Current.CancellationToken);

        var remaining = Assert.Single(Directory.EnumerateFiles(backupDirectory, "control-*.db"));
        Assert.Contains(remaining, new[] { first, second });
        var backupStore = new ControlStore(remaining, _jsonOptions);
        Assert.Equal(deviceId, Assert.Single(await backupStore.ListDevicesAsync(TestContext.Current.CancellationToken)).DeviceId);
    }

    private static EndpointPolicy CreatePolicy()
    {
        return new EndpointPolicy(
            1,
            Guid.NewGuid(),
            1,
            true,
            RouteMode.PassthroughOriginal,
            null,
            false,
            60,
            60,
            DateTimeOffset.UtcNow,
            [BaseUrlAllowlist.LegacyCcrBaseUrl]);
    }

    private static HeartbeatRequest CreateHeartbeat(Guid deviceId, AgentType agentType)
    {
        var now = DateTimeOffset.UtcNow;
        return new HeartbeatRequest(
            1,
            Guid.NewGuid(),
            now,
            new DeviceIdentity(deviceId, "test-host", "Windows", "1.0.0", Guid.NewGuid()),
            new PolicyClientState(1, 1, PolicyApplyStatus.Applied, null, null),
            new ProxyClientState(ProxyState.Listening, "127.0.0.1:18080", 1, AuditState.Healthy),
            [new EndpointUser("S-1-5-21-test", "test")],
            [new AgentInventoryItem(
                Guid.NewGuid(),
                "S-1-5-21-test",
                agentType,
                agentType.ToString(),
                "1.0.0",
                InstallMethod.Native,
                100,
                true,
                true,
                null,
                null,
                null,
                RouteStatus.Attached,
                "https://api.example.com",
                now)]);
    }

    private static JsonSerializerOptions CreateJsonOptions()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        options.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.CamelCase));
        return options;
    }
}
