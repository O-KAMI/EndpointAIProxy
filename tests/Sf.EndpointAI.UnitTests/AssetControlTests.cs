using System.Text;
using Microsoft.Data.Sqlite;
using Sf.EndpointAI.Client.Core.Configuration;
using Sf.EndpointAI.Client.Core.Routing;
using Sf.EndpointAI.Client.Core.Security;
using Sf.EndpointAI.Client.Core.State;
using Sf.EndpointAI.Client.Core.Windows;
using Sf.EndpointAI.Client.Service;
using Sf.EndpointAI.Contracts;

namespace Sf.EndpointAI.UnitTests;

public sealed class AssetControlTests : IDisposable
{
    private readonly string _profileRoot = Path.Combine(Path.GetTempPath(), $"sf-assets-{Guid.NewGuid():N}");

    [Fact]
    public async Task Asset_builder_reports_configured_model_and_sanitized_original_target()
    {
        Directory.CreateDirectory(Path.Combine(_profileRoot, ".codex"));
        await File.WriteAllTextAsync(
            Path.Combine(_profileRoot, ".codex", "config.toml"),
            "model = \"gpt-test\"\nopenai_base_url = \"http://127.0.0.1:18080/r/test\"\n",
            Encoding.UTF8,
            TestContext.Current.CancellationToken);
        var now = DateTimeOffset.UtcNow;
        var route = new RouteRecord(
            "abcdefghijklmnopqrstuv",
            "S-1-5-21-test",
            AgentType.CodexCli,
            "direct",
            new Uri("https://api.example.com/v1?token=secret"),
            new Uri("http://127.0.0.1:18080/r/abcdefghijklmnopqrstuv"),
            RouteStatus.Attached,
            now,
            now);
        var builder = new AgentAssetSnapshotBuilder(
            new FakeProfileProvider(new WindowsUserProfile(route.UserSid, _profileRoot)),
            new CcSwitchModeState(),
            new BaseUrlBypassPolicy());

        var asset = Assert.Single(await builder.BuildAsync([route], now, TestContext.Current.CancellationToken));

        Assert.Equal("gpt-test", asset.ConfiguredModel);
        Assert.Equal("codex", asset.AgentFamily);
        Assert.Equal(AgentWireApi.OpenAiResponses, asset.WireApi);
        Assert.DoesNotContain("secret", asset.OriginalTargetBaseUrl, StringComparison.Ordinal);
        Assert.Equal(AgentConfigurationSource.Direct, asset.ConfigurationSource);
    }

    [Fact]
    public async Task Allowlisted_direct_configuration_is_reported_without_a_local_route()
    {
        Directory.CreateDirectory(Path.Combine(_profileRoot, ".claude"));
        await File.WriteAllTextAsync(
            Path.Combine(_profileRoot, ".claude", "settings.json"),
            "{\"env\":{\"ANTHROPIC_BASE_URL\":\"https://internal.example.invalid/ccr/\",\"ANTHROPIC_MODEL\":\"claude-test\"}}",
            Encoding.UTF8,
            TestContext.Current.CancellationToken);
        var builder = new AgentAssetSnapshotBuilder(
            new FakeProfileProvider(new WindowsUserProfile("S-1-5-21-test", _profileRoot)),
            new CcSwitchModeState(),
            new BaseUrlBypassPolicy());

        var asset = Assert.Single(await builder.BuildAsync([], DateTimeOffset.UtcNow, TestContext.Current.CancellationToken));

        Assert.True(asset.AllowlistBypassed);
        Assert.Equal(RouteStatus.Bypassed, asset.RouteStatus);
        Assert.Null(asset.LocalRouteUrl);
        Assert.Equal("claude-test", asset.ConfiguredModel);
    }

    [Fact]
    public async Task Residual_route_is_reported_as_allowlist_bypassed_until_reconciliation_finishes()
    {
        Directory.CreateDirectory(Path.Combine(_profileRoot, ".codex"));
        await File.WriteAllTextAsync(
            Path.Combine(_profileRoot, ".codex", "config.toml"),
            "model = \"gpt-test\"\nopenai_base_url = \"http://127.0.0.1:18080/r/abcdefghijklmnopqrstuv\"\n",
            Encoding.UTF8,
            TestContext.Current.CancellationToken);
        var now = DateTimeOffset.UtcNow;
        var route = new RouteRecord(
            "abcdefghijklmnopqrstuv",
            "S-1-5-21-test",
            AgentType.CodexCli,
            "direct",
            new Uri("https://model.example.invalid/v1"),
            new Uri("http://127.0.0.1:18080/r/abcdefghijklmnopqrstuv"),
            RouteStatus.Attached,
            now,
            now);
        var bypassPolicy = new BaseUrlBypassPolicy();
        bypassPolicy.Replace(["https://model.example.invalid/v1/"]);
        var builder = new AgentAssetSnapshotBuilder(
            new FakeProfileProvider(new WindowsUserProfile(route.UserSid, _profileRoot)),
            new CcSwitchModeState(),
            bypassPolicy);

        var asset = Assert.Single(await builder.BuildAsync([route], now, TestContext.Current.CancellationToken));

        Assert.True(asset.AllowlistBypassed);
        Assert.Equal(RouteStatus.Bypassed, asset.RouteStatus);
        Assert.Equal("https://model.example.invalid/v1", asset.OriginalTargetBaseUrl);
    }

    [Fact]
    public async Task External_direct_configuration_remains_reported_without_a_local_route()
    {
        Directory.CreateDirectory(Path.Combine(_profileRoot, ".codex"));
        await File.WriteAllTextAsync(
            Path.Combine(_profileRoot, ".codex", "config.toml"),
            "model = \"gpt-test\"\nopenai_base_url = \"https://api.example.com/v1\"\n",
            Encoding.UTF8,
            TestContext.Current.CancellationToken);
        var builder = new AgentAssetSnapshotBuilder(
            new FakeProfileProvider(new WindowsUserProfile("S-1-5-21-test", _profileRoot)),
            new CcSwitchModeState(),
            new BaseUrlBypassPolicy());

        var asset = Assert.Single(await builder.BuildAsync([], DateTimeOffset.UtcNow, TestContext.Current.CancellationToken));

        Assert.False(asset.AllowlistBypassed);
        Assert.Equal(RouteStatus.Discovered, asset.RouteStatus);
        Assert.Equal("gpt-test", asset.ConfiguredModel);
        Assert.Equal("https://api.example.com/v1", asset.EffectiveConfiguredBaseUrl);
    }

    [Fact]
    public async Task Direct_codex_asset_uses_the_active_custom_provider_base_url()
    {
        Directory.CreateDirectory(Path.Combine(_profileRoot, ".codex"));
        await File.WriteAllTextAsync(
            Path.Combine(_profileRoot, ".codex", "config.toml"),
            """
            model = "custom-model"
            model_provider = "active"

            [model_providers.unused]
            base_url = "https://unused.example/v1"

            [model_providers.active]
            base_url = "https://active.example/v1"
            """,
            Encoding.UTF8,
            TestContext.Current.CancellationToken);
        var builder = new AgentAssetSnapshotBuilder(
            new FakeProfileProvider(new WindowsUserProfile("S-1-5-21-test", _profileRoot)),
            new CcSwitchModeState(),
            new BaseUrlBypassPolicy());

        var asset = Assert.Single(await builder.BuildAsync([], DateTimeOffset.UtcNow, TestContext.Current.CancellationToken));

        Assert.Equal("custom-model", asset.ConfiguredModel);
        Assert.Equal("https://active.example/v1", asset.OriginalTargetBaseUrl);
    }

    [Fact]
    public void Activity_tracker_distinguishes_gateway_http_error_from_connection_failure()
    {
        var now = DateTimeOffset.UtcNow;
        var route = new RouteRecord(
            "abcdefghijklmnopqrstuv",
            "S-1-5-21-test",
            AgentType.ClaudeCode,
            "direct",
            new Uri("https://api.example.com"),
            new Uri("http://127.0.0.1:18080/r/abcdefghijklmnopqrstuv"),
            RouteStatus.Attached,
            now,
            now);
        var tracker = new ProxyActivityTracker();

        tracker.Record(route, "GATEWAY_HTTP_ERROR", 403, "GATEWAY_HTTP_ERROR", 15.25);
        var gatewayError = Assert.Single(tracker.Snapshot([route]));
        Assert.Equal(ProxyTrafficState.GatewayReachedWithError, gatewayError.State);
        Assert.Equal(403, gatewayError.LastHttpStatusCode);

        tracker.Record(route, "GATEWAY_CONNECTION_FAILED", 502, "GATEWAY_CONNECTION_FAILED", null);
        var connectionError = Assert.Single(tracker.Snapshot([route]));
        Assert.Equal(ProxyTrafficState.ConnectionFailed, connectionError.State);
        Assert.Equal(2, connectionError.RequestCountSinceBoot);
        Assert.Equal(2, connectionError.FailureCountSinceBoot);

        var detachedAsset = new AgentEndpointAsset(
            AgentAssetIdentity.Create(route),
            route.UserSid,
            "claude",
            AgentConfigurationSource.Direct,
            "direct",
            null,
            true,
            "claude-test",
            AgentWireApi.AnthropicMessages,
            "https://api.example.com",
            "https://api.example.com",
            null,
            false,
            RouteStatus.Discovered,
            now);
        Assert.Equal(2, Assert.Single(tracker.Snapshot([detachedAsset])).RequestCountSinceBoot);
    }

    [Fact]
    public void Asset_identity_remains_stable_when_provider_target_changes()
    {
        var now = DateTimeOffset.UtcNow;
        var first = new RouteRecord(
            "abcdefghijklmnopqrstuv",
            "S-1-5-21-test",
            AgentType.CodexCli,
            "direct",
            new Uri("https://api.one.example/v1"),
            new Uri("http://127.0.0.1:18080/r/abcdefghijklmnopqrstuv"),
            RouteStatus.Attached,
            now,
            now);
        var second = first with { OriginalBaseUri = new Uri("https://api.two.example/v1") };

        Assert.Equal(AgentAssetIdentity.Create(first), AgentAssetIdentity.Create(second));
    }

    [Fact]
    public async Task Cc_switch_route_and_database_observations_are_one_logical_asset_each()
    {
        var ccSwitchDirectory = Path.Combine(_profileRoot, ".cc-switch");
        Directory.CreateDirectory(ccSwitchDirectory);
        var databasePath = Path.Combine(ccSwitchDirectory, "cc-switch.db");
        const string providerRouteId = "providerrouteabcdefghij";
        const string endpointRouteId = "endpointrouteabcdefghij";
        await using (var connection = new SqliteConnection($"Data Source={databasePath}"))
        {
            await connection.OpenAsync(TestContext.Current.CancellationToken);
            await using var command = connection.CreateCommand();
            command.Parameters.AddWithValue(
                "$settings",
                "{\"config\":\"model = \\\"kimi-k3\\\"\\nmodel_provider = \\\"moonshot\\\"\\n[model_providers.moonshot]\\nbase_url = \\\"http://127.0.0.1:18080/r/" + providerRouteId + "\\\"\\nwire_api = \\\"responses\\\"\\n\",\"api_key\":\"secret\"}");
            command.Parameters.AddWithValue("$endpoint", "http://127.0.0.1:18080/r/" + endpointRouteId);
            command.CommandText = """
                CREATE TABLE providers (
                    id TEXT NOT NULL, app_type TEXT NOT NULL, name TEXT NOT NULL,
                    settings_config TEXT NOT NULL, is_current INTEGER NOT NULL,
                    PRIMARY KEY (id, app_type));
                CREATE TABLE provider_endpoints (
                    id INTEGER PRIMARY KEY, provider_id TEXT NOT NULL,
                    app_type TEXT NOT NULL, url TEXT NOT NULL);
                INSERT INTO providers VALUES ('moonshot', 'codex', 'Moonshot', $settings, 1);
                INSERT INTO provider_endpoints VALUES (3, 'moonshot', 'codex', $endpoint);
                """;
            await command.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
        }

        var now = DateTimeOffset.UtcNow;
        var routes = new[]
        {
            new RouteRecord(
                providerRouteId,
                "S-1-5-21-test",
                AgentType.CcSwitch,
                "codex:moonshot",
                new Uri("https://api.moonshot.cn/v1"),
                new Uri("http://127.0.0.1:18080/r/" + providerRouteId),
                RouteStatus.Attached,
                now,
                now),
            new RouteRecord(
                endpointRouteId,
                "S-1-5-21-test",
                AgentType.CcSwitch,
                "codex:moonshot:endpoint:3",
                new Uri("https://api.moonshot.cn/v1"),
                new Uri("http://127.0.0.1:18080/r/" + endpointRouteId),
                RouteStatus.Attached,
                now,
                now),
        };
        var builder = new AgentAssetSnapshotBuilder(
            new FakeProfileProvider(new WindowsUserProfile("S-1-5-21-test", _profileRoot)),
            new CcSwitchModeState(),
            new BaseUrlBypassPolicy());

        var assets = await builder.BuildAsync(routes, now, TestContext.Current.CancellationToken);

        Assert.Equal(2, assets.Count);
        Assert.All(assets, asset => Assert.Equal("kimi-k3", asset.ConfiguredModel));
        Assert.Contains(assets, asset => asset.ConfigurationSource == AgentConfigurationSource.CcSwitchProvider);
        Assert.Contains(assets, asset => asset.ConfigurationSource == AgentConfigurationSource.CcSwitchEndpoint);
        Assert.Equal(routes.Select(AgentAssetIdentity.Create).ToHashSet(), assets.Select(asset => asset.AssetId).ToHashSet());
    }

    [Fact]
    public async Task Current_cc_switch_configuration_does_not_borrow_its_model_for_a_historical_direct_route()
    {
        const string userSid = "S-1-5-21-cc-current";
        const string providerRouteId = "currentproviderroute12";
        const string directRouteId = "historicaldirectroute";
        Directory.CreateDirectory(Path.Combine(_profileRoot, ".codex"));
        await File.WriteAllTextAsync(
            Path.Combine(_profileRoot, ".codex", "config.toml"),
            $"model = \"kimi-k3\"\nmodel_provider = \"moonshot\"\n[model_providers.moonshot]\nbase_url = \"http://127.0.0.1:18080/r/{providerRouteId}\"\nwire_api = \"responses\"\n",
            Encoding.UTF8,
            TestContext.Current.CancellationToken);
        await CreateCodexAssetDatabaseAsync(
            providerRouteId,
            includeCurrentEndpoint: false,
            includeInactiveProvider: false);
        var now = DateTimeOffset.UtcNow;
        var routes = new[]
        {
            new RouteRecord(
                directRouteId,
                userSid,
                AgentType.CodexCli,
                "direct",
                new Uri("https://ark.cn-beijing.volces.com/api/plan"),
                new Uri("http://127.0.0.1:18080/r/" + directRouteId),
                RouteStatus.Attached,
                now,
                now),
            new RouteRecord(
                providerRouteId,
                userSid,
                AgentType.CcSwitch,
                "codex:moonshot",
                new Uri("https://api.moonshot.cn/anthropic"),
                new Uri("http://127.0.0.1:18080/r/" + providerRouteId),
                RouteStatus.Attached,
                now,
                now),
        };
        var builder = new AgentAssetSnapshotBuilder(
            new FakeProfileProvider(new WindowsUserProfile(userSid, _profileRoot)),
            new CcSwitchModeState(),
            new BaseUrlBypassPolicy());

        var asset = Assert.Single(await builder.BuildAsync(routes, now, TestContext.Current.CancellationToken));

        Assert.Equal(AgentConfigurationSource.CcSwitchProvider, asset.ConfigurationSource);
        Assert.Equal("kimi-k3", asset.ConfiguredModel);
        Assert.Equal("https://api.moonshot.cn/anthropic", asset.OriginalTargetBaseUrl);
        Assert.DoesNotContain("volces", asset.OriginalTargetBaseUrl, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Deleted_cc_switch_endpoint_route_is_not_reported_without_a_database_entity()
    {
        const string userSid = "S-1-5-21-deleted-endpoint";
        const string providerRouteId = "providerroutecurrent12";
        const string deletedEndpointRouteId = "deletedendpointroute1";
        Directory.CreateDirectory(Path.Combine(_profileRoot, ".codex"));
        await File.WriteAllTextAsync(
            Path.Combine(_profileRoot, ".codex", "config.toml"),
            $"model = \"kimi-k3\"\nmodel_provider = \"moonshot\"\n[model_providers.moonshot]\nbase_url = \"http://127.0.0.1:18080/r/{providerRouteId}\"\nwire_api = \"responses\"\n",
            Encoding.UTF8,
            TestContext.Current.CancellationToken);
        await CreateCodexAssetDatabaseAsync(
            providerRouteId,
            includeCurrentEndpoint: false,
            includeInactiveProvider: false);
        var now = DateTimeOffset.UtcNow;
        var routes = new[]
        {
            new RouteRecord(
                providerRouteId,
                userSid,
                AgentType.CcSwitch,
                "codex:moonshot",
                new Uri("https://api.moonshot.cn/anthropic"),
                new Uri("http://127.0.0.1:18080/r/" + providerRouteId),
                RouteStatus.Attached,
                now,
                now),
            new RouteRecord(
                deletedEndpointRouteId,
                userSid,
                AgentType.CcSwitch,
                "codex:moonshot:endpoint:3",
                new Uri("https://deleted.example/v1"),
                new Uri("http://127.0.0.1:18080/r/" + deletedEndpointRouteId),
                RouteStatus.Attached,
                now,
                now),
        };
        var builder = new AgentAssetSnapshotBuilder(
            new FakeProfileProvider(new WindowsUserProfile(userSid, _profileRoot)),
            new CcSwitchModeState(),
            new BaseUrlBypassPolicy());

        var asset = Assert.Single(await builder.BuildAsync(routes, now, TestContext.Current.CancellationToken));

        Assert.Equal(AgentConfigurationSource.CcSwitchProvider, asset.ConfigurationSource);
        Assert.Null(asset.EndpointId);
        Assert.DoesNotContain("deleted.example", asset.OriginalTargetBaseUrl, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Existing_inactive_cc_switch_provider_and_endpoint_remain_reported_as_inactive()
    {
        const string userSid = "S-1-5-21-inactive-config";
        const string providerRouteId = "providerroutecurrent34";
        Directory.CreateDirectory(Path.Combine(_profileRoot, ".codex"));
        await File.WriteAllTextAsync(
            Path.Combine(_profileRoot, ".codex", "config.toml"),
            $"model = \"kimi-k3\"\nmodel_provider = \"moonshot\"\n[model_providers.moonshot]\nbase_url = \"http://127.0.0.1:18080/r/{providerRouteId}\"\nwire_api = \"responses\"\n",
            Encoding.UTF8,
            TestContext.Current.CancellationToken);
        await CreateCodexAssetDatabaseAsync(
            providerRouteId,
            includeCurrentEndpoint: false,
            includeInactiveProvider: true);
        var now = DateTimeOffset.UtcNow;
        var route = new RouteRecord(
            providerRouteId,
            userSid,
            AgentType.CcSwitch,
            "codex:moonshot",
            new Uri("https://api.moonshot.cn/anthropic"),
            new Uri("http://127.0.0.1:18080/r/" + providerRouteId),
            RouteStatus.Attached,
            now,
            now);
        var builder = new AgentAssetSnapshotBuilder(
            new FakeProfileProvider(new WindowsUserProfile(userSid, _profileRoot)),
            new CcSwitchModeState(),
            new BaseUrlBypassPolicy());

        var assets = await builder.BuildAsync([route], now, TestContext.Current.CancellationToken);

        Assert.Single(assets, asset => asset.IsCurrent);
        Assert.Equal(2, assets.Count(asset => !asset.IsCurrent));
        Assert.Contains(assets, asset => !asset.IsCurrent
            && asset.ConfigurationSource == AgentConfigurationSource.CcSwitchProvider
            && asset.ProviderId == "glm");
        Assert.Contains(assets, asset => !asset.IsCurrent
            && asset.ConfigurationSource == AgentConfigurationSource.CcSwitchEndpoint
            && asset.ProviderId == "glm"
            && asset.EndpointId == "7");
    }

    [Fact]
    public async Task Remote_disable_persists_state_without_stopping_the_control_service()
    {
        Directory.CreateDirectory(Path.Combine(_profileRoot, ".codex"));
        var configPath = Path.Combine(_profileRoot, ".codex", "config.toml");
        await File.WriteAllTextAsync(
            configPath,
            "model = \"gpt-test\"\nopenai_base_url = \"https://api.example.com/v1\"\n",
            Encoding.UTF8,
            TestContext.Current.CancellationToken);
        var databasePath = Path.Combine(_profileRoot, "state", "client.db");
        var protector = new TestProtector();
        var registry = new SqliteRouteRegistry(databasePath, protector);
        await registry.InitializeAsync(TestContext.Current.CancellationToken);
        var stateStore = new SqliteClientStateStore(databasePath, protector);
        await stateStore.InitializeAsync(TestContext.Current.CancellationToken);
        var stateProvider = new ClientOperationStateProvider();
        using var mutationGate = new RouteMutationGate();
        var attachmentCoordinator = new AgentConfigAttachmentCoordinator(
            registry,
            new Uri("http://127.0.0.1:18080"),
            new BaseUrlBypassPolicy());
        var profileProvider = new FakeProfileProvider(new WindowsUserProfile("S-1-5-21-test", _profileRoot));
        var backupRoot = Path.Combine(_profileRoot, "backups");
        var attached = await attachmentCoordinator.AttachAsync(
            profileProvider.GetProfiles()[0],
            backupRoot,
            TestContext.Current.CancellationToken);
        Assert.Contains(attached.Items, item => item.Status == RouteStatus.Attached);
        Assert.Contains("127.0.0.1:18080", await File.ReadAllTextAsync(configPath, TestContext.Current.CancellationToken));
        var coordinator = new RemoteOperationCoordinator(
            profileProvider,
            attachmentCoordinator,
            new RouteAttachmentOptions(backupRoot, TimeSpan.FromSeconds(60)),
            mutationGate,
            stateStore,
            stateProvider);

        var result = await coordinator.ExecuteAsync(RemoteCommandType.DisableProxy, TestContext.Current.CancellationToken);

        Assert.True(result.Succeeded);
        Assert.Equal(ClientOperationState.Disabled, stateProvider.Current.State);
        Assert.Equal(ClientOperationState.Disabled, (await stateStore.LoadOperationStateAsync(TestContext.Current.CancellationToken)).State);
        Assert.Contains("https://api.example.com/v1", await File.ReadAllTextAsync(configPath, TestContext.Current.CancellationToken));
        Assert.Empty(await registry.ListAsync(TestContext.Current.CancellationToken));

        var enabled = await coordinator.ExecuteAsync(RemoteCommandType.EnableProxy, TestContext.Current.CancellationToken);

        Assert.True(enabled.Succeeded);
        Assert.Equal(ClientOperationState.Enabled, stateProvider.Current.State);
        Assert.Contains("127.0.0.1:18080", await File.ReadAllTextAsync(configPath, TestContext.Current.CancellationToken));
        Assert.Single(await registry.ListAsync(TestContext.Current.CancellationToken));
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        if (Directory.Exists(_profileRoot))
        {
            Directory.Delete(_profileRoot, recursive: true);
        }
    }

    private async Task CreateCodexAssetDatabaseAsync(
        string currentProviderRouteId,
        bool includeCurrentEndpoint,
        bool includeInactiveProvider)
    {
        var ccSwitchDirectory = Path.Combine(_profileRoot, ".cc-switch");
        Directory.CreateDirectory(ccSwitchDirectory);
        var databasePath = Path.Combine(ccSwitchDirectory, "cc-switch.db");
        await using var connection = new SqliteConnection($"Data Source={databasePath}");
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        await using var command = connection.CreateCommand();
        command.Parameters.AddWithValue(
            "$currentSettings",
            "{\"config\":\"model = \\\"kimi-k3\\\"\\nmodel_provider = \\\"moonshot\\\"\\n[model_providers.moonshot]\\nbase_url = \\\"http://127.0.0.1:18080/r/" + currentProviderRouteId + "\\\"\\nwire_api = \\\"responses\\\"\\n\",\"api_key\":\"secret\"}");
        command.CommandText = """
            CREATE TABLE providers (
                id TEXT NOT NULL, app_type TEXT NOT NULL, name TEXT NOT NULL,
                settings_config TEXT NOT NULL, is_current INTEGER NOT NULL,
                PRIMARY KEY (id, app_type));
            CREATE TABLE provider_endpoints (
                id INTEGER PRIMARY KEY, provider_id TEXT NOT NULL,
                app_type TEXT NOT NULL, url TEXT NOT NULL);
            INSERT INTO providers VALUES ('moonshot', 'codex', 'Moonshot', $currentSettings, 1);
            """;
        if (includeCurrentEndpoint)
        {
            command.CommandText += "INSERT INTO provider_endpoints VALUES (3, 'moonshot', 'codex', 'https://api.moonshot.cn/anthropic');";
        }

        if (includeInactiveProvider)
        {
            command.CommandText += """
                INSERT INTO providers VALUES (
                    'glm', 'codex', 'GLM',
                    '{"config":"model = \"glm-5.3\"\nmodel_provider = \"glm\"\n[model_providers.glm]\nbase_url = \"https://ark.cn-beijing.volces.com/api/plan\"\nwire_api = \"responses\"\n","api_key":"secret"}',
                    0);
                INSERT INTO provider_endpoints VALUES (7, 'glm', 'codex', 'https://ark.cn-beijing.volces.com/api/plan');
                """;
        }

        await command.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
    }

    private sealed class FakeProfileProvider(params WindowsUserProfile[] profiles) : IUserProfileProvider
    {
        public IReadOnlyList<WindowsUserProfile> GetProfiles() => profiles;
    }

    private sealed class TestProtector : ITextProtector
    {
        public byte[] Protect(string value) => Encoding.UTF8.GetBytes(value);

        public string Unprotect(byte[] protectedValue) => Encoding.UTF8.GetString(protectedValue);
    }
}
