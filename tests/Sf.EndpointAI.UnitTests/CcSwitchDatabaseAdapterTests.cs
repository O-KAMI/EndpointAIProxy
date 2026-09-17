using System.Text.Json.Nodes;
using Microsoft.Data.Sqlite;
using Sf.EndpointAI.Client.Core.Configuration;

namespace Sf.EndpointAI.UnitTests;

public sealed class CcSwitchDatabaseAdapterTests : IAsyncLifetime
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), $"sf-ccswitch-{Guid.NewGuid():N}");
    private string DatabasePath => Path.Combine(_directory, "cc-switch.db");

    public async ValueTask InitializeAsync()
    {
        Directory.CreateDirectory(_directory);
        await using var connection = new SqliteConnection($"Data Source={DatabasePath}");
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            PRAGMA user_version=5;
            CREATE TABLE providers (
                id TEXT NOT NULL,
                app_type TEXT NOT NULL,
                name TEXT NOT NULL,
                settings_config TEXT NOT NULL,
                is_current INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (id, app_type)
            );
            CREATE TABLE provider_endpoints (
                id INTEGER PRIMARY KEY,
                provider_id TEXT NOT NULL,
                app_type TEXT NOT NULL,
                url TEXT NOT NULL
            );
            CREATE TABLE proxy_config (
                app_type TEXT PRIMARY KEY,
                proxy_enabled INTEGER NOT NULL,
                enabled INTEGER NOT NULL,
                listen_address TEXT NOT NULL,
                listen_port INTEGER NOT NULL,
                live_takeover_active INTEGER NOT NULL
            );
            CREATE TABLE proxy_live_backup (
                app_type TEXT PRIMARY KEY,
                original_config TEXT NOT NULL,
                backed_up_at TEXT NOT NULL
            );
            INSERT INTO providers VALUES (
                'anthropic-direct', 'claude', 'Anthropic Direct',
                '{"env":{"ANTHROPIC_BASE_URL":"https://api.anthropic.com","ANTHROPIC_AUTH_TOKEN":"keep-secret"},"apiFormat":"anthropic"}',
                1);
            INSERT INTO providers VALUES (
                'openai-direct', 'codex', 'OpenAI Direct',
                '{"auth":{"OPENAI_API_KEY":"keep-secret"},"config":"model_provider = \"custom\"\n[model_providers.custom]\nbase_url = \"https://api.openai.com/v1\"\nwire_api = \"responses\"\n"}',
                1);
            INSERT INTO provider_endpoints VALUES (1, 'anthropic-direct', 'claude', 'https://api.anthropic.com');
            INSERT INTO provider_endpoints VALUES (2, 'openai-direct', 'codex', 'https://api.openai.com/v1');
            INSERT INTO proxy_config VALUES ('claude', 0, 0, '127.0.0.1', 15721, 0);
            INSERT INTO proxy_config VALUES ('codex', 0, 0, '127.0.0.1', 15721, 0);
            """;
        await command.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
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
    public async Task Inspects_and_updates_supported_providers_without_changing_keys()
    {
        var inspection = await CcSwitchDatabaseAdapter.InspectAsync(DatabasePath, TestContext.Current.CancellationToken);
        Assert.Equal(5, inspection.UserVersion);
        Assert.Equal(2, inspection.Providers.Count);
        Assert.Equal(2, inspection.Endpoints.Count);
        Assert.Equal(2, inspection.ProxyConfigs.Count);
        Assert.True(inspection.ProviderSchemaSupported);
        Assert.True(inspection.ProxySchemaSupported);
        Assert.True(inspection.EndpointSchemaSupported);
        Assert.All(inspection.Providers, provider => Assert.Null(provider.ErrorCode));

        var mutations = inspection.Providers.Select((provider, index) =>
        {
            var injected = new Uri($"http://127.0.0.1:18080/r/provider-route-{index}");
            var transformed = CcSwitchSettingsTransformer.InjectBaseUrl(provider.AppType, provider.SettingsConfig, injected);
            return new CcSwitchProviderMutation(
                provider.ProviderId,
                provider.AppType,
                provider.SettingsConfig,
                transformed.SettingsConfig);
        }).ToArray();

        var result = await CcSwitchDatabaseAdapter.ApplyAsync(
            DatabasePath,
            mutations,
            Path.Combine(_directory, "backups"),
            TestContext.Current.CancellationToken);

        Assert.Equal(2, result.UpdatedProviders);
        Assert.Equal(0, result.UpdatedEndpoints);
        Assert.True(File.Exists(result.BackupPath));
        await using var connection = new SqliteConnection($"Data Source={DatabasePath};Mode=ReadOnly");
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT settings_config FROM providers ORDER BY app_type;";
        await using var reader = await command.ExecuteReaderAsync(TestContext.Current.CancellationToken);
        while (await reader.ReadAsync(TestContext.Current.CancellationToken))
        {
            var root = JsonNode.Parse(reader.GetString(0))!.AsObject();
            var key = root["auth"]?["OPENAI_API_KEY"]?.GetValue<string>()
                ?? root["env"]?["ANTHROPIC_AUTH_TOKEN"]?.GetValue<string>();
            Assert.Equal("keep-secret", key);
        }
    }

    [Fact]
    public async Task Updates_provider_endpoints_in_the_same_backed_up_transaction()
    {
        var inspection = await CcSwitchDatabaseAdapter.InspectAsync(DatabasePath, TestContext.Current.CancellationToken);
        var endpointMutations = inspection.Endpoints.Select((endpoint, index) => new CcSwitchEndpointMutation(
            endpoint.EndpointId,
            endpoint.ProviderId,
            endpoint.AppType,
            endpoint.Url,
            $"http://127.0.0.1:18080/r/endpoint-{index}"))
            .ToArray();

        var result = await CcSwitchDatabaseAdapter.ApplyAsync(
            DatabasePath,
            [],
            endpointMutations,
            Path.Combine(_directory, "endpoint-backups"),
            TestContext.Current.CancellationToken);

        Assert.Equal(0, result.UpdatedProviders);
        Assert.Equal(2, result.UpdatedEndpoints);
        Assert.True(File.Exists(result.BackupPath));
        await using var connection = new SqliteConnection($"Data Source={DatabasePath};Mode=ReadOnly");
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT url FROM provider_endpoints ORDER BY id;";
        await using var reader = await command.ExecuteReaderAsync(TestContext.Current.CancellationToken);
        var index = 0;
        while (await reader.ReadAsync(TestContext.Current.CancellationToken))
        {
            Assert.Equal($"http://127.0.0.1:18080/r/endpoint-{index}", reader.GetString(0));
            index++;
        }
    }

    [Fact]
    public async Task Concurrent_provider_change_rolls_back_the_transaction()
    {
        var inspection = await CcSwitchDatabaseAdapter.InspectAsync(DatabasePath, TestContext.Current.CancellationToken);
        var provider = inspection.Providers[0];
        var mutation = new CcSwitchProviderMutation(
            provider.ProviderId,
            provider.AppType,
            "stale-settings",
            "updated-settings");

        var exception = await Assert.ThrowsAsync<ConfigMutationException>(() => CcSwitchDatabaseAdapter.ApplyAsync(
            DatabasePath,
            [mutation],
            Path.Combine(_directory, "backups"),
            TestContext.Current.CancellationToken));

        Assert.Equal("CCSWITCH_DB_CHANGED_CONCURRENTLY", exception.Code);
    }

    [Fact]
    public async Task Incompatible_provider_schema_is_reported_without_guessing_ownership()
    {
        var brokenPath = Path.Combine(_directory, "broken.db");
        await using (var connection = new SqliteConnection($"Data Source={brokenPath}"))
        {
            await connection.OpenAsync(TestContext.Current.CancellationToken);
            await using var command = connection.CreateCommand();
            command.CommandText = "CREATE TABLE providers (id TEXT, app_type TEXT);";
            await command.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
        }

        var inspection = await CcSwitchDatabaseAdapter.InspectAsync(
            brokenPath,
            TestContext.Current.CancellationToken);

        Assert.False(inspection.ProviderSchemaSupported);
        Assert.Empty(inspection.Providers);
    }
}
