using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Data.Sqlite;
using Sf.EndpointAI.Client.Core.Configuration;
using Sf.EndpointAI.Client.Core.Routing;
using Sf.EndpointAI.Client.Core.Security;
using Sf.EndpointAI.Client.Core.State;
using Sf.EndpointAI.Client.Core.Windows;
using Sf.EndpointAI.Contracts;

namespace Sf.EndpointAI.UnitTests;

public sealed class AgentConfigAttachmentCoordinatorTests : IAsyncLifetime
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), $"sf-attachment-{Guid.NewGuid():N}");
    private string ProfilePath => Path.Combine(_directory, "profile");
    private string StatePath => Path.Combine(_directory, "state", "client.db");
    private string BackupRoot => Path.Combine(_directory, "backups");

    public ValueTask InitializeAsync()
    {
        Directory.CreateDirectory(ProfilePath);
        return ValueTask.CompletedTask;
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
    public async Task Attaches_direct_claude_and_codex_and_is_idempotent()
    {
        var claudePath = Path.Combine(ProfilePath, ".claude", "settings.json");
        var codexPath = Path.Combine(ProfilePath, ".codex", "config.toml");
        Directory.CreateDirectory(Path.GetDirectoryName(claudePath)!);
        Directory.CreateDirectory(Path.GetDirectoryName(codexPath)!);
        await File.WriteAllTextAsync(
            claudePath,
            "{\"env\":{\"ANTHROPIC_BASE_URL\":\"https://api.anthropic.com\"},\"keep\":true}",
            TestContext.Current.CancellationToken);
        await File.WriteAllTextAsync(
            codexPath,
            "model = \"gpt-codex\"\nopenai_base_url = \"https://api.openai.com/v1\"\n",
            TestContext.Current.CancellationToken);
        var registry = await CreateRegistryAsync();
        var coordinator = new AgentConfigAttachmentCoordinator(registry, new Uri("http://127.0.0.1:18080"));
        var profile = new WindowsUserProfile("S-1-5-21-direct", ProfilePath);

        var first = await coordinator.AttachAsync(profile, BackupRoot, TestContext.Current.CancellationToken);
        var second = await coordinator.AttachAsync(profile, BackupRoot, TestContext.Current.CancellationToken);

        Assert.False(first.CcSwitchManaged);
        Assert.Equal(2, first.Items.Count);
        Assert.All(first.Items, item => Assert.Equal(RouteStatus.Attached, item.Status));
        Assert.All(first.Items, item => Assert.NotNull(item.BackupPath));
        Assert.All(second.Items, item => Assert.Null(item.BackupPath));
        var routes = await registry.ListAsync(TestContext.Current.CancellationToken);
        Assert.Equal(2, routes.Count);
        Assert.Contains(routes, route => route.OriginalBaseUri.AbsoluteUri == "https://api.anthropic.com/");
        Assert.Contains(routes, route => route.OriginalBaseUri.AbsoluteUri == "https://api.openai.com/v1");
        Assert.Contains("http://127.0.0.1:18080/r/", await File.ReadAllTextAsync(claudePath, TestContext.Current.CancellationToken));
        Assert.Contains("http://127.0.0.1:18080/r/", await File.ReadAllTextAsync(codexPath, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Recovers_original_base_urls_from_013_direct_gateway_backups()
    {
        var claudePath = Path.Combine(ProfilePath, ".claude", "settings.json");
        var codexPath = Path.Combine(ProfilePath, ".codex", "config.toml");
        Directory.CreateDirectory(Path.GetDirectoryName(claudePath)!);
        Directory.CreateDirectory(Path.GetDirectoryName(codexPath)!);
        await File.WriteAllTextAsync(
            claudePath,
            "{\"env\":{\"ANTHROPIC_BASE_URL\":\"http://192.0.2.2:8080\"}}",
            TestContext.Current.CancellationToken);
        await File.WriteAllTextAsync(
            codexPath,
            "model = \"kimi-k3\"\nmodel_provider = \"company\"\n[model_providers.company]\nbase_url = \"http://192.0.2.2:8080\"\nwire_api = \"responses\"\n",
            TestContext.Current.CancellationToken);
        var profile = new WindowsUserProfile("S-1-5-21-direct-gateway", ProfilePath);
        var claudeBackupDirectory = Path.Combine(BackupRoot, profile.Sid, "ClaudeCode-direct-gateway");
        var codexBackupDirectory = Path.Combine(BackupRoot, profile.Sid, "CodexCli-direct-gateway");
        Directory.CreateDirectory(claudeBackupDirectory);
        Directory.CreateDirectory(codexBackupDirectory);
        await File.WriteAllTextAsync(
            Path.Combine(claudeBackupDirectory, "settings.json.20260826.bak"),
            "{\"env\":{\"ANTHROPIC_BASE_URL\":\"https://api.anthropic.com\"}}",
            TestContext.Current.CancellationToken);
        await File.WriteAllTextAsync(
            Path.Combine(codexBackupDirectory, "config.toml.20260826.bak"),
            "model = \"kimi-k3\"\nmodel_provider = \"company\"\n[model_providers.company]\nbase_url = \"https://api.moonshot.cn/v1\"\nwire_api = \"responses\"\n",
            TestContext.Current.CancellationToken);
        var registry = await CreateRegistryAsync();
        var coordinator = new AgentConfigAttachmentCoordinator(registry, new Uri("http://127.0.0.1:18080"));

        var first = await coordinator.AttachAsync(profile, BackupRoot, TestContext.Current.CancellationToken);
        var second = await coordinator.AttachAsync(profile, BackupRoot, TestContext.Current.CancellationToken);

        Assert.False(first.CcSwitchManaged);
        Assert.Equal(2, first.Items.Count);
        Assert.All(first.Items, item => Assert.NotNull(item.BackupPath));
        Assert.All(second.Items, item => Assert.Null(item.BackupPath));
        var routes = await registry.ListAsync(TestContext.Current.CancellationToken);
        Assert.Equal(2, routes.Count);
        Assert.Contains(routes, route => route.OriginalBaseUri.AbsoluteUri == "https://api.anthropic.com/");
        Assert.Contains(routes, route => route.OriginalBaseUri.AbsoluteUri == "https://api.moonshot.cn/v1");
        Assert.Contains("http://127.0.0.1:18080/r/", await File.ReadAllTextAsync(claudePath, TestContext.Current.CancellationToken));
        Assert.Contains("http://127.0.0.1:18080/r/", await File.ReadAllTextAsync(codexPath, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Attaches_ccswitch_database_and_current_live_config_without_changing_key()
    {
        var ccSwitchDirectory = Path.Combine(ProfilePath, ".cc-switch");
        var ccSwitchDatabase = Path.Combine(ccSwitchDirectory, "cc-switch.db");
        var claudePath = Path.Combine(ProfilePath, ".claude", "settings.json");
        Directory.CreateDirectory(ccSwitchDirectory);
        Directory.CreateDirectory(Path.GetDirectoryName(claudePath)!);
        await File.WriteAllTextAsync(
            claudePath,
            "{\"env\":{\"ANTHROPIC_BASE_URL\":\"https://api.anthropic.com\",\"ANTHROPIC_AUTH_TOKEN\":\"live-secret\"}}",
            TestContext.Current.CancellationToken);
        await CreateCcSwitchDatabaseAsync(ccSwitchDatabase);
        var registry = await CreateRegistryAsync();
        var coordinator = new AgentConfigAttachmentCoordinator(registry, new Uri("http://127.0.0.1:18080"));
        var profile = new WindowsUserProfile("S-1-5-21-ccswitch", ProfilePath);

        var result = await coordinator.AttachAsync(profile, BackupRoot, TestContext.Current.CancellationToken);

        Assert.True(result.CcSwitchManaged);
        Assert.Equal(2, result.Items.Count(item => item.Status == RouteStatus.Attached));
        Assert.All(result.Items, item => Assert.NotNull(item.BackupPath));
        Assert.Equal(CcSwitchOperatingMode.Ordinary, Assert.Single(result.CcSwitchApps!).Mode);
        var liveRoot = JsonNode.Parse(await File.ReadAllTextAsync(claudePath, TestContext.Current.CancellationToken))!.AsObject();
        Assert.Equal("live-secret", liveRoot["env"]!["ANTHROPIC_AUTH_TOKEN"]!.GetValue<string>());
        Assert.StartsWith("http://127.0.0.1:18080/r/", liveRoot["env"]!["ANTHROPIC_BASE_URL"]!.GetValue<string>());

        await using var connection = new SqliteConnection($"Data Source={ccSwitchDatabase};Mode=ReadOnly");
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT settings_config FROM providers WHERE id='anthropic-direct' AND app_type='claude';";
        var settings = JsonNode.Parse((string)(await command.ExecuteScalarAsync(TestContext.Current.CancellationToken))!)!.AsObject();
        Assert.Equal("db-secret", settings["env"]!["ANTHROPIC_AUTH_TOKEN"]!.GetValue<string>());
        Assert.StartsWith("http://127.0.0.1:18080/r/", settings["env"]!["ANTHROPIC_BASE_URL"]!.GetValue<string>());
    }

    [Fact]
    public async Task Direct_allowlisted_base_url_is_not_modified_or_routed()
    {
        var claudePath = Path.Combine(ProfilePath, ".claude", "settings.json");
        Directory.CreateDirectory(Path.GetDirectoryName(claudePath)!);
        const string content = "{\"env\":{\"ANTHROPIC_BASE_URL\":\"https://internal.example.invalid/ccr/\",\"ANTHROPIC_AUTH_TOKEN\":\"keep\"}}";
        await File.WriteAllTextAsync(claudePath, content, TestContext.Current.CancellationToken);
        var registry = await CreateRegistryAsync();
        var coordinator = new AgentConfigAttachmentCoordinator(registry, new Uri("http://127.0.0.1:18080"));
        var profile = new WindowsUserProfile("S-1-5-21-allowlisted", ProfilePath);

        var result = await coordinator.AttachAsync(profile, BackupRoot, TestContext.Current.CancellationToken);

        var item = Assert.Single(result.Items);
        Assert.Equal(RouteStatus.Bypassed, item.Status);
        Assert.Equal(BaseUrlBypassPolicy.BypassCode, item.ErrorCode);
        Assert.Equal(content, await File.ReadAllTextAsync(claudePath, TestContext.Current.CancellationToken));
        Assert.Empty(await registry.ListAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Upgrade_restores_allowlisted_original_and_retires_016_route()
    {
        var claudePath = Path.Combine(ProfilePath, ".claude", "settings.json");
        Directory.CreateDirectory(Path.GetDirectoryName(claudePath)!);
        var registry = await CreateRegistryAsync();
        var provisioner = new RouteProvisioner(registry, new Uri("http://127.0.0.1:18080"));
        var route = await provisioner.EnsureAsync(
            "S-1-5-21-upgrade-allowlisted",
            AgentType.ClaudeCode,
            "direct",
            new Uri("https://internal.example.invalid/ccr"),
            TestContext.Current.CancellationToken);
        await File.WriteAllTextAsync(
            claudePath,
            $"{{\"env\":{{\"ANTHROPIC_BASE_URL\":\"{route.InjectedBaseUri.AbsoluteUri}\"}}}}",
            TestContext.Current.CancellationToken);
        var coordinator = new AgentConfigAttachmentCoordinator(registry, new Uri("http://127.0.0.1:18080"));
        var profile = new WindowsUserProfile("S-1-5-21-upgrade-allowlisted", ProfilePath);

        var result = await coordinator.AttachAsync(profile, BackupRoot, TestContext.Current.CancellationToken);

        Assert.Equal(RouteStatus.Bypassed, Assert.Single(result.Items).Status);
        Assert.Contains(
            "https://internal.example.invalid/ccr",
            await File.ReadAllTextAsync(claudePath, TestContext.Current.CancellationToken));
        Assert.Empty(await registry.ListAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Dynamic_allowlist_restores_original_and_removal_reattaches_direct_route()
    {
        const string original = "https://model.example.invalid/v1";
        var claudePath = Path.Combine(ProfilePath, ".claude", "settings.json");
        Directory.CreateDirectory(Path.GetDirectoryName(claudePath)!);
        await File.WriteAllTextAsync(
            claudePath,
            $"{{\"env\":{{\"ANTHROPIC_BASE_URL\":\"{original}\",\"ANTHROPIC_AUTH_TOKEN\":\"keep\"}}}}",
            TestContext.Current.CancellationToken);
        var registry = await CreateRegistryAsync();
        var bypassPolicy = new BaseUrlBypassPolicy();
        bypassPolicy.Replace([]);
        var coordinator = new AgentConfigAttachmentCoordinator(
            registry,
            new Uri("http://127.0.0.1:18080"),
            bypassPolicy);
        var profile = new WindowsUserProfile("S-1-5-21-dynamic-allowlist", ProfilePath);

        var attached = await coordinator.AttachAsync(profile, BackupRoot, TestContext.Current.CancellationToken);
        Assert.Equal(RouteStatus.Attached, Assert.Single(attached.Items).Status);
        Assert.StartsWith(
            "http://127.0.0.1:18080/r/",
            JsonNode.Parse(await File.ReadAllTextAsync(claudePath, TestContext.Current.CancellationToken))!["env"]!["ANTHROPIC_BASE_URL"]!.GetValue<string>());

        Assert.True(bypassPolicy.Replace([original]));
        var bypassed = await coordinator.AttachAsync(profile, BackupRoot, TestContext.Current.CancellationToken);
        Assert.Equal(RouteStatus.Bypassed, Assert.Single(bypassed.Items).Status);
        Assert.Equal(
            original,
            JsonNode.Parse(await File.ReadAllTextAsync(claudePath, TestContext.Current.CancellationToken))!["env"]!["ANTHROPIC_BASE_URL"]!.GetValue<string>());
        Assert.Empty(await registry.ListAsync(TestContext.Current.CancellationToken));

        Assert.True(bypassPolicy.Replace([]));
        var reattached = await coordinator.AttachAsync(profile, BackupRoot, TestContext.Current.CancellationToken);
        Assert.Equal(RouteStatus.Attached, Assert.Single(reattached.Items).Status);
        Assert.Single(await registry.ListAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Local_proxy_mode_keeps_live_15721_and_routes_provider_and_endpoint_to_18080()
    {
        var ccSwitchDirectory = Path.Combine(ProfilePath, ".cc-switch");
        var ccSwitchDatabase = Path.Combine(ccSwitchDirectory, "cc-switch.db");
        var claudePath = Path.Combine(ProfilePath, ".claude", "settings.json");
        Directory.CreateDirectory(ccSwitchDirectory);
        Directory.CreateDirectory(Path.GetDirectoryName(claudePath)!);
        const string live = "{\"env\":{\"ANTHROPIC_BASE_URL\":\"http://127.0.0.1:15721\",\"ANTHROPIC_AUTH_TOKEN\":\"PROXY_MANAGED\"}}";
        await File.WriteAllTextAsync(claudePath, live, TestContext.Current.CancellationToken);
        await CreateCcSwitchDatabaseAsync(ccSwitchDatabase);
        await ExecuteDatabaseAsync(
            ccSwitchDatabase,
            "UPDATE proxy_config SET proxy_enabled=1, enabled=1, live_takeover_active=1 WHERE app_type='claude'; INSERT INTO proxy_live_backup VALUES ('claude', '{}', '2026-08-27T00:00:00Z');");
        var registry = await CreateRegistryAsync();
        var coordinator = new AgentConfigAttachmentCoordinator(registry, new Uri("http://127.0.0.1:18080"));
        var profile = new WindowsUserProfile("S-1-5-21-local-proxy", ProfilePath);

        var result = await coordinator.AttachAsync(profile, BackupRoot, TestContext.Current.CancellationToken);

        var mode = Assert.Single(result.CcSwitchApps!);
        Assert.Equal(CcSwitchOperatingMode.LocalProxy, mode.Mode);
        Assert.Equal(live, await File.ReadAllTextAsync(claudePath, TestContext.Current.CancellationToken));
        await using var connection = new SqliteConnection($"Data Source={ccSwitchDatabase};Mode=ReadOnly");
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        await using var providerCommand = connection.CreateCommand();
        providerCommand.CommandText = "SELECT settings_config FROM providers WHERE id='anthropic-direct';";
        var settings = JsonNode.Parse((string)(await providerCommand.ExecuteScalarAsync(TestContext.Current.CancellationToken))!)!.AsObject();
        Assert.StartsWith("http://127.0.0.1:18080/r/", settings["env"]!["ANTHROPIC_BASE_URL"]!.GetValue<string>());
        Assert.Equal("db-secret", settings["env"]!["ANTHROPIC_AUTH_TOKEN"]!.GetValue<string>());
        await using var endpointCommand = connection.CreateCommand();
        endpointCommand.CommandText = "SELECT url FROM provider_endpoints WHERE id=1;";
        Assert.StartsWith(
            "http://127.0.0.1:18080/r/",
            (string)(await endpointCommand.ExecuteScalarAsync(TestContext.Current.CancellationToken))!);
    }

    [Fact]
    public async Task Closing_local_proxy_reattaches_codex_live_config_to_existing_route()
    {
        var ccSwitchDirectory = Path.Combine(ProfilePath, ".cc-switch");
        var ccSwitchDatabase = Path.Combine(ccSwitchDirectory, "cc-switch.db");
        var codexPath = Path.Combine(ProfilePath, ".codex", "config.toml");
        Directory.CreateDirectory(ccSwitchDirectory);
        Directory.CreateDirectory(Path.GetDirectoryName(codexPath)!);
        const string takeoverLive = "model = \"kimi-k3\"\nmodel_provider = \"moonshot\"\n[model_providers.moonshot]\nbase_url = \"http://127.0.0.1:15721/v1\"\nwire_api = \"responses\"\n";
        const string restoredLive = "model = \"kimi-k3\"\nmodel_provider = \"moonshot\"\n[model_providers.moonshot]\nbase_url = \"https://api.moonshot.cn/v1\"\nwire_api = \"responses\"\n";
        await File.WriteAllTextAsync(codexPath, takeoverLive, TestContext.Current.CancellationToken);
        await CreateCodexCcSwitchDatabaseAsync(ccSwitchDatabase);
        var registry = await CreateRegistryAsync();
        var coordinator = new AgentConfigAttachmentCoordinator(registry, new Uri("http://127.0.0.1:18080"));
        var profile = new WindowsUserProfile("S-1-5-21-codex-close", ProfilePath);

        var local = await coordinator.AttachAsync(profile, BackupRoot, TestContext.Current.CancellationToken);
        var routes = await registry.ListAsync(TestContext.Current.CancellationToken);
        Assert.NotEmpty(routes);
        var providerTarget = InspectCodexBaseUrl(await ReadCodexProviderTomlAsync(ccSwitchDatabase));
        Assert.Equal(CcSwitchOperatingMode.LocalProxy, Assert.Single(local.CcSwitchApps!).Mode);
        Assert.Equal(takeoverLive, await File.ReadAllTextAsync(codexPath, TestContext.Current.CancellationToken));

        // CC Switch restores Live Config before it clears the per-app enabled flag.
        await File.WriteAllTextAsync(codexPath, restoredLive, TestContext.Current.CancellationToken);
        var transition = await coordinator.AttachAsync(profile, BackupRoot, TestContext.Current.CancellationToken);

        Assert.Equal(CcSwitchOperatingMode.Inconsistent, Assert.Single(transition.CcSwitchApps!).Mode);
        Assert.Equal(restoredLive, await File.ReadAllTextAsync(codexPath, TestContext.Current.CancellationToken));

        // Once CC Switch finishes its shutdown sequence, ordinary reconciliation must reattach immediately.
        await ExecuteDatabaseAsync(
            ccSwitchDatabase,
            "DELETE FROM proxy_live_backup WHERE app_type='codex'; UPDATE proxy_config SET proxy_enabled=0, enabled=0, live_takeover_active=0 WHERE app_type='codex';");

        var ordinary = await coordinator.AttachAsync(profile, BackupRoot, TestContext.Current.CancellationToken);

        Assert.Equal(CcSwitchOperatingMode.Ordinary, Assert.Single(ordinary.CcSwitchApps!).Mode);
        var reconciledLive = await File.ReadAllTextAsync(codexPath, TestContext.Current.CancellationToken);
        Assert.Contains(providerTarget, reconciledLive);
        Assert.DoesNotContain("https://api.moonshot.cn/v1", reconciledLive);
        Assert.Contains(providerTarget, await ReadCodexProviderTomlAsync(ccSwitchDatabase));
        Assert.StartsWith("http://127.0.0.1:18080/r/", await ReadEndpointUrlAsync(ccSwitchDatabase));
        Assert.Equal(routes.Count, (await registry.ListAsync(TestContext.Current.CancellationToken)).Count);
    }

    [Fact]
    public async Task Stale_live_backup_does_not_block_codex_ordinary_reconciliation()
    {
        var ccSwitchDirectory = Path.Combine(ProfilePath, ".cc-switch");
        var ccSwitchDatabase = Path.Combine(ccSwitchDirectory, "cc-switch.db");
        var codexPath = Path.Combine(ProfilePath, ".codex", "config.toml");
        Directory.CreateDirectory(ccSwitchDirectory);
        Directory.CreateDirectory(Path.GetDirectoryName(codexPath)!);
        const string takeoverLive = "model = \"kimi-k3\"\nmodel_provider = \"moonshot\"\n[model_providers.moonshot]\nbase_url = \"http://127.0.0.1:15721/v1\"\nwire_api = \"responses\"\n";
        const string restoredLive = "model = \"kimi-k3\"\nmodel_provider = \"moonshot\"\n[model_providers.moonshot]\nbase_url = \"https://api.moonshot.cn/v1\"\nwire_api = \"responses\"\n";
        await File.WriteAllTextAsync(codexPath, takeoverLive, TestContext.Current.CancellationToken);
        await CreateCodexCcSwitchDatabaseAsync(ccSwitchDatabase);
        var registry = await CreateRegistryAsync();
        var coordinator = new AgentConfigAttachmentCoordinator(registry, new Uri("http://127.0.0.1:18080"));
        var profile = new WindowsUserProfile("S-1-5-21-codex-stale-backup", ProfilePath);

        await coordinator.AttachAsync(profile, BackupRoot, TestContext.Current.CancellationToken);
        var providerTarget = InspectCodexBaseUrl(await ReadCodexProviderTomlAsync(ccSwitchDatabase));
        await File.WriteAllTextAsync(codexPath, restoredLive, TestContext.Current.CancellationToken);
        await ExecuteDatabaseAsync(
            ccSwitchDatabase,
            "UPDATE proxy_config SET enabled=0 WHERE app_type='codex';");

        var result = await coordinator.AttachAsync(profile, BackupRoot, TestContext.Current.CancellationToken);

        var status = Assert.Single(result.CcSwitchApps!);
        Assert.Equal(CcSwitchOperatingMode.Ordinary, status.Mode);
        Assert.Equal("CCSWITCH_STALE_LIVE_BACKUP_IGNORED", status.ErrorCode);
        Assert.Contains(
            providerTarget,
            await File.ReadAllTextAsync(codexPath, TestContext.Current.CancellationToken));
        Assert.Equal(1L, await ReadScalarInt64Async(
            ccSwitchDatabase,
            "SELECT COUNT(*) FROM proxy_live_backup WHERE app_type='codex';"));
        Assert.Equal(1L, await ReadScalarInt64Async(
            ccSwitchDatabase,
            "SELECT proxy_enabled FROM proxy_config WHERE app_type='codex';"));
        Assert.Equal(1L, await ReadScalarInt64Async(
            ccSwitchDatabase,
            "SELECT live_takeover_active FROM proxy_config WHERE app_type='codex';"));
    }

    [Fact]
    public async Task Cc_switch_claude_only_database_attaches_unmanaged_codex_directly()
    {
        var ccSwitchDatabase = Path.Combine(ProfilePath, ".cc-switch", "cc-switch.db");
        var claudePath = Path.Combine(ProfilePath, ".claude", "settings.json");
        var codexPath = Path.Combine(ProfilePath, ".codex", "config.toml");
        Directory.CreateDirectory(Path.GetDirectoryName(ccSwitchDatabase)!);
        Directory.CreateDirectory(Path.GetDirectoryName(claudePath)!);
        Directory.CreateDirectory(Path.GetDirectoryName(codexPath)!);
        const string codex = "model = \"doubao\"\nmodel_provider = \"volcengine\"\n[model_providers.volcengine]\nbase_url = \"https://ark.cn-beijing.volces.com/api/plan/v3\"\nwire_api = \"responses\"\nenv_key = \"ARK_API_KEY\"\n";
        await File.WriteAllTextAsync(
            claudePath,
            "{\"env\":{\"ANTHROPIC_BASE_URL\":\"https://api.anthropic.com\"}}",
            TestContext.Current.CancellationToken);
        await File.WriteAllTextAsync(codexPath, codex, TestContext.Current.CancellationToken);
        await CreateCcSwitchDatabaseAsync(ccSwitchDatabase);
        var registry = await CreateRegistryAsync();
        var coordinator = new AgentConfigAttachmentCoordinator(registry, new Uri("http://127.0.0.1:18080"));
        var profile = new WindowsUserProfile("S-1-5-21-mixed-claude", ProfilePath);

        var first = await coordinator.AttachAsync(profile, BackupRoot, TestContext.Current.CancellationToken);
        var second = await coordinator.AttachAsync(profile, BackupRoot, TestContext.Current.CancellationToken);

        Assert.True(first.CcSwitchManaged);
        var direct = Assert.Single(first.Items, item => item.AgentType == AgentType.CodexCli && item.ProviderId == "direct");
        Assert.Equal(new Uri("https://ark.cn-beijing.volces.com/api/plan/v3"), direct.OriginalBaseUri);
        Assert.NotNull(direct.BackupPath);
        var attachedCodex = await File.ReadAllTextAsync(codexPath, TestContext.Current.CancellationToken);
        Assert.Contains("http://127.0.0.1:18080/r/", attachedCodex);
        Assert.DoesNotContain("https://ark.cn-beijing.volces.com/api/plan/v3", attachedCodex);
        Assert.Contains("wire_api = \"responses\"", attachedCodex);
        Assert.Contains("env_key = \"ARK_API_KEY\"", attachedCodex);
        Assert.Equal(
            "Already attached.",
            Assert.Single(second.Items, item => item.AgentType == AgentType.CodexCli && item.ProviderId == "direct").Message);
    }

    [Fact]
    public async Task Cc_switch_codex_only_database_attaches_unmanaged_claude_directly()
    {
        var ccSwitchDatabase = Path.Combine(ProfilePath, ".cc-switch", "cc-switch.db");
        var claudePath = Path.Combine(ProfilePath, ".claude", "settings.json");
        var codexPath = Path.Combine(ProfilePath, ".codex", "config.toml");
        Directory.CreateDirectory(Path.GetDirectoryName(ccSwitchDatabase)!);
        Directory.CreateDirectory(Path.GetDirectoryName(claudePath)!);
        Directory.CreateDirectory(Path.GetDirectoryName(codexPath)!);
        await File.WriteAllTextAsync(
            claudePath,
            "{\"env\":{\"ANTHROPIC_BASE_URL\":\"https://api.anthropic.com\",\"ANTHROPIC_AUTH_TOKEN\":\"keep\"}}",
            TestContext.Current.CancellationToken);
        await File.WriteAllTextAsync(
            codexPath,
            "model = \"kimi\"\nmodel_provider = \"moonshot\"\n[model_providers.moonshot]\nbase_url = \"https://api.moonshot.cn/v1\"\nwire_api = \"responses\"\n",
            TestContext.Current.CancellationToken);
        await CreateCodexCcSwitchDatabaseAsync(ccSwitchDatabase);
        var registry = await CreateRegistryAsync();
        var coordinator = new AgentConfigAttachmentCoordinator(registry, new Uri("http://127.0.0.1:18080"));
        var profile = new WindowsUserProfile("S-1-5-21-mixed-codex", ProfilePath);

        var result = await coordinator.AttachAsync(profile, BackupRoot, TestContext.Current.CancellationToken);

        Assert.True(result.CcSwitchManaged);
        var direct = Assert.Single(result.Items, item => item.AgentType == AgentType.ClaudeCode && item.ProviderId == "direct");
        Assert.Equal(new Uri("https://api.anthropic.com"), direct.OriginalBaseUri);
        var attachedClaude = await File.ReadAllTextAsync(claudePath, TestContext.Current.CancellationToken);
        Assert.Contains("http://127.0.0.1:18080/r/", attachedClaude);
        Assert.Contains("keep", attachedClaude);
    }

    [Fact]
    public async Task Mixed_detach_restores_cc_switch_and_direct_configs()
    {
        var ccSwitchDatabase = Path.Combine(ProfilePath, ".cc-switch", "cc-switch.db");
        var claudePath = Path.Combine(ProfilePath, ".claude", "settings.json");
        var codexPath = Path.Combine(ProfilePath, ".codex", "config.toml");
        Directory.CreateDirectory(Path.GetDirectoryName(ccSwitchDatabase)!);
        Directory.CreateDirectory(Path.GetDirectoryName(claudePath)!);
        Directory.CreateDirectory(Path.GetDirectoryName(codexPath)!);
        await File.WriteAllTextAsync(
            claudePath,
            "{\"env\":{\"ANTHROPIC_BASE_URL\":\"https://api.anthropic.com\"}}",
            TestContext.Current.CancellationToken);
        const string codex = "model = \"doubao\"\nmodel_provider = \"volcengine\"\n[model_providers.volcengine]\nbase_url = \"https://ark.cn-beijing.volces.com/api/plan/v3\"\nwire_api = \"responses\"\n";
        await File.WriteAllTextAsync(codexPath, codex, TestContext.Current.CancellationToken);
        await CreateCcSwitchDatabaseAsync(ccSwitchDatabase);
        var registry = await CreateRegistryAsync();
        var coordinator = new AgentConfigAttachmentCoordinator(registry, new Uri("http://127.0.0.1:18080"));
        var profile = new WindowsUserProfile("S-1-5-21-mixed-detach", ProfilePath);

        await coordinator.AttachAsync(profile, BackupRoot, TestContext.Current.CancellationToken);
        await coordinator.DetachAsync(profile, BackupRoot, TestContext.Current.CancellationToken);

        Assert.Empty(await registry.ListAsync(TestContext.Current.CancellationToken));
        Assert.Contains(
            "https://api.anthropic.com",
            await File.ReadAllTextAsync(claudePath, TestContext.Current.CancellationToken));
        Assert.Equal(codex, await File.ReadAllTextAsync(codexPath, TestContext.Current.CancellationToken));
        Assert.Equal("https://api.anthropic.com", await ReadProviderBaseUrlAsync(ccSwitchDatabase));
        Assert.Equal("https://api.anthropic.com", await ReadEndpointUrlAsync(ccSwitchDatabase));
    }

    [Fact]
    public async Task Direct_to_cc_switch_handoff_creates_owned_routes_and_retires_direct_route()
    {
        var codexPath = Path.Combine(ProfilePath, ".codex", "config.toml");
        Directory.CreateDirectory(Path.GetDirectoryName(codexPath)!);
        await File.WriteAllTextAsync(
            codexPath,
            "model = \"kimi\"\nmodel_provider = \"moonshot\"\n[model_providers.moonshot]\nbase_url = \"https://api.moonshot.cn/v1\"\nwire_api = \"responses\"\n",
            TestContext.Current.CancellationToken);
        var registry = await CreateRegistryAsync();
        var coordinator = new AgentConfigAttachmentCoordinator(registry, new Uri("http://127.0.0.1:18080"));
        var profile = new WindowsUserProfile("S-1-5-21-direct-to-cc", ProfilePath);
        var directResult = await coordinator.AttachAsync(profile, BackupRoot, TestContext.Current.CancellationToken);
        var direct = Assert.Single(directResult.Items);
        var ccSwitchDatabase = Path.Combine(ProfilePath, ".cc-switch", "cc-switch.db");
        Directory.CreateDirectory(Path.GetDirectoryName(ccSwitchDatabase)!);
        await CreateCodexCcSwitchDatabaseAsync(ccSwitchDatabase);
        var settings = new JsonObject
        {
            ["config"] = $"model = \"kimi\"\nmodel_provider = \"moonshot\"\n[model_providers.moonshot]\nbase_url = \"{direct.InjectedBaseUri}\"\nwire_api = \"responses\"\n",
            ["api_key"] = "db-secret",
        }.ToJsonString();
        await ExecuteDatabaseWithParametersAsync(
            ccSwitchDatabase,
            "UPDATE providers SET settings_config=$settings WHERE app_type='codex'; UPDATE provider_endpoints SET url=$url WHERE app_type='codex'; UPDATE proxy_config SET proxy_enabled=0, enabled=0, live_takeover_active=0 WHERE app_type='codex'; DELETE FROM proxy_live_backup WHERE app_type='codex';",
            ("$settings", settings),
            ("$url", direct.InjectedBaseUri!.AbsoluteUri));

        var result = await coordinator.AttachAsync(profile, BackupRoot, TestContext.Current.CancellationToken);

        Assert.True(result.CcSwitchManaged);
        Assert.DoesNotContain(result.Items, item => item.Status == RouteStatus.Error);
        var routes = await registry.ListAsync(TestContext.Current.CancellationToken);
        Assert.DoesNotContain(routes, route => route.AgentType == AgentType.CodexCli && route.ProviderId == "direct");
        Assert.Contains(routes, route => route.AgentType == AgentType.CcSwitch && route.ProviderId == "codex:moonshot-direct");
        Assert.Contains(routes, route => route.AgentType == AgentType.CcSwitch && route.ProviderId.StartsWith("codex:moonshot-direct:endpoint:", StringComparison.Ordinal));
        Assert.Contains(
            routes.Single(route => route.ProviderId == "codex:moonshot-direct").InjectedBaseUri.AbsoluteUri,
            await File.ReadAllTextAsync(codexPath, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Deleted_cc_switch_endpoint_is_retired_after_all_references_are_absent()
    {
        var ccSwitchDatabase = Path.Combine(ProfilePath, ".cc-switch", "cc-switch.db");
        var codexPath = Path.Combine(ProfilePath, ".codex", "config.toml");
        Directory.CreateDirectory(Path.GetDirectoryName(ccSwitchDatabase)!);
        Directory.CreateDirectory(Path.GetDirectoryName(codexPath)!);
        await File.WriteAllTextAsync(
            codexPath,
            "model = \"kimi-k3\"\nmodel_provider = \"moonshot\"\n[model_providers.moonshot]\nbase_url = \"http://127.0.0.1:15721/v1\"\nwire_api = \"responses\"\n",
            TestContext.Current.CancellationToken);
        await CreateCodexCcSwitchDatabaseAsync(ccSwitchDatabase);
        var registry = await CreateRegistryAsync();
        var coordinator = new AgentConfigAttachmentCoordinator(registry, new Uri("http://127.0.0.1:18080"));
        var profile = new WindowsUserProfile("S-1-5-21-deleted-endpoint", ProfilePath);

        await coordinator.AttachAsync(profile, BackupRoot, TestContext.Current.CancellationToken);
        Assert.Contains(
            await registry.ListAsync(TestContext.Current.CancellationToken),
            route => route.ProviderId == "codex:moonshot-direct:endpoint:1");
        await ExecuteDatabaseAsync(
            ccSwitchDatabase,
            "DELETE FROM provider_endpoints WHERE app_type='codex' AND provider_id='moonshot-direct' AND id=1;");

        var result = await coordinator.AttachAsync(profile, BackupRoot, TestContext.Current.CancellationToken);

        Assert.DoesNotContain(result.Items, item => item.ErrorCode == "ORPHAN_ROUTE_RETIREMENT_DEFERRED");
        var remaining = await registry.ListAsync(TestContext.Current.CancellationToken);
        Assert.DoesNotContain(remaining, route => route.ProviderId == "codex:moonshot-direct:endpoint:1");
        Assert.Single(remaining, route => route.ProviderId == "codex:moonshot-direct");
    }

    [Fact]
    public async Task Deleted_cc_switch_endpoint_route_is_retained_when_a_live_config_cannot_be_verified()
    {
        var ccSwitchDatabase = Path.Combine(ProfilePath, ".cc-switch", "cc-switch.db");
        var codexPath = Path.Combine(ProfilePath, ".codex", "config.toml");
        var claudePath = Path.Combine(ProfilePath, ".claude", "settings.json");
        Directory.CreateDirectory(Path.GetDirectoryName(ccSwitchDatabase)!);
        Directory.CreateDirectory(Path.GetDirectoryName(codexPath)!);
        Directory.CreateDirectory(Path.GetDirectoryName(claudePath)!);
        await File.WriteAllTextAsync(
            codexPath,
            "model = \"kimi-k3\"\nmodel_provider = \"moonshot\"\n[model_providers.moonshot]\nbase_url = \"http://127.0.0.1:15721/v1\"\nwire_api = \"responses\"\n",
            TestContext.Current.CancellationToken);
        await File.WriteAllTextAsync(claudePath, "[]", TestContext.Current.CancellationToken);
        await CreateCodexCcSwitchDatabaseAsync(ccSwitchDatabase);
        var registry = await CreateRegistryAsync();
        var coordinator = new AgentConfigAttachmentCoordinator(registry, new Uri("http://127.0.0.1:18080"));
        var profile = new WindowsUserProfile("S-1-5-21-deferred-endpoint", ProfilePath);

        await coordinator.AttachAsync(profile, BackupRoot, TestContext.Current.CancellationToken);
        await ExecuteDatabaseAsync(
            ccSwitchDatabase,
            "DELETE FROM provider_endpoints WHERE app_type='codex' AND provider_id='moonshot-direct' AND id=1;");

        var result = await coordinator.AttachAsync(profile, BackupRoot, TestContext.Current.CancellationToken);

        Assert.Contains(result.Items, item => item.ErrorCode == "ORPHAN_ROUTE_RETIREMENT_DEFERRED"
            && item.ProviderId == "codex:moonshot-direct:endpoint:1");
        Assert.Contains(
            await registry.ListAsync(TestContext.Current.CancellationToken),
            route => route.ProviderId == "codex:moonshot-direct:endpoint:1");
    }

    [Fact]
    public async Task Cc_switch_to_direct_handoff_retires_all_old_cc_switch_routes()
    {
        var codexPath = Path.Combine(ProfilePath, ".codex", "config.toml");
        var ccSwitchDatabase = Path.Combine(ProfilePath, ".cc-switch", "cc-switch.db");
        Directory.CreateDirectory(Path.GetDirectoryName(codexPath)!);
        Directory.CreateDirectory(Path.GetDirectoryName(ccSwitchDatabase)!);
        await File.WriteAllTextAsync(
            codexPath,
            "model = \"kimi\"\nmodel_provider = \"moonshot\"\n[model_providers.moonshot]\nbase_url = \"https://api.moonshot.cn/v1\"\nwire_api = \"responses\"\n",
            TestContext.Current.CancellationToken);
        await CreateCodexCcSwitchDatabaseAsync(ccSwitchDatabase);
        var registry = await CreateRegistryAsync();
        var coordinator = new AgentConfigAttachmentCoordinator(registry, new Uri("http://127.0.0.1:18080"));
        var profile = new WindowsUserProfile("S-1-5-21-cc-to-direct", ProfilePath);
        await coordinator.AttachAsync(profile, BackupRoot, TestContext.Current.CancellationToken);
        await ExecuteDatabaseAsync(
            ccSwitchDatabase,
            "DELETE FROM provider_endpoints WHERE app_type='codex'; DELETE FROM providers WHERE app_type='codex'; DELETE FROM proxy_config WHERE app_type='codex';");

        var result = await coordinator.AttachAsync(profile, BackupRoot, TestContext.Current.CancellationToken);

        Assert.False(result.CcSwitchManaged);
        var routes = await registry.ListAsync(TestContext.Current.CancellationToken);
        var direct = Assert.Single(routes);
        Assert.Equal(AgentType.CodexCli, direct.AgentType);
        Assert.Equal("direct", direct.ProviderId);
        Assert.Equal(new Uri("https://api.moonshot.cn/v1"), direct.OriginalBaseUri);
        Assert.Contains(
            direct.InjectedBaseUri.AbsoluteUri,
            await File.ReadAllTextAsync(codexPath, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Detach_recovers_legacy_cc_switch_mapping_that_reused_a_direct_route()
    {
        var codexPath = Path.Combine(ProfilePath, ".codex", "config.toml");
        Directory.CreateDirectory(Path.GetDirectoryName(codexPath)!);
        await File.WriteAllTextAsync(
            codexPath,
            "model = \"kimi\"\nmodel_provider = \"moonshot\"\n[model_providers.moonshot]\nbase_url = \"https://api.moonshot.cn/v1\"\nwire_api = \"responses\"\n",
            TestContext.Current.CancellationToken);
        var registry = await CreateRegistryAsync();
        var coordinator = new AgentConfigAttachmentCoordinator(registry, new Uri("http://127.0.0.1:18080"));
        var profile = new WindowsUserProfile("S-1-5-21-legacy-direct", ProfilePath);
        var direct = Assert.Single((await coordinator.AttachAsync(
            profile,
            BackupRoot,
            TestContext.Current.CancellationToken)).Items);
        var ccSwitchDatabase = Path.Combine(ProfilePath, ".cc-switch", "cc-switch.db");
        Directory.CreateDirectory(Path.GetDirectoryName(ccSwitchDatabase)!);
        await CreateCodexCcSwitchDatabaseAsync(ccSwitchDatabase);
        var settings = new JsonObject
        {
            ["config"] = $"model = \"kimi\"\nmodel_provider = \"moonshot\"\n[model_providers.moonshot]\nbase_url = \"{direct.InjectedBaseUri}\"\nwire_api = \"responses\"\n",
            ["api_key"] = "db-secret",
        }.ToJsonString();
        await ExecuteDatabaseWithParametersAsync(
            ccSwitchDatabase,
            "UPDATE providers SET settings_config=$settings WHERE app_type='codex'; UPDATE provider_endpoints SET url=$url WHERE app_type='codex'; UPDATE proxy_config SET proxy_enabled=0, enabled=0, live_takeover_active=0 WHERE app_type='codex'; DELETE FROM proxy_live_backup WHERE app_type='codex';",
            ("$settings", settings),
            ("$url", direct.InjectedBaseUri!.AbsoluteUri));

        await coordinator.DetachAsync(profile, BackupRoot, TestContext.Current.CancellationToken);

        Assert.Empty(await registry.ListAsync(TestContext.Current.CancellationToken));
        Assert.Contains(
            "https://api.moonshot.cn/v1",
            await File.ReadAllTextAsync(codexPath, TestContext.Current.CancellationToken));
        Assert.Contains("https://api.moonshot.cn/v1", await ReadCodexProviderTomlAsync(ccSwitchDatabase));
        Assert.Equal("https://api.moonshot.cn/v1", await ReadEndpointUrlAsync(ccSwitchDatabase));
    }

    [Fact]
    public async Task Unsupported_cc_switch_schema_blocks_both_direct_fallbacks()
    {
        var claudePath = Path.Combine(ProfilePath, ".claude", "settings.json");
        var codexPath = Path.Combine(ProfilePath, ".codex", "config.toml");
        var ccSwitchDatabase = Path.Combine(ProfilePath, ".cc-switch", "cc-switch.db");
        Directory.CreateDirectory(Path.GetDirectoryName(claudePath)!);
        Directory.CreateDirectory(Path.GetDirectoryName(codexPath)!);
        Directory.CreateDirectory(Path.GetDirectoryName(ccSwitchDatabase)!);
        const string claude = "{\"env\":{\"ANTHROPIC_BASE_URL\":\"https://api.anthropic.com\"}}";
        const string codex = "model = \"gpt\"\nopenai_base_url = \"https://api.openai.com/v1\"\n";
        await File.WriteAllTextAsync(claudePath, claude, TestContext.Current.CancellationToken);
        await File.WriteAllTextAsync(codexPath, codex, TestContext.Current.CancellationToken);
        await ExecuteDatabaseAsync(
            ccSwitchDatabase,
            "CREATE TABLE providers (id TEXT, app_type TEXT); INSERT INTO providers VALUES ('broken', 'claude');");
        var registry = await CreateRegistryAsync();
        var coordinator = new AgentConfigAttachmentCoordinator(registry, new Uri("http://127.0.0.1:18080"));
        var profile = new WindowsUserProfile("S-1-5-21-schema-block", ProfilePath);

        var result = await coordinator.AttachAsync(profile, BackupRoot, TestContext.Current.CancellationToken);

        Assert.False(result.CcSwitchManaged);
        Assert.Equal(2, result.Items.Count(item => item.ErrorCode == "CCSWITCH_SCHEMA_UNSUPPORTED"));
        Assert.Equal(claude, await File.ReadAllTextAsync(claudePath, TestContext.Current.CancellationToken));
        Assert.Equal(codex, await File.ReadAllTextAsync(codexPath, TestContext.Current.CancellationToken));
        Assert.Empty(await registry.ListAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Unmanaged_app_in_local_proxy_mode_is_not_direct_attached()
    {
        var codexPath = Path.Combine(ProfilePath, ".codex", "config.toml");
        var ccSwitchDatabase = Path.Combine(ProfilePath, ".cc-switch", "cc-switch.db");
        Directory.CreateDirectory(Path.GetDirectoryName(codexPath)!);
        Directory.CreateDirectory(Path.GetDirectoryName(ccSwitchDatabase)!);
        const string takeover = "model = \"kimi\"\nmodel_provider = \"moonshot\"\n[model_providers.moonshot]\nbase_url = \"http://127.0.0.1:15721/v1\"\nwire_api = \"responses\"\n";
        await File.WriteAllTextAsync(codexPath, takeover, TestContext.Current.CancellationToken);
        await CreateCodexCcSwitchDatabaseAsync(ccSwitchDatabase);
        await ExecuteDatabaseAsync(
            ccSwitchDatabase,
            "DELETE FROM provider_endpoints WHERE app_type='codex'; DELETE FROM providers WHERE app_type='codex';");
        var registry = await CreateRegistryAsync();
        var coordinator = new AgentConfigAttachmentCoordinator(registry, new Uri("http://127.0.0.1:18080"));
        var profile = new WindowsUserProfile("S-1-5-21-unmanaged-local", ProfilePath);

        var result = await coordinator.AttachAsync(profile, BackupRoot, TestContext.Current.CancellationToken);

        Assert.False(result.CcSwitchManaged);
        Assert.Contains(result.Items, item => item.ErrorCode == "CCSWITCH_PROXY_LISTENER_UNAVAILABLE"
            || item.ErrorCode == "CCSWITCH_PROXY_STATE_INCONSISTENT");
        Assert.Equal(takeover, await File.ReadAllTextAsync(codexPath, TestContext.Current.CancellationToken));
        Assert.Empty(await registry.ListAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Ordinary_cc_switch_app_with_no_current_provider_is_blocked()
    {
        var claudePath = Path.Combine(ProfilePath, ".claude", "settings.json");
        var ccSwitchDatabase = Path.Combine(ProfilePath, ".cc-switch", "cc-switch.db");
        Directory.CreateDirectory(Path.GetDirectoryName(claudePath)!);
        Directory.CreateDirectory(Path.GetDirectoryName(ccSwitchDatabase)!);
        const string live = "{\"env\":{\"ANTHROPIC_BASE_URL\":\"https://api.anthropic.com\"}}";
        await File.WriteAllTextAsync(claudePath, live, TestContext.Current.CancellationToken);
        await CreateCcSwitchDatabaseAsync(ccSwitchDatabase);
        await ExecuteDatabaseAsync(ccSwitchDatabase, "UPDATE providers SET is_current=0 WHERE app_type='claude';");
        var registry = await CreateRegistryAsync();
        var coordinator = new AgentConfigAttachmentCoordinator(registry, new Uri("http://127.0.0.1:18080"));
        var profile = new WindowsUserProfile("S-1-5-21-no-current", ProfilePath);

        var result = await coordinator.AttachAsync(profile, BackupRoot, TestContext.Current.CancellationToken);

        Assert.True(result.CcSwitchManaged);
        Assert.Contains(result.Items, item => item.ErrorCode == "CCSWITCH_CURRENT_PROVIDER_INVALID");
        Assert.Equal(live, await File.ReadAllTextAsync(claudePath, TestContext.Current.CancellationToken));
        Assert.Equal("https://api.anthropic.com", await ReadProviderBaseUrlAsync(ccSwitchDatabase));
        Assert.Empty(await registry.ListAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Ordinary_mode_detach_restores_database_live_config_and_removes_routes()
    {
        var ccSwitchDirectory = Path.Combine(ProfilePath, ".cc-switch");
        var ccSwitchDatabase = Path.Combine(ccSwitchDirectory, "cc-switch.db");
        var claudePath = Path.Combine(ProfilePath, ".claude", "settings.json");
        Directory.CreateDirectory(ccSwitchDirectory);
        Directory.CreateDirectory(Path.GetDirectoryName(claudePath)!);
        await File.WriteAllTextAsync(
            claudePath,
            "{\"env\":{\"ANTHROPIC_BASE_URL\":\"https://api.anthropic.com\",\"ANTHROPIC_AUTH_TOKEN\":\"live-secret\"}}",
            TestContext.Current.CancellationToken);
        await CreateCcSwitchDatabaseAsync(ccSwitchDatabase);
        var registry = await CreateRegistryAsync();
        var coordinator = new AgentConfigAttachmentCoordinator(registry, new Uri("http://127.0.0.1:18080"));
        var profile = new WindowsUserProfile("S-1-5-21-detach-ordinary", ProfilePath);

        await coordinator.AttachAsync(profile, BackupRoot, TestContext.Current.CancellationToken);
        var result = await coordinator.DetachAsync(profile, BackupRoot, TestContext.Current.CancellationToken);

        Assert.Equal(2, result.Items.Count);
        Assert.Empty(await registry.ListAsync(TestContext.Current.CancellationToken));
        var liveRoot = JsonNode.Parse(await File.ReadAllTextAsync(claudePath, TestContext.Current.CancellationToken))!.AsObject();
        Assert.Equal("https://api.anthropic.com", liveRoot["env"]!["ANTHROPIC_BASE_URL"]!.GetValue<string>());
        Assert.Equal("live-secret", liveRoot["env"]!["ANTHROPIC_AUTH_TOKEN"]!.GetValue<string>());
        Assert.Equal("https://api.anthropic.com", await ReadProviderBaseUrlAsync(ccSwitchDatabase));
        Assert.Equal("https://api.anthropic.com", await ReadEndpointUrlAsync(ccSwitchDatabase));
    }

    [Fact]
    public async Task Local_proxy_detach_restores_database_but_keeps_takeover_live_config()
    {
        var ccSwitchDirectory = Path.Combine(ProfilePath, ".cc-switch");
        var ccSwitchDatabase = Path.Combine(ccSwitchDirectory, "cc-switch.db");
        var claudePath = Path.Combine(ProfilePath, ".claude", "settings.json");
        Directory.CreateDirectory(ccSwitchDirectory);
        Directory.CreateDirectory(Path.GetDirectoryName(claudePath)!);
        const string live = "{\"env\":{\"ANTHROPIC_BASE_URL\":\"http://127.0.0.1:15721\",\"ANTHROPIC_AUTH_TOKEN\":\"PROXY_MANAGED\"}}";
        await File.WriteAllTextAsync(claudePath, live, TestContext.Current.CancellationToken);
        await CreateCcSwitchDatabaseAsync(ccSwitchDatabase);
        await ExecuteDatabaseAsync(
            ccSwitchDatabase,
            "UPDATE proxy_config SET proxy_enabled=1, enabled=1, live_takeover_active=1 WHERE app_type='claude'; INSERT INTO proxy_live_backup VALUES ('claude', '{}', '2026-08-27T00:00:00Z');");
        var registry = await CreateRegistryAsync();
        var coordinator = new AgentConfigAttachmentCoordinator(registry, new Uri("http://127.0.0.1:18080"));
        var profile = new WindowsUserProfile("S-1-5-21-detach-local-proxy", ProfilePath);

        await coordinator.AttachAsync(profile, BackupRoot, TestContext.Current.CancellationToken);
        var result = await coordinator.DetachAsync(profile, BackupRoot, TestContext.Current.CancellationToken);

        Assert.Equal(CcSwitchOperatingMode.LocalProxy, Assert.Single(result.CcSwitchApps!).Mode);
        Assert.Equal(live, await File.ReadAllTextAsync(claudePath, TestContext.Current.CancellationToken));
        Assert.Equal("https://api.anthropic.com", await ReadProviderBaseUrlAsync(ccSwitchDatabase));
        Assert.Equal("https://api.anthropic.com", await ReadEndpointUrlAsync(ccSwitchDatabase));
        Assert.Empty(await registry.ListAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Cc_switch_allowlisted_provider_and_endpoint_are_left_unchanged()
    {
        var ccSwitchDirectory = Path.Combine(ProfilePath, ".cc-switch");
        var ccSwitchDatabase = Path.Combine(ccSwitchDirectory, "cc-switch.db");
        var claudePath = Path.Combine(ProfilePath, ".claude", "settings.json");
        Directory.CreateDirectory(ccSwitchDirectory);
        Directory.CreateDirectory(Path.GetDirectoryName(claudePath)!);
        const string live = "{\"env\":{\"ANTHROPIC_BASE_URL\":\"https://internal.example.invalid/ccr/\",\"ANTHROPIC_AUTH_TOKEN\":\"keep\"}}";
        await File.WriteAllTextAsync(claudePath, live, TestContext.Current.CancellationToken);
        await CreateCcSwitchDatabaseAsync(ccSwitchDatabase);
        await ExecuteDatabaseAsync(
            ccSwitchDatabase,
            """
            UPDATE providers
            SET settings_config='{"env":{"ANTHROPIC_BASE_URL":"https://internal.example.invalid/ccr/","ANTHROPIC_AUTH_TOKEN":"db-secret"}}'
            WHERE id='anthropic-direct';
            UPDATE provider_endpoints SET url='https://internal.example.invalid/ccr' WHERE id=1;
            """);
        var registry = await CreateRegistryAsync();
        var coordinator = new AgentConfigAttachmentCoordinator(registry, new Uri("http://127.0.0.1:18080"));
        var profile = new WindowsUserProfile("S-1-5-21-ccswitch-allowlisted", ProfilePath);

        var result = await coordinator.AttachAsync(profile, BackupRoot, TestContext.Current.CancellationToken);

        Assert.Equal(2, result.Items.Count(item => item.Status == RouteStatus.Bypassed));
        Assert.Empty(await registry.ListAsync(TestContext.Current.CancellationToken));
        Assert.Equal(live, await File.ReadAllTextAsync(claudePath, TestContext.Current.CancellationToken));
        Assert.Equal("https://internal.example.invalid/ccr/", await ReadProviderBaseUrlAsync(ccSwitchDatabase));
        Assert.Equal("https://internal.example.invalid/ccr", await ReadEndpointUrlAsync(ccSwitchDatabase));
    }

    [Fact]
    public async Task Dynamic_allowlist_restores_and_reattaches_cc_switch_provider_and_endpoint()
    {
        var ccSwitchDirectory = Path.Combine(ProfilePath, ".cc-switch");
        var ccSwitchDatabase = Path.Combine(ccSwitchDirectory, "cc-switch.db");
        var claudePath = Path.Combine(ProfilePath, ".claude", "settings.json");
        Directory.CreateDirectory(ccSwitchDirectory);
        Directory.CreateDirectory(Path.GetDirectoryName(claudePath)!);
        await File.WriteAllTextAsync(
            claudePath,
            "{\"env\":{\"ANTHROPIC_BASE_URL\":\"https://api.anthropic.com\",\"ANTHROPIC_AUTH_TOKEN\":\"live-secret\"}}",
            TestContext.Current.CancellationToken);
        await CreateCcSwitchDatabaseAsync(ccSwitchDatabase);
        var registry = await CreateRegistryAsync();
        var bypassPolicy = new BaseUrlBypassPolicy();
        bypassPolicy.Replace([]);
        var coordinator = new AgentConfigAttachmentCoordinator(
            registry,
            new Uri("http://127.0.0.1:18080"),
            bypassPolicy);
        var profile = new WindowsUserProfile("S-1-5-21-ccswitch-dynamic-allowlist", ProfilePath);

        await coordinator.AttachAsync(profile, BackupRoot, TestContext.Current.CancellationToken);
        Assert.StartsWith("http://127.0.0.1:18080/r/", await ReadProviderBaseUrlAsync(ccSwitchDatabase));
        Assert.StartsWith("http://127.0.0.1:18080/r/", await ReadEndpointUrlAsync(ccSwitchDatabase));
        Assert.Equal(2, (await registry.ListAsync(TestContext.Current.CancellationToken)).Count);

        bypassPolicy.Replace(["https://API.ANTHROPIC.COM:443/"]);
        var restored = await coordinator.AttachAsync(profile, BackupRoot, TestContext.Current.CancellationToken);
        Assert.Equal(2, restored.Items.Count(item => item.Status == RouteStatus.Bypassed));
        Assert.Equal("https://api.anthropic.com", await ReadProviderBaseUrlAsync(ccSwitchDatabase));
        Assert.Equal("https://api.anthropic.com", await ReadEndpointUrlAsync(ccSwitchDatabase));
        Assert.Empty(await registry.ListAsync(TestContext.Current.CancellationToken));
        Assert.Contains("live-secret", await File.ReadAllTextAsync(claudePath, TestContext.Current.CancellationToken));

        bypassPolicy.Replace([]);
        var reattached = await coordinator.AttachAsync(profile, BackupRoot, TestContext.Current.CancellationToken);
        Assert.Equal(2, reattached.Items.Count(item => item.Status == RouteStatus.Attached));
        Assert.StartsWith("http://127.0.0.1:18080/r/", await ReadProviderBaseUrlAsync(ccSwitchDatabase));
        Assert.StartsWith("http://127.0.0.1:18080/r/", await ReadEndpointUrlAsync(ccSwitchDatabase));
        Assert.Equal(2, (await registry.ListAsync(TestContext.Current.CancellationToken)).Count);
    }

    [Fact]
    public async Task Live_config_failure_restores_ccswitch_database()
    {
        var ccSwitchDirectory = Path.Combine(ProfilePath, ".cc-switch");
        var ccSwitchDatabase = Path.Combine(ccSwitchDirectory, "cc-switch.db");
        var claudePath = Path.Combine(ProfilePath, ".claude", "settings.json");
        var codexPath = Path.Combine(ProfilePath, ".codex", "config.toml");
        Directory.CreateDirectory(ccSwitchDirectory);
        Directory.CreateDirectory(Path.GetDirectoryName(claudePath)!);
        Directory.CreateDirectory(Path.GetDirectoryName(codexPath)!);
        await File.WriteAllTextAsync(claudePath, "[]", TestContext.Current.CancellationToken);
        await File.WriteAllTextAsync(
            codexPath,
            "model = \"gpt\"\nopenai_base_url = \"https://api.openai.com/v1\"\n",
            TestContext.Current.CancellationToken);
        await CreateCcSwitchDatabaseAsync(ccSwitchDatabase);
        var registry = await CreateRegistryAsync();
        var coordinator = new AgentConfigAttachmentCoordinator(registry, new Uri("http://127.0.0.1:18080"));
        var profile = new WindowsUserProfile("S-1-5-21-rollback", ProfilePath);

        var result = await coordinator.AttachAsync(
            profile,
            BackupRoot,
            TestContext.Current.CancellationToken);

        var error = Assert.Single(result.Items, item => item.Status == RouteStatus.Error);
        Assert.Equal("CLAUDE_SETTINGS_ROOT_INVALID", error.ErrorCode);
        Assert.Single(result.Items, item => item.AgentType == AgentType.CodexCli && item.Status == RouteStatus.Attached);
        await using var connection = new SqliteConnection($"Data Source={ccSwitchDatabase};Mode=ReadOnly");
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT settings_config FROM providers WHERE id='anthropic-direct' AND app_type='claude';";
        var settings = JsonNode.Parse((string)(await command.ExecuteScalarAsync(TestContext.Current.CancellationToken))!)!.AsObject();
        Assert.Equal(
            "https://api.anthropic.com",
            settings["env"]!["ANTHROPIC_BASE_URL"]!.GetValue<string>());
        var route = Assert.Single(await registry.ListAsync(TestContext.Current.CancellationToken));
        Assert.Equal(AgentType.CodexCli, route.AgentType);
    }

    private async Task<SqliteRouteRegistry> CreateRegistryAsync()
    {
        var registry = new SqliteRouteRegistry(StatePath, new TestProtector());
        await registry.InitializeAsync(TestContext.Current.CancellationToken);
        return registry;
    }

    private static async Task CreateCcSwitchDatabaseAsync(string path)
    {
        await using var connection = new SqliteConnection($"Data Source={path}");
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            PRAGMA user_version=11;
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
                '{"env":{"ANTHROPIC_BASE_URL":"https://api.anthropic.com","ANTHROPIC_AUTH_TOKEN":"db-secret"},"apiFormat":"anthropic"}',
                1);
            INSERT INTO provider_endpoints VALUES (1, 'anthropic-direct', 'claude', 'https://api.anthropic.com');
            INSERT INTO proxy_config VALUES ('claude', 0, 0, '127.0.0.1', 15721, 0);
            """;
        await command.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
    }

    private static async Task CreateCodexCcSwitchDatabaseAsync(string path)
    {
        await using var connection = new SqliteConnection($"Data Source={path}");
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        await using var command = connection.CreateCommand();
        command.Parameters.AddWithValue(
            "$settings",
            new JsonObject
            {
                ["config"] = "model = \"kimi-k3\"\nmodel_provider = \"moonshot\"\n[model_providers.moonshot]\nbase_url = \"https://api.moonshot.cn/v1\"\nwire_api = \"responses\"\n",
                ["api_key"] = "db-secret",
            }.ToJsonString());
        command.CommandText = """
            PRAGMA user_version=11;
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
                'moonshot-direct', 'codex', 'Moonshot Direct',
                $settings,
                1);
            INSERT INTO provider_endpoints VALUES (1, 'moonshot-direct', 'codex', 'https://api.moonshot.cn/v1');
            INSERT INTO proxy_config VALUES ('codex', 1, 1, '127.0.0.1', 15721, 1);
            INSERT INTO proxy_live_backup VALUES ('codex', '{}', '2026-08-27T00:00:00Z');
            """;
        await command.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
    }

    private static async Task ExecuteDatabaseAsync(string path, string sql)
    {
        await using var connection = new SqliteConnection($"Data Source={path}");
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
    }

    private static async Task ExecuteDatabaseWithParametersAsync(
        string path,
        string sql,
        params (string Name, object Value)[] parameters)
    {
        await using var connection = new SqliteConnection($"Data Source={path}");
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        foreach (var parameter in parameters)
        {
            command.Parameters.AddWithValue(parameter.Name, parameter.Value);
        }

        await command.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
    }

    private static async Task<string> ReadProviderBaseUrlAsync(string path)
    {
        await using var connection = new SqliteConnection($"Data Source={path};Mode=ReadOnly");
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT settings_config FROM providers WHERE id='anthropic-direct';";
        var settings = JsonNode.Parse((string)(await command.ExecuteScalarAsync(TestContext.Current.CancellationToken))!)!.AsObject();
        return settings["env"]!["ANTHROPIC_BASE_URL"]!.GetValue<string>();
    }

    private static async Task<string> ReadEndpointUrlAsync(string path)
    {
        await using var connection = new SqliteConnection($"Data Source={path};Mode=ReadOnly");
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT url FROM provider_endpoints WHERE id=1;";
        return (string)(await command.ExecuteScalarAsync(TestContext.Current.CancellationToken))!;
    }

    private static async Task<string> ReadCodexProviderTomlAsync(string path)
    {
        await using var connection = new SqliteConnection($"Data Source={path};Mode=ReadOnly");
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT settings_config FROM providers WHERE app_type='codex';";
        var settings = JsonNode.Parse((string)(await command.ExecuteScalarAsync(TestContext.Current.CancellationToken))!)!.AsObject();
        return settings["config"]!.GetValue<string>();
    }

    private static async Task<long> ReadScalarInt64Async(string path, string sql)
    {
        await using var connection = new SqliteConnection($"Data Source={path};Mode=ReadOnly");
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        return (long)(await command.ExecuteScalarAsync(TestContext.Current.CancellationToken))!;
    }

    private static string InspectCodexBaseUrl(string toml)
    {
        var inspection = CodexSettingsTransformer.InjectBaseUrl(
            Encoding.UTF8.GetBytes(toml),
            new Uri("http://127.0.0.1:18080/r/test-inspection"));
        return inspection.PreviousValue!;
    }

    private sealed class TestProtector : ITextProtector
    {
        public byte[] Protect(string value) => Encoding.UTF8.GetBytes($"protected:{value}");

        public string Unprotect(byte[] protectedValue) => Encoding.UTF8.GetString(protectedValue)["protected:".Length..];
    }
}
