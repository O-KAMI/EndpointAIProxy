using Sf.EndpointAI.Client.Core.Discovery;
using Sf.EndpointAI.Client.Core.Windows;
using Sf.EndpointAI.Contracts;

namespace Sf.EndpointAI.UnitTests;

public sealed class DiscoveryCollectorsTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), $"sf-discovery-{Guid.NewGuid():N}");
    private readonly IUserProfileProvider _profiles;

    public DiscoveryCollectorsTests()
    {
        Directory.CreateDirectory(_directory);
        _profiles = new FakeProfileProvider(new WindowsUserProfile("S-1-5-21-discovery", _directory));
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }

        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task Package_cli_and_config_evidence_confirm_claude()
    {
        var manifest = Path.Combine(
            _directory,
            "AppData",
            "Roaming",
            "npm",
            "node_modules",
            "@anthropic-ai",
            "claude-code",
            "package.json");
        var shim = Path.Combine(_directory, "AppData", "Roaming", "npm", "claude.cmd");
        var settings = Path.Combine(_directory, ".claude", "settings.json");
        Directory.CreateDirectory(Path.GetDirectoryName(manifest)!);
        Directory.CreateDirectory(Path.GetDirectoryName(shim)!);
        Directory.CreateDirectory(Path.GetDirectoryName(settings)!);
        await File.WriteAllTextAsync(manifest, "{\"version\":\"1.2.3\"}", TestContext.Current.CancellationToken);
        await File.WriteAllTextAsync(shim, "@echo off", TestContext.Current.CancellationToken);
        await File.WriteAllTextAsync(settings, "{}", TestContext.Current.CancellationToken);

        var engine = new AgentDiscoveryEngine(
        [
            new PackageManifestCollector(_profiles),
            new CliCommandCollector(_profiles),
            new ConfigArtifactCollector(_profiles),
        ]);
        var snapshot = await engine.DiscoverAsync(TestContext.Current.CancellationToken);

        var claude = Assert.Single(snapshot.Agents);
        Assert.True(claude.Confirmed);
        Assert.Equal(AgentType.ClaudeCli, claude.AgentType);
        Assert.Equal("1.2.3", claude.Version);
        Assert.Equal(InstallMethod.Npm, claude.InstallMethod);
        Assert.Equal(2, snapshot.Evidence.Count);
    }

    [Fact]
    public async Task Collector_io_failure_does_not_hide_other_evidence()
    {
        var engine = new AgentDiscoveryEngine(
        [
            new ThrowingCollector(),
            new FixedCollector(),
        ]);

        var snapshot = await engine.DiscoverAsync(TestContext.Current.CancellationToken);

        Assert.Single(snapshot.Failures);
        Assert.Single(snapshot.Evidence);
    }

    [Fact]
    public async Task Codex_ide_and_desktop_are_reported_as_distinct_surfaces()
    {
        var extensionManifest = Path.Combine(
            _directory,
            ".vscode",
            "extensions",
            "openai.chatgpt-1.2.3-win32-x64",
            "package.json");
        var olderExtensionManifest = Path.Combine(
            _directory,
            ".vscode",
            "extensions",
            "openai.chatgpt-1.1.0-win32-x64",
            "package.json");
        var desktopPackage = Path.Combine(
            _directory,
            "AppData",
            "Local",
            "Packages",
            "OpenAI.Codex_test");
        Directory.CreateDirectory(Path.GetDirectoryName(extensionManifest)!);
        Directory.CreateDirectory(Path.GetDirectoryName(olderExtensionManifest)!);
        Directory.CreateDirectory(desktopPackage);
        await File.WriteAllTextAsync(
            extensionManifest,
            "{\"publisher\":\"OpenAI\",\"name\":\"chatgpt\",\"version\":\"1.2.3\"}",
            TestContext.Current.CancellationToken);
        await File.WriteAllTextAsync(
            olderExtensionManifest,
            "{\"publisher\":\"OpenAI\",\"name\":\"chatgpt\",\"version\":\"1.1.0\"}",
            TestContext.Current.CancellationToken);

        var engine = new AgentDiscoveryEngine([new CodexSurfaceArtifactCollector(_profiles)]);

        var snapshot = await engine.DiscoverAsync(TestContext.Current.CancellationToken);

        Assert.Empty(snapshot.Failures);
        Assert.Collection(
            snapshot.Agents.OrderBy(agent => agent.AgentType),
            ide =>
            {
                Assert.Equal(AgentType.CodexIde, ide.AgentType);
                Assert.Equal("1.2.3", ide.Version);
                Assert.Equal(InstallMethod.VsCodeExtension, ide.InstallMethod);
                Assert.True(ide.Confirmed);
            },
            desktop =>
            {
                Assert.Equal(AgentType.CodexDesktop, desktop.AgentType);
                Assert.Null(desktop.Version);
                Assert.Equal(InstallMethod.MicrosoftStore, desktop.InstallMethod);
                Assert.True(desktop.Confirmed);
            });
    }

    [Fact]
    public async Task Claude_ide_and_desktop_are_reported_without_claiming_cli_from_shared_config()
    {
        var extensionManifest = Path.Combine(
            _directory,
            ".vscode",
            "extensions",
            "anthropic.claude-code-2.3.4-win32-x64",
            "package.json");
        var desktopExecutable = Path.Combine(
            _directory,
            "AppData",
            "Local",
            "AnthropicClaude",
            "Claude.exe");
        var settings = Path.Combine(_directory, ".claude", "settings.json");
        Directory.CreateDirectory(Path.GetDirectoryName(extensionManifest)!);
        Directory.CreateDirectory(Path.GetDirectoryName(desktopExecutable)!);
        Directory.CreateDirectory(Path.GetDirectoryName(settings)!);
        await File.WriteAllTextAsync(
            extensionManifest,
            "{\"publisher\":\"Anthropic\",\"name\":\"claude-code\",\"version\":\"2.3.4\"}",
            TestContext.Current.CancellationToken);
        await File.WriteAllTextAsync(desktopExecutable, string.Empty, TestContext.Current.CancellationToken);
        await File.WriteAllTextAsync(settings, "{}", TestContext.Current.CancellationToken);

        var engine = new AgentDiscoveryEngine(
        [
            new ClaudeSurfaceArtifactCollector(_profiles),
            new ConfigArtifactCollector(_profiles),
        ]);
        var snapshot = await engine.DiscoverAsync(TestContext.Current.CancellationToken);

        Assert.Contains(snapshot.Agents, agent => agent.AgentType == AgentType.ClaudeIde && agent.Confirmed);
        Assert.Contains(snapshot.Agents, agent => agent.AgentType == AgentType.ClaudeDesktop && agent.Confirmed);
        Assert.DoesNotContain(snapshot.Agents, agent => agent.AgentType == AgentType.ClaudeCli);
    }

    [Fact]
    public async Task Six_agent_surfaces_and_cc_switch_are_distinct_inventory_items()
    {
        var files = new Dictionary<string, string>
        {
            [Path.Combine("AppData", "Roaming", "npm", "node_modules", "@anthropic-ai", "claude-code", "package.json")] = "{\"version\":\"1.0.0\"}",
            [Path.Combine("AppData", "Roaming", "npm", "claude.cmd")] = "@echo off",
            [Path.Combine(".vscode", "extensions", "anthropic.claude-code-1.0.0", "package.json")] = "{\"publisher\":\"Anthropic\",\"name\":\"claude-code\",\"version\":\"1.0.0\"}",
            [Path.Combine("AppData", "Local", "AnthropicClaude", "Claude.exe")] = string.Empty,
            [Path.Combine("AppData", "Roaming", "npm", "node_modules", "@openai", "codex", "package.json")] = "{\"version\":\"1.0.0\"}",
            [Path.Combine("AppData", "Roaming", "npm", "codex.cmd")] = "@echo off",
            [Path.Combine(".vscode", "extensions", "openai.chatgpt-1.0.0", "package.json")] = "{\"publisher\":\"OpenAI\",\"name\":\"chatgpt\",\"version\":\"1.0.0\"}",
            [Path.Combine(".cc-switch", "cc-switch.db")] = string.Empty,
            [Path.Combine("AppData", "Local", "Programs", "CC Switch", "CC Switch.exe")] = string.Empty,
        };
        foreach (var pair in files)
        {
            var path = Path.Combine(_directory, pair.Key);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            await File.WriteAllTextAsync(path, pair.Value, TestContext.Current.CancellationToken);
        }

        Directory.CreateDirectory(Path.Combine(_directory, "AppData", "Local", "Packages", "OpenAI.Codex_test"));
        var engine = new AgentDiscoveryEngine(
        [
            new PackageManifestCollector(_profiles),
            new CliCommandCollector(_profiles),
            new ConfigArtifactCollector(_profiles),
            new ClaudeSurfaceArtifactCollector(_profiles),
            new CodexSurfaceArtifactCollector(_profiles),
        ]);

        var snapshot = await engine.DiscoverAsync(TestContext.Current.CancellationToken);
        var types = snapshot.Agents.Where(agent => agent.Confirmed).Select(agent => agent.AgentType).ToHashSet();

        Assert.True(types.SetEquals(
        [
            AgentType.ClaudeCli,
            AgentType.ClaudeIde,
            AgentType.ClaudeDesktop,
            AgentType.CodexCli,
            AgentType.CodexIde,
            AgentType.CodexDesktop,
            AgentType.CcSwitch,
        ]));
    }

    [Fact]
    public async Task Redirected_application_data_discovers_codex_cli_with_version()
    {
        var redirectedRoaming = Path.Combine(_directory, "redirected", "Application Data");
        var npmRoot = Path.Combine(redirectedRoaming, "npm");
        var manifest = Path.Combine(npmRoot, "node_modules", "@openai", "codex", "package.json");
        Directory.CreateDirectory(Path.GetDirectoryName(manifest)!);
        await File.WriteAllTextAsync(manifest, "{\"version\":\"2.7.1\"}", TestContext.Current.CancellationToken);
        await File.WriteAllTextAsync(Path.Combine(npmRoot, "codex.cmd"), "@echo off", TestContext.Current.CancellationToken);
        var profiles = new FakeProfileProvider(new WindowsUserProfile(
            "S-1-5-21-redirected",
            _directory,
            redirectedRoaming,
            Path.Combine(_directory, "redirected", "Local Application Data"),
            [npmRoot]));
        var engine = new AgentDiscoveryEngine(
        [
            new PackageManifestCollector(profiles),
            new CliCommandCollector(profiles),
        ]);

        var snapshot = await engine.DiscoverAsync(TestContext.Current.CancellationToken);

        var codex = Assert.Single(snapshot.Agents);
        Assert.True(codex.Confirmed);
        Assert.Equal(AgentType.CodexCli, codex.AgentType);
        Assert.Equal("2.7.1", codex.Version);
        Assert.Equal(InstallMethod.Npm, codex.InstallMethod);
    }

    [Fact]
    public async Task Running_process_uses_owner_sid_outside_profile_and_without_executable_path()
    {
        var profile = new WindowsUserProfile("S-1-5-21-owner", _directory);
        var provider = new FixedProcessSnapshotProvider(
        [
            new RunningProcessSnapshot(
                42,
                "codex",
                @"C:\Program Files\WindowsApps\OpenAI.Codex_test\codex.exe",
                "3.0.0",
                profile.Sid),
            new RunningProcessSnapshot(43, "claude", null, null, profile.Sid),
        ]);
        var engine = new AgentDiscoveryEngine(
        [
            new RunningProcessCollector(new FakeProfileProvider(profile), provider),
        ]);

        var snapshot = await engine.DiscoverAsync(TestContext.Current.CancellationToken);

        Assert.Contains(snapshot.Agents, agent =>
            agent.AgentType == AgentType.CodexCli
            && agent.Confirmed
            && agent.Version == "3.0.0");
        Assert.Contains(snapshot.Agents, agent =>
            agent.AgentType == AgentType.ClaudeCli
            && agent.Confirmed
            && agent.Evidence.Single().Artifact.StartsWith("process::claude", StringComparison.Ordinal));
    }

    private sealed class FakeProfileProvider(params WindowsUserProfile[] profiles) : IUserProfileProvider
    {
        public IReadOnlyList<WindowsUserProfile> GetProfiles() => profiles;
    }

    private sealed class ThrowingCollector : IAgentEvidenceCollector
    {
        public string Name => "broken";

        public Task<IReadOnlyList<AgentEvidence>> CollectAsync(CancellationToken cancellationToken = default)
        {
            throw new IOException("fixture failure");
        }
    }

    private sealed class FixedCollector : IAgentEvidenceCollector
    {
        public string Name => "fixed";

        public Task<IReadOnlyList<AgentEvidence>> CollectAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IReadOnlyList<AgentEvidence>>(
            [
                new AgentEvidence(
                    "S-1-5-21-fixed",
                    AgentType.ClaudeCli,
                    Name,
                    EvidenceStrength.Medium,
                    "fixture",
                    null,
                    InstallMethod.Unknown,
                    DateTimeOffset.UtcNow),
            ]);
        }
    }

    private sealed class FixedProcessSnapshotProvider(IReadOnlyList<RunningProcessSnapshot> snapshots)
        : IRunningProcessSnapshotProvider
    {
        public IReadOnlyList<RunningProcessSnapshot> GetProcesses(IReadOnlySet<string> processNames) =>
            snapshots.Where(snapshot => processNames.Contains(snapshot.ProcessName)).ToArray();
    }
}
