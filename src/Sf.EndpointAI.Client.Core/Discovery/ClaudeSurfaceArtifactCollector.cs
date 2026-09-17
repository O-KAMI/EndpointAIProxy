using System.Text.Json;
using System.Xml.Linq;
using Sf.EndpointAI.Client.Core.Windows;
using Sf.EndpointAI.Contracts;

namespace Sf.EndpointAI.Client.Core.Discovery;

public sealed class ClaudeSurfaceArtifactCollector(IUserProfileProvider profileProvider) : IAgentEvidenceCollector
{
    private static readonly string[] IdeExtensionRoots =
    [
        Path.Combine(".vscode", "extensions"),
        Path.Combine(".vscode-insiders", "extensions"),
        Path.Combine(".cursor", "extensions"),
    ];

    private static readonly string[] DesktopExecutablePaths =
    [
        Path.Combine("AnthropicClaude", "Claude.exe"),
        Path.Combine("Programs", "Claude", "Claude.exe"),
    ];

    public string Name => "claude-surface-artifact";

    public async Task<IReadOnlyList<AgentEvidence>> CollectAsync(CancellationToken cancellationToken = default)
    {
        var evidence = new List<AgentEvidence>();
        var observedAt = DateTimeOffset.UtcNow;
        foreach (var profile in profileProvider.GetProfiles())
        {
            foreach (var relativeRoot in IdeExtensionRoots)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var root = SafeProfilePath(profile, relativeRoot);
                if (root is null || !Directory.Exists(root))
                {
                    continue;
                }

                var artifacts = new List<IdeArtifact>();
                foreach (var directory in Directory.EnumerateDirectories(root, "anthropic.claude-code-*", SearchOption.TopDirectoryOnly))
                {
                    var manifestPath = Path.Combine(directory, "package.json");
                    var version = await TryReadVsCodeManifestAsync(manifestPath, cancellationToken);
                    if (version.Found)
                    {
                        artifacts.Add(new IdeArtifact(manifestPath, version.Version, InstallMethod.VsCodeExtension));
                    }
                }

                AddNewestIdeArtifact(profile, artifacts, evidence, observedAt);
            }

            await CollectJetBrainsAsync(profile, evidence, observedAt, cancellationToken);

            foreach (var relativePath in DesktopExecutablePaths)
            {
                var path = SafeRootPath(profile.EffectiveLocalAppDataPath, relativePath);
                if (path is not null && File.Exists(path))
                {
                    evidence.Add(CreateDesktopEvidence(profile, path, observedAt, InstallMethod.Native));
                }
            }

            var desktopRoot = SafeRootPath(profile.EffectiveLocalAppDataPath, "AnthropicClaude");
            if (desktopRoot is not null && Directory.Exists(desktopRoot))
            {
                foreach (var appDirectory in Directory.EnumerateDirectories(desktopRoot, "app-*", SearchOption.TopDirectoryOnly))
                {
                    var executable = Path.Combine(appDirectory, "Claude.exe");
                    if (File.Exists(executable))
                    {
                        evidence.Add(CreateDesktopEvidence(profile, executable, observedAt, InstallMethod.Native));
                    }
                }
            }

            var packagesRoot = SafeRootPath(profile.EffectiveLocalAppDataPath, "Packages");
            if (packagesRoot is not null && Directory.Exists(packagesRoot))
            {
                foreach (var directory in Directory.EnumerateDirectories(packagesRoot, "Anthropic.Claude_*", SearchOption.TopDirectoryOnly))
                {
                    evidence.Add(CreateDesktopEvidence(profile, directory, observedAt, InstallMethod.MicrosoftStore));
                }
            }
        }

        return evidence;
    }

    private static async Task CollectJetBrainsAsync(
        WindowsUserProfile profile,
        List<AgentEvidence> evidence,
        DateTimeOffset observedAt,
        CancellationToken cancellationToken)
    {
        var root = SafeProfilePath(
            profile,
            OperatingSystem.IsMacOS()
                ? Path.Combine("Library", "Application Support", "JetBrains")
                : Path.Combine("AppData", "Roaming", "JetBrains"));
        if (root is null || !Directory.Exists(root))
        {
            return;
        }

        var artifacts = new List<IdeArtifact>();
        foreach (var productDirectory in Directory.EnumerateDirectories(root, "*", SearchOption.TopDirectoryOnly))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var plugins = Path.Combine(productDirectory, "plugins");
            if (!Directory.Exists(plugins))
            {
                continue;
            }

            foreach (var pluginDirectory in Directory.EnumerateDirectories(plugins, "*claude*", SearchOption.TopDirectoryOnly))
            {
                var descriptor = Path.Combine(pluginDirectory, "META-INF", "plugin.xml");
                var version = await TryReadJetBrainsDescriptorAsync(descriptor, cancellationToken);
                if (version.Found)
                {
                    artifacts.Add(new IdeArtifact(descriptor, version.Version, InstallMethod.JetBrainsPlugin));
                }
            }
        }

        AddNewestIdeArtifact(profile, artifacts, evidence, observedAt);
    }

    private static void AddNewestIdeArtifact(
        WindowsUserProfile profile,
        IReadOnlyList<IdeArtifact> artifacts,
        List<AgentEvidence> evidence,
        DateTimeOffset observedAt)
    {
        var newest = artifacts
            .OrderByDescending(item => ParseVersion(item.Version))
            .ThenByDescending(item => item.Version, StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault();
        if (newest is null)
        {
            return;
        }

        evidence.Add(new AgentEvidence(
            profile.Sid,
            AgentType.ClaudeIde,
            "claude-surface-artifact",
            EvidenceStrength.Strong,
            newest.ManifestPath,
            newest.Version,
            newest.InstallMethod,
            observedAt));
    }

    private static async Task<(bool Found, string? Version)> TryReadVsCodeManifestAsync(
        string path,
        CancellationToken cancellationToken)
    {
        try
        {
            await using var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            var root = document.RootElement;
            var publisher = root.TryGetProperty("publisher", out var publisherValue) ? publisherValue.GetString() : null;
            var name = root.TryGetProperty("name", out var nameValue) ? nameValue.GetString() : null;
            if (!string.Equals(publisher, "anthropic", StringComparison.OrdinalIgnoreCase)
                || !string.Equals(name, "claude-code", StringComparison.OrdinalIgnoreCase))
            {
                return (false, null);
            }

            return (true, root.TryGetProperty("version", out var version) ? version.GetString() : null);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            return (false, null);
        }
    }

    private static async Task<(bool Found, string? Version)> TryReadJetBrainsDescriptorAsync(
        string path,
        CancellationToken cancellationToken)
    {
        try
        {
            await using var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var document = await XDocument.LoadAsync(stream, LoadOptions.None, cancellationToken);
            var id = document.Root?.Element("id")?.Value;
            var name = document.Root?.Element("name")?.Value;
            var vendor = document.Root?.Element("vendor")?.Value;
            var isClaude = (id?.Contains("claude", StringComparison.OrdinalIgnoreCase) ?? false)
                || (name?.Contains("claude", StringComparison.OrdinalIgnoreCase) ?? false);
            if (!isClaude || !(vendor?.Contains("anthropic", StringComparison.OrdinalIgnoreCase) ?? false))
            {
                return (false, null);
            }

            return (true, document.Root?.Element("version")?.Value);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Xml.XmlException)
        {
            return (false, null);
        }
    }

    private static AgentEvidence CreateDesktopEvidence(
        WindowsUserProfile profile,
        string artifact,
        DateTimeOffset observedAt,
        InstallMethod installMethod)
    {
        string? version = null;
        if (File.Exists(artifact))
        {
            try
            {
                version = System.Diagnostics.FileVersionInfo.GetVersionInfo(artifact).ProductVersion;
            }
            catch (System.ComponentModel.Win32Exception)
            {
                // Version is optional discovery metadata.
            }
        }

        return new AgentEvidence(
            profile.Sid,
            AgentType.ClaudeDesktop,
            "claude-surface-artifact",
            EvidenceStrength.Strong,
            artifact,
            version,
            installMethod,
            observedAt);
    }

    private static string? SafeProfilePath(WindowsUserProfile profile, string relativePath)
    {
        var path = Path.GetFullPath(Path.Combine(profile.ProfilePath, relativePath));
        return path.StartsWith(profile.ProfilePath + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
            ? path
            : null;
    }

    private static string? SafeRootPath(string root, string relativePath)
    {
        var path = Path.GetFullPath(Path.Combine(root, relativePath));
        return path.StartsWith(root.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
            ? path
            : null;
    }

    private static Version? ParseVersion(string? value) => Version.TryParse(value, out var version) ? version : null;

    private sealed record IdeArtifact(string ManifestPath, string? Version, InstallMethod InstallMethod);
}
