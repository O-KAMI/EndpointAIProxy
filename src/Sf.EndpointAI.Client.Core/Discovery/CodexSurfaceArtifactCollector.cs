using System.Text.Json;
using Sf.EndpointAI.Client.Core.Windows;
using Sf.EndpointAI.Contracts;

namespace Sf.EndpointAI.Client.Core.Discovery;

public sealed class CodexSurfaceArtifactCollector(IUserProfileProvider profileProvider) : IAgentEvidenceCollector
{
    private static readonly string[] IdeExtensionRoots =
    [
        Path.Combine(".vscode", "extensions"),
        Path.Combine(".vscode-insiders", "extensions"),
        Path.Combine(".cursor", "extensions"),
    ];

    private static readonly string[] DesktopPackagePatterns =
    [
        "OpenAI.Codex_*",
        "OpenAI.ChatGPT-Desktop_*",
    ];

    public string Name => "codex-surface-artifact";

    public async Task<IReadOnlyList<AgentEvidence>> CollectAsync(CancellationToken cancellationToken = default)
    {
        var observedAt = DateTimeOffset.UtcNow;
        var evidence = new List<AgentEvidence>();
        foreach (var profile in profileProvider.GetProfiles())
        {
            cancellationToken.ThrowIfCancellationRequested();
            foreach (var relativeRoot in IdeExtensionRoots)
            {
                var root = SafeProfilePath(profile, relativeRoot);
                if (root is null || !Directory.Exists(root))
                {
                    continue;
                }

                var installedExtensions = new List<IdeArtifact>();
                foreach (var extensionDirectory in Directory.EnumerateDirectories(root, "openai.chatgpt-*", SearchOption.TopDirectoryOnly))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var manifestPath = Path.Combine(extensionDirectory, "package.json");
                    var manifest = await TryReadIdeManifestAsync(manifestPath, cancellationToken);
                    if (manifest is null)
                    {
                        continue;
                    }

                    installedExtensions.Add(new IdeArtifact(manifestPath, manifest));
                }

                var activeExtension = installedExtensions
                    .OrderByDescending(item => ParseVersion(item.Manifest.Version))
                    .ThenByDescending(item => item.Manifest.Version, StringComparer.OrdinalIgnoreCase)
                    .FirstOrDefault();
                if (activeExtension is not null)
                {
                    evidence.Add(new AgentEvidence(
                        profile.Sid,
                        AgentType.CodexIde,
                        Name,
                        EvidenceStrength.Strong,
                        activeExtension.ManifestPath,
                        activeExtension.Manifest.Version,
                        InstallMethod.VsCodeExtension,
                        observedAt));
                }
            }

            var packagesRoot = SafeRootPath(profile.EffectiveLocalAppDataPath, "Packages");
            if (packagesRoot is null || !Directory.Exists(packagesRoot))
            {
                continue;
            }

            foreach (var pattern in DesktopPackagePatterns)
            {
                foreach (var packageDirectory in Directory.EnumerateDirectories(packagesRoot, pattern, SearchOption.TopDirectoryOnly))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    evidence.Add(new AgentEvidence(
                        profile.Sid,
                        AgentType.CodexDesktop,
                        Name,
                        EvidenceStrength.Strong,
                        packageDirectory,
                        null,
                        InstallMethod.MicrosoftStore,
                        observedAt));
                }
            }
        }

        return evidence;
    }

    private static async Task<IdeManifest?> TryReadIdeManifestAsync(string path, CancellationToken cancellationToken)
    {
        try
        {
            await using var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            var root = document.RootElement;
            if (!TryGetString(root, "publisher", out var publisher)
                || !TryGetString(root, "name", out var name)
                || !string.Equals(publisher, "openai", StringComparison.OrdinalIgnoreCase)
                || !string.Equals(name, "chatgpt", StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }

            return new IdeManifest(TryGetString(root, "version", out var version) ? version : null);
        }
        catch (IOException)
        {
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static bool TryGetString(JsonElement root, string propertyName, out string? value)
    {
        if (root.TryGetProperty(propertyName, out var property)
            && property.ValueKind == JsonValueKind.String)
        {
            value = property.GetString();
            return !string.IsNullOrWhiteSpace(value);
        }

        value = null;
        return false;
    }

    private static Version? ParseVersion(string? value) =>
        Version.TryParse(value, out var version) ? version : null;

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

    private sealed record IdeManifest(string? Version);

    private sealed record IdeArtifact(string ManifestPath, IdeManifest Manifest);
}
