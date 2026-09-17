using System.Text.Json;
using Sf.EndpointAI.Client.Core.Windows;
using Sf.EndpointAI.Contracts;

namespace Sf.EndpointAI.Client.Core.Discovery;

public sealed class PackageManifestCollector(IUserProfileProvider profileProvider) : IAgentEvidenceCollector
{
    private static readonly PackageSignature[] Signatures =
    [
        new(AgentType.ClaudeCli, InstallMethod.Npm, Path.Combine("node_modules", "@anthropic-ai", "claude-code", "package.json")),
        new(AgentType.CodexCli, InstallMethod.Npm, Path.Combine("node_modules", "@openai", "codex", "package.json")),
        new(AgentType.QoderCli, InstallMethod.Npm, Path.Combine("node_modules", "@qoder-ai", "qodercli", "package.json")),
    ];

    public string Name => "package-manifest";

    public async Task<IReadOnlyList<AgentEvidence>> CollectAsync(CancellationToken cancellationToken = default)
    {
        var evidence = new List<AgentEvidence>();
        foreach (var profile in profileProvider.GetProfiles())
        {
            foreach (var root in GetNpmRoots(profile))
            {
                foreach (var signature in Signatures)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var path = SafeRootPath(root, signature.RelativePath);
                    if (path is null || !File.Exists(path))
                    {
                        continue;
                    }

                    evidence.Add(new AgentEvidence(
                        profile.Sid,
                        signature.AgentType,
                        Name,
                        EvidenceStrength.Strong,
                        path,
                        await TryReadVersionAsync(path, cancellationToken),
                        signature.InstallMethod,
                        DateTimeOffset.UtcNow));
                }
            }
        }

        return evidence;
    }

    private static async Task<string?> TryReadVersionAsync(string path, CancellationToken cancellationToken)
    {
        try
        {
            await using var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            return document.RootElement.TryGetProperty("version", out var version)
                && version.ValueKind == JsonValueKind.String
                ? version.GetString()
                : null;
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

    private static string[] GetNpmRoots(WindowsUserProfile profile) =>
        profile.EffectiveExecutableSearchPaths
            .Append(Path.Combine(profile.EffectiveRoamingAppDataPath, "npm"))
            .Append(Path.Combine(profile.EffectiveLocalAppDataPath, "npm"))
            .Append(Path.Combine(profile.ProfilePath, ".npm-global", "lib"))
            .Append("/opt/homebrew/lib")
            .Append("/usr/local/lib")
            .Where(Path.IsPathFullyQualified)
            .Select(Path.GetFullPath)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

    private static string? SafeRootPath(string root, string relativePath)
    {
        var path = Path.GetFullPath(Path.Combine(root, relativePath));
        return path.StartsWith(root.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
            ? path
            : null;
    }

    private sealed record PackageSignature(AgentType AgentType, InstallMethod InstallMethod, string RelativePath);
}
