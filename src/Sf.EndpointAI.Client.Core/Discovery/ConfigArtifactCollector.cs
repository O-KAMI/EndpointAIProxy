using Sf.EndpointAI.Client.Core.Windows;
using Sf.EndpointAI.Contracts;

namespace Sf.EndpointAI.Client.Core.Discovery;

public sealed class ConfigArtifactCollector(IUserProfileProvider profileProvider) : IAgentEvidenceCollector
{
    private static readonly ArtifactSignature[] Signatures =
    [
        new(AgentType.QoderCli, Path.Combine(".qoder", "settings.json")),
        new(AgentType.CcSwitch, Path.Combine(".cc-switch", "cc-switch.db")),
    ];

    public string Name => "config-artifact";

    public Task<IReadOnlyList<AgentEvidence>> CollectAsync(CancellationToken cancellationToken = default)
    {
        var observedAt = DateTimeOffset.UtcNow;
        var evidence = new List<AgentEvidence>();
        foreach (var profile in profileProvider.GetProfiles())
        {
            cancellationToken.ThrowIfCancellationRequested();
            foreach (var signature in Signatures)
            {
                var path = Path.GetFullPath(Path.Combine(profile.ProfilePath, signature.RelativePath));
                if (!path.StartsWith(profile.ProfilePath + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
                    || !File.Exists(path))
                {
                    continue;
                }

                evidence.Add(new AgentEvidence(
                    profile.Sid,
                    signature.AgentType,
                    Name,
                    EvidenceStrength.Medium,
                    path,
                    null,
                    InstallMethod.Unknown,
                    observedAt));
            }
        }

        return Task.FromResult<IReadOnlyList<AgentEvidence>>(evidence);
    }

    private sealed record ArtifactSignature(AgentType AgentType, string RelativePath);
}
