using Sf.EndpointAI.Client.Core.Discovery;
using Sf.EndpointAI.Client.Core.Windows;
using Sf.EndpointAI.Contracts;

namespace Sf.EndpointAI.Client.Core.MacOS;

public sealed class MacInstalledApplicationCollector(IUserProfileProvider profileProvider) : IAgentEvidenceCollector
{
    private static readonly AppSignature[] Signatures =
    [
        new("Claude.app", AgentType.ClaudeDesktop),
        new("ChatClaude.app", AgentType.ClaudeDesktop),
        new("ChatGPT.app", AgentType.CodexDesktop),
        new("Codex.app", AgentType.CodexDesktop),
        new("Qoder.app", AgentType.QoderIde),
        new("CC Switch.app", AgentType.CcSwitch),
        new("CCSwitch.app", AgentType.CcSwitch),
    ];

    public string Name => "macos-installed-application";

    public Task<IReadOnlyList<AgentEvidence>> CollectAsync(CancellationToken cancellationToken = default)
    {
        var evidence = new List<AgentEvidence>();
        var observedAt = DateTimeOffset.UtcNow;
        foreach (var profile in profileProvider.GetProfiles())
        {
            foreach (var root in new[] { "/Applications", Path.Combine(profile.ProfilePath, "Applications") })
            {
                foreach (var signature in Signatures)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var path = Path.Combine(root, signature.BundleName);
                    if (!Directory.Exists(path))
                    {
                        continue;
                    }

                    evidence.Add(new AgentEvidence(
                        profile.Sid,
                        signature.AgentType,
                        Name,
                        EvidenceStrength.Strong,
                        path,
                        null,
                        InstallMethod.Native,
                        observedAt));
                }
            }
        }

        return Task.FromResult<IReadOnlyList<AgentEvidence>>(evidence);
    }

    private sealed record AppSignature(string BundleName, AgentType AgentType);
}
