using Sf.EndpointAI.Client.Core.Discovery;
using Sf.EndpointAI.Contracts;

namespace Sf.EndpointAI.UnitTests;

public sealed class AgentIdentityEngineTests
{
    [Fact]
    public void One_strong_evidence_confirms_supported_agent()
    {
        var evidence = CreateEvidence(AgentType.ClaudeCode, "npm-package", EvidenceStrength.Strong);

        var result = Assert.Single(AgentIdentityEngine.Identify([evidence]));

        Assert.True(result.Confirmed);
        Assert.Equal(AgentType.ClaudeCode, result.AgentType);
        Assert.Equal(60, result.Confidence);
    }

    [Fact]
    public void Two_independent_medium_collectors_confirm_agent()
    {
        AgentEvidence[] evidence =
        [
            CreateEvidence(AgentType.CodexCli, "config", EvidenceStrength.Medium),
            CreateEvidence(AgentType.CodexCli, "process", EvidenceStrength.Medium),
        ];

        var result = Assert.Single(AgentIdentityEngine.Identify(evidence));

        Assert.True(result.Confirmed);
        Assert.Equal(60, result.Confidence);
    }

    [Fact]
    public void Network_evidence_alone_remains_unknown()
    {
        var evidence = CreateEvidence(AgentType.ClaudeCode, "network", EvidenceStrength.Weak);

        var result = Assert.Single(AgentIdentityEngine.Identify([evidence]));

        Assert.False(result.Confirmed);
        Assert.Equal(AgentType.UnknownCandidate, result.AgentType);
        Assert.Equal(10, result.Confidence);
    }

    private static AgentEvidence CreateEvidence(
        AgentType type,
        string collector,
        EvidenceStrength strength)
    {
        return new AgentEvidence(
            "S-1-5-21-test",
            type,
            collector,
            strength,
            $"artifact-{collector}",
            "1.0.0",
            InstallMethod.Npm,
            DateTimeOffset.UtcNow);
    }
}
