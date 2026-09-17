using Sf.EndpointAI.Contracts;

namespace Sf.EndpointAI.Client.Core.Discovery;

public sealed record AgentEvidence(
    string UserSid,
    AgentType CandidateType,
    string Collector,
    EvidenceStrength Strength,
    string Artifact,
    string? Version,
    InstallMethod InstallMethod,
    DateTimeOffset ObservedAtUtc);

public sealed record AgentIdentityResult(
    string UserSid,
    AgentType AgentType,
    bool Confirmed,
    int Confidence,
    string? Version,
    InstallMethod InstallMethod,
    IReadOnlyList<AgentEvidence> Evidence);

public interface IAgentEvidenceCollector
{
    string Name { get; }

    Task<IReadOnlyList<AgentEvidence>> CollectAsync(CancellationToken cancellationToken = default);
}
