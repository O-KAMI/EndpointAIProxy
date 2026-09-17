namespace Sf.EndpointAI.Client.Core.Discovery;

public sealed record EvidenceCollectorFailure(string Collector, string ErrorType, string Message);

public sealed record AgentDiscoverySnapshot(
    DateTimeOffset StartedAtUtc,
    DateTimeOffset CompletedAtUtc,
    IReadOnlyList<AgentIdentityResult> Agents,
    IReadOnlyList<AgentEvidence> Evidence,
    IReadOnlyList<EvidenceCollectorFailure> Failures);

public sealed class AgentDiscoveryEngine(IEnumerable<IAgentEvidenceCollector> collectors)
{
    private readonly IReadOnlyList<IAgentEvidenceCollector> _collectors = collectors.ToArray();

    public async Task<AgentDiscoverySnapshot> DiscoverAsync(CancellationToken cancellationToken = default)
    {
        var startedAt = DateTimeOffset.UtcNow;
        var evidence = new List<AgentEvidence>();
        var failures = new List<EvidenceCollectorFailure>();
        foreach (var collector in _collectors)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                evidence.AddRange(await collector.CollectAsync(cancellationToken));
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidOperationException)
            {
                failures.Add(new EvidenceCollectorFailure(
                    collector.Name,
                    exception.GetType().Name,
                    exception.Message));
            }
        }

        return new AgentDiscoverySnapshot(
            startedAt,
            DateTimeOffset.UtcNow,
            AgentIdentityEngine.Identify(evidence),
            evidence,
            failures);
    }
}
