using Sf.EndpointAI.Contracts;

namespace Sf.EndpointAI.Client.Core.Discovery;

public static class AgentIdentityEngine
{
    public static IReadOnlyList<AgentIdentityResult> Identify(IEnumerable<AgentEvidence> evidence)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        return evidence
            .GroupBy(item => (item.UserSid, item.CandidateType))
            .Select(group => Identify(group.Key.UserSid, group.Key.CandidateType, group.ToArray()))
            .OrderBy(result => result.UserSid, StringComparer.Ordinal)
            .ThenBy(result => result.AgentType)
            .ToArray();
    }

    private static AgentIdentityResult Identify(
        string userSid,
        AgentType candidateType,
        IReadOnlyList<AgentEvidence> evidence)
    {
        var distinct = evidence
            .GroupBy(item => (item.Collector, item.Artifact), StringTupleComparer.OrdinalIgnoreCase)
            .Select(group => group.OrderByDescending(item => item.Strength).First())
            .ToArray();
        var hasStrong = distinct.Any(item => item.Strength == EvidenceStrength.Strong);
        var mediumCollectors = distinct
            .Where(item => item.Strength == EvidenceStrength.Medium)
            .Select(item => item.Collector)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Count();
        var confirmed = candidateType != AgentType.UnknownCandidate && (hasStrong || mediumCollectors >= 2);
        var confidence = Math.Min(100, distinct.Sum(item => item.Strength switch
        {
            EvidenceStrength.Strong => 60,
            EvidenceStrength.Medium => 30,
            EvidenceStrength.Weak => 10,
            _ => 0,
        }));
        if (!confirmed)
        {
            confidence = Math.Min(confidence, 59);
        }

        var version = distinct.Select(item => item.Version).FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));
        var installMethod = distinct
            .Select(item => item.InstallMethod)
            .FirstOrDefault(method => method != InstallMethod.Unknown);
        return new AgentIdentityResult(
            userSid,
            confirmed ? candidateType : AgentType.UnknownCandidate,
            confirmed,
            confidence,
            version,
            installMethod,
            distinct);
    }

    private sealed class StringTupleComparer : IEqualityComparer<(string Collector, string Artifact)>
    {
        public static readonly StringTupleComparer OrdinalIgnoreCase = new();

        public bool Equals((string Collector, string Artifact) x, (string Collector, string Artifact) y)
        {
            return string.Equals(x.Collector, y.Collector, StringComparison.OrdinalIgnoreCase)
                && string.Equals(x.Artifact, y.Artifact, StringComparison.OrdinalIgnoreCase);
        }

        public int GetHashCode((string Collector, string Artifact) value)
        {
            return HashCode.Combine(
                StringComparer.OrdinalIgnoreCase.GetHashCode(value.Collector),
                StringComparer.OrdinalIgnoreCase.GetHashCode(value.Artifact));
        }
    }
}
