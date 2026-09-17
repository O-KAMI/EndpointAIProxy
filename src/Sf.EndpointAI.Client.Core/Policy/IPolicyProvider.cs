using Sf.EndpointAI.Contracts;

namespace Sf.EndpointAI.Client.Core.Policy;

public interface IPolicyProvider
{
    EndpointPolicy Current { get; }
}

public sealed class StaticPolicyProvider(EndpointPolicy policy) : IPolicyProvider
{
    public EndpointPolicy Current { get; } = policy;
}

public sealed class DynamicPolicyProvider : IPolicyProvider
{
    private EndpointPolicy _current;

    public DynamicPolicyProvider(EndpointPolicy initialPolicy)
    {
        PolicyValidator.Validate(initialPolicy);
        _current = initialPolicy;
    }

    public EndpointPolicy Current => Volatile.Read(ref _current);

    public bool TryApply(EndpointPolicy policy)
    {
        PolicyValidator.Validate(policy);
        while (true)
        {
            var current = Current;
            if (policy.PolicyVersion < current.PolicyVersion
                || (policy.PolicyVersion == current.PolicyVersion
                    && policy.ServerInstanceId == current.ServerInstanceId))
            {
                return false;
            }

            if (Interlocked.CompareExchange(ref _current, policy, current) == current)
            {
                return true;
            }
        }
    }
}
