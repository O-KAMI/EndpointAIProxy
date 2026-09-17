using Sf.EndpointAI.Contracts;

namespace Sf.EndpointAI.Client.Service;

public sealed class AuditHealthState
{
    private int _degraded;

    public AuditState Current => Volatile.Read(ref _degraded) == 0 ? AuditState.Healthy : AuditState.Degraded;

    public void MarkDegraded()
    {
        Interlocked.Exchange(ref _degraded, 1);
    }
}
