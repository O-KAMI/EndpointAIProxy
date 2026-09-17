namespace Sf.EndpointAI.Client.Service;

public sealed record RouteReconciliationRuntimeSnapshot(
    DateTimeOffset? LastReconcileAtUtc,
    string? LastReconcileResult,
    string? LastReconcileErrorCode);

public sealed class RouteReconciliationRuntimeState
{
    private RouteReconciliationRuntimeSnapshot _current = new(null, null, null);

    public RouteReconciliationRuntimeSnapshot Current => Volatile.Read(ref _current);

    public void Record(string? errorCode)
    {
        Volatile.Write(
            ref _current,
            new RouteReconciliationRuntimeSnapshot(
                DateTimeOffset.UtcNow,
                errorCode is null ? "SUCCESS" : "FAILED",
                errorCode));
    }
}
