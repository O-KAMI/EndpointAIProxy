namespace Sf.EndpointAI.Client.Service;

public sealed record ControlPlaneRuntimeSnapshot(
    Guid? DeviceId,
    DateTimeOffset? LastControlSyncAtUtc,
    string? LastControlErrorCode);

public sealed class ControlPlaneRuntimeState
{
    private ControlPlaneRuntimeSnapshot _current = new(null, null, null);

    public ControlPlaneRuntimeSnapshot Current => Volatile.Read(ref _current);

    public void SetDeviceId(Guid deviceId) => Update(Current with { DeviceId = deviceId });

    public void RecordSuccess(DateTimeOffset observedAtUtc) =>
        Update(Current with { LastControlSyncAtUtc = observedAtUtc, LastControlErrorCode = null });

    public void RecordFailure(string errorCode) => Update(Current with { LastControlErrorCode = errorCode });

    private void Update(ControlPlaneRuntimeSnapshot value) => Volatile.Write(ref _current, value);
}
