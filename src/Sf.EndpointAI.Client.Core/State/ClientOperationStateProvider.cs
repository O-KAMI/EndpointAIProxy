using Sf.EndpointAI.Contracts;

namespace Sf.EndpointAI.Client.Core.State;

public sealed class ClientOperationStateProvider
{
    private StoredClientOperationState _current = new(
        ClientOperationState.Enabled,
        DateTimeOffset.UtcNow,
        null,
        null);

    public StoredClientOperationState Current => Volatile.Read(ref _current);

    public void Update(StoredClientOperationState state) => Volatile.Write(ref _current, state);
}
