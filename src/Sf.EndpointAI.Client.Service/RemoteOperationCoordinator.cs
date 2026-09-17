using Sf.EndpointAI.Client.Core.Configuration;
using Sf.EndpointAI.Client.Core.State;
using Sf.EndpointAI.Client.Core.Windows;
using Sf.EndpointAI.Contracts;

namespace Sf.EndpointAI.Client.Service;

public sealed class RouteMutationGate : IDisposable
{
    private readonly SemaphoreSlim _gate = new(1, 1);

    public async Task<IDisposable> EnterAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        return new Releaser(_gate);
    }

    public void Dispose() => _gate.Dispose();

    private sealed class Releaser(SemaphoreSlim gate) : IDisposable
    {
        private int _disposed;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                gate.Release();
            }
        }
    }
}

public sealed record RemoteOperationResult(
    bool Succeeded,
    ClientOperationState State,
    string ResultCode,
    string ResultSummary);

public sealed class RemoteOperationCoordinator(
    IUserProfileProvider profileProvider,
    AgentConfigAttachmentCoordinator attachmentCoordinator,
    RouteAttachmentOptions attachmentOptions,
    RouteMutationGate mutationGate,
    SqliteClientStateStore stateStore,
    ClientOperationStateProvider operationStateProvider) : IRemoteOperationCoordinator
{
    public async Task<RemoteOperationResult> ExecuteAsync(
        RemoteCommandType commandType,
        CancellationToken cancellationToken)
    {
        using var lease = await mutationGate.EnterAsync(cancellationToken);
        if (commandType == RemoteCommandType.DisableProxy)
        {
            var blockingState = new StoredClientOperationState(
                ClientOperationState.Disabled,
                DateTimeOffset.UtcNow,
                null,
                null);
            await stateStore.SaveOperationStateAsync(blockingState, cancellationToken);
            operationStateProvider.Update(blockingState);
        }

        var failures = new List<string>();
        foreach (var profile in profileProvider.GetProfiles())
        {
            try
            {
                var result = commandType == RemoteCommandType.DisableProxy
                    ? await attachmentCoordinator.DetachAsync(profile, attachmentOptions.BackupRoot, cancellationToken)
                    : await attachmentCoordinator.AttachAsync(profile, attachmentOptions.BackupRoot, cancellationToken);
                failures.AddRange(result.Items
                    .Where(item => item.Status is RouteStatus.Error or RouteStatus.NonCompliant)
                    .Select(item => $"{profile.Sid}:{item.ErrorCode ?? item.Status.ToString()}"));
            }
            catch (Exception exception) when (exception is ConfigMutationException or IOException or UnauthorizedAccessException)
            {
                failures.Add($"{profile.Sid}:{(exception as ConfigMutationException)?.Code ?? exception.GetType().Name}");
            }
        }

        var succeeded = failures.Count == 0;
        var state = commandType switch
        {
            RemoteCommandType.DisableProxy when succeeded => ClientOperationState.Disabled,
            RemoteCommandType.DisableProxy => ClientOperationState.DisableFailed,
            RemoteCommandType.EnableProxy when succeeded => ClientOperationState.Enabled,
            _ => ClientOperationState.EnableFailed,
        };
        var resultCode = succeeded
            ? commandType == RemoteCommandType.DisableProxy ? "PROXY_DISABLED" : "PROXY_ENABLED"
            : commandType == RemoteCommandType.DisableProxy ? "PROXY_DISABLE_FAILED" : "PROXY_ENABLE_FAILED";
        var summary = succeeded
            ? commandType == RemoteCommandType.DisableProxy
                ? "All managed Agent configurations were detached."
                : "All supported Agent configurations were attached."
            : string.Join(',', failures).Truncate(512);
        var storedState = new StoredClientOperationState(
                state,
                DateTimeOffset.UtcNow,
                succeeded ? null : resultCode,
                succeeded ? null : summary);
        await stateStore.SaveOperationStateAsync(storedState, cancellationToken);
        operationStateProvider.Update(storedState);
        return new RemoteOperationResult(succeeded, state, resultCode, summary);
    }
}

internal static class RemoteOperationStringExtensions
{
    public static string Truncate(this string value, int length) =>
        value.Length <= length ? value : value[..length];
}
