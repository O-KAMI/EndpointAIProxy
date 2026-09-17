using Sf.EndpointAI.Client.Core.Policy;
using Sf.EndpointAI.Client.Core.State;
using Sf.EndpointAI.Contracts;

namespace Sf.EndpointAI.Client.Service;

public interface IRemoteOperationCoordinator
{
    Task<RemoteOperationResult> ExecuteAsync(RemoteCommandType commandType, CancellationToken cancellationToken);
}

public sealed class RemoteCommandExecutor(
    RemoteControlClient controlClient,
    SqliteClientStateStore stateStore,
    IRemoteOperationCoordinator operationCoordinator,
    ControlPlaneRuntimeState controlPlaneRuntimeState,
    ILogger<RemoteCommandExecutor> logger)
{
    public async Task ResumeExecutingAsync(
        Guid deviceId,
        string deviceToken,
        CancellationToken cancellationToken)
    {
        var receipts = await stateStore.ListExecutingCommandReceiptsAsync(deviceId, cancellationToken);
        foreach (var receipt in receipts)
        {
            RemoteCommandLog.CommandExecutionResumed(logger, receipt.CommandId, deviceId, receipt.Type);
            await TryReportStatusAsync(deviceId, deviceToken, receipt, cancellationToken);
            await CompleteLocalExecutionAsync(deviceId, deviceToken, receipt, cancellationToken);
        }
    }

    public async Task ExecuteAsync(
        Guid deviceId,
        string deviceToken,
        SignedRemoteCommand command,
        CancellationToken cancellationToken)
    {
        var payload = command.Payload;
        if (payload.DeviceId != deviceId)
        {
            throw new InvalidOperationException("The remote command targets another device.");
        }

        var existing = await stateStore.LoadCommandReceiptAsync(payload.CommandId, cancellationToken);
        if (existing is not null && existing.Type != payload.Type)
        {
            throw new InvalidOperationException("The persisted command receipt type does not match the signed command.");
        }

        if (existing?.Status is RemoteCommandStatus.Succeeded or RemoteCommandStatus.Failed)
        {
            if (await TryReportStatusAsync(deviceId, deviceToken, existing, cancellationToken))
            {
                RemoteCommandLog.TerminalStatusReplayed(logger, payload.CommandId, deviceId, existing.Status, existing.ResultCode);
            }
            return;
        }

        var receivedAt = existing?.ReceivedAtUtc ?? DateTimeOffset.UtcNow;
        if (existing is null && payload.ExpiresAtUtc <= receivedAt)
        {
            var expired = new StoredCommandReceipt(
                payload.CommandId,
                payload.Type,
                RemoteCommandStatus.Failed,
                receivedAt,
                receivedAt,
                "COMMAND_EXPIRED",
                "The command expired before local execution.",
                deviceId,
                payload.IssuedAtUtc,
                payload.ExpiresAtUtc);
            await stateStore.SaveCommandReceiptAsync(expired, cancellationToken);
            await TryReportStatusAsync(deviceId, deviceToken, expired, cancellationToken);
            RemoteCommandLog.CommandExpired(logger, payload.CommandId, deviceId, payload.Type);
            return;
        }

        var executing = (existing ?? new StoredCommandReceipt(
                payload.CommandId,
                payload.Type,
                RemoteCommandStatus.Executing,
                receivedAt,
                null,
                null,
                null)) with
            {
                Status = RemoteCommandStatus.Executing,
                DeviceId = deviceId,
                IssuedAtUtc = payload.IssuedAtUtc,
                ExpiresAtUtc = payload.ExpiresAtUtc,
            };
        await stateStore.SaveCommandReceiptAsync(executing, cancellationToken);
        if (existing is null)
        {
            RemoteCommandLog.CommandReceived(logger, payload.CommandId, deviceId, payload.Type);
        }
        else
        {
            RemoteCommandLog.CommandExecutionResumed(logger, payload.CommandId, deviceId, payload.Type);
        }

        await TryReportStatusAsync(deviceId, deviceToken, executing, cancellationToken);
        await CompleteLocalExecutionAsync(deviceId, deviceToken, executing, cancellationToken);
    }

    private async Task CompleteLocalExecutionAsync(
        Guid deviceId,
        string deviceToken,
        StoredCommandReceipt executing,
        CancellationToken cancellationToken)
    {
        RemoteCommandLog.CommandExecutionStarted(logger, executing.CommandId, deviceId, executing.Type);
        var result = await operationCoordinator.ExecuteAsync(executing.Type, cancellationToken);
        var completedAt = DateTimeOffset.UtcNow;
        var receipt = executing with
        {
            Status = result.Succeeded ? RemoteCommandStatus.Succeeded : RemoteCommandStatus.Failed,
            CompletedAtUtc = completedAt,
            ResultCode = result.ResultCode,
            ResultSummary = result.ResultSummary,
        };
        await stateStore.SaveCommandReceiptAsync(receipt, cancellationToken);
        await TryReportStatusAsync(deviceId, deviceToken, receipt, cancellationToken);
        RemoteCommandLog.CommandExecutionCompleted(logger, executing.CommandId, deviceId, receipt.Status, result.ResultCode);
    }

    private async Task<bool> TryReportStatusAsync(
        Guid deviceId,
        string deviceToken,
        StoredCommandReceipt receipt,
        CancellationToken cancellationToken)
    {
        try
        {
            await controlClient.SendCommandStatusAsync(
                new RemoteCommandStatusUpdate(
                    1,
                    deviceId,
                    receipt.CommandId,
                    receipt.Status,
                    receipt.CompletedAtUtc ?? receipt.ReceivedAtUtc,
                    receipt.ResultCode,
                    receipt.ResultSummary),
                deviceToken,
                cancellationToken);
            return true;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException or InvalidOperationException or TaskCanceledException)
        {
            controlPlaneRuntimeState.RecordFailure("COMMAND_STATUS_REPORT_FAILED");
            RemoteCommandLog.StatusReportFailed(
                logger,
                receipt.CommandId,
                deviceId,
                receipt.Status,
                exception.GetType().Name,
                exception);
            return false;
        }
    }
}

internal static partial class RemoteCommandLog
{
    [LoggerMessage(4101, LogLevel.Information, "Remote command {CommandId} for device {DeviceId} was received: {CommandType}.")]
    public static partial void CommandReceived(ILogger logger, Guid commandId, Guid deviceId, RemoteCommandType commandType);

    [LoggerMessage(4102, LogLevel.Warning, "Remote command {CommandId} for device {DeviceId} is resuming local execution: {CommandType}.")]
    public static partial void CommandExecutionResumed(ILogger logger, Guid commandId, Guid deviceId, RemoteCommandType commandType);

    [LoggerMessage(4103, LogLevel.Information, "Remote command {CommandId} for device {DeviceId} started local execution: {CommandType}.")]
    public static partial void CommandExecutionStarted(ILogger logger, Guid commandId, Guid deviceId, RemoteCommandType commandType);

    [LoggerMessage(4104, LogLevel.Information, "Remote command {CommandId} for device {DeviceId} completed with {Status}: {ResultCode}.")]
    public static partial void CommandExecutionCompleted(ILogger logger, Guid commandId, Guid deviceId, RemoteCommandStatus status, string? resultCode);

    [LoggerMessage(4105, LogLevel.Warning, "Remote command {CommandId} for device {DeviceId} expired before local execution: {CommandType}.")]
    public static partial void CommandExpired(ILogger logger, Guid commandId, Guid deviceId, RemoteCommandType commandType);

    [LoggerMessage(4106, LogLevel.Information, "Remote command {CommandId} for device {DeviceId} replayed terminal status {Status}: {ResultCode}.")]
    public static partial void TerminalStatusReplayed(ILogger logger, Guid commandId, Guid deviceId, RemoteCommandStatus status, string? resultCode);

    [LoggerMessage(4107, LogLevel.Warning, "Remote command {CommandId} for device {DeviceId} could not report status {Status}: {ErrorType}.")]
    public static partial void StatusReportFailed(ILogger logger, Guid commandId, Guid deviceId, RemoteCommandStatus status, string errorType, Exception exception);
}
