using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Sf.EndpointAI.Client.Core.Policy;
using Sf.EndpointAI.Client.Core.State;
using Sf.EndpointAI.Client.Service;
using Sf.EndpointAI.Contracts;

namespace Sf.EndpointAI.UnitTests;

public sealed class RemoteCommandExecutorTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), $"sf-command-executor-{Guid.NewGuid():N}");

    public RemoteCommandExecutorTests() => Directory.CreateDirectory(_directory);

    [Fact]
    public async Task Executing_status_failure_does_not_block_local_execution()
    {
        var handler = new StatusHandler(HttpStatusCode.ServiceUnavailable, HttpStatusCode.NoContent);
        var coordinator = new TestOperationCoordinator();
        var (executor, store, deviceId, command) = await CreateAsync(handler, coordinator);

        await executor.ExecuteAsync(deviceId, "device-token", command, TestContext.Current.CancellationToken);

        Assert.Equal(1, coordinator.ExecutionCount);
        Assert.Equal(RemoteCommandStatus.Succeeded, (await store.LoadCommandReceiptAsync(command.Payload.CommandId, TestContext.Current.CancellationToken))?.Status);
        Assert.Equal(2, handler.RequestCount);
    }

    [Fact]
    public async Task Final_status_failure_is_replayed_without_repeating_operation()
    {
        var handler = new StatusHandler(HttpStatusCode.NoContent, HttpStatusCode.ServiceUnavailable, HttpStatusCode.NoContent);
        var coordinator = new TestOperationCoordinator();
        var (executor, store, deviceId, command) = await CreateAsync(handler, coordinator);

        await executor.ExecuteAsync(deviceId, "device-token", command, TestContext.Current.CancellationToken);
        await executor.ExecuteAsync(deviceId, "device-token", command, TestContext.Current.CancellationToken);

        Assert.Equal(1, coordinator.ExecutionCount);
        Assert.Equal(RemoteCommandStatus.Succeeded, (await store.LoadCommandReceiptAsync(command.Payload.CommandId, TestContext.Current.CancellationToken))?.Status);
        Assert.Equal(3, handler.RequestCount);
    }

    [Fact]
    public async Task Existing_executing_receipt_resumes_after_expiry()
    {
        var handler = new StatusHandler(HttpStatusCode.NoContent, HttpStatusCode.NoContent);
        var coordinator = new TestOperationCoordinator();
        var (executor, store, deviceId, command) = await CreateAsync(handler, coordinator, expiresAtUtc: DateTimeOffset.UtcNow.AddMinutes(-1));
        await store.SaveCommandReceiptAsync(new StoredCommandReceipt(
            command.Payload.CommandId,
            command.Payload.Type,
            RemoteCommandStatus.Executing,
            DateTimeOffset.UtcNow.AddMinutes(-10),
            null,
            null,
            null), TestContext.Current.CancellationToken);

        await executor.ExecuteAsync(deviceId, "device-token", command, TestContext.Current.CancellationToken);

        Assert.Equal(1, coordinator.ExecutionCount);
        Assert.Equal(RemoteCommandStatus.Succeeded, (await store.LoadCommandReceiptAsync(command.Payload.CommandId, TestContext.Current.CancellationToken))?.Status);
    }

    [Fact]
    public async Task Persisted_executing_command_resumes_after_restart_without_server_redelivery()
    {
        var handler = new StatusHandler(HttpStatusCode.NoContent, HttpStatusCode.NoContent);
        var coordinator = new TestOperationCoordinator();
        var (executor, store, deviceId, command) = await CreateAsync(handler, coordinator, expiresAtUtc: DateTimeOffset.UtcNow.AddMinutes(-1));
        await store.SaveCommandReceiptAsync(new StoredCommandReceipt(
            command.Payload.CommandId,
            command.Payload.Type,
            RemoteCommandStatus.Executing,
            DateTimeOffset.UtcNow.AddMinutes(-10),
            null,
            null,
            null,
            deviceId,
            command.Payload.IssuedAtUtc,
            command.Payload.ExpiresAtUtc), TestContext.Current.CancellationToken);

        await executor.ResumeExecutingAsync(deviceId, "device-token", TestContext.Current.CancellationToken);

        Assert.Equal(1, coordinator.ExecutionCount);
        Assert.Equal(RemoteCommandStatus.Succeeded, (await store.LoadCommandReceiptAsync(command.Payload.CommandId, TestContext.Current.CancellationToken))?.Status);
        Assert.Equal(2, handler.RequestCount);
    }

    [Fact]
    public async Task Newly_received_expired_command_is_failed_without_execution()
    {
        var handler = new StatusHandler(HttpStatusCode.NoContent);
        var coordinator = new TestOperationCoordinator();
        var (executor, store, deviceId, command) = await CreateAsync(handler, coordinator, expiresAtUtc: DateTimeOffset.UtcNow.AddMinutes(-1));

        await executor.ExecuteAsync(deviceId, "device-token", command, TestContext.Current.CancellationToken);

        var receipt = await store.LoadCommandReceiptAsync(command.Payload.CommandId, TestContext.Current.CancellationToken);
        Assert.Equal(0, coordinator.ExecutionCount);
        Assert.Equal(RemoteCommandStatus.Failed, receipt?.Status);
        Assert.Equal("COMMAND_EXPIRED", receipt?.ResultCode);
    }

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        if (Directory.Exists(_directory)) Directory.Delete(_directory, recursive: true);
    }

    private async Task<(RemoteCommandExecutor Executor, SqliteClientStateStore Store, Guid DeviceId, SignedRemoteCommand Command)> CreateAsync(
        HttpMessageHandler handler,
        IRemoteOperationCoordinator coordinator,
        DateTimeOffset? expiresAtUtc = null)
    {
        var store = new SqliteClientStateStore(Path.Combine(_directory, $"{Guid.NewGuid():N}.db"));
        await store.InitializeAsync(TestContext.Current.CancellationToken);
        var deviceId = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;
        var command = new SignedRemoteCommand(
            new RemoteCommandPayload(1, Guid.NewGuid(), deviceId, RemoteCommandType.DisableProxy, now, expiresAtUtc ?? now.AddMinutes(10)),
            "test-signature");
        var options = new RemoteControlOptions(new Uri("https://127.0.0.1:18180"), null, new byte[32], Convert.ToBase64String(new byte[32]));
        var client = new RemoteControlClient(new HttpClient(handler) { BaseAddress = options.ServerOrigin }, options);
        return (new RemoteCommandExecutor(
            client,
            store,
            coordinator,
            new ControlPlaneRuntimeState(),
            NullLogger<RemoteCommandExecutor>.Instance), store, deviceId, command);
    }

    private sealed class TestOperationCoordinator : IRemoteOperationCoordinator
    {
        public int ExecutionCount { get; private set; }

        public Task<RemoteOperationResult> ExecuteAsync(RemoteCommandType commandType, CancellationToken cancellationToken)
        {
            ExecutionCount++;
            return Task.FromResult(new RemoteOperationResult(true, ClientOperationState.Disabled, "PROXY_DISABLED", "done"));
        }
    }

    private sealed class StatusHandler(params HttpStatusCode[] statuses) : HttpMessageHandler
    {
        private readonly Queue<HttpStatusCode> _statuses = new(statuses);
        public int RequestCount { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            RequestCount++;
            var status = _statuses.Count > 0 ? _statuses.Dequeue() : HttpStatusCode.NoContent;
            return Task.FromResult(new HttpResponseMessage(status));
        }
    }
}
