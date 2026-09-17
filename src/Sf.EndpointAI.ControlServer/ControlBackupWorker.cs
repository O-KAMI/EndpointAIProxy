namespace Sf.EndpointAI.ControlServer;

public sealed record ControlBackupOptions(string BackupDirectory, int RetentionCount, TimeSpan Interval);

public sealed class ControlBackupState
{
    private DateTimeOffset? _lastSucceededAtUtc;
    private string? _lastError;

    public DateTimeOffset? LastSucceededAtUtc => _lastSucceededAtUtc;
    public string? LastError => _lastError;

    public void MarkSucceeded()
    {
        _lastSucceededAtUtc = DateTimeOffset.UtcNow;
        _lastError = null;
    }

    public void MarkFailed(Exception exception) => _lastError = exception.GetType().Name;
}

public sealed class ControlBackupWorker(
    ControlStore store,
    ControlBackupOptions options,
    ControlBackupState state,
    ILogger<ControlBackupWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var path = await store.BackupAsync(options.BackupDirectory, options.RetentionCount, stoppingToken);
                state.MarkSucceeded();
                ControlBackupLog.Completed(logger, path);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or Microsoft.Data.Sqlite.SqliteException)
            {
                state.MarkFailed(exception);
                ControlBackupLog.Failed(logger, exception);
            }

            await Task.Delay(options.Interval, stoppingToken);
        }
    }
}

internal static partial class ControlBackupLog
{
    [LoggerMessage(EventId = 4101, Level = LogLevel.Information, Message = "Control database backup completed at {BackupPath}.")]
    public static partial void Completed(ILogger logger, string backupPath);

    [LoggerMessage(EventId = 4102, Level = LogLevel.Error, Message = "Control database backup failed.")]
    public static partial void Failed(ILogger logger, Exception exception);
}
