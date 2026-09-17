using Sf.EndpointAI.Client.Core.Capture;
using Sf.EndpointAI.Client.Core.Diagnostics;

namespace Sf.EndpointAI.Client.Service;

public sealed class LogStorageMaintenanceWorker(
    LogCompressionScheduler compressionQueue,
    GzipLogFileCompressor compressor,
    OperationalLogFileTracker operationalLogTracker,
    CaptureOptions captureOptions,
    JsonlFileLoggerOptions operationalLogOptions,
    CaptureRetentionManager captureRetention,
    OperationalLogRetentionManager operationalLogRetention,
    AuditHealthState auditHealth,
    ILogger<LogStorageMaintenanceWorker> logger) : BackgroundService
{
    private static readonly TimeSpan RecoveryInterval = TimeSpan.FromMinutes(5);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var nextRecovery = DateTimeOffset.MinValue;
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var now = DateTimeOffset.UtcNow;
                if (now >= nextRecovery)
                {
                    await CompressEligibleFilesAsync(stoppingToken);
                    nextRecovery = now + RecoveryInterval;
                }

                while (compressionQueue.TryDequeue(out var path))
                {
                    await TryCompressAsync(path, stoppingToken);
                }

                await RunRetentionAsync(stoppingToken);

                var wait = nextRecovery - DateTimeOffset.UtcNow;
                if (wait < TimeSpan.Zero)
                {
                    wait = TimeSpan.Zero;
                }

                await compressionQueue.WaitAsync(wait, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                auditHealth.MarkDegraded();
                LogStorageMaintenanceLog.MaintenanceFailed(logger, exception);
                await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken);
            }
        }
    }

    private async Task CompressEligibleFilesAsync(CancellationToken cancellationToken)
    {
        if (Directory.Exists(captureOptions.RootDirectory))
        {
            foreach (var path in Directory
                .EnumerateFiles(captureOptions.RootDirectory, "*.md", SearchOption.AllDirectories)
                .OrderBy(path => File.GetLastWriteTimeUtc(path)))
            {
                await TryCompressAsync(path, cancellationToken);
            }
        }

        if (Directory.Exists(operationalLogOptions.RootDirectory))
        {
            foreach (var path in Directory
                .EnumerateFiles(operationalLogOptions.RootDirectory, "*.jsonl", SearchOption.TopDirectoryOnly)
                .OrderBy(path => File.GetLastWriteTimeUtc(path)))
            {
                await TryCompressAsync(path, cancellationToken);
            }
        }
    }

    private async Task TryCompressAsync(string path, CancellationToken cancellationToken)
    {
        if (!IsEligible(path) || !File.Exists(path) || operationalLogTracker.IsActive(path))
        {
            return;
        }

        try
        {
            await compressor.CompressAsync(path, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            auditHealth.MarkDegraded();
            LogStorageMaintenanceLog.CompressionFailed(
                logger,
                Path.GetFileName(path),
                exception.GetType().Name);
        }
    }

    private async Task RunRetentionAsync(CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        var captures = await captureRetention.CleanupAsync(now, cancellationToken);
        if (captures.DeletedFiles > 0)
        {
            LogStorageMaintenanceLog.CaptureCleanupCompleted(
                logger,
                captures.DeletedFiles,
                captures.DeletedBytes,
                captures.RemainingBytes);
        }

        var operational = await operationalLogRetention.CleanupAsync(
            now,
            operationalLogTracker.ActivePath,
            cancellationToken);
        if (operational.DeletedFiles > 0)
        {
            LogStorageMaintenanceLog.OperationalCleanupCompleted(
                logger,
                operational.DeletedFiles,
                operational.DeletedBytes,
                operational.RemainingBytes);
        }
    }

    private bool IsEligible(string path)
    {
        var fullPath = Path.GetFullPath(path);
        if (fullPath.EndsWith(".md", StringComparison.OrdinalIgnoreCase))
        {
            return IsUnderRoot(fullPath, captureOptions.RootDirectory);
        }

        return fullPath.EndsWith(".jsonl", StringComparison.OrdinalIgnoreCase)
            && IsUnderRoot(fullPath, operationalLogOptions.RootDirectory);
    }

    private static bool IsUnderRoot(string path, string root)
    {
        var fullRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        return path.StartsWith(fullRoot, StringComparison.OrdinalIgnoreCase);
    }
}

internal static partial class LogStorageMaintenanceLog
{
    [LoggerMessage(EventId = 3112, Level = LogLevel.Warning, Message = "Failed to compress log file {FileName}: {ExceptionType}.")]
    public static partial void CompressionFailed(ILogger logger, string fileName, string exceptionType);

    [LoggerMessage(EventId = 3113, Level = LogLevel.Warning, Message = "Log storage maintenance failed.")]
    public static partial void MaintenanceFailed(ILogger logger, Exception exception);

    [LoggerMessage(
        EventId = 3114,
        Level = LogLevel.Information,
        Message = "Capture retention removed {DeletedFiles} file(s) and {DeletedBytes} byte(s); {RemainingBytes} byte(s) remain.")]
    public static partial void CaptureCleanupCompleted(ILogger logger, int deletedFiles, long deletedBytes, long remainingBytes);

    [LoggerMessage(
        EventId = 3115,
        Level = LogLevel.Information,
        Message = "Operational log retention removed {DeletedFiles} file(s) and {DeletedBytes} byte(s); {RemainingBytes} byte(s) remain.")]
    public static partial void OperationalCleanupCompleted(ILogger logger, int deletedFiles, long deletedBytes, long remainingBytes);
}
