using System.IO.Compression;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Sf.EndpointAI.Client.Core.Capture;
using Sf.EndpointAI.Client.Core.Diagnostics;
using Sf.EndpointAI.Client.Service;

namespace Sf.EndpointAI.UnitTests;

public sealed class LogCompressionTests : IDisposable
{
    private static readonly Action<ILogger, Exception?> WriteTestEvent = LoggerMessage.Define(
        LogLevel.Information,
        new EventId(1, "TestEvent"),
        "test event");
    private readonly string _directory = Path.Combine(Path.GetTempPath(), $"sf-endpoint-ai-compression-{Guid.NewGuid():N}");

    public LogCompressionTests() => Directory.CreateDirectory(_directory);

    public void Dispose()
    {
        if (Directory.Exists(_directory)) Directory.Delete(_directory, recursive: true);
    }

    [Fact]
    public async Task Compresses_completed_file_and_preserves_content_and_timestamp()
    {
        var source = Path.Combine(_directory, "capture.md");
        var content = string.Concat(Enumerable.Repeat("compressible capture content\n", 100));
        await File.WriteAllTextAsync(source, content, TestContext.Current.CancellationToken);
        var timestamp = DateTime.UtcNow.AddHours(-1);
        File.SetLastWriteTimeUtc(source, timestamp);

        var destination = await new GzipLogFileCompressor().CompressAsync(
            source,
            TestContext.Current.CancellationToken);

        Assert.False(File.Exists(source));
        Assert.True(File.Exists(destination));
        Assert.Equal(timestamp, File.GetLastWriteTimeUtc(destination), TimeSpan.FromSeconds(1));
        await using var file = File.OpenRead(destination);
        await using var gzip = new GZipStream(file, CompressionMode.Decompress);
        using var reader = new StreamReader(gzip, Encoding.UTF8);
        Assert.Equal(content, await reader.ReadToEndAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Logger_does_not_reuse_segment_number_owned_by_compressed_file()
    {
        await File.WriteAllBytesAsync(
            Path.Combine(_directory, $"{DateTimeOffset.UtcNow:yyyy-MM-dd}.001.jsonl.gz"),
            [1, 2, 3],
            TestContext.Current.CancellationToken);
        var provider = new JsonlFileLoggerProvider(new JsonlFileLoggerOptions(_directory));
        var logger = provider.CreateLogger("test");

        WriteTestEvent(logger, null);
        provider.Dispose();

        Assert.True(File.Exists(Path.Combine(_directory, $"{DateTimeOffset.UtcNow:yyyy-MM-dd}.002.jsonl")));
    }

    [Fact]
    public async Task Compression_failure_preserves_source_and_removes_temporary_file()
    {
        var source = Path.Combine(_directory, "blocked.md");
        await File.WriteAllTextAsync(source, "source must survive", TestContext.Current.CancellationToken);
        Directory.CreateDirectory(source + ".gz");

        await Assert.ThrowsAnyAsync<IOException>(() => new GzipLogFileCompressor().CompressAsync(
            source,
            TestContext.Current.CancellationToken));

        Assert.True(File.Exists(source));
        Assert.False(File.Exists(source + ".gz.tmp"));
    }

    [Fact]
    public async Task Maintenance_recovers_completed_capture_and_skips_active_operational_log()
    {
        var captureRoot = Path.Combine(_directory, "captures");
        var operationalRoot = Path.Combine(_directory, "service-logs");
        Directory.CreateDirectory(captureRoot);
        Directory.CreateDirectory(operationalRoot);
        var capture = Path.Combine(captureRoot, "completed.md");
        var operational = Path.Combine(operationalRoot, "active.jsonl");
        await File.WriteAllTextAsync(capture, "completed capture", TestContext.Current.CancellationToken);
        await File.WriteAllTextAsync(operational, "{}\n", TestContext.Current.CancellationToken);
        using var scheduler = new LogCompressionScheduler();
        var tracker = new OperationalLogFileTracker();
        tracker.SetActive(operational);
        var captureOptions = new CaptureOptions(captureRoot);
        var operationalOptions = new JsonlFileLoggerOptions(operationalRoot);
        var worker = new LogStorageMaintenanceWorker(
            scheduler,
            new GzipLogFileCompressor(),
            tracker,
            captureOptions,
            operationalOptions,
            new CaptureRetentionManager(captureOptions),
            new OperationalLogRetentionManager(new OperationalLogRetentionOptions(operationalRoot)),
            new AuditHealthState(),
            NullLogger<LogStorageMaintenanceWorker>.Instance);

        await worker.StartAsync(TestContext.Current.CancellationToken);
        try
        {
            await WaitForCompressionAsync(capture, TestContext.Current.CancellationToken);
            Assert.False(File.Exists(capture));
            Assert.True(File.Exists(operational));
            Assert.False(File.Exists(operational + ".gz"));

            tracker.Clear(operational);
            Assert.True(scheduler.TryQueue(operational));
            await WaitForCompressionAsync(operational, TestContext.Current.CancellationToken);
            Assert.False(File.Exists(operational));
        }
        finally
        {
            await worker.StopAsync(CancellationToken.None);
        }
    }

    private static async Task WaitForCompressionAsync(string sourcePath, CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < 100; attempt++)
        {
            if (!File.Exists(sourcePath) && File.Exists(sourcePath + ".gz")) return;
            await Task.Delay(TimeSpan.FromMilliseconds(50), cancellationToken);
        }

        throw new TimeoutException($"File was not compressed: {Path.GetFileName(sourcePath)}");
    }
}
