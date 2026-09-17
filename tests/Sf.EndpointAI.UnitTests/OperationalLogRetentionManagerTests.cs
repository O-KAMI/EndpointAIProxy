using Sf.EndpointAI.Client.Core.Diagnostics;

namespace Sf.EndpointAI.UnitTests;

public sealed class OperationalLogRetentionManagerTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), $"sf-endpoint-ai-operational-retention-{Guid.NewGuid():N}");

    public OperationalLogRetentionManagerTests() => Directory.CreateDirectory(_directory);

    public void Dispose()
    {
        if (Directory.Exists(_directory)) Directory.Delete(_directory, recursive: true);
    }

    [Fact]
    public async Task Deletes_expired_files_and_preserves_active_file()
    {
        var now = DateTimeOffset.UtcNow;
        var expired = await CreateFileAsync("expired.001.jsonl", 20, now.AddDays(-8));
        var active = await CreateFileAsync("current.001.jsonl", 20, now.AddDays(-8));
        var manager = new OperationalLogRetentionManager(new OperationalLogRetentionOptions(_directory));

        var result = await manager.CleanupAsync(now, active, TestContext.Current.CancellationToken);

        Assert.Equal(1, result.DeletedFiles);
        Assert.False(File.Exists(expired));
        Assert.True(File.Exists(active));
    }

    [Fact]
    public async Task Deletes_oldest_segments_to_low_watermark()
    {
        var now = DateTimeOffset.UtcNow;
        var first = await CreateFileAsync("2026-09-01.001.jsonl", 40, now.AddMinutes(-4));
        var second = await CreateFileAsync("2026-09-01.002.jsonl", 40, now.AddMinutes(-3));
        var third = await CreateFileAsync("2026-09-01.003.jsonl", 40, now.AddMinutes(-2));
        var active = await CreateFileAsync("2026-09-01.004.jsonl", 40, now.AddMinutes(-1));
        var manager = new OperationalLogRetentionManager(new OperationalLogRetentionOptions(
            _directory,
            TimeSpan.FromDays(7),
            MaximumDirectoryBytes: 100,
            TargetDirectoryBytes: 90));

        var result = await manager.CleanupAsync(now, active, TestContext.Current.CancellationToken);

        Assert.Equal(2, result.DeletedFiles);
        Assert.False(File.Exists(first));
        Assert.False(File.Exists(second));
        Assert.True(File.Exists(third));
        Assert.True(File.Exists(active));
        Assert.Equal(80, result.RemainingBytes);
    }

    [Fact]
    public async Task Applies_low_watermark_to_plain_compressed_and_temporary_segments()
    {
        var now = DateTimeOffset.UtcNow;
        var compressed = await CreateFileAsync("2026-09-01.001.jsonl.gz", 40, now.AddMinutes(-4));
        var temporary = await CreateFileAsync("2026-09-01.002.jsonl.gz.tmp", 40, now.AddMinutes(-3));
        var plain = await CreateFileAsync("2026-09-01.003.jsonl", 40, now.AddMinutes(-2));
        var active = await CreateFileAsync("2026-09-01.004.jsonl", 40, now.AddMinutes(-1));
        var manager = new OperationalLogRetentionManager(new OperationalLogRetentionOptions(
            _directory,
            TimeSpan.FromDays(7),
            MaximumDirectoryBytes: 100,
            TargetDirectoryBytes: 90));

        var result = await manager.CleanupAsync(now, active, TestContext.Current.CancellationToken);

        Assert.Equal(2, result.DeletedFiles);
        Assert.False(File.Exists(compressed));
        Assert.False(File.Exists(temporary));
        Assert.True(File.Exists(plain));
        Assert.True(File.Exists(active));
        Assert.Equal(80, result.RemainingBytes);
    }

    private async Task<string> CreateFileAsync(string name, int length, DateTimeOffset lastWrite)
    {
        var path = Path.Combine(_directory, name);
        await File.WriteAllTextAsync(path, new string('x', length), TestContext.Current.CancellationToken);
        File.SetLastWriteTimeUtc(path, lastWrite.UtcDateTime);
        return path;
    }
}
