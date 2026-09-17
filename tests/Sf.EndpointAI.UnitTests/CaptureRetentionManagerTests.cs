using Sf.EndpointAI.Client.Core.Capture;

namespace Sf.EndpointAI.UnitTests;

public sealed class CaptureRetentionManagerTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), $"sf-endpoint-ai-retention-{Guid.NewGuid():N}");

    public CaptureRetentionManagerTests()
    {
        Directory.CreateDirectory(_directory);
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    [Fact]
    public async Task Deletes_expired_completed_and_partial_files_but_keeps_recent_partial()
    {
        var now = DateTimeOffset.UtcNow;
        var expired = Path.Combine(_directory, "expired.md");
        var expiredPartial = Path.Combine(_directory, "expired.partial");
        var expiredSummary = Path.Combine(_directory, "expired.jsonl");
        var activePartial = Path.Combine(_directory, "active.partial");
        await File.WriteAllTextAsync(expired, "expired", TestContext.Current.CancellationToken);
        await File.WriteAllTextAsync(expiredPartial, "expired-partial", TestContext.Current.CancellationToken);
        await File.WriteAllTextAsync(expiredSummary, "{}", TestContext.Current.CancellationToken);
        await File.WriteAllTextAsync(activePartial, "active", TestContext.Current.CancellationToken);
        File.SetLastWriteTimeUtc(expired, now.UtcDateTime.AddDays(-8));
        File.SetLastWriteTimeUtc(expiredPartial, now.UtcDateTime.AddDays(-8));
        File.SetLastWriteTimeUtc(expiredSummary, now.UtcDateTime.AddDays(-8));
        var manager = new CaptureRetentionManager(new CaptureOptions(_directory));

        var result = await manager.CleanupAsync(now, TestContext.Current.CancellationToken);

        Assert.Equal(3, result.DeletedFiles);
        Assert.False(File.Exists(expired));
        Assert.False(File.Exists(expiredPartial));
        Assert.False(File.Exists(expiredSummary));
        Assert.True(File.Exists(activePartial));
    }

    [Fact]
    public async Task Counts_compressed_and_temporary_files_toward_directory_limit()
    {
        var now = DateTimeOffset.UtcNow;
        var compressed = Path.Combine(_directory, "first.md.gz");
        var temporary = Path.Combine(_directory, "second.md.gz.tmp");
        var recent = Path.Combine(_directory, "third.md");
        await File.WriteAllTextAsync(compressed, new string('a', 40), TestContext.Current.CancellationToken);
        await File.WriteAllTextAsync(temporary, new string('b', 40), TestContext.Current.CancellationToken);
        await File.WriteAllTextAsync(recent, new string('c', 40), TestContext.Current.CancellationToken);
        File.SetLastWriteTimeUtc(compressed, now.AddMinutes(-3).UtcDateTime);
        File.SetLastWriteTimeUtc(temporary, now.AddMinutes(-2).UtcDateTime);
        File.SetLastWriteTimeUtc(recent, now.AddMinutes(-1).UtcDateTime);
        var manager = new CaptureRetentionManager(new CaptureOptions(
            _directory,
            MaximumDirectoryBytes: 80));

        var result = await manager.CleanupAsync(now, TestContext.Current.CancellationToken);

        Assert.Equal(1, result.DeletedFiles);
        Assert.False(File.Exists(compressed));
        Assert.True(File.Exists(temporary));
        Assert.True(File.Exists(recent));
        Assert.Equal(80, result.RemainingBytes);
    }
}
