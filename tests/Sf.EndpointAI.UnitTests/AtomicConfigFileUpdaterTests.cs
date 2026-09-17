using Sf.EndpointAI.Client.Core.Configuration;

namespace Sf.EndpointAI.UnitTests;

public sealed class AtomicConfigFileUpdaterTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), $"sf-config-update-{Guid.NewGuid():N}");

    public AtomicConfigFileUpdaterTests()
    {
        Directory.CreateDirectory(_directory);
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }

        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task Replaces_backs_up_verifies_and_restores()
    {
        var target = Path.Combine(_directory, "settings.json");
        var backups = Path.Combine(_directory, "backups");
        var original = "{\"value\":1}"u8.ToArray();
        var updated = "{\"value\":2}"u8.ToArray();
        await File.WriteAllBytesAsync(target, original, TestContext.Current.CancellationToken);
        var result = await AtomicConfigFileUpdater.ApplyAsync(target, original, updated, backups, TestContext.Current.CancellationToken);

        Assert.NotNull(result.BackupPath);
        Assert.True(File.Exists(result.BackupPath));
        Assert.Equal(updated, await File.ReadAllBytesAsync(target, TestContext.Current.CancellationToken));
        AtomicConfigFileUpdater.Restore(target, result.BackupPath);
        Assert.Equal(original, await File.ReadAllBytesAsync(target, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Rejects_concurrent_change_without_overwriting_it()
    {
        var target = Path.Combine(_directory, "config.toml");
        await File.WriteAllTextAsync(target, "current", TestContext.Current.CancellationToken);
        var exception = await Assert.ThrowsAsync<ConfigMutationException>(() => AtomicConfigFileUpdater.ApplyAsync(
            target,
            "stale"u8.ToArray(),
            "updated"u8.ToArray(),
            Path.Combine(_directory, "backups"),
            TestContext.Current.CancellationToken));

        Assert.Equal("CONFIG_CHANGED_CONCURRENTLY", exception.Code);
        Assert.Equal("current", await File.ReadAllTextAsync(target, TestContext.Current.CancellationToken));
    }
}
