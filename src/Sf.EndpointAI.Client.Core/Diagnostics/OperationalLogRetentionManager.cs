namespace Sf.EndpointAI.Client.Core.Diagnostics;

public sealed record OperationalLogRetentionOptions(
    string RootDirectory,
    TimeSpan? Retention = null,
    long MaximumDirectoryBytes = 50L * 1024L * 1024L,
    long TargetDirectoryBytes = 45L * 1024L * 1024L)
{
    public TimeSpan EffectiveRetention => Retention ?? TimeSpan.FromDays(7);
}

public sealed record OperationalLogCleanupResult(int DeletedFiles, long DeletedBytes, long RemainingBytes);

public sealed class OperationalLogRetentionManager(OperationalLogRetentionOptions options)
{
    public Task<OperationalLogCleanupResult> CleanupAsync(
        DateTimeOffset now,
        string? activePath = null,
        CancellationToken cancellationToken = default)
    {
        if (!Directory.Exists(options.RootDirectory))
        {
            return Task.FromResult(new OperationalLogCleanupResult(0, 0, 0));
        }

        var activeFullPath = string.IsNullOrWhiteSpace(activePath) ? null : Path.GetFullPath(activePath);
        var files = Directory.EnumerateFiles(options.RootDirectory, "*", SearchOption.TopDirectoryOnly)
            .Where(IsManagedLogFile)
            .Select(path => new FileInfo(path))
            .Where(file => !file.Attributes.HasFlag(FileAttributes.ReparsePoint))
            .OrderBy(file => file.LastWriteTimeUtc)
            .ThenBy(file => file.Name, StringComparer.Ordinal)
            .ToList();
        var deletedFiles = 0;
        long deletedBytes = 0;
        var cutoff = now - options.EffectiveRetention;

        foreach (var file in files.ToArray())
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (IsActive(file, activeFullPath) || file.LastWriteTimeUtc >= cutoff.UtcDateTime)
            {
                continue;
            }

            deletedBytes += file.Length;
            file.Delete();
            files.Remove(file);
            deletedFiles++;
        }

        var remaining = files.Sum(file => file.Exists ? file.Length : 0L);
        if (remaining > options.MaximumDirectoryBytes)
        {
            foreach (var file in files)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (remaining <= options.TargetDirectoryBytes || IsActive(file, activeFullPath) || !file.Exists)
                {
                    continue;
                }

                var length = file.Length;
                file.Delete();
                remaining -= length;
                deletedBytes += length;
                deletedFiles++;
            }
        }

        return Task.FromResult(new OperationalLogCleanupResult(deletedFiles, deletedBytes, remaining));
    }

    private static bool IsActive(FileInfo file, string? activeFullPath) =>
        activeFullPath is not null
        && string.Equals(file.FullName, activeFullPath, StringComparison.OrdinalIgnoreCase);

    private static bool IsManagedLogFile(string path) =>
        path.EndsWith(".jsonl", StringComparison.OrdinalIgnoreCase)
        || path.EndsWith(".jsonl.gz", StringComparison.OrdinalIgnoreCase)
        || path.EndsWith(".jsonl.gz.tmp", StringComparison.OrdinalIgnoreCase);
}
