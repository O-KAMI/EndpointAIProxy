namespace Sf.EndpointAI.Client.Core.Capture;

public sealed class CaptureRetentionManager(CaptureOptions options)
{
    public Task<CaptureCleanupResult> CleanupAsync(
        DateTimeOffset nowUtc,
        CancellationToken cancellationToken = default)
    {
        if (!Directory.Exists(options.RootDirectory))
        {
            return Task.FromResult(new CaptureCleanupResult(0, 0, 0));
        }

        var captureFiles = Directory
            .EnumerateFiles(options.RootDirectory, "*", SearchOption.AllDirectories)
            .Where(IsManagedCaptureFile)
            .Select(path => new FileInfo(path))
            .OrderBy(file => file.LastWriteTimeUtc)
            .ToList();
        var deletedFiles = 0;
        long deletedBytes = 0;
        var expiration = nowUtc.UtcDateTime - options.EffectiveRetention;

        foreach (var file in captureFiles.Where(file => file.LastWriteTimeUtc < expiration).ToArray())
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (TryDelete(file, out var length))
            {
                captureFiles.Remove(file);
                deletedFiles++;
                deletedBytes += length;
            }
        }

        var remainingBytes = captureFiles.Sum(file => file.Length);
        foreach (var file in captureFiles.ToArray())
        {
            if (remainingBytes <= options.MaximumDirectoryBytes)
            {
                break;
            }

            cancellationToken.ThrowIfCancellationRequested();
            if (TryDelete(file, out var length))
            {
                remainingBytes -= length;
                deletedFiles++;
                deletedBytes += length;
            }
        }

        return Task.FromResult(new CaptureCleanupResult(deletedFiles, deletedBytes, remainingBytes));
    }

    private static bool IsManagedCaptureFile(string path) =>
        path.EndsWith(".md", StringComparison.OrdinalIgnoreCase)
        || path.EndsWith(".md.gz", StringComparison.OrdinalIgnoreCase)
        || path.EndsWith(".md.gz.tmp", StringComparison.OrdinalIgnoreCase)
        || path.EndsWith(".partial", StringComparison.OrdinalIgnoreCase)
        || path.EndsWith(".jsonl", StringComparison.OrdinalIgnoreCase);

    private static bool TryDelete(FileInfo file, out long length)
    {
        try
        {
            length = file.Length;
            file.Delete();
            return true;
        }
        catch (IOException)
        {
            length = 0;
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            length = 0;
            return false;
        }
    }
}

public sealed record CaptureCleanupResult(int DeletedFiles, long DeletedBytes, long RemainingBytes);
