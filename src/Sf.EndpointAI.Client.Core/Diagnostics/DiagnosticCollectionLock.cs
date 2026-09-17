namespace Sf.EndpointAI.Client.Core.Diagnostics;

public sealed class DiagnosticCollectionLock : IDisposable
{
    private readonly FileStream _stream;

    private DiagnosticCollectionLock(FileStream stream) => _stream = stream;

    public static DiagnosticCollectionLock? TryAcquire(string dataRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataRoot);
        var directory = Path.Combine(Path.GetFullPath(dataRoot), "diagnostics");
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "collection.lock");
        try
        {
            return new DiagnosticCollectionLock(new FileStream(
                path,
                FileMode.OpenOrCreate,
                FileAccess.ReadWrite,
                FileShare.None,
                bufferSize: 1,
                FileOptions.None));
        }
        catch (IOException)
        {
            return null;
        }
    }

    public void Dispose() => _stream.Dispose();
}

public static class DiagnosticPathResolver
{
    public static string ResolveInstallDirectory(string? processPath, string appContextBaseDirectory)
    {
        if (!string.IsNullOrWhiteSpace(processPath))
        {
            var directory = Path.GetDirectoryName(Path.GetFullPath(processPath));
            if (!string.IsNullOrWhiteSpace(directory))
            {
                return directory;
            }
        }

        return Path.GetFullPath(appContextBaseDirectory);
    }
}
