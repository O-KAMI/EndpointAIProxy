using System.IO.Compression;

namespace Sf.EndpointAI.Client.Service;

public sealed class GzipLogFileCompressor
{
    public async Task<string> CompressAsync(string sourcePath, CancellationToken cancellationToken = default)
    {
        var source = Path.GetFullPath(sourcePath);
        var destination = source + ".gz";
        var temporary = destination + ".tmp";
        var lastWriteTimeUtc = File.GetLastWriteTimeUtc(source);

        try
        {
            if (File.Exists(destination))
            {
                try
                {
                    await ValidateAsync(destination, cancellationToken);
                    File.Delete(source);
                    return destination;
                }
                catch (InvalidDataException)
                {
                    File.Delete(destination);
                }
            }

            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }

            await using (var input = new FileStream(
                source,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read | FileShare.Delete,
                64 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan))
            await using (var output = new FileStream(
                temporary,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                64 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                await using (var gzip = new GZipStream(output, CompressionLevel.Fastest, leaveOpen: true))
                {
                    await input.CopyToAsync(gzip, 64 * 1024, cancellationToken);
                }

                await output.FlushAsync(cancellationToken);
                output.Flush(flushToDisk: true);
            }

            File.Move(temporary, destination, overwrite: false);
            File.SetLastWriteTimeUtc(destination, lastWriteTimeUtc);
            File.Delete(source);
            return destination;
        }
        finally
        {
            TryDelete(temporary);
        }
    }

    private static async Task ValidateAsync(string path, CancellationToken cancellationToken)
    {
        await using var input = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete,
            64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        await using var gzip = new GZipStream(input, CompressionMode.Decompress);
        await gzip.CopyToAsync(Stream.Null, 64 * 1024, cancellationToken);
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // A later maintenance pass will remove a stale temporary file.
        }
    }
}
