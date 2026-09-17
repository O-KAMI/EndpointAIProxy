using System.Security.Cryptography;
using Sf.EndpointAI.Client.Core.MacOS;

namespace Sf.EndpointAI.Client.Core.Configuration;

public sealed record ConfigFileUpdateResult(
    string TargetPath,
    string? BackupPath,
    string PreviousSha256,
    string UpdatedSha256,
    bool Created);

public sealed class AtomicConfigFileUpdater
{
    public static async Task<ConfigFileUpdateResult> ApplyAsync(
        string targetPath,
        ReadOnlyMemory<byte> expectedContent,
        ReadOnlyMemory<byte> updatedContent,
        string backupDirectory,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(targetPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(backupDirectory);
        var fullTargetPath = Path.GetFullPath(targetPath);
        var fullBackupDirectory = Path.GetFullPath(backupDirectory);
        var parent = Path.GetDirectoryName(fullTargetPath)
            ?? throw new ConfigMutationException("CONFIG_PARENT_MISSING", "The configuration path has no parent directory.");
        Directory.CreateDirectory(parent);
        Directory.CreateDirectory(fullBackupDirectory);

        var existed = File.Exists(fullTargetPath);
        var unixMode = existed && !OperatingSystem.IsWindows()
            ? File.GetUnixFileMode(fullTargetPath)
            : (UnixFileMode?)null;
        var currentContent = existed
            ? await File.ReadAllBytesAsync(fullTargetPath, cancellationToken)
            : [];
        if (!currentContent.AsSpan().SequenceEqual(expectedContent.Span))
        {
            throw new ConfigMutationException(
                "CONFIG_CHANGED_CONCURRENTLY",
                "The configuration changed after it was inspected; no update was applied.");
        }

        var previousHash = Convert.ToHexStringLower(SHA256.HashData(currentContent));
        var updatedHash = Convert.ToHexStringLower(SHA256.HashData(updatedContent.Span));
        var tempPath = Path.Combine(parent, $".{Path.GetFileName(fullTargetPath)}.{Guid.NewGuid():N}.tmp");
        string? backupPath = null;
        try
        {
            await using (var stream = new FileStream(
                tempPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 64 * 1024,
                FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(updatedContent, cancellationToken);
                await stream.FlushAsync(cancellationToken);
                stream.Flush(flushToDisk: true);
            }

            if (!OperatingSystem.IsWindows() && unixMode is not null)
            {
                File.SetUnixFileMode(tempPath, unixMode.Value);
                if (OperatingSystem.IsMacOS())
                {
                    MacFileOwnership.CopyFrom(fullTargetPath, tempPath);
                }
            }

            var verifyCurrent = existed
                ? await File.ReadAllBytesAsync(fullTargetPath, cancellationToken)
                : [];
            if (!verifyCurrent.AsSpan().SequenceEqual(expectedContent.Span))
            {
                throw new ConfigMutationException(
                    "CONFIG_CHANGED_CONCURRENTLY",
                    "The configuration changed while the replacement was being prepared; no update was applied.");
            }

            if (existed)
            {
                backupPath = CreateBackupPath(fullBackupDirectory, fullTargetPath);
                File.Replace(tempPath, fullTargetPath, backupPath, ignoreMetadataErrors: false);
            }
            else
            {
                File.Move(tempPath, fullTargetPath);
            }

            var persisted = await File.ReadAllBytesAsync(fullTargetPath, cancellationToken);
            if (!persisted.AsSpan().SequenceEqual(updatedContent.Span))
            {
                throw new ConfigMutationException("CONFIG_VERIFY_FAILED", "The persisted configuration did not pass byte verification.");
            }

            return new ConfigFileUpdateResult(
                fullTargetPath,
                backupPath,
                previousHash,
                updatedHash,
                Created: !existed);
        }
        finally
        {
            if (File.Exists(tempPath))
            {
                File.Delete(tempPath);
            }
        }
    }

    public static void Restore(string targetPath, string backupPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(targetPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(backupPath);
        var fullTargetPath = Path.GetFullPath(targetPath);
        var fullBackupPath = Path.GetFullPath(backupPath);
        if (!File.Exists(fullBackupPath))
        {
            throw new FileNotFoundException("The configuration backup does not exist.", fullBackupPath);
        }

        var parent = Path.GetDirectoryName(fullTargetPath)
            ?? throw new ConfigMutationException("CONFIG_PARENT_MISSING", "The configuration path has no parent directory.");
        Directory.CreateDirectory(parent);
        var tempPath = Path.Combine(parent, $".{Path.GetFileName(fullTargetPath)}.{Guid.NewGuid():N}.restore.tmp");
        try
        {
            File.Copy(fullBackupPath, tempPath, overwrite: false);
            if (!OperatingSystem.IsWindows())
            {
                var metadataSource = File.Exists(fullTargetPath) ? fullTargetPath : fullBackupPath;
                File.SetUnixFileMode(tempPath, File.GetUnixFileMode(metadataSource));
                if (OperatingSystem.IsMacOS())
                {
                    MacFileOwnership.CopyFrom(metadataSource, tempPath);
                }
            }
            if (File.Exists(fullTargetPath))
            {
                File.Move(tempPath, fullTargetPath, overwrite: true);
            }
            else
            {
                File.Move(tempPath, fullTargetPath);
            }
        }
        finally
        {
            if (File.Exists(tempPath))
            {
                File.Delete(tempPath);
            }
        }
    }

    private static string CreateBackupPath(string backupDirectory, string targetPath)
    {
        var timestamp = DateTimeOffset.UtcNow.ToString("yyyyMMddTHHmmssfffffffZ", System.Globalization.CultureInfo.InvariantCulture);
        return Path.Combine(backupDirectory, $"{Path.GetFileName(targetPath)}.{timestamp}.{Guid.NewGuid():N}.bak");
    }
}
