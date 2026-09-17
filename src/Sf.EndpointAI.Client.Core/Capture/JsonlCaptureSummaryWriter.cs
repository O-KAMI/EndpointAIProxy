using System.Text;
using System.Text.Json;

namespace Sf.EndpointAI.Client.Core.Capture;

public sealed class JsonlCaptureSummaryWriter(CaptureOptions options) : IDisposable
{
    private static readonly UTF8Encoding Utf8NoBom = new(false);
    private readonly SemaphoreSlim _gate = new(1, 1);

    public async Task<string> AppendAsync(CaptureSummary summary, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(summary);
        var directory = Path.Combine(options.RootDirectory, "summary");
        var path = Path.Combine(
            directory,
            $"{summary.StartedAtUtc.UtcDateTime:yyyy-MM-dd}.jsonl");
        var line = JsonSerializer.Serialize(summary) + "\n";

        await _gate.WaitAsync(cancellationToken);
        try
        {
            Directory.CreateDirectory(directory);
            await using var stream = new FileStream(
                path,
                FileMode.Append,
                FileAccess.Write,
                FileShare.Read,
                16 * 1024,
                FileOptions.Asynchronous | FileOptions.WriteThrough);
            var bytes = Utf8NoBom.GetBytes(line);
            await stream.WriteAsync(bytes, cancellationToken);
            await stream.FlushAsync(cancellationToken);
            return path;
        }
        finally
        {
            _gate.Release();
        }
    }

    public void Dispose()
    {
        _gate.Dispose();
    }
}
