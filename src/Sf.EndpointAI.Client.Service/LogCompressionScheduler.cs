using System.Collections.Concurrent;

namespace Sf.EndpointAI.Client.Service;

public sealed class LogCompressionScheduler : IDisposable
{
    private const int MaximumQueuedPaths = 4096;
    private readonly ConcurrentDictionary<string, byte> _paths = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim _signal = new(0, 1);
    private int _queuedCount;
    private int _disposed;

    public bool TryQueue(string path)
    {
        if (Volatile.Read(ref _disposed) != 0
            || string.IsNullOrWhiteSpace(path)
            || Volatile.Read(ref _queuedCount) >= MaximumQueuedPaths)
        {
            return false;
        }

        var fullPath = Path.GetFullPath(path);
        if (!_paths.TryAdd(fullPath, 0))
        {
            return true;
        }

        if (Interlocked.Increment(ref _queuedCount) > MaximumQueuedPaths)
        {
            if (_paths.TryRemove(fullPath, out _))
            {
                Interlocked.Decrement(ref _queuedCount);
            }
            return false;
        }

        try
        {
            if (_signal.CurrentCount == 0)
            {
                _signal.Release();
            }
        }
        catch (SemaphoreFullException)
        {
            // Another producer already signaled the single reader.
        }
        catch (ObjectDisposedException)
        {
            if (_paths.TryRemove(fullPath, out _))
            {
                Interlocked.Decrement(ref _queuedCount);
            }
            return false;
        }

        return true;
    }

    public bool TryDequeue(out string path)
    {
        foreach (var candidate in _paths.Keys)
        {
            if (_paths.TryRemove(candidate, out _))
            {
                Interlocked.Decrement(ref _queuedCount);
                path = candidate;
                return true;
            }
        }

        path = string.Empty;
        return false;
    }

    public Task<bool> WaitAsync(TimeSpan timeout, CancellationToken cancellationToken) =>
        _signal.WaitAsync(timeout, cancellationToken);

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            _signal.Dispose();
        }
    }
}
