using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using System.Globalization;
using Sf.EndpointAI.Client.Core.Diagnostics;

namespace Sf.EndpointAI.Client.Service;

public sealed record JsonlFileLoggerOptions(
    string RootDirectory,
    long MaximumFileBytes = 20L * 1024L * 1024L,
    int QueueCapacity = 4096);

public sealed class JsonlFileLoggerProvider : ILoggerProvider, ISupportExternalScope
{
    private static readonly UTF8Encoding Utf8NoBom = new(false);
    private readonly JsonlFileLoggerOptions _options;
    private readonly Channel<OperationalLogEntry> _channel;
    private readonly CancellationTokenSource _shutdown = new();
    private readonly Task _writerTask;
    private readonly LogCompressionScheduler? _compressionQueue;
    private readonly OperationalLogFileTracker? _activeFileTracker;
    private IExternalScopeProvider _scopeProvider = new LoggerExternalScopeProvider();
    private long _droppedEntries;

    public JsonlFileLoggerProvider(
        JsonlFileLoggerOptions options,
        LogCompressionScheduler? compressionQueue = null,
        OperationalLogFileTracker? activeFileTracker = null)
    {
        _options = options;
        _compressionQueue = compressionQueue;
        _activeFileTracker = activeFileTracker;
        _channel = Channel.CreateBounded<OperationalLogEntry>(new BoundedChannelOptions(options.QueueCapacity)
        {
            SingleReader = true,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.Wait,
        });
        _writerTask = Task.Run(WriteLoopAsync);
    }

    public ILogger CreateLogger(string categoryName) => new JsonlFileLogger(this, categoryName);

    public void SetScopeProvider(IExternalScopeProvider scopeProvider) => _scopeProvider = scopeProvider;

    public void Dispose()
    {
        _channel.Writer.TryComplete();
        _shutdown.CancelAfter(TimeSpan.FromSeconds(3));
        try
        {
            _writerTask.GetAwaiter().GetResult();
        }
        catch (OperationCanceledException)
        {
            // Service shutdown must not wait indefinitely for diagnostic logging.
        }

        _shutdown.Dispose();
    }

    private bool TryWrite(OperationalLogEntry entry)
    {
        if (_channel.Writer.TryWrite(entry))
        {
            return true;
        }

        Interlocked.Increment(ref _droppedEntries);
        return false;
    }

    private async Task WriteLoopAsync()
    {
        FileStream? stream = null;
        string? activePath = null;
        try
        {
            Directory.CreateDirectory(_options.RootDirectory);
            await foreach (var first in _channel.Reader.ReadAllAsync(_shutdown.Token))
            {
                await Task.Delay(TimeSpan.FromMilliseconds(100), _shutdown.Token);
                var batch = new List<OperationalLogEntry>(128) { first };
                while (batch.Count < 256 && _channel.Reader.TryRead(out var entry))
                {
                    batch.Add(entry);
                }

                var dropped = Interlocked.Exchange(ref _droppedEntries, 0);
                if (dropped > 0)
                {
                    batch.Add(new OperationalLogEntry(
                        DateTimeOffset.UtcNow,
                        LogLevel.Warning,
                        "Sf.EndpointAI.Client.Service.JsonlFileLoggerProvider",
                        3901,
                        "LOG_EVENTS_DROPPED",
                        $"{dropped} operational log events were dropped because the queue was full.",
                        null,
                        new Dictionary<string, object?> { ["DroppedCount"] = dropped }));
                }

                foreach (var entry in batch)
                {
                    if (stream is null
                        || activePath is null
                        || !Path.GetFileName(activePath).StartsWith(entry.TimestampUtc.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture), StringComparison.Ordinal)
                        || stream.Length >= _options.MaximumFileBytes)
                    {
                        if (stream is not null)
                        {
                            var closedPath = activePath;
                            await stream.FlushAsync(_shutdown.Token);
                            await stream.DisposeAsync();
                            if (closedPath is not null)
                            {
                                _activeFileTracker?.Clear(closedPath);
                                _compressionQueue?.TryQueue(closedPath);
                            }
                        }

                        activePath = GetNextLogPath(entry.TimestampUtc);
                        stream = new FileStream(
                            activePath,
                            FileMode.Append,
                            FileAccess.Write,
                            FileShare.Read | FileShare.Delete,
                            64 * 1024,
                            FileOptions.Asynchronous | FileOptions.SequentialScan);
                        _activeFileTracker?.SetActive(activePath);
                    }

                    var bytes = Utf8NoBom.GetBytes(JsonSerializer.Serialize(entry) + "\n");
                    await stream.WriteAsync(bytes, _shutdown.Token);
                }

                await stream!.FlushAsync(_shutdown.Token);
            }
        }
        catch (OperationCanceledException) when (_shutdown.IsCancellationRequested)
        {
            // Normal provider shutdown.
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            try
            {
                Console.Error.WriteLine($"EndpointAI operational logging stopped: {exception.GetType().Name}: {exception.Message}");
            }
            catch
            {
                // Logging failure must never terminate the proxy.
            }
        }
        finally
        {
            if (stream is not null)
            {
                try
                {
                    var closedPath = activePath;
                    await stream.FlushAsync(CancellationToken.None);
                    await stream.DisposeAsync();
                    if (closedPath is not null)
                    {
                        _activeFileTracker?.Clear(closedPath);
                        _compressionQueue?.TryQueue(closedPath);
                    }
                }
                catch (IOException)
                {
                    // Best-effort shutdown.
                }
            }
        }
    }

    private string GetNextLogPath(DateTimeOffset timestamp)
    {
        var datePrefix = timestamp.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        for (var segment = 1; segment < 10_000; segment++)
        {
            var path = Path.Combine(_options.RootDirectory, $"{datePrefix}.{segment:000}.jsonl");
            if (!File.Exists(path) && !File.Exists(path + ".gz"))
            {
                return path;
            }
        }

        throw new IOException("Operational log segment limit was reached.");
    }

    private sealed class JsonlFileLogger(JsonlFileLoggerProvider provider, string categoryName) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull =>
            provider._scopeProvider.Push(state);

        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Information;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel))
            {
                return;
            }

            var properties = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
            if (state is IEnumerable<KeyValuePair<string, object?>> structuredState)
            {
                foreach (var item in structuredState)
                {
                    if (item.Key.Equals("{OriginalFormat}", StringComparison.Ordinal))
                    {
                        continue;
                    }

                    properties[item.Key] = SanitizeValue(item.Key, item.Value);
                }
            }

            provider.TryWrite(new OperationalLogEntry(
                DateTimeOffset.UtcNow,
                logLevel,
                categoryName,
                eventId.Id,
                eventId.Name,
                DiagnosticSanitizer.SanitizeText(formatter(state, exception)),
                exception is null
                    ? null
                    : DiagnosticSanitizer.SanitizeText($"{exception.GetType().Name}: {exception.Message}"),
                properties));
        }

        private static string? SanitizeValue(string name, object? value)
        {
            if (DiagnosticSanitizer.IsSensitiveName(name))
            {
                return DiagnosticSanitizer.Redacted;
            }

            if (value is null)
            {
                return null;
            }

            var text = Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty;
            if (name.Equals("UserSid", StringComparison.OrdinalIgnoreCase))
            {
                return DiagnosticSanitizer.HashIdentifier(text);
            }

            return name.Contains("url", StringComparison.OrdinalIgnoreCase)
                || name.Contains("uri", StringComparison.OrdinalIgnoreCase)
                ? DiagnosticSanitizer.SanitizeUri(text)
                : DiagnosticSanitizer.SanitizeText(text);
        }
    }
}

public sealed record OperationalLogEntry(
    DateTimeOffset TimestampUtc,
    LogLevel Level,
    string Category,
    int EventId,
    string? EventName,
    string Message,
    string? Exception,
    IReadOnlyDictionary<string, object?> Properties);
