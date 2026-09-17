using System.Security.Cryptography;
using System.Text;

namespace Sf.EndpointAI.Client.Core.Capture;

public sealed class MarkdownCaptureSession : IAsyncDisposable
{
    private static readonly byte[] Fence = Encoding.UTF8.GetBytes("\n``````\n");
    private readonly CaptureOptions _options;
    private readonly CaptureMetadata _metadata;
    private readonly FileStream _stream;
    private readonly string _partialPath;
    private readonly string _completedPath;
    private readonly IncrementalHash _requestHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    private readonly IncrementalHash _responseHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    private bool _requestBodyStarted;
    private bool _responseBodyStarted;
    private bool _completed;
    private long _capturedBodyBytes;
    private long _requestBodyBytes;
    private long _responseBodyBytes;

    private MarkdownCaptureSession(
        CaptureOptions options,
        CaptureMetadata metadata,
        FileStream stream,
        string partialPath,
        string completedPath)
    {
        _options = options;
        _metadata = metadata;
        _stream = stream;
        _partialPath = partialPath;
        _completedPath = completedPath;
    }

    public bool IsDegraded { get; private set; }

    public string CompletedPath => _completedPath;

    public long RequestBodyBytes => _requestBodyBytes;

    public long ResponseBodyBytes => _responseBodyBytes;

    public bool IsTruncated => _capturedBodyBytes >= _options.MaximumCapturedBodyBytes;

    public static async Task<MarkdownCaptureSession> CreateAsync(
        CaptureOptions options,
        CaptureMetadata metadata,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(metadata);

        var dayDirectory = Path.Combine(
            options.RootDirectory,
            SanitizePathSegment(metadata.UserSid),
            metadata.StartedAtUtc.UtcDateTime.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture));
        Directory.CreateDirectory(dayDirectory);

        var stem = $"{metadata.StartedAtUtc.UtcDateTime:yyyyMMddTHHmmssfffZ}_{metadata.RequestId:N}";
        var partialPath = Path.Combine(dayDirectory, $"{stem}.partial");
        var completedPath = Path.Combine(dayDirectory, $"{stem}.md");
        var stream = new FileStream(
            partialPath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.Read,
            64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        var session = new MarkdownCaptureSession(options, metadata, stream, partialPath, completedPath);
        await session.WriteTextAsync($$"""
            # SF Endpoint AI Proxy Capture

            - Request ID: `{{metadata.RequestId}}`
            - Started UTC: `{{metadata.StartedAtUtc:O}}`
            - User ID: `{{EscapeInline(metadata.UserId)}}`
            - User SID: `{{metadata.UserSid}}`
            - Agent: `{{metadata.Agent}}`
            - Agent surface: `{{metadata.AgentSurface}}`
            - Provider: `{{metadata.ProviderId}}`
            - Route: `{{metadata.RouteId}}`
            - Original BaseURL: `{{metadata.OriginalBaseUrl}}`
            - Original authority: `{{metadata.OriginalAuthority}}`
            - Inbound: `{{metadata.Method}} {{metadata.InboundPathAndQuery}}`
            - Outbound: `{{metadata.Method}} {{metadata.OutboundUri.AbsoluteUri}}`

            """, cancellationToken);
        return session;
    }

    public Task WriteInboundHeadersAsync(
        IEnumerable<KeyValuePair<string, IEnumerable<string>>> headers,
        CancellationToken cancellationToken = default)
    {
        return WriteHeaderSectionAsync("Inbound request headers", headers, cancellationToken);
    }

    public Task WriteOutboundHeadersAsync(
        IEnumerable<KeyValuePair<string, IEnumerable<string>>> headers,
        CancellationToken cancellationToken = default)
    {
        return WriteHeaderSectionAsync("Outbound request headers", headers, cancellationToken);
    }

    public async ValueTask CaptureRequestBytesAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (!_requestBodyStarted)
        {
            _requestBodyStarted = true;
            await WriteTextAsync("## Request body\n\n``````\n", cancellationToken);
        }

        _requestHash.AppendData(buffer.Span);
        _requestBodyBytes += buffer.Length;
        await WriteCapturedBodyBytesAsync(buffer, cancellationToken);
    }

    public async Task BeginResponseAsync(
        int statusCode,
        string? reasonPhrase,
        IEnumerable<KeyValuePair<string, IEnumerable<string>>> headers,
        CancellationToken cancellationToken = default)
    {
        if (_requestBodyStarted)
        {
            await WriteBytesAsync(Fence, cancellationToken);
        }

        await WriteTextAsync($"## Upstream response\n\n`{statusCode} {reasonPhrase}`\n\n", cancellationToken);
        await WriteHeaderBlockAsync(headers, cancellationToken);
    }

    public async ValueTask CaptureResponseBytesAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (!_responseBodyStarted)
        {
            _responseBodyStarted = true;
            await WriteTextAsync("\n## Response body\n\n``````\n", cancellationToken);
        }

        _responseHash.AppendData(buffer.Span);
        _responseBodyBytes += buffer.Length;
        await WriteCapturedBodyBytesAsync(buffer, cancellationToken);
    }

    public async Task CompleteAsync(
        string outcome,
        string? errorCode = null,
        string? errorSummary = null,
        ProxyTiming? timing = null,
        CancellationToken cancellationToken = default)
    {
        if (_completed)
        {
            return;
        }

        _completed = true;
        if (_responseBodyStarted)
        {
            await WriteBytesAsync(Fence, cancellationToken);
        }

        var requestHash = Convert.ToHexString(_requestHash.GetHashAndReset()).ToLowerInvariant();
        var responseHash = Convert.ToHexString(_responseHash.GetHashAndReset()).ToLowerInvariant();
        if (timing is not null)
        {
            await WriteTextAsync($$"""
                ## Latency

                - Agent request received UTC: `{{FormatTimestamp(timing.AgentRequestReceivedAtUtc)}}`
                - Gateway request started UTC: `{{FormatTimestamp(timing.GatewayRequestStartedAtUtc)}}`
                - Gateway response headers received UTC: `{{FormatTimestamp(timing.GatewayResponseHeadersReceivedAtUtc)}}`
                - Agent response started UTC: `{{FormatTimestamp(timing.AgentResponseStartedAtUtc)}}`
                - Gateway round trip milliseconds: `{{FormatMilliseconds(timing.GatewayRoundTripMilliseconds)}}`

                """, cancellationToken);
        }

        await WriteTextAsync($$"""
            ## Completion

            - Outcome: `{{outcome}}`
            - Request bytes: `{{_requestBodyBytes}}`
            - Request SHA-256: `{{requestHash}}`
            - Response bytes: `{{_responseBodyBytes}}`
            - Response SHA-256: `{{responseHash}}`
            - Capture truncated: `{{IsTruncated}}`
            - Capture degraded: `{{IsDegraded}}`
            - Error code: `{{errorCode ?? string.Empty}}`
            - Error summary: `{{EscapeInline(errorSummary)}}`
            - Completed UTC: `{{DateTimeOffset.UtcNow:O}}`
            """, cancellationToken);

        await SafeFlushAndCloseAsync(cancellationToken);
        if (!IsDegraded)
        {
            try
            {
                File.Move(_partialPath, _completedPath, overwrite: false);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                IsDegraded = true;
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (!_completed)
        {
            await CompleteAsync("INTERRUPTED");
        }

        _requestHash.Dispose();
        _responseHash.Dispose();
        await _stream.DisposeAsync();
    }

    private async Task WriteHeaderSectionAsync(
        string title,
        IEnumerable<KeyValuePair<string, IEnumerable<string>>> headers,
        CancellationToken cancellationToken)
    {
        await WriteTextAsync($"## {title}\n\n", cancellationToken);
        await WriteHeaderBlockAsync(headers, cancellationToken);
    }

    private async Task WriteHeaderBlockAsync(
        IEnumerable<KeyValuePair<string, IEnumerable<string>>> headers,
        CancellationToken cancellationToken)
    {
        await WriteTextAsync("``````http\n", cancellationToken);
        foreach (var header in headers)
        {
            var values = CaptureHeaderRedactor.Redact(header.Key, header.Value);
            foreach (var value in values)
            {
                await WriteTextAsync($"{header.Key}: {value}\n", cancellationToken);
            }
        }

        await WriteTextAsync("``````\n\n", cancellationToken);
    }

    private async ValueTask WriteCapturedBodyBytesAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken)
    {
        var remaining = _options.MaximumCapturedBodyBytes - _capturedBodyBytes;
        if (remaining <= 0)
        {
            return;
        }

        var count = (int)Math.Min(buffer.Length, remaining);
        await WriteBytesAsync(buffer[..count], cancellationToken);
        _capturedBodyBytes += count;
    }

    private async Task WriteTextAsync(string value, CancellationToken cancellationToken)
    {
        await WriteBytesAsync(Encoding.UTF8.GetBytes(value), cancellationToken);
    }

    private async ValueTask WriteBytesAsync(ReadOnlyMemory<byte> value, CancellationToken cancellationToken)
    {
        if (IsDegraded)
        {
            return;
        }

        try
        {
            await _stream.WriteAsync(value, cancellationToken);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            IsDegraded = true;
        }
    }

    private async Task SafeFlushAndCloseAsync(CancellationToken cancellationToken)
    {
        try
        {
            await _stream.FlushAsync(cancellationToken);
            _stream.Flush(flushToDisk: true);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            IsDegraded = true;
        }
        finally
        {
            await _stream.DisposeAsync();
        }
    }

    private static string SanitizePathSegment(string value)
    {
        var invalid = Path.GetInvalidFileNameChars();
        return string.Concat(value.Select(character => invalid.Contains(character) ? '_' : character));
    }

    private static string EscapeInline(string? value)
    {
        return string.IsNullOrEmpty(value) ? string.Empty : value.Replace("`", "'", StringComparison.Ordinal);
    }

    private static string FormatTimestamp(DateTimeOffset? value)
    {
        return value?.ToString("O", System.Globalization.CultureInfo.InvariantCulture) ?? "null";
    }

    private static string FormatMilliseconds(long? value)
    {
        return value?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "null";
    }
}
