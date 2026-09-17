using System.Text;
using Sf.EndpointAI.Client.Core.Capture;

namespace Sf.EndpointAI.UnitTests;

public sealed class MarkdownCaptureSessionTests : IAsyncLifetime
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), $"sf-endpoint-ai-capture-{Guid.NewGuid():N}");

    public ValueTask InitializeAsync()
    {
        Directory.CreateDirectory(_directory);
        return ValueTask.CompletedTask;
    }

    public ValueTask DisposeAsync()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }

        return ValueTask.CompletedTask;
    }

    [Fact]
    public async Task Writes_request_response_and_completion_to_one_markdown_file()
    {
        var metadata = new CaptureMetadata(
            Guid.NewGuid(),
            DateTimeOffset.UtcNow,
            "DOMAIN\\user",
            "S-1-5-21-test",
            "ClaudeCode",
            "cli",
            "anthropic",
            "abcdefghijklmnopqrstuv",
            "https://api.anthropic.com",
            "api.anthropic.com",
            "POST",
            "/r/abcdefghijklmnopqrstuv/v1/messages",
            new Uri("https://api.anthropic.com/v1/messages"));
        await using var capture = await MarkdownCaptureSession.CreateAsync(
            new CaptureOptions(_directory, MaximumCapturedBodyBytes: 1024),
            metadata,
            TestContext.Current.CancellationToken);

        await capture.WriteInboundHeadersAsync(
        [
            new KeyValuePair<string, IEnumerable<string>>("Authorization", ["Bearer test-token"]),
        ], TestContext.Current.CancellationToken);
        await capture.WriteOutboundHeadersAsync([], TestContext.Current.CancellationToken);
        await capture.CaptureRequestBytesAsync(Encoding.UTF8.GetBytes("{\"model\":\"test\"}"), TestContext.Current.CancellationToken);
        await capture.BeginResponseAsync(200, "OK", [], TestContext.Current.CancellationToken);
        await capture.CaptureResponseBytesAsync(Encoding.UTF8.GetBytes("{\"result\":\"ok\"}"), TestContext.Current.CancellationToken);
        var timing = new ProxyTiming(
            new DateTimeOffset(2026, 8, 27, 1, 2, 3, TimeSpan.Zero),
            new DateTimeOffset(2026, 8, 27, 1, 2, 3, 10, TimeSpan.Zero),
            new DateTimeOffset(2026, 8, 27, 1, 2, 3, 135, TimeSpan.Zero),
            new DateTimeOffset(2026, 8, 27, 1, 2, 3, 140, TimeSpan.Zero),
            125);
        await capture.CompleteAsync(
            "COMPLETED",
            timing: timing,
            cancellationToken: TestContext.Current.CancellationToken);

        var text = await File.ReadAllTextAsync(capture.CompletedPath, TestContext.Current.CancellationToken);
        Assert.DoesNotContain("Bearer test-token", text, StringComparison.Ordinal);
        Assert.Contains("Authorization: [REDACTED]", text, StringComparison.Ordinal);
        Assert.Contains("{\"model\":\"test\"}", text, StringComparison.Ordinal);
        Assert.Contains("{\"result\":\"ok\"}", text, StringComparison.Ordinal);
        Assert.Contains("Agent request received UTC: `2026-08-27T01:02:03.0000000+00:00`", text, StringComparison.Ordinal);
        Assert.Contains("Gateway response headers received UTC: `2026-08-27T01:02:03.1350000+00:00`", text, StringComparison.Ordinal);
        Assert.Contains("Gateway round trip milliseconds: `125`", text, StringComparison.Ordinal);
        Assert.Contains("Outcome: `COMPLETED`", text, StringComparison.Ordinal);
    }
}
