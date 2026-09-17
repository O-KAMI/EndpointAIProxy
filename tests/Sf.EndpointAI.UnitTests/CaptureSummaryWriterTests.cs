using System.Text.Json;
using Sf.EndpointAI.Client.Core.Capture;

namespace Sf.EndpointAI.UnitTests;

public sealed class CaptureSummaryWriterTests : IAsyncLifetime
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), $"sf-summary-{Guid.NewGuid():N}");

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
    public async Task Concurrent_appends_produce_one_valid_json_object_per_line()
    {
        using var writer = new JsonlCaptureSummaryWriter(new CaptureOptions(_directory));
        var started = new DateTimeOffset(2026, 8, 26, 1, 2, 3, TimeSpan.Zero);
        var tasks = Enumerable.Range(0, 8).Select(index => writer.AppendAsync(new CaptureSummary(
            Guid.NewGuid(),
            started,
            started.AddMilliseconds(index + 1),
            started,
            started.AddMilliseconds(1),
            started.AddMilliseconds(index + 1),
            started.AddMilliseconds(index + 1),
            index,
            "DOMAIN\\user",
            "S-1-5-21-test",
            "Codex",
            "ide",
            "codex:provider",
            "abcdefghijklmnopqrstuv",
            "https://api.openai.com/v1",
            "/r/route/responses",
            "/v1/responses",
            200,
            index + 1,
            "SUCCESS",
            null,
            null,
            10,
            20,
            false,
            false,
            $"capture-{index}.md"), TestContext.Current.CancellationToken));

        var paths = await Task.WhenAll(tasks);
        var lines = await File.ReadAllLinesAsync(paths[0], TestContext.Current.CancellationToken);
        Assert.Equal(8, lines.Length);
        Assert.All(lines, line =>
        {
            var root = JsonDocument.Parse(line).RootElement;
            Assert.Equal("SUCCESS", root.GetProperty("Outcome").GetString());
            Assert.Equal(started, root.GetProperty("AgentRequestReceivedAtUtc").GetDateTimeOffset());
            Assert.Equal(JsonValueKind.Number, root.GetProperty("GatewayRoundTripMilliseconds").ValueKind);
        });
    }

    [Fact]
    public async Task Unreached_latency_phases_are_written_as_null()
    {
        using var writer = new JsonlCaptureSummaryWriter(new CaptureOptions(_directory));
        var started = new DateTimeOffset(2026, 8, 27, 1, 2, 3, TimeSpan.Zero);
        var path = await writer.AppendAsync(new CaptureSummary(
            Guid.NewGuid(),
            started,
            started.AddMilliseconds(10),
            started,
            started.AddMilliseconds(1),
            null,
            null,
            null,
            "DOMAIN\\user",
            "S-1-5-21-test",
            "Codex",
            "ide",
            "codex:provider",
            "abcdefghijklmnopqrstuv",
            "https://api.openai.com/v1",
            "/r/route/responses",
            "/v1/responses",
            502,
            10,
            "GATEWAY_CONNECTION_FAILED",
            "GATEWAY_CONNECTION_FAILED",
            "connection failed",
            10,
            0,
            false,
            false,
            "capture.md"), TestContext.Current.CancellationToken);

        var line = Assert.Single(await File.ReadAllLinesAsync(path, TestContext.Current.CancellationToken));
        var root = JsonDocument.Parse(line).RootElement;
        Assert.Equal(JsonValueKind.Null, root.GetProperty("GatewayResponseHeadersReceivedAtUtc").ValueKind);
        Assert.Equal(JsonValueKind.Null, root.GetProperty("AgentResponseStartedAtUtc").ValueKind);
        Assert.Equal(JsonValueKind.Null, root.GetProperty("GatewayRoundTripMilliseconds").ValueKind);
    }
}
