using System.IO.Compression;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Sf.EndpointAI.Client.Core.Diagnostics;
using Sf.EndpointAI.Client.Core.Discovery;
using Sf.EndpointAI.Client.Core.State;
using Sf.EndpointAI.Client.Core.Windows;
using Sf.EndpointAI.Contracts;

namespace Sf.EndpointAI.UnitTests;

public sealed class DiagnosticBundleCollectorTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"sf-endpoint-ai-diagnostics-{Guid.NewGuid():N}");

    public DiagnosticBundleCollectorTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true);
    }

    [Fact]
    public async Task Creates_versioned_bundle_and_removes_canary_secrets()
    {
        const string canary = "sk-diagnostic-canary-12345678901234567890";
        var dataRoot = Path.Combine(_root, "data");
        var outputRoot = Path.Combine(_root, "output");
        var installRoot = Path.Combine(_root, "install");
        var summaryRoot = Path.Combine(dataRoot, "captures", "summary");
        var logRoot = Path.Combine(dataRoot, "logs");
        Directory.CreateDirectory(summaryRoot);
        Directory.CreateDirectory(logRoot);
        Directory.CreateDirectory(installRoot);
        var stateStore = new SqliteClientStateStore(Path.Combine(dataRoot, "state", "client.db"));
        await stateStore.InitializeAsync(TestContext.Current.CancellationToken);
        var deviceId = await stateStore.GetOrCreateDeviceIdAsync(TestContext.Current.CancellationToken);
        await stateStore.SaveOperationStateAsync(
            new StoredClientOperationState(ClientOperationState.Enabled, DateTimeOffset.UtcNow, null, null),
            TestContext.Current.CancellationToken);
        await using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = Path.Combine(dataRoot, "state", "client.db"),
        }.ConnectionString))
        {
            await connection.OpenAsync(TestContext.Current.CancellationToken);
            await using var command = connection.CreateCommand();
            command.CommandText = """
                INSERT INTO cached_policy (
                    singleton_id, policy_json, signature, policy_version, server_instance_id, received_at_utc)
                VALUES (1, '{}', $secret, 17, $serverId, $receivedAt);
                INSERT INTO device_credential (
                    singleton_id, protected_token, enrolled_at_utc, server_origin, server_certificate_spki_sha256)
                VALUES (1, $protectedToken, $receivedAt, 'https://control.example/', 'pin');
                """;
            command.Parameters.AddWithValue("$secret", canary);
            command.Parameters.AddWithValue("$serverId", Guid.NewGuid().ToString("D"));
            command.Parameters.AddWithValue("$receivedAt", DateTimeOffset.UtcNow.ToString("O"));
            command.Parameters.Add("$protectedToken", SqliteType.Blob).Value = Encoding.UTF8.GetBytes(canary);
            await command.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
        }
        var requestId = Guid.NewGuid();
        await File.WriteAllTextAsync(
            Path.Combine(summaryRoot, $"{DateTimeOffset.UtcNow:yyyy-MM-dd}.jsonl"),
            JsonSerializer.Serialize(new
            {
                RequestId = requestId,
                StartedAtUtc = DateTimeOffset.UtcNow,
                Outcome = "GATEWAY_HTTP_ERROR",
                Authorization = $"Bearer {canary}",
                ErrorSummary = $"token={canary}",
            }) + "\n",
            TestContext.Current.CancellationToken);
        var activeLogPath = Path.Combine(logRoot, "service-active.jsonl");
        await File.WriteAllTextAsync(activeLogPath, "{\"code\":\"ROUTE_RETIREMENT_DEFERRED\"}\n", TestContext.Current.CancellationToken);
        await using var activeWriter = new FileStream(
            activeLogPath,
            FileMode.Open,
            FileAccess.ReadWrite,
            FileShare.ReadWrite | FileShare.Delete);
        var now = DateTimeOffset.UtcNow;
        var discovery = new AgentDiscoverySnapshot(now, now, [], [], []);
        var collector = new DiagnosticBundleCollector(
            new DiagnosticCollectionOptions(
                dataRoot,
                installRoot,
                outputRoot,
                TimeSpan.FromHours(1),
                requestId,
                MaximumStagedBytes: 1,
                EnableActiveProbes: false,
                EnableSystemCommands: false,
                RouteRegistryAvailable: false),
            [],
            [],
            discovery,
            new WindowsUserAccountResolver());

        var result = await collector.CollectAsync(TestContext.Current.CancellationToken);

        Assert.True(File.Exists(result.BundlePath));
        Assert.True(File.Exists(result.BundlePath + ".sha256"));
        using var archive = ZipFile.OpenRead(result.BundlePath);
        Assert.Contains(archive.Entries, entry => entry.FullName == "manifest.json");
        Assert.Contains(archive.Entries, entry => entry.FullName == "assessment.json");
        Assert.Contains(archive.Entries, entry => entry.FullName == "state/client-runtime.json");
        var manifestEntry = Assert.Single(archive.Entries, entry => entry.FullName == "manifest.json");
        using (var reader = new StreamReader(manifestEntry.Open()))
        using (var manifest = JsonDocument.Parse(await reader.ReadToEndAsync(TestContext.Current.CancellationToken)))
        {
            Assert.Equal(2, manifest.RootElement.GetProperty("DiagnosticsSchemaVersion").GetInt32());
            var routeSection = Assert.Single(
                manifest.RootElement.GetProperty("Sections").EnumerateArray(),
                section => section.GetProperty("Name").GetString() == "routes");
            Assert.Equal("Failed", routeSection.GetProperty("Status").GetString());
            var requestSection = Assert.Single(
                manifest.RootElement.GetProperty("Sections").EnumerateArray(),
                section => section.GetProperty("Name").GetString() == "requests");
            Assert.Equal("Truncated", requestSection.GetProperty("Status").GetString());
        }
        var combinedText = string.Empty;
        foreach (var entry in archive.Entries)
        {
            using var reader = new StreamReader(entry.Open());
            combinedText += await reader.ReadToEndAsync(TestContext.Current.CancellationToken);
        }

        Assert.DoesNotContain(canary, combinedText, StringComparison.Ordinal);
        Assert.Contains(deviceId.ToString("D"), combinedText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("DiagnosticsSchemaVersion", combinedText, StringComparison.Ordinal);
        Assert.Contains("RECENT_GATEWAY_HTTP_ERROR", combinedText, StringComparison.Ordinal);
        Assert.Contains("ROUTE_RETIREMENT_DEFERRED", combinedText, StringComparison.Ordinal);
        Assert.Contains("\"Status\": \"Unknown\"", combinedText, StringComparison.Ordinal);
        Assert.True(result.Partial);
        Assert.True(result.Truncated);
    }

    [Fact]
    public async Task Reads_compressed_operational_logs_and_capture_referenced_as_markdown()
    {
        var dataRoot = Path.Combine(_root, "compressed-data");
        var outputRoot = Path.Combine(_root, "compressed-output");
        var installRoot = Path.Combine(_root, "compressed-install");
        var summaryRoot = Path.Combine(dataRoot, "captures", "summary");
        var captureRoot = Path.Combine(dataRoot, "captures", "S-1-5-test", "2026-09-09");
        var serviceLogRoot = Path.Combine(dataRoot, "logs", "service");
        Directory.CreateDirectory(summaryRoot);
        Directory.CreateDirectory(captureRoot);
        Directory.CreateDirectory(serviceLogRoot);
        Directory.CreateDirectory(installRoot);
        var requestId = Guid.NewGuid();
        var markdownPath = Path.Combine(captureRoot, $"{requestId:N}.md");
        await WriteGzipAsync(
            markdownPath + ".gz",
            "# Capture\n\n## Response body\n\n``````\n{\"error\":{\"code\":\"MODEL_UNAVAILABLE\"}}\n``````\n\n## Completion\n",
            TestContext.Current.CancellationToken);
        await File.WriteAllTextAsync(
            Path.Combine(summaryRoot, $"{DateTimeOffset.UtcNow:yyyy-MM-dd}.jsonl"),
            JsonSerializer.Serialize(new
            {
                RequestId = requestId,
                StartedAtUtc = DateTimeOffset.UtcNow,
                Outcome = "GATEWAY_HTTP_ERROR",
                CaptureDegraded = false,
                MarkdownPath = markdownPath,
            }) + "\n",
            TestContext.Current.CancellationToken);
        await WriteGzipAsync(
            Path.Combine(serviceLogRoot, $"{DateTimeOffset.UtcNow:yyyy-MM-dd}.001.jsonl.gz"),
            "{\"EventName\":\"ROUTE_RETIREMENT_DEFERRED\"}\n",
            TestContext.Current.CancellationToken);
        var now = DateTimeOffset.UtcNow;
        var collector = new DiagnosticBundleCollector(
            new DiagnosticCollectionOptions(
                dataRoot,
                installRoot,
                outputRoot,
                TimeSpan.FromHours(1),
                requestId,
                EnableActiveProbes: false,
                EnableSystemCommands: false),
            [],
            [],
            new AgentDiscoverySnapshot(now, now, [], [], []),
            new WindowsUserAccountResolver());

        var result = await collector.CollectAsync(TestContext.Current.CancellationToken);

        using var archive = ZipFile.OpenRead(result.BundlePath);
        var operationalEntry = Assert.Single(archive.Entries, entry => entry.FullName == "service/operational-log.jsonl");
        using var operationalReader = new StreamReader(operationalEntry.Open());
        Assert.Contains(
            "ROUTE_RETIREMENT_DEFERRED",
            await operationalReader.ReadToEndAsync(TestContext.Current.CancellationToken),
            StringComparison.Ordinal);
        var captureEntry = Assert.Single(
            archive.Entries,
            entry => entry.FullName == $"requests/sanitized-captures/{requestId:N}.md");
        using var captureReader = new StreamReader(captureEntry.Open());
        var capture = await captureReader.ReadToEndAsync(TestContext.Current.CancellationToken);
        Assert.Contains("MODEL_UNAVAILABLE", capture, StringComparison.Ordinal);
        Assert.Contains("[OMITTED FROM DIAGNOSTICS]", capture, StringComparison.Ordinal);
    }

    private static async Task WriteGzipAsync(string path, string content, CancellationToken cancellationToken)
    {
        await using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        await using var gzip = new GZipStream(file, CompressionLevel.Fastest);
        await using var writer = new StreamWriter(gzip, new UTF8Encoding(false));
        await writer.WriteAsync(content.AsMemory(), cancellationToken);
    }
}
