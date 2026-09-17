using System.Text;
using Microsoft.Data.Sqlite;
using Sf.EndpointAI.Client.Core.Routing;
using Sf.EndpointAI.Client.Core.Security;
using Sf.EndpointAI.Client.Core.State;
using Sf.EndpointAI.Contracts;

namespace Sf.EndpointAI.UnitTests;

public sealed class SqliteRouteRegistryTests : IAsyncLifetime
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), $"sf-endpoint-ai-{Guid.NewGuid():N}");

    public ValueTask InitializeAsync()
    {
        Directory.CreateDirectory(_directory);
        return ValueTask.CompletedTask;
    }

    public ValueTask DisposeAsync()
    {
        SqliteConnection.ClearAllPools();
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }

        return ValueTask.CompletedTask;
    }

    [Fact]
    public async Task Upsert_and_find_round_trip_route()
    {
        var registry = new SqliteRouteRegistry(Path.Combine(_directory, "client.db"), new TestProtector());
        await registry.InitializeAsync(TestContext.Current.CancellationToken);
        var now = DateTimeOffset.UtcNow;
        var route = new RouteRecord(
            RouteIdGenerator.Create(),
            "S-1-5-21-test",
            AgentType.ClaudeCode,
            "anthropic",
            new Uri("https://api.anthropic.com/v1"),
            new Uri("http://127.0.0.1:18080/r/abcdefghijklmnopqrstuv"),
            RouteStatus.Pending,
            now,
            now);

        await registry.UpsertAsync(route, TestContext.Current.CancellationToken);
        var restored = await registry.FindAsync(route.RouteId, TestContext.Current.CancellationToken);

        Assert.NotNull(restored);
        Assert.Equal(route.OriginalBaseUri, restored.OriginalBaseUri);
        Assert.Equal(route.UserSid, restored.UserSid);
        Assert.Equal(route.AgentType, restored.AgentType);
    }

    [Fact]
    public async Task Provisioner_reuses_identity_and_updates_original_target()
    {
        var registry = new SqliteRouteRegistry(Path.Combine(_directory, "provisioner.db"), new TestProtector());
        await registry.InitializeAsync(TestContext.Current.CancellationToken);
        var provisioner = new RouteProvisioner(registry, new Uri("http://127.0.0.1:18080"));

        var first = await provisioner.EnsureAsync(
            "S-1-5-21-test",
            AgentType.CodexCli,
            "custom",
            new Uri("https://api.openai.com/v1"),
            TestContext.Current.CancellationToken);
        var second = await provisioner.EnsureAsync(
            "S-1-5-21-test",
            AgentType.CodexCli,
            "custom",
            new Uri("https://gateway.example/openai/v1"),
            TestContext.Current.CancellationToken);

        Assert.Equal(first.RouteId, second.RouteId);
        Assert.Equal(first.InjectedBaseUri, second.InjectedBaseUri);
        Assert.Equal("https://gateway.example/openai/v1", second.OriginalBaseUri.AbsoluteUri);
        Assert.Single(await registry.ListAsync(TestContext.Current.CancellationToken));
    }

    private sealed class TestProtector : ITextProtector
    {
        public byte[] Protect(string value) => Encoding.UTF8.GetBytes($"protected:{value}");

        public string Unprotect(byte[] protectedValue)
        {
            return Encoding.UTF8.GetString(protectedValue)["protected:".Length..];
        }
    }
}
