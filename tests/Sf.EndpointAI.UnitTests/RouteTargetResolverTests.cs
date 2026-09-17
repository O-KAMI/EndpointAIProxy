using Sf.EndpointAI.Client.Core.Policy;
using Sf.EndpointAI.Client.Core.Routing;
using Sf.EndpointAI.Client.Core.State;
using Sf.EndpointAI.Contracts;

namespace Sf.EndpointAI.UnitTests;

public sealed class RouteTargetResolverTests
{
    [Fact]
    public async Task Gateway_policy_switch_and_rollback_affect_new_requests_without_recreating_resolver()
    {
        var route = CreateRoute("https://api.openai.com/v1");
        var initial = new EndpointPolicy(1, Guid.NewGuid(), 1, true, RouteMode.FixedGateway,
            "http://gateway.example.invalid", true, 60, 60, DateTimeOffset.UtcNow);
        var provider = new DynamicPolicyProvider(initial);
        var resolver = new RouteTargetResolver(new FakeRouteRegistry(route), provider);
        var before = await resolver.ResolveAsync(route.RouteId, "/responses", "?stream=true", TestContext.Current.CancellationToken);
        Assert.True(provider.TryApply(initial with { PolicyVersion = 2, GatewayOrigin = "http://gateway.example.invalid:30080" }));
        var after = await resolver.ResolveAsync(route.RouteId, "/responses", "?stream=true", TestContext.Current.CancellationToken);
        Assert.Equal("http://gateway.example.invalid/v1/responses?stream=true", before!.TargetUri.AbsoluteUri);
        Assert.Equal("http://gateway.example.invalid:30080/v1/responses?stream=true", after!.TargetUri.AbsoluteUri);
        Assert.False(provider.TryApply(initial));
        Assert.True(provider.TryApply(initial with { PolicyVersion = 3 }));
        var rollback = await resolver.ResolveAsync(route.RouteId, "/responses", "?stream=true", TestContext.Current.CancellationToken);
        Assert.Equal(before.TargetUri, rollback!.TargetUri);
    }

    [Fact]
    public async Task Passthrough_reconstructs_original_base_path_and_query()
    {
        var route = CreateRoute("https://api.openai.com/v1");
        var resolver = CreateResolver(route, RouteMode.PassthroughOriginal);

        var result = await resolver.ResolveAsync(route.RouteId, "/responses", "?stream=true", TestContext.Current.CancellationToken);

        Assert.NotNull(result);
        Assert.False(result.IsSfGateway);
        Assert.Equal("https://api.openai.com/v1/responses?stream=true", result.TargetUri.AbsoluteUri);
    }

    [Fact]
    public async Task Fixed_gateway_changes_only_origin()
    {
        var route = CreateRoute("https://api.openai.com/v1");
        var resolver = CreateResolver(route, RouteMode.FixedGateway, "https://internal.example.invalid:8443");

        var result = await resolver.ResolveAsync(route.RouteId, "/responses", "?stream=true", TestContext.Current.CancellationToken);

        Assert.NotNull(result);
        Assert.True(result.IsSfGateway);
        Assert.Equal("https://internal.example.invalid:8443/v1/responses?stream=true", result.TargetUri.AbsoluteUri);
    }

    [Fact]
    public async Task Fixed_gateway_preserves_chat_completions_path_without_conversion()
    {
        var route = CreateRoute("https://api.moonshot.cn/v1");
        var resolver = CreateResolver(route, RouteMode.FixedGateway, "http://192.0.2.2:8080", allowInsecure: true);

        var result = await resolver.ResolveAsync(
            route.RouteId,
            "/chat/completions",
            string.Empty,
            TestContext.Current.CancellationToken);

        Assert.NotNull(result);
        Assert.Equal("http://192.0.2.2:8080/v1/chat/completions", result.TargetUri.AbsoluteUri);
    }

    [Fact]
    public async Task Invalid_route_identifier_is_not_resolved()
    {
        var route = CreateRoute("https://api.openai.com/v1");
        var resolver = CreateResolver(route, RouteMode.PassthroughOriginal);

        var result = await resolver.ResolveAsync("../api.openai.com", "/responses", string.Empty, TestContext.Current.CancellationToken);

        Assert.Null(result);
    }

    [Theory]
    [InlineData(ClientOperationState.Disabled)]
    [InlineData(ClientOperationState.DisableFailed)]
    [InlineData(ClientOperationState.EnableFailed)]
    public async Task Non_enabled_remote_operation_state_blocks_forwarding(ClientOperationState state)
    {
        var route = CreateRoute("https://api.openai.com/v1");
        var policy = new EndpointPolicy(
            1,
            Guid.NewGuid(),
            1,
            true,
            RouteMode.PassthroughOriginal,
            null,
            false,
            60,
            60,
            DateTimeOffset.UtcNow);
        var operationState = new ClientOperationStateProvider();
        operationState.Update(new StoredClientOperationState(state, DateTimeOffset.UtcNow, null, null));
        var resolver = new RouteTargetResolver(
            new FakeRouteRegistry(route),
            new StaticPolicyProvider(policy),
            operationState);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            resolver.ResolveAsync(route.RouteId, "/responses", string.Empty, TestContext.Current.CancellationToken));
    }

    [Fact]
    public void Route_identifier_has_128_bits_of_random_input()
    {
        var routeId = RouteIdGenerator.Create();

        Assert.Equal(22, routeId.Length);
        Assert.True(RouteTargetResolver.IsValidRouteId(routeId));
    }

    private static RouteTargetResolver CreateResolver(
        RouteRecord route,
        RouteMode mode,
        string? gateway = null,
        bool allowInsecure = false)
    {
        var policy = new EndpointPolicy(1, Guid.NewGuid(), 1, true, mode, gateway, allowInsecure, 60, 60, DateTimeOffset.UtcNow);
        return new RouteTargetResolver(new FakeRouteRegistry(route), new StaticPolicyProvider(policy));
    }

    private static RouteRecord CreateRoute(string originalBaseUri)
    {
        var now = DateTimeOffset.UtcNow;
        return new RouteRecord(
            RouteIdGenerator.Create(),
            "S-1-5-21-test",
            AgentType.CodexCli,
            "openai",
            new Uri(originalBaseUri),
            new Uri("http://127.0.0.1:18080/r/test"),
            RouteStatus.Pending,
            now,
            now);
    }

    private sealed class FakeRouteRegistry(RouteRecord route) : IRouteRegistry
    {
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task<RouteRecord?> FindAsync(string routeId, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<RouteRecord?>(route.RouteId == routeId ? route : null);
        }

        public Task<RouteRecord?> FindByIdentityAsync(
            string userSid,
            AgentType agentType,
            string providerId,
            CancellationToken cancellationToken = default)
        {
            var matches = route.UserSid == userSid
                && route.AgentType == agentType
                && route.ProviderId == providerId;
            return Task.FromResult<RouteRecord?>(matches ? route : null);
        }

        public Task<IReadOnlyList<RouteRecord>> ListAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IReadOnlyList<RouteRecord>>([route]);
        }

        public Task UpsertAsync(RouteRecord value, CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public Task DeleteByIdentityAsync(
            string userSid,
            AgentType agentType,
            string providerId,
            CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }
    }
}
