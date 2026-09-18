using Sf.EndpointAI.Contracts;
using Sf.EndpointAI.ControlServer;

namespace Sf.EndpointAI.UnitTests;

public sealed class AnalyticsServiceTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-09-17T04:00:00Z", System.Globalization.CultureInfo.InvariantCulture);
    private static readonly EndpointPolicy Policy = new(1, Guid.NewGuid(), 4, true,
        RouteMode.FixedGateway, "https://gateway.example.test", false, 60, 60, Now, []);

    [Fact]
    public void Running_coverage_deduplicates_devices_and_instances_and_separates_tools()
    {
        var claude = Agent(AgentType.ClaudeCli);
        var first = Device(agents: [claude, claude, Agent(AgentType.ClaudeIde), Agent(AgentType.CodexCli),
            Agent(AgentType.CcSwitch), Agent(AgentType.UnknownCandidate), Agent(AgentType.QoderCli) with { Running = false }]);
        var second = Device(agents: [Agent(AgentType.CodexDesktop)]);
        var offline = Device(agents: [Agent(AgentType.QoderIde)], seen: Now.AddHours(-1));
        var snapshot = AnalyticsService.Build([first, first, second, offline], Policy, Now, new());

        Assert.Equal(2, snapshot.TotalDevices);
        Assert.Equal(2, snapshot.RunningAgentDevices);
        Assert.Equal(2, snapshot.Agents.Count);
        var codex = Assert.Single(snapshot.Agents, b => b.Key == "Codex");
        var claudeBucket = Assert.Single(snapshot.Agents, b => b.Key == "Claude");
        Assert.Equal(2, codex.DeviceCount);
        Assert.Equal(100, codex.Percentage);
        Assert.Equal(1, claudeBucket.DeviceCount);
        Assert.Equal(2, claudeBucket.InstanceCount);
        Assert.Equal(150, snapshot.Agents.Sum(b => b.Percentage));
        Assert.Equal(100, snapshot.Agents.Sum(b => b.InstancePercentage));
        Assert.Equal("CC Switch", Assert.Single(snapshot.Tools).Key);
        Assert.Equal(3, AnalyticsService.Build([first, second, offline], Policy, Now, new("all")).TotalDevices);
        var drill = Assert.Single(AnalyticsService.DrillDown([first], Now, new()).Devices);
        Assert.Contains("Qoder", drill.DiscoveredAgents);
        Assert.DoesNotContain("Qoder", drill.RunningAgents);
    }

    [Theory]
    [InlineData(150, DeviceOnlineState.Online)]
    [InlineData(151, DeviceOnlineState.Stale)]
    [InlineData(330, DeviceOnlineState.Stale)]
    [InlineData(331, DeviceOnlineState.Offline)]
    public void Online_state_uses_existing_heartbeat_freshness(int seconds, DeviceOnlineState expected)
        => Assert.Equal(expected, AnalyticsService.OnlineState(Device(seen: Now.AddSeconds(-seconds)).Device, Now));

    [Fact]
    public void Provider_observation_requires_requests_and_uses_original_target()
    {
        var openai = Endpoint("https://api.openai.com/v1");
        var configuredOnly = Endpoint("https://api.moonshot.cn/v1");
        var bypass = Endpoint("https://api.deepseek.com/v1") with { AllowlistBypassed = true, RouteStatus = RouteStatus.Bypassed };
        var old = Endpoint("https://api.anthropic.com") with { IsCurrent = false };
        var row = Device(endpoints: [openai, openai, configuredOnly, bypass, old],
            activity: [Activity(openai), Activity(openai), Activity(bypass) with { State = ProxyTrafficState.AllowlistBypassed }, Activity(old)]);
        var observed = AnalyticsService.Build([row], Policy, Now, new());
        Assert.Equal(["Anthropic", "OpenAI"], observed.Providers.Select(b => b.Key).Order().ToArray());
        Assert.Equal(1, observed.Providers[0].DeviceCount);
        var configured = AnalyticsService.Build([row], Policy, Now, new(ProviderMode: "configured"));
        Assert.Equal(["DeepSeek", "Kimi", "OpenAI"], configured.Providers.Select(b => b.Key).Order().ToArray());
        Assert.DoesNotContain(configured.Providers, b => b.Key.Contains("gateway.example.test"));
    }

    [Theory]
    [InlineData("https://api.openai.com/v1", "OpenAI")]
    [InlineData("https://my.openai.azure.com/v1", "Azure OpenAI")]
    [InlineData("https://ark.cn-beijing.volces.com/api/v3", "火山云")]
    [InlineData("https://api.moonshot.ai/v1", "Kimi")]
    [InlineData("https://api.openai.com.evil.test/v1", "未知/中转 · api.openai.com.evil.test")]
    [InlineData("https://notapi.openai.com/v1", "未知/中转 · notapi.openai.com")]
    [InlineData("https://api.openai.com@relay.example.test/v1", "未知/中转 · relay.example.test")]
    [InlineData("https://relay.example.test/openai", "未知/中转 · relay.example.test")]
    [InlineData(null, "无法识别")]
    [InlineData("file:///api.openai.com", "无法识别")]
    public void Provider_mapping_does_not_infer_vendor_from_spoofed_or_relay_urls(string? url, string expected)
        => Assert.Equal(expected, AnalyticsService.Provider(url));

    [Fact]
    public void Latest_failure_recovery_never_observed_and_mount_failure_are_distinct()
    {
        var endpoint = Endpoint("https://api.openai.com/v1");
        var failed = Device(endpoints: [endpoint], activity: [Activity(endpoint) with
        { State = ProxyTrafficState.ConnectionFailed, LastFailureAtUtc = Now, FailureCountSinceBoot = 1, LastHttpStatusCode = null, LastErrorCode = "CONNECT_FAILED" }]);
        var recovered = Device(endpoints: [endpoint], activity: [Activity(endpoint) with { FailureCountSinceBoot = 1, LastFailureAtUtc = Now.AddMinutes(-1) }]);
        var never = Device(endpoints: [endpoint], activity: [Activity(endpoint) with
        { State = ProxyTrafficState.NeverObserved, LastRequestAtUtc = null, LastSuccessAtUtc = null, RequestCountSinceBoot = 0, SuccessCountSinceBoot = 0 }]);
        var mount = Device(endpoints: [endpoint with { RouteStatus = RouteStatus.Error }]);
        StoredDeviceDetails[] devices = [failed, recovered, never, mount];
        var snapshot = AnalyticsService.Build(devices, Policy, Now, new());
        Assert.Equal(1, snapshot.AnomalyDevices);
        Assert.Equal(2, snapshot.EverAnomalyDevices);
        Assert.Equal(1, snapshot.OtherUnproxiedDevices);
        Assert.Equal("ConnectionFailed", Assert.Single(snapshot.Errors).Key);
        Assert.Equal(failed.Device.DeviceId, Assert.Single(AnalyticsService.DrillDown(devices, Now, new(), kind: "anomaly").Devices).Device.DeviceId);
        var recoveredView = Assert.Single(AnalyticsService.DrillDown(devices, Now, new(), anomaly: "none").Devices);
        Assert.Equal(recovered.Device.DeviceId, recoveredView.Device.DeviceId);
        Assert.True(recoveredView.EverAnomaly);
        var request = Assert.Single(AnalyticsService.DrillDown(devices, Now, new(), kind: "anomaly").Devices[0].Requests);
        Assert.Equal("CONNECT_FAILED", request.LastErrorCode);
        Assert.Equal(Now, request.LastFailureAtUtc);
    }

    [Fact]
    public void Allowlist_counts_exact_active_bypass_urls_and_deduplicates_terminals()
    {
        const string url = "https://relay.example.test/v1";
        var bypass = Endpoint(url) with { AllowlistBypassed = true, RouteStatus = RouteStatus.Bypassed };
        var secondUrl = Endpoint(url + "/other") with { AllowlistBypassed = true, RouteStatus = RouteStatus.Bypassed };
        var a = Device(endpoints: [bypass, bypass with { AssetId = Guid.NewGuid(), OriginalTargetBaseUrl = url + "/" }, secondUrl]);
        var b = Device(endpoints: [bypass]);
        var c = Device(endpoints: [bypass with { IsCurrent = false }, bypass with { AssetId = Guid.NewGuid(), AllowlistBypassed = false }]);
        var snapshot = AnalyticsService.Build([a, b, c], Policy with { AllowlistedBaseUrls = [url, "https://new.example.test"] }, Now, new());
        Assert.Equal(2, snapshot.AllowlistDevices);
        Assert.Equal(2, Assert.Single(snapshot.Allowlist, x => x.Key == url).DeviceCount);
        Assert.Equal(1, Assert.Single(snapshot.Allowlist, x => x.Key == url + "/other").DeviceCount);
        Assert.Equal(0, Assert.Single(snapshot.Allowlist, x => x.Key == "https://new.example.test").DeviceCount);
        Assert.Equal(2, AnalyticsService.DrillDown([a, b, c], Now, new(), kind: "allowlist", key: url).Total);
    }

    [Fact]
    public void Legacy_and_missing_fields_are_visible_as_insufficient_not_successful_requests()
    {
        var legacy = Device() with { Device = Device().Device with { SchemaVersion = 1 } };
        var missing = Device(endpoints: [Endpoint(null)]);
        var snapshot = AnalyticsService.Build([legacy, missing], Policy, Now, new());
        Assert.Equal(1, snapshot.LegacyDevices);
        Assert.Equal(2, snapshot.UnknownDevices);
        Assert.Empty(snapshot.Providers);
        Assert.Equal(0, snapshot.AnomalyDevices);
        Assert.All(AnalyticsService.DrillDown([legacy, missing], Now, new()).Devices, d => Assert.True(d.DataInsufficient));
        var empty = AnalyticsService.Build([], Policy, Now, new());
        Assert.Equal(0, empty.TotalDevices);
        Assert.Null(empty.DataObservedAtUtc);
        Assert.Empty(empty.Agents);
    }

    [Fact]
    public void Retained_last_result_is_observed_but_not_a_failure_in_the_current_boot()
    {
        var endpoint = Endpoint("https://api.openai.com/v1");
        var row = Device(endpoints: [endpoint], activity: [Activity(endpoint) with
        {
            State = ProxyTrafficState.ConnectionFailed,
            LastRequestAtUtc = Now.AddHours(-2),
            RequestCountSinceBoot = 0,
            SuccessCountSinceBoot = 0,
            FailureCountSinceBoot = 0,
        }]);
        var snapshot = AnalyticsService.Build([row], Policy, Now, new());
        Assert.Equal("OpenAI", Assert.Single(snapshot.Providers).Key);
        Assert.Equal(1, snapshot.AnomalyDevices);
        Assert.Equal(0, snapshot.EverAnomalyDevices);
        Assert.Equal(1, AnalyticsService.DrillDown([row], Now, new(), kind: "anomaly").Total);
    }

    [Fact]
    public void Inactive_configuration_request_failure_remains_visible_and_unknown_hosts_are_explicit()
    {
        var endpoint = Endpoint("https://relay.example.test/v1") with { IsCurrent = false };
        var row = Device(endpoints: [endpoint], activity: [Activity(endpoint) with { State = ProxyTrafficState.RouteFailed }]);
        var snapshot = AnalyticsService.Build([row], Policy, Now, new());
        Assert.Equal(1, snapshot.AnomalyDevices);
        Assert.Equal(1, snapshot.UnknownDevices);
        Assert.Equal("未知/中转 · relay.example.test", Assert.Single(snapshot.Providers).Key);
        Assert.Empty(AnalyticsService.Build([row], Policy, Now, new(ProviderMode: "configured")).Providers);
        Assert.Equal(1, AnalyticsService.DrillDown([row], Now, new(), kind: "error", key: "RouteFailed").Total);
    }

    [Fact]
    public void Bucket_drilldowns_share_filters_and_pagination_preserves_total()
    {
        var endpoint = Endpoint("https://api.openai.com/v1");
        var rows = Enumerable.Range(0, 5).Select(i => Device(agents: [Agent(AgentType.CodexCli)], endpoints: [endpoint],
            activity: [Activity(endpoint)], seen: Now.AddSeconds(-i))).ToArray();
        rows[4] = rows[4] with { Device = rows[4].Device with { OsVersion = "Windows", AppliedPolicyVersion = 3 } };
        var query = new AnalyticsQuery(Os: "macOS");
        var snapshot = AnalyticsService.Build(rows, Policy, Now, query);
        var first = AnalyticsService.DrillDown(rows, Now, query, kind: "provider", key: "OpenAI", take: 2);
        var second = AnalyticsService.DrillDown(rows, Now, query, kind: "provider", key: "OpenAI", skip: 2, take: 2);
        Assert.Equal(Assert.Single(snapshot.Providers).DeviceCount, first.Total);
        Assert.Equal(4, first.Total);
        Assert.Equal(4, first.Devices.Concat(second.Devices).Select(x => x.Device.DeviceId).Distinct().Count());
        Assert.Equal(0, snapshot.Policy.PendingDevices);
        Assert.Equal(1, AnalyticsService.Build(rows, Policy, Now, new()).Policy.PendingDevices);
        Assert.Empty(AnalyticsService.DrillDown(rows, Now, query, skip: 99).Devices);
        Assert.Equal(0, AnalyticsService.DrillDown(rows, Now, query, provider: "Kimi").Total);
    }

    private static StoredDeviceDetails Device(IReadOnlyList<AgentInventoryItem>? agents = null,
        IReadOnlyList<AgentEndpointAsset>? endpoints = null, IReadOnlyList<ProxyActivityAsset>? activity = null, DateTimeOffset? seen = null)
        => new(new StoredDeviceSummary(Guid.NewGuid(), seen ?? Now, "host", "macOS", agents?.Count ?? 0, 4,
            ProxyState.Listening, "0.1.22", endpoints?.Count ?? 0, ClientOperationState.Enabled, 60, 2), agents ?? [], endpoints ?? [], activity ?? [], null);

    private static AgentInventoryItem Agent(AgentType type) => new(Guid.NewGuid(), "user", type, type.ToString(), "1.0", InstallMethod.Native,
        100, true, true, null, null, null, RouteStatus.Attached, null, Now);

    private static AgentEndpointAsset Endpoint(string? url) => new(Guid.NewGuid(), "user", "codex", AgentConfigurationSource.Direct,
        "openai", null, true, "gpt-test", AgentWireApi.OpenAiResponses, url, "https://gateway.example.test", "http://127.0.0.1:18080/r/test", false, RouteStatus.Attached, Now);

    private static ProxyActivityAsset Activity(AgentEndpointAsset endpoint) => new(endpoint.AssetId, ProxyTrafficState.Succeeded,
        Now, Now, null, 200, "SUCCESS", null, 10, 1, 1, 0);
}
