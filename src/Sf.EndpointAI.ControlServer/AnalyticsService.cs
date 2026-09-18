using Sf.EndpointAI.Contracts;

namespace Sf.EndpointAI.ControlServer;

public sealed record AnalyticsQuery(string Scope = "online", string? Os = null, string ProviderMode = "observed");
public sealed record AnalyticsBucket(string Key, string Label, int DeviceCount, int InstanceCount, double Percentage, double InstancePercentage, IReadOnlyList<string> AgentFamilies);
public sealed record AnalyticsPolicy(long Version, int AppliedDevices, int PendingDevices);
public sealed record AnalyticsRequest(Guid AssetId, string AgentFamily, string Provider, string? TargetBaseUrl, ProxyTrafficState State,
    int? LastHttpStatusCode, string? LastErrorCode, string? LastOutcome, DateTimeOffset? LastFailureAtUtc,
    DateTimeOffset? LastRequestAtUtc, DateTimeOffset ObservedAtUtc, bool EverFailed, bool Observed);
public sealed record AnalyticsDevice(StoredDeviceSummary Device, DeviceOnlineState OnlineState, IReadOnlyList<string> RunningAgents,
    IReadOnlyList<string> DiscoveredAgents, IReadOnlyList<string> Providers, IReadOnlyList<string> Allowlist,
    bool HasAnomaly, bool EverAnomaly, bool OtherUnproxied, bool DataInsufficient, IReadOnlyList<AnalyticsRequest> Requests);
public sealed record AnalyticsSnapshot(DateTimeOffset UpdatedAtUtc, DateTimeOffset? DataObservedAtUtc, string Scope, string ProviderMode,
    int TotalDevices, int OnlineDevices, int RunningAgentDevices, int AnomalyDevices, int EverAnomalyDevices, int AllowlistDevices,
    int OtherUnproxiedDevices, int UnknownDevices, int LegacyDevices, IReadOnlyList<AnalyticsBucket> Agents, IReadOnlyList<AnalyticsBucket> Tools,
    IReadOnlyList<AnalyticsBucket> Providers, IReadOnlyList<AnalyticsBucket> Errors, IReadOnlyList<AnalyticsBucket> Allowlist,
    IReadOnlyList<string> OperatingSystems, AnalyticsPolicy Policy);
public sealed record AnalyticsDevicePage(int Total, int Skip, int Take, DateTimeOffset UpdatedAtUtc, IReadOnlyList<AnalyticsDevice> Devices);

public static class AnalyticsService
{
    public static DeviceOnlineState OnlineState(StoredDeviceSummary device, DateTimeOffset now)
    {
        var elapsed = now - device.LastSeenAtUtc;
        var interval = TimeSpan.FromSeconds(Math.Clamp(device.HeartbeatIntervalSeconds, 15, 3600));
        return elapsed <= interval * 2 + TimeSpan.FromSeconds(30) ? DeviceOnlineState.Online
            : elapsed <= interval * 5 + TimeSpan.FromSeconds(30) ? DeviceOnlineState.Stale : DeviceOnlineState.Offline;
    }

    public static string? AgentFamily(AgentType type) => type switch
    {
        AgentType.ClaudeCode or AgentType.ClaudeCli or AgentType.ClaudeIde or AgentType.ClaudeDesktop => "Claude",
        AgentType.CodexCli or AgentType.CodexIde or AgentType.CodexDesktop => "Codex",
        AgentType.QoderCli or AgentType.QoderIde => "Qoder",
        AgentType.CcSwitch => "CC Switch",
        _ => null,
    };

    // Only domains controlled by the named vendor are recognized. Arbitrary
    // gateways are intentionally never inferred from a model name or provider id.
    public static string Provider(string? target)
    {
        if (!Uri.TryCreate(target, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https")) return "无法识别";
        var host = uri.IdnHost.ToLowerInvariant();
        var mappings = new (string Domain, string Name)[]
        {
            ("api.openai.com", "OpenAI"), ("api.anthropic.com", "Anthropic"),
            ("generativelanguage.googleapis.com", "Google Gemini"), ("aiplatform.googleapis.com", "Google Vertex AI"),
            ("openai.azure.com", "Azure OpenAI"), ("services.ai.azure.com", "Azure AI"),
            ("volces.com", "火山云"), ("moonshot.cn", "Kimi"), ("moonshot.ai", "Kimi"),
            ("deepseek.com", "DeepSeek"), ("dashscope.aliyuncs.com", "阿里云百炼"),
            ("dashscope-intl.aliyuncs.com", "阿里云百炼"), ("api.z.ai", "智谱"), ("open.bigmodel.cn", "智谱"),
            ("api.minimax.io", "MiniMax"), ("api.minimaxi.com", "MiniMax"), ("api.x.ai", "xAI"),
        };
        foreach (var (domain, name) in mappings)
            if (host == domain || host.EndsWith("." + domain, StringComparison.Ordinal)) return name;
        return "未知/中转 · " + host;
    }

    private static bool Failed(ProxyTrafficState state) => state is ProxyTrafficState.ConnectionFailed or ProxyTrafficState.RouteFailed or ProxyTrafficState.GatewayReachedWithError;
    private static bool Observed(ProxyActivityAsset activity) => activity.LastRequestAtUtc is not null || activity.RequestCountSinceBoot > 0;
    private static AgentEndpointAsset[] Current(StoredDeviceDetails details) => details.Endpoints.Where(e => e.IsCurrent).DistinctBy(e => e.AssetId).ToArray();
    private static string FamilyName(string value) => value.ToLowerInvariant() switch { "claude" => "Claude", "codex" => "Codex", "qoder" => "Qoder", _ => value };
    private static bool Bypassed(AgentEndpointAsset endpoint) => endpoint.AllowlistBypassed && endpoint.RouteStatus == RouteStatus.Bypassed && !string.IsNullOrWhiteSpace(endpoint.OriginalTargetBaseUrl);
    private static string AllowlistKey(string value)
    {
        try { return BaseUrlAllowlist.NormalizeEntry(value); }
        catch (FormatException) { return value; }
    }

    private static AnalyticsDevice Project(StoredDeviceDetails details, DateTimeOffset now, AnalyticsQuery query)
    {
        var current = Current(details);
        var activity = details.Activity.GroupBy(a => a.AssetId).ToDictionary(g => g.Key, g => g.OrderByDescending(a => a.LastRequestAtUtc).First());
        var endpoints = details.Endpoints.DistinctBy(e => e.AssetId).ToArray();
        var requests = endpoints.Select(e =>
        {
            activity.TryGetValue(e.AssetId, out var a);
            return new AnalyticsRequest(e.AssetId, FamilyName(e.AgentFamily), Provider(e.OriginalTargetBaseUrl), e.OriginalTargetBaseUrl,
                a?.State ?? ProxyTrafficState.NeverObserved, a?.LastHttpStatusCode, a?.LastErrorCode, a?.LastOutcome,
                a?.LastFailureAtUtc, a?.LastRequestAtUtc, e.ObservedAtUtc, a?.FailureCountSinceBoot > 0, a is not null && Observed(a));
        }).ToArray();
        var families = details.Agents.Where(a => a.Running).Select(a => AgentFamily(a.AgentType)).OfType<string>().Where(f => f != "CC Switch").Distinct().Order().ToArray();
        var configured = query.ProviderMode == "configured";
        var providers = (configured ? current : endpoints).Where(e => configured || activity.TryGetValue(e.AssetId, out var a) && Observed(a) && a.State != ProxyTrafficState.AllowlistBypassed)
            .Select(e => Provider(e.OriginalTargetBaseUrl)).Distinct().Order().ToArray();
        return new AnalyticsDevice(details.Device, OnlineState(details.Device, now), families,
            details.Agents.Where(a => !a.Running && a.Installed).Select(a => AgentFamily(a.AgentType)).OfType<string>()
                .Concat(current.Select(e => FamilyName(e.AgentFamily))).Where(f => !families.Contains(f)).Distinct().Order().ToArray(),
            providers, current.Where(Bypassed).Select(e => AllowlistKey(e.OriginalTargetBaseUrl!)).Distinct(StringComparer.Ordinal).Order().ToArray(),
            requests.Any(r => r.Observed && Failed(r.State)), requests.Any(r => r.EverFailed),
            details.Device.OperationState is ClientOperationState.Disabled or ClientOperationState.DisableFailed or ClientOperationState.EnableFailed
                || details.Device.ProxyState is ProxyState.Stopped or ProxyState.Degraded
                || current.Any(e => !Bypassed(e) && e.RouteStatus is not RouteStatus.Attached),
            details.Device.SchemaVersion < 2 || providers.Any(p => p == "无法识别" || p.StartsWith("未知/中转", StringComparison.Ordinal))
                || current.Any(e => !activity.ContainsKey(e.AssetId)), requests);
    }

    private static (StoredDeviceDetails Details, AnalyticsDevice View)[] Select(IReadOnlyList<StoredDeviceDetails> devices, DateTimeOffset now, AnalyticsQuery query)
        => devices.DistinctBy(d => d.Device.DeviceId).Select(d => (Details: d, View: Project(d, now, query)))
            .Where(d => query.Scope.ToLowerInvariant() switch
            {
                "all" => true, "stale" => d.View.OnlineState == DeviceOnlineState.Stale,
                "offline" => d.View.OnlineState == DeviceOnlineState.Offline, "legacyclient" => d.Details.Device.SchemaVersion < 2,
                _ => d.View.OnlineState == DeviceOnlineState.Online,
            })
            .Where(d => string.IsNullOrWhiteSpace(query.Os) || d.Details.Device.OsVersion.Contains(query.Os, StringComparison.OrdinalIgnoreCase)).ToArray();

    public static AnalyticsSnapshot Build(IReadOnlyList<StoredDeviceDetails> devices, EndpointPolicy policy, DateTimeOffset now, AnalyticsQuery query)
    {
        var rows = Select(devices, now, query);
        var total = rows.Length;
        double Percent(int count, int denominator) => denominator == 0 ? 0 : Math.Round(100d * count / denominator, 1);
        var instances = rows.SelectMany(r => r.Details.Agents.Where(a => a.Running && AgentFamily(a.AgentType) is not null)
            .DistinctBy(a => a.InstanceId).Select(a => (r.Details.Device.DeviceId, Family: AgentFamily(a.AgentType)!))).ToArray();
        var instanceTotal = instances.Count(i => i.Family != "CC Switch");
        AnalyticsBucket[] AgentBuckets(bool tools) => instances.Where(i => (i.Family == "CC Switch") == tools).GroupBy(i => i.Family)
            .Select(g => new AnalyticsBucket(g.Key, g.Key, g.Select(i => i.DeviceId).Distinct().Count(), g.Count(),
                Percent(g.Select(i => i.DeviceId).Distinct().Count(), total), Percent(g.Count(), tools ? instances.Count(i => i.Family == "CC Switch") : instanceTotal), [g.Key]))
            .OrderByDescending(b => b.DeviceCount).ThenBy(b => b.Key).ToArray();
        AnalyticsBucket[] Buckets(IEnumerable<(Guid DeviceId, string Key, string Family)> entries) => entries.GroupBy(e => e.Key, StringComparer.Ordinal)
            .Select(g => new AnalyticsBucket(g.Key, g.Key, g.Select(e => e.DeviceId).Distinct().Count(), 0,
                Percent(g.Select(e => e.DeviceId).Distinct().Count(), total), 0, g.Select(e => e.Family).Where(f => f.Length > 0).Distinct().Order().ToArray()))
            .OrderByDescending(b => b.DeviceCount).ThenBy(b => b.Key).ToArray();
        var providers = Buckets(rows.SelectMany(r => r.View.Providers.Select(p => (r.Details.Device.DeviceId, p, ""))));
        var errors = Buckets(rows.SelectMany(r => r.View.Requests.Where(a => a.Observed && Failed(a.State))
            .Select(a => (r.Details.Device.DeviceId, a.State.ToString(), a.AgentFamily))));
        var allowlist = Buckets(rows.SelectMany(r => Current(r.Details).Where(Bypassed)
            .Select(e => (r.Details.Device.DeviceId, AllowlistKey(e.OriginalTargetBaseUrl!), FamilyName(e.AgentFamily))))).ToList();
        foreach (var url in policy.AllowlistedBaseUrls ?? [])
            if (allowlist.All(b => b.Key != url)) allowlist.Add(new AnalyticsBucket(url, url, 0, 0, 0, 0, []));
        var applied = rows.Count(r => r.Details.Device.AppliedPolicyVersion == policy.PolicyVersion);
        return new AnalyticsSnapshot(now, rows.Length == 0 ? null : rows.Max(r => r.Details.Device.LastSeenAtUtc), query.Scope, query.ProviderMode,
            total, rows.Count(r => r.View.OnlineState == DeviceOnlineState.Online), rows.Count(r => r.View.RunningAgents.Count > 0),
            rows.Count(r => r.View.HasAnomaly), rows.Count(r => r.View.EverAnomaly), rows.Count(r => r.View.Allowlist.Count > 0),
            rows.Count(r => r.View.OtherUnproxied), rows.Count(r => r.View.DataInsufficient), rows.Count(r => r.Details.Device.SchemaVersion < 2),
            AgentBuckets(false), AgentBuckets(true), providers, errors, allowlist.OrderByDescending(b => b.DeviceCount).ThenBy(b => b.Key).ToArray(),
            devices.Select(d => d.Device.OsVersion).Distinct().Order().ToArray(), new AnalyticsPolicy(policy.PolicyVersion, applied, total - applied));
    }

    public static AnalyticsDevicePage DrillDown(IReadOnlyList<StoredDeviceDetails> devices, DateTimeOffset now, AnalyticsQuery query,
        string? kind = null, string? key = null, string? search = null, int skip = 0, int take = 50,
        string? agent = null, string? provider = null, string? anomaly = null, string? allowlist = null)
    {
        var selected = Select(devices, now, query).Where(r => kind switch
        {
            "online" => r.View.OnlineState == DeviceOnlineState.Online,
            "running" => r.View.RunningAgents.Count > 0,
            "agent" => r.View.RunningAgents.Contains(key),
            "tool" => r.Details.Agents.Any(a => a.Running && AgentFamily(a.AgentType) == key),
            "provider" => r.View.Providers.Contains(key),
            "error" => r.View.Requests.Any(a => a.Observed && Failed(a.State) && a.State.ToString() == key),
            "anomaly" => r.View.HasAnomaly, "everAnomaly" => r.View.EverAnomaly,
            "allowlist" => key is null ? r.View.Allowlist.Count > 0 : r.View.Allowlist.Contains(key, StringComparer.Ordinal),
            "otherUnproxied" => r.View.OtherUnproxied, "unknown" => r.View.DataInsufficient,
            _ => true,
        }).Select(r => r.View)
            .Where(r => string.IsNullOrWhiteSpace(search) || r.Device.Hostname.Contains(search, StringComparison.OrdinalIgnoreCase) || r.Device.DeviceId.ToString().Contains(search, StringComparison.OrdinalIgnoreCase))
            .Where(r => string.IsNullOrWhiteSpace(agent) || r.RunningAgents.Contains(agent))
            .Where(r => string.IsNullOrWhiteSpace(provider) || r.Providers.Contains(provider))
            .Where(r => anomaly switch { "latest" => r.HasAnomaly, "ever" => r.EverAnomaly, "none" => !r.HasAnomaly && r.Requests.Any(a => a.Observed), _ => true })
            .Where(r => string.IsNullOrWhiteSpace(allowlist) || (allowlist == "any" ? r.Allowlist.Count > 0 : r.Allowlist.Contains(allowlist, StringComparer.Ordinal)))
            .OrderByDescending(r => r.Device.LastSeenAtUtc).ThenBy(r => r.Device.DeviceId).ToArray();
        skip = Math.Max(0, skip); take = Math.Clamp(take, 1, 500);
        return new AnalyticsDevicePage(selected.Length, skip, take, now, selected.Skip(skip).Take(take).ToArray());
    }
}
