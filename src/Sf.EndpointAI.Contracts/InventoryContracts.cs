namespace Sf.EndpointAI.Contracts;

public sealed record DeviceIdentity(
    Guid DeviceId,
    string Hostname,
    string OsVersion,
    string ServiceVersion,
    Guid BootId);

public sealed record EndpointUser(string Sid, string AccountName);

public sealed record AgentInventoryItem(
    Guid InstanceId,
    string UserSid,
    AgentType AgentType,
    string DisplayName,
    string? Version,
    InstallMethod InstallMethod,
    int DiscoveryConfidence,
    bool Installed,
    bool Running,
    string? RouterType,
    string? CcSwitchVersion,
    string? CcSwitchMode,
    RouteStatus RouteStatus,
    string? ObservedTargetOrigin,
    DateTimeOffset LastSeenAtUtc);

public sealed record HeartbeatRequest(
    int SchemaVersion,
    Guid HeartbeatId,
    DateTimeOffset ObservedAtUtc,
    DeviceIdentity Device,
    PolicyClientState Policy,
    ProxyClientState Proxy,
    IReadOnlyList<EndpointUser> Users,
    IReadOnlyList<AgentInventoryItem> Agents);

public sealed record HeartbeatResponse(
    DateTimeOffset ServerTimeUtc,
    long AcceptedPolicyVersion,
    int NextHeartbeatSeconds);

public sealed record DeviceRuntimeState(
    DateTimeOffset ServiceStartedAtUtc,
    long UptimeSeconds,
    ClientOperationState OperationState,
    bool ProxyListenerAvailable,
    DateTimeOffset? LastControlSyncAtUtc,
    DateTimeOffset? LastReconcileAtUtc,
    string? LastReconcileResult,
    string? LastReconcileErrorCode);

public sealed record AgentEndpointAsset(
    Guid AssetId,
    string UserSid,
    string AgentFamily,
    AgentConfigurationSource ConfigurationSource,
    string? ProviderId,
    string? EndpointId,
    bool IsCurrent,
    string? ConfiguredModel,
    AgentWireApi WireApi,
    string? OriginalTargetBaseUrl,
    string? EffectiveConfiguredBaseUrl,
    string? LocalRouteUrl,
    bool AllowlistBypassed,
    RouteStatus RouteStatus,
    DateTimeOffset ObservedAtUtc);

public sealed record ProxyActivityAsset(
    Guid AssetId,
    ProxyTrafficState State,
    DateTimeOffset? LastRequestAtUtc,
    DateTimeOffset? LastSuccessAtUtc,
    DateTimeOffset? LastFailureAtUtc,
    int? LastHttpStatusCode,
    string? LastOutcome,
    string? LastErrorCode,
    double? LastGatewayRoundTripMilliseconds,
    long RequestCountSinceBoot,
    long SuccessCountSinceBoot,
    long FailureCountSinceBoot);

public sealed record HeartbeatV2Request(
    int SchemaVersion,
    Guid HeartbeatId,
    DateTimeOffset ObservedAtUtc,
    DeviceIdentity Device,
    DeviceRuntimeState Runtime,
    PolicyClientState Policy,
    ProxyClientState Proxy,
    IReadOnlyList<EndpointUser> Users,
    IReadOnlyList<AgentInventoryItem> Agents,
    IReadOnlyList<AgentEndpointAsset> Endpoints,
    IReadOnlyList<ProxyActivityAsset> Activity);

public sealed record HeartbeatV2Response(
    DateTimeOffset ServerTimeUtc,
    long AcceptedPolicyVersion,
    int NextHeartbeatSeconds,
    SignedRemoteCommand? Command);
