namespace Sf.EndpointAI.Contracts;

public sealed record EndpointPolicy(
    int SchemaVersion,
    Guid ServerInstanceId,
    long PolicyVersion,
    bool Enabled,
    RouteMode RouteMode,
    string? GatewayOrigin,
    bool AllowInsecureGateway,
    int PollIntervalSeconds,
    int HeartbeatIntervalSeconds,
    DateTimeOffset IssuedAtUtc,
    IReadOnlyList<string>? AllowlistedBaseUrls = null);

public sealed record PolicyClientState(
    long? LastReceivedVersion,
    long? AppliedVersion,
    PolicyApplyStatus ApplyStatus,
    string? LastErrorCode,
    string? LastErrorSummary);

public sealed record ProxyClientState(
    ProxyState State,
    string ListenEndpoint,
    int ActiveRouteCount,
    AuditState AuditState);
