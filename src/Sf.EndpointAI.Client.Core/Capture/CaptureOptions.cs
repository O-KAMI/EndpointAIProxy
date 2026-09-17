namespace Sf.EndpointAI.Client.Core.Capture;

public sealed record CaptureOptions(
    string RootDirectory,
    long MaximumCapturedBodyBytes = 50L * 1024L * 1024L,
    TimeSpan? Retention = null,
    long MaximumDirectoryBytes = 512L * 1024L * 1024L)
{
    public TimeSpan EffectiveRetention => Retention ?? TimeSpan.FromDays(7);
}

public sealed record CaptureMetadata(
    Guid RequestId,
    DateTimeOffset StartedAtUtc,
    string UserId,
    string UserSid,
    string Agent,
    string AgentSurface,
    string ProviderId,
    string RouteId,
    string OriginalBaseUrl,
    string OriginalAuthority,
    string Method,
    string InboundPathAndQuery,
    Uri OutboundUri);

public sealed record CaptureSummary(
    Guid RequestId,
    DateTimeOffset StartedAtUtc,
    DateTimeOffset CompletedAtUtc,
    DateTimeOffset AgentRequestReceivedAtUtc,
    DateTimeOffset? GatewayRequestStartedAtUtc,
    DateTimeOffset? GatewayResponseHeadersReceivedAtUtc,
    DateTimeOffset? AgentResponseStartedAtUtc,
    long? GatewayRoundTripMilliseconds,
    string UserId,
    string UserSid,
    string Agent,
    string AgentSurface,
    string ProviderId,
    string RouteId,
    string OriginalBaseUrl,
    string InboundPathAndQuery,
    string OutboundPathAndQuery,
    int? StatusCode,
    long DurationMilliseconds,
    string Outcome,
    string? ErrorCode,
    string? ErrorSummary,
    long RequestBytes,
    long ResponseBytes,
    bool CaptureTruncated,
    bool CaptureDegraded,
    string? MarkdownPath);
