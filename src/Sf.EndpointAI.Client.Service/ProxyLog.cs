namespace Sf.EndpointAI.Client.Service;

internal static partial class ProxyLog
{
    [LoggerMessage(1002, LogLevel.Warning, "The upstream request failed.")]
    public static partial void UpstreamRequestFailed(ILogger logger, Exception exception);

    [LoggerMessage(1003, LogLevel.Error, "Unhandled local proxy failure.")]
    public static partial void UnhandledProxyFailure(ILogger logger, Exception exception);

    [LoggerMessage(1004, LogLevel.Error, "Request capture could not be created.")]
    public static partial void CaptureCreateFailed(ILogger logger, Exception exception);

    [LoggerMessage(1005, LogLevel.Warning, "SF_PROXY_DEVICE_ID is missing; using an ephemeral device identifier for this process.")]
    public static partial void EphemeralDeviceId(ILogger logger);

    [LoggerMessage(1006, LogLevel.Warning, "Windows account lookup failed for {UserSid}; the SID is used as UserID.")]
    public static partial void UserSidFallback(ILogger logger, string userSid);

    [LoggerMessage(1007, LogLevel.Warning, "The JSONL request summary could not be written.")]
    public static partial void CaptureSummaryFailed(ILogger logger, Exception exception);

    [LoggerMessage(1008, LogLevel.Warning, "Retired route {RouteId} for allowlisted BaseURL {BaseUrl} was blocked locally.")]
    public static partial void AllowlistedRouteBlocked(ILogger logger, string routeId, string baseUrl);

    [LoggerMessage(
        1009,
        LogLevel.Information,
        "Proxy request {RequestId} completed. Route={RouteId}, Provider={ProviderId}, Outcome={Outcome}, StatusCode={StatusCode}, GatewayRoundTripMilliseconds={GatewayRoundTripMilliseconds}, ErrorCode={ErrorCode}.")]
    public static partial void RequestCompleted(
        ILogger logger,
        Guid requestId,
        string routeId,
        string providerId,
        string outcome,
        int? statusCode,
        long? gatewayRoundTripMilliseconds,
        string? errorCode);

}

internal static partial class LifecycleLog
{
    [LoggerMessage(
        EventId = 9001,
        Level = LogLevel.Information,
        Message = "EndpointAI proxy service starting. Version={Version}, RouteMode={RouteMode}, GatewayOrigin={GatewayOrigin}, AutoAttach={AutoAttach}.")]
    public static partial void ServiceStarting(
        ILogger logger,
        string version,
        string routeMode,
        string gatewayOrigin,
        bool autoAttach);
}
