namespace Sf.EndpointAI.Client.Core.Capture;

public sealed record ProxyTiming(
    DateTimeOffset AgentRequestReceivedAtUtc,
    DateTimeOffset? GatewayRequestStartedAtUtc,
    DateTimeOffset? GatewayResponseHeadersReceivedAtUtc,
    DateTimeOffset? AgentResponseStartedAtUtc,
    long? GatewayRoundTripMilliseconds);

public sealed class ProxyTimingTracker
{
    private readonly TimeProvider _timeProvider;
    private long? _gatewayRequestStartedTimestamp;

    public ProxyTimingTracker(TimeProvider? timeProvider = null)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
        AgentRequestReceivedAtUtc = _timeProvider.GetUtcNow();
    }

    public DateTimeOffset AgentRequestReceivedAtUtc { get; }

    public DateTimeOffset? GatewayRequestStartedAtUtc { get; private set; }

    public DateTimeOffset? GatewayResponseHeadersReceivedAtUtc { get; private set; }

    public DateTimeOffset? AgentResponseStartedAtUtc { get; private set; }

    public long? GatewayRoundTripMilliseconds { get; private set; }

    public void MarkGatewayRequestStarted()
    {
        if (GatewayRequestStartedAtUtc is not null)
        {
            return;
        }

        _gatewayRequestStartedTimestamp = _timeProvider.GetTimestamp();
        GatewayRequestStartedAtUtc = _timeProvider.GetUtcNow();
    }

    public void MarkGatewayResponseHeadersReceived()
    {
        if (GatewayResponseHeadersReceivedAtUtc is not null || _gatewayRequestStartedTimestamp is null)
        {
            return;
        }

        var responseTimestamp = _timeProvider.GetTimestamp();
        GatewayResponseHeadersReceivedAtUtc = _timeProvider.GetUtcNow();
        GatewayRoundTripMilliseconds = Math.Max(
            0,
            (long)_timeProvider.GetElapsedTime(_gatewayRequestStartedTimestamp.Value, responseTimestamp).TotalMilliseconds);
    }

    public void MarkAgentResponseStarted()
    {
        AgentResponseStartedAtUtc ??= _timeProvider.GetUtcNow();
    }

    public ProxyTiming Snapshot()
    {
        return new ProxyTiming(
            AgentRequestReceivedAtUtc,
            GatewayRequestStartedAtUtc,
            GatewayResponseHeadersReceivedAtUtc,
            AgentResponseStartedAtUtc,
            GatewayRoundTripMilliseconds);
    }
}
