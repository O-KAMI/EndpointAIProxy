using Sf.EndpointAI.Client.Core.Capture;

namespace Sf.EndpointAI.UnitTests;

public sealed class ProxyTimingTrackerTests
{
    [Fact]
    public void Records_phase_timestamps_and_monotonic_gateway_round_trip()
    {
        var clock = new ManualTimeProvider(new DateTimeOffset(2026, 8, 27, 1, 2, 3, TimeSpan.Zero));
        var tracker = new ProxyTimingTracker(clock);

        clock.Advance(TimeSpan.FromMilliseconds(5));
        tracker.MarkGatewayRequestStarted();
        clock.Advance(TimeSpan.FromMilliseconds(125));
        tracker.MarkGatewayResponseHeadersReceived();
        clock.Advance(TimeSpan.FromMilliseconds(3));
        tracker.MarkAgentResponseStarted();

        var timing = tracker.Snapshot();
        Assert.Equal(new DateTimeOffset(2026, 8, 27, 1, 2, 3, TimeSpan.Zero), timing.AgentRequestReceivedAtUtc);
        Assert.Equal(timing.AgentRequestReceivedAtUtc.AddMilliseconds(5), timing.GatewayRequestStartedAtUtc);
        Assert.Equal(timing.AgentRequestReceivedAtUtc.AddMilliseconds(130), timing.GatewayResponseHeadersReceivedAtUtc);
        Assert.Equal(timing.AgentRequestReceivedAtUtc.AddMilliseconds(133), timing.AgentResponseStartedAtUtc);
        Assert.Equal(125, timing.GatewayRoundTripMilliseconds);
    }

    [Fact]
    public void Leaves_unreached_gateway_and_agent_phases_null()
    {
        var tracker = new ProxyTimingTracker(new ManualTimeProvider(DateTimeOffset.UnixEpoch));

        tracker.MarkGatewayRequestStarted();

        var timing = tracker.Snapshot();
        Assert.NotNull(timing.GatewayRequestStartedAtUtc);
        Assert.Null(timing.GatewayResponseHeadersReceivedAtUtc);
        Assert.Null(timing.AgentResponseStartedAtUtc);
        Assert.Null(timing.GatewayRoundTripMilliseconds);
    }

    [Fact]
    public void Gateway_round_trip_is_not_affected_by_wall_clock_adjustment()
    {
        var clock = new ManualTimeProvider(new DateTimeOffset(2026, 8, 27, 1, 2, 3, TimeSpan.Zero));
        var tracker = new ProxyTimingTracker(clock);
        tracker.MarkGatewayRequestStarted();

        clock.AdvanceTimestamp(TimeSpan.FromMilliseconds(200));
        clock.AdjustUtc(TimeSpan.FromSeconds(-5));
        tracker.MarkGatewayResponseHeadersReceived();

        var timing = tracker.Snapshot();
        Assert.Equal(200, timing.GatewayRoundTripMilliseconds);
        Assert.True(timing.GatewayResponseHeadersReceivedAtUtc < timing.GatewayRequestStartedAtUtc);
    }

    private sealed class ManualTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        private DateTimeOffset _utcNow = utcNow;
        private long _timestamp;

        public override long TimestampFrequency => TimeSpan.TicksPerSecond;

        public override DateTimeOffset GetUtcNow() => _utcNow;

        public override long GetTimestamp() => _timestamp;

        public void Advance(TimeSpan value)
        {
            AdjustUtc(value);
            AdvanceTimestamp(value);
        }

        public void AdjustUtc(TimeSpan value) => _utcNow = _utcNow.Add(value);

        public void AdvanceTimestamp(TimeSpan value) => _timestamp += value.Ticks;
    }
}
