using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using Sf.EndpointAI.Client.Core.Routing;
using Sf.EndpointAI.Contracts;

namespace Sf.EndpointAI.Client.Service;

public static class AgentAssetIdentity
{
    public static Guid Create(RouteRecord route)
    {
        return Create(route.UserSid, GetFamily(route), route.ProviderId);
    }

    public static Guid Create(string userSid, string family, string providerId)
    {
        var input = Encoding.UTF8.GetBytes($"{userSid}|{family}|{providerId}");
        return new Guid(SHA256.HashData(input).AsSpan(0, 16));
    }

    public static string GetFamily(RouteRecord route)
    {
        if (route.AgentType == AgentType.CcSwitch)
        {
            return route.ProviderId.StartsWith("claude:", StringComparison.Ordinal) ? "claude" : "codex";
        }

        return route.AgentType is AgentType.ClaudeCode or AgentType.ClaudeCli or AgentType.ClaudeIde or AgentType.ClaudeDesktop
            ? "claude"
            : "codex";
    }
}

public sealed class ProxyActivityTracker
{
    private readonly ConcurrentDictionary<Guid, ActivityCounter> _activity = new();

    public void Record(
        RouteRecord route,
        string outcome,
        int? httpStatusCode,
        string? errorCode,
        double? gatewayRoundTripMilliseconds)
    {
        var counter = _activity.GetOrAdd(AgentAssetIdentity.Create(route), _ => new ActivityCounter());
        counter.Record(outcome, httpStatusCode, errorCode, gatewayRoundTripMilliseconds);
    }

    public IReadOnlyList<ProxyActivityAsset> Snapshot(IReadOnlyList<RouteRecord> routes)
        => SnapshotAssetIds(routes.Select(AgentAssetIdentity.Create));

    public IReadOnlyList<ProxyActivityAsset> Snapshot(IReadOnlyList<AgentEndpointAsset> endpoints)
        => SnapshotAssetIds(endpoints.Select(endpoint => endpoint.AssetId));

    private ProxyActivityAsset[] SnapshotAssetIds(IEnumerable<Guid> assetIds)
    {
        return assetIds.Distinct().Select(assetId =>
        {
            return _activity.TryGetValue(assetId, out var counter)
                ? counter.Snapshot(assetId)
                : new ProxyActivityAsset(
                    assetId,
                    ProxyTrafficState.NeverObserved,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    0,
                    0,
                    0);
        }).ToArray();
    }

    private sealed class ActivityCounter
    {
        private long _lastRequestTicks;
        private long _lastSuccessTicks;
        private long _lastFailureTicks;
        private long _requestCount;
        private long _successCount;
        private long _failureCount;
        private int _state;
        private int _lastHttpStatusCode = -1;
        private long _lastRoundTripBits = BitConverter.DoubleToInt64Bits(double.NaN);
        private string? _lastOutcome;
        private string? _lastErrorCode;

        public void Record(string outcome, int? httpStatusCode, string? errorCode, double? roundTripMilliseconds)
        {
            var nowTicks = DateTimeOffset.UtcNow.UtcDateTime.Ticks;
            var state = Classify(outcome);
            Interlocked.Exchange(ref _lastRequestTicks, nowTicks);
            Interlocked.Increment(ref _requestCount);
            Interlocked.Exchange(ref _state, (int)state);
            Interlocked.Exchange(ref _lastHttpStatusCode, httpStatusCode ?? -1);
            Interlocked.Exchange(
                ref _lastRoundTripBits,
                BitConverter.DoubleToInt64Bits(roundTripMilliseconds ?? double.NaN));
            Volatile.Write(ref _lastOutcome, outcome);
            Volatile.Write(ref _lastErrorCode, errorCode);
            if (state == ProxyTrafficState.Succeeded)
            {
                Interlocked.Exchange(ref _lastSuccessTicks, nowTicks);
                Interlocked.Increment(ref _successCount);
            }
            else
            {
                Interlocked.Exchange(ref _lastFailureTicks, nowTicks);
                Interlocked.Increment(ref _failureCount);
            }
        }

        public ProxyActivityAsset Snapshot(Guid assetId)
        {
            var roundTrip = BitConverter.Int64BitsToDouble(Interlocked.Read(ref _lastRoundTripBits));
            var status = Volatile.Read(ref _lastHttpStatusCode);
            return new ProxyActivityAsset(
                assetId,
                (ProxyTrafficState)Volatile.Read(ref _state),
                ReadTimestamp(Interlocked.Read(ref _lastRequestTicks)),
                ReadTimestamp(Interlocked.Read(ref _lastSuccessTicks)),
                ReadTimestamp(Interlocked.Read(ref _lastFailureTicks)),
                status < 0 ? null : status,
                Volatile.Read(ref _lastOutcome),
                Volatile.Read(ref _lastErrorCode),
                double.IsNaN(roundTrip) ? null : roundTrip,
                Interlocked.Read(ref _requestCount),
                Interlocked.Read(ref _successCount),
                Interlocked.Read(ref _failureCount));
        }

        private static ProxyTrafficState Classify(string outcome) => outcome switch
        {
            "SUCCESS" => ProxyTrafficState.Succeeded,
            "GATEWAY_HTTP_ERROR" or "UPSTREAM_REDIRECT_BLOCKED" => ProxyTrafficState.GatewayReachedWithError,
            "GATEWAY_CONNECTION_FAILED" => ProxyTrafficState.ConnectionFailed,
            _ => ProxyTrafficState.RouteFailed,
        };

        private static DateTimeOffset? ReadTimestamp(long ticks) =>
            ticks == 0 ? null : new DateTimeOffset(ticks, TimeSpan.Zero);
    }
}
