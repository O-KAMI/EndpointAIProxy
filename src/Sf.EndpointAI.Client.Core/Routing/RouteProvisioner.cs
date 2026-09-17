using Sf.EndpointAI.Contracts;

namespace Sf.EndpointAI.Client.Core.Routing;

public sealed class RouteProvisioner(IRouteRegistry registry, Uri localProxyOrigin)
{
    private readonly Uri _localProxyOrigin = ValidateLocalOrigin(localProxyOrigin);

    public async Task<RouteRecord> EnsureAsync(
        string userSid,
        AgentType agentType,
        string providerId,
        Uri originalBaseUri,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userSid);
        ArgumentException.ThrowIfNullOrWhiteSpace(providerId);
        ArgumentNullException.ThrowIfNull(originalBaseUri);
        if (!originalBaseUri.IsAbsoluteUri)
        {
            throw new ArgumentException("The original BaseURL must be absolute.", nameof(originalBaseUri));
        }

        var existing = await registry.FindByIdentityAsync(userSid, agentType, providerId, cancellationToken);
        var now = DateTimeOffset.UtcNow;
        var routeId = existing?.RouteId ?? RouteIdGenerator.Create();
        var injectedBaseUri = new Uri(_localProxyOrigin, $"/r/{routeId}");
        var route = new RouteRecord(
            routeId,
            userSid,
            agentType,
            providerId,
            originalBaseUri,
            injectedBaseUri,
            RouteStatus.Pending,
            existing?.CreatedAtUtc ?? now,
            now);
        await registry.UpsertAsync(route, cancellationToken);
        return route;
    }

    private static Uri ValidateLocalOrigin(Uri value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (!value.IsAbsoluteUri
            || !value.IsLoopback
            || !string.Equals(value.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
            || value.AbsolutePath != "/")
        {
            throw new ArgumentException("The local proxy origin must be an absolute loopback HTTP origin.", nameof(value));
        }

        return value;
    }
}
