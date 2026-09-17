using Sf.EndpointAI.Client.Core.Policy;
using Sf.EndpointAI.Client.Core.State;
using Sf.EndpointAI.Contracts;

namespace Sf.EndpointAI.Client.Core.Routing;

public sealed class RouteTargetResolver(
    IRouteRegistry routeRegistry,
    IPolicyProvider policyProvider,
    ClientOperationStateProvider? operationStateProvider = null)
{
    public async Task<ResolvedRouteTarget?> ResolveAsync(
        string routeId,
        string escapedSuffixPath,
        string queryString,
        CancellationToken cancellationToken = default)
    {
        if (!IsValidRouteId(routeId))
        {
            return null;
        }

        var route = await routeRegistry.FindAsync(routeId, cancellationToken);
        if (route is null)
        {
            return null;
        }

        var policy = policyProvider.Current;
        if (!policy.Enabled)
        {
            throw new InvalidOperationException("Endpoint AI proxy policy is disabled.");
        }

        if (operationStateProvider is not null
            && operationStateProvider.Current.State != ClientOperationState.Enabled)
        {
            throw new InvalidOperationException("Endpoint AI proxy is not enabled for forwarding.");
        }

        var reconstructedPath = CombineEscapedPaths(route.OriginalBaseUri, escapedSuffixPath);
        var targetOrigin = policy.RouteMode switch
        {
            RouteMode.PassthroughOriginal => GetOrigin(route.OriginalBaseUri),
            RouteMode.FixedGateway => PolicyValidator.ValidateGatewayOrigin(policy.GatewayOrigin, policy.AllowInsecureGateway),
            _ => throw new InvalidOperationException($"Unsupported route mode: {policy.RouteMode}."),
        };

        var builder = new UriBuilder(targetOrigin)
        {
            Path = reconstructedPath,
            Query = queryString.TrimStart('?'),
        };
        return new ResolvedRouteTarget(
            route,
            builder.Uri,
            policy.RouteMode == RouteMode.FixedGateway,
            policy.AllowInsecureGateway);
    }

    public static bool IsValidRouteId(string value)
    {
        if (value.Length != 22)
        {
            return false;
        }

        return value.All(character =>
            char.IsAsciiLetterOrDigit(character) || character is '-' or '_');
    }

    internal static string CombineEscapedPaths(Uri originalBaseUri, string escapedSuffixPath)
    {
        var basePath = originalBaseUri.GetComponents(UriComponents.Path, UriFormat.UriEscaped).Trim('/');
        var suffix = escapedSuffixPath.Trim('/');
        if (basePath.Length == 0 && suffix.Length == 0)
        {
            return "/";
        }

        if (basePath.Length == 0)
        {
            return $"/{suffix}";
        }

        if (suffix.Length == 0)
        {
            return $"/{basePath}";
        }

        return $"/{basePath}/{suffix}";
    }

    private static Uri GetOrigin(Uri uri)
    {
        return new UriBuilder(uri.Scheme, uri.Host, uri.IsDefaultPort ? -1 : uri.Port).Uri;
    }

}
