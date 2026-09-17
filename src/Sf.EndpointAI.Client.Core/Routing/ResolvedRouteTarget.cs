namespace Sf.EndpointAI.Client.Core.Routing;

public sealed record ResolvedRouteTarget(
    RouteRecord Route,
    Uri TargetUri,
    bool IsSfGateway,
    bool AllowInsecureGateway);
