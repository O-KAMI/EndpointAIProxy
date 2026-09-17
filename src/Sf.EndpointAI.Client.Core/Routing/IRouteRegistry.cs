namespace Sf.EndpointAI.Client.Core.Routing;

public interface IRouteRegistry
{
    Task InitializeAsync(CancellationToken cancellationToken = default);

    Task<RouteRecord?> FindAsync(string routeId, CancellationToken cancellationToken = default);

    Task<RouteRecord?> FindByIdentityAsync(
        string userSid,
        Sf.EndpointAI.Contracts.AgentType agentType,
        string providerId,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<RouteRecord>> ListAsync(CancellationToken cancellationToken = default);

    Task UpsertAsync(RouteRecord route, CancellationToken cancellationToken = default);

    Task DeleteByIdentityAsync(
        string userSid,
        Sf.EndpointAI.Contracts.AgentType agentType,
        string providerId,
        CancellationToken cancellationToken = default);
}
