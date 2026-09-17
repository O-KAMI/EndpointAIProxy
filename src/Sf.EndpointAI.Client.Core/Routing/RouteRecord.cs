using Sf.EndpointAI.Contracts;

namespace Sf.EndpointAI.Client.Core.Routing;

public sealed record RouteRecord(
    string RouteId,
    string UserSid,
    AgentType AgentType,
    string ProviderId,
    Uri OriginalBaseUri,
    Uri InjectedBaseUri,
    RouteStatus Status,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset UpdatedAtUtc);

public static class RouteIdGenerator
{
    public static string Create()
    {
        Span<byte> bytes = stackalloc byte[16];
        System.Security.Cryptography.RandomNumberGenerator.Fill(bytes);
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}
