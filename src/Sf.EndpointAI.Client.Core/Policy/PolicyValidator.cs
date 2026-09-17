using Sf.EndpointAI.Contracts;

namespace Sf.EndpointAI.Client.Core.Policy;

public static class PolicyValidator
{
    public static void Validate(EndpointPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        if (policy.SchemaVersion != 1)
        {
            throw new PolicyValidationException("POLICY_SCHEMA_UNSUPPORTED", "Only policy schema version 1 is supported.");
        }

        if (policy.ServerInstanceId == Guid.Empty || policy.PolicyVersion < 1)
        {
            throw new PolicyValidationException("POLICY_IDENTITY_INVALID", "The policy server identity and version are required.");
        }

        if (policy.PollIntervalSeconds is < 15 or > 3600
            || policy.HeartbeatIntervalSeconds is < 15 or > 3600)
        {
            throw new PolicyValidationException("POLICY_INTERVAL_INVALID", "Policy intervals must be between 15 and 3600 seconds.");
        }

        if (policy.AllowlistedBaseUrls is not null)
        {
            try
            {
                BaseUrlAllowlist.Normalize(policy.AllowlistedBaseUrls);
            }
            catch (FormatException exception)
            {
                throw new PolicyValidationException("POLICY_ALLOWLIST_INVALID", exception.Message);
            }
        }

        if (policy.RouteMode == RouteMode.FixedGateway)
        {
            ValidateGatewayOrigin(policy.GatewayOrigin, policy.AllowInsecureGateway);
        }
    }

    public static Uri ValidateGatewayOrigin(string? value, bool allowInsecureGateway)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri)
            || (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
                && !(allowInsecureGateway
                    && string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)))
            || !string.IsNullOrEmpty(uri.UserInfo)
            || uri.AbsolutePath != "/"
            || !string.IsNullOrEmpty(uri.Query)
            || !string.IsNullOrEmpty(uri.Fragment))
        {
            throw new PolicyValidationException(
                "POLICY_GATEWAY_INVALID",
                "Fixed gateway mode requires a valid origin; HTTP must be explicitly allowed by policy.");
        }

        return uri;
    }
}

public sealed class PolicyValidationException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}
