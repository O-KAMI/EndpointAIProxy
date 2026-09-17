using Sf.EndpointAI.Contracts;

namespace Sf.EndpointAI.Client.Core.Routing;

public enum BaseUrlRoutingDecision
{
    Proxy,
    Bypass,
}

public sealed class BaseUrlBypassPolicy
{
    public const string BypassCode = "BASE_URL_ALLOWLIST_BYPASS";
    private readonly object _sync = new();
    private HashSet<string> _allowlistedBaseUrls = CreateSet(null);

    public BaseUrlRoutingDecision Decide(Uri baseUri)
    {
        ArgumentNullException.ThrowIfNull(baseUri);
        return TryNormalize(baseUri, out var normalized)
            && Volatile.Read(ref _allowlistedBaseUrls).Contains(normalized)
            ? BaseUrlRoutingDecision.Bypass
            : BaseUrlRoutingDecision.Proxy;
    }

    public bool ShouldBypass(Uri baseUri) => Decide(baseUri) == BaseUrlRoutingDecision.Bypass;

    public bool Replace(IReadOnlyList<string>? allowlistedBaseUrls)
    {
        var replacement = CreateSet(allowlistedBaseUrls);
        lock (_sync)
        {
            if (_allowlistedBaseUrls.SetEquals(replacement))
            {
                return false;
            }

            Volatile.Write(ref _allowlistedBaseUrls, replacement);
            return true;
        }
    }

    public IReadOnlyList<string> Snapshot() => Volatile.Read(ref _allowlistedBaseUrls)
        .OrderBy(value => value, StringComparer.Ordinal)
        .ToArray();

    private static HashSet<string> CreateSet(IReadOnlyList<string>? values)
    {
        var effective = values ?? [BaseUrlAllowlist.LegacyCcrBaseUrl];
        return new HashSet<string>(BaseUrlAllowlist.Normalize(effective), StringComparer.Ordinal);
    }

    private static bool TryNormalize(Uri value, out string normalized)
    {
        try
        {
            normalized = BaseUrlAllowlist.NormalizeEntry(value.OriginalString);
            return true;
        }
        catch (FormatException)
        {
            normalized = string.Empty;
            return false;
        }
    }
}
