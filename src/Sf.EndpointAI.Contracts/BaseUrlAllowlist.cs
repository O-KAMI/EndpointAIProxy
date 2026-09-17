namespace Sf.EndpointAI.Contracts;

public static class BaseUrlAllowlist
{
    public const string LegacyCcrBaseUrl = "https://internal.example.invalid/ccr";
    public const int MaximumEntries = 256;
    public const int MaximumEntryLength = 2048;

    public static IReadOnlyList<string> Normalize(IEnumerable<string> values)
    {
        ArgumentNullException.ThrowIfNull(values);
        var result = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var value in values)
        {
            if (result.Count >= MaximumEntries)
            {
                throw new FormatException($"The Base URL allowlist cannot contain more than {MaximumEntries} entries.");
            }

            var normalized = NormalizeEntry(value);
            if (seen.Add(normalized))
            {
                result.Add(normalized);
            }
        }

        return result;
    }

    public static string NormalizeEntry(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > MaximumEntryLength)
        {
            throw new FormatException($"Each allowlisted Base URL must contain between 1 and {MaximumEntryLength} characters.");
        }

        var trimmed = value.Trim();
        if (!Uri.TryCreate(trimmed, UriKind.Absolute, out var uri)
            || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
            || string.IsNullOrWhiteSpace(uri.IdnHost)
            || !string.IsNullOrEmpty(uri.UserInfo)
            || !string.IsNullOrEmpty(uri.Query)
            || !string.IsNullOrEmpty(uri.Fragment)
            || trimmed.Contains('?')
            || trimmed.Contains('#')
            || GetOriginalAuthority(trimmed).Contains('@'))
        {
            throw new FormatException("An allowlisted Base URL must be an absolute HTTP or HTTPS URL without credentials, query, or fragment.");
        }

        var builder = new UriBuilder(uri)
        {
            Scheme = uri.Scheme.ToLowerInvariant(),
            Host = uri.IdnHost.ToLowerInvariant(),
            Port = uri.IsDefaultPort ? -1 : uri.Port,
            Query = string.Empty,
            Fragment = string.Empty,
        };
        return builder.Uri.AbsoluteUri.TrimEnd('/');
    }

    private static string GetOriginalAuthority(string value)
    {
        var schemeEnd = value.IndexOf("://", StringComparison.Ordinal);
        if (schemeEnd < 0)
        {
            return string.Empty;
        }

        var authorityStart = schemeEnd + 3;
        var authorityEnd = value.IndexOfAny(['/', '?', '#'], authorityStart);
        return authorityEnd < 0 ? value[authorityStart..] : value[authorityStart..authorityEnd];
    }
}
