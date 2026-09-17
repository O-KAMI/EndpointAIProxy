namespace Sf.EndpointAI.Client.Core.Capture;

public static class CaptureHeaderRedactor
{
    private static readonly string[] SensitiveFragments =
    [
        "authorization",
        "cookie",
        "api-key",
        "apikey",
        "token",
        "secret",
    ];

    public static IReadOnlyList<string> Redact(string headerName, IEnumerable<string> values)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(headerName);
        ArgumentNullException.ThrowIfNull(values);
        return IsSensitive(headerName) ? ["[REDACTED]"] : values.ToArray();
    }

    public static bool IsSensitive(string headerName)
    {
        return SensitiveFragments.Any(fragment => headerName.Contains(fragment, StringComparison.OrdinalIgnoreCase));
    }
}
