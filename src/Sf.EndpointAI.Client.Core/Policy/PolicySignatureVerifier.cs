using System.Security.Cryptography;

namespace Sf.EndpointAI.Client.Core.Policy;

public static class PolicySignatureVerifier
{
    public static void Verify(ReadOnlySpan<byte> body, string signatureHeader, ReadOnlySpan<byte> hmacKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(signatureHeader);
        if (hmacKey.Length < 32)
        {
            throw new PolicySignatureException("POLICY_HMAC_KEY_INVALID", "The policy HMAC key must contain at least 32 bytes.");
        }

        const string prefix = "v1:";
        if (!signatureHeader.StartsWith(prefix, StringComparison.Ordinal))
        {
            throw new PolicySignatureException("POLICY_SIGNATURE_VERSION_UNSUPPORTED", "The policy signature version is unsupported.");
        }

        byte[] actual;
        try
        {
            actual = FromBase64Url(signatureHeader[prefix.Length..]);
        }
        catch (FormatException exception)
        {
            throw new PolicySignatureException("POLICY_SIGNATURE_MALFORMED", "The policy signature is malformed.", exception);
        }

        var expected = HMACSHA256.HashData(hmacKey, body);
        if (actual.Length != expected.Length || !CryptographicOperations.FixedTimeEquals(actual, expected))
        {
            throw new PolicySignatureException("POLICY_SIGNATURE_INVALID", "The policy signature is invalid.");
        }
    }

    public static string Sign(ReadOnlySpan<byte> body, ReadOnlySpan<byte> hmacKey)
    {
        if (hmacKey.Length < 32)
        {
            throw new ArgumentException("The HMAC key must contain at least 32 bytes.", nameof(hmacKey));
        }

        return $"v1:{ToBase64Url(HMACSHA256.HashData(hmacKey, body))}";
    }

    private static byte[] FromBase64Url(string value)
    {
        var padded = value.Replace('-', '+').Replace('_', '/');
        padded += (padded.Length % 4) switch
        {
            2 => "==",
            3 => "=",
            0 => string.Empty,
            _ => throw new FormatException("Invalid Base64URL length."),
        };
        return Convert.FromBase64String(padded);
    }

    private static string ToBase64Url(byte[] value)
    {
        return Convert.ToBase64String(value)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}

public sealed class PolicySignatureException(string code, string message, Exception? innerException = null)
    : Exception(message, innerException)
{
    public string Code { get; } = code;
}
