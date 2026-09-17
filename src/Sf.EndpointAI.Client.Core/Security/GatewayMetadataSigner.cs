using System.Security.Cryptography;
using System.Text;

namespace Sf.EndpointAI.Client.Core.Security;

public sealed record GatewayMetadata(
    Guid DeviceId,
    string UserId,
    string UserSid,
    string Agent,
    string AgentSurface,
    string ProviderId,
    string OriginalBaseUrl,
    string OriginalAuthority,
    Guid RequestId,
    DateTimeOffset TimestampUtc,
    string Method,
    string PathAndQuery);

public sealed class GatewayMetadataSigner(byte[] key)
{
    private readonly byte[] _key = key.Length >= 32
        ? key.ToArray()
        : throw new ArgumentException("The gateway metadata key must contain at least 32 bytes.", nameof(key));

    public string Sign(GatewayMetadata metadata)
    {
        var canonical = string.Join('\n',
            "v1",
            metadata.RequestId.ToString("D"),
            metadata.TimestampUtc.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture),
            metadata.DeviceId.ToString("D"),
            metadata.UserId,
            metadata.UserSid,
            metadata.Agent,
            metadata.AgentSurface,
            metadata.ProviderId,
            metadata.OriginalBaseUrl,
            metadata.OriginalAuthority,
            metadata.Method.ToUpperInvariant(),
            metadata.PathAndQuery);
        using var hmac = new HMACSHA256(_key);
        return $"v1:{ToBase64Url(hmac.ComputeHash(Encoding.UTF8.GetBytes(canonical)))}";
    }

    private static string ToBase64Url(byte[] value)
    {
        return Convert.ToBase64String(value)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}
