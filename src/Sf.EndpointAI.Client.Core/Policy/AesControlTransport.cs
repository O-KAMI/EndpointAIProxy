using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Sf.EndpointAI.Client.Core.Policy;

/// <summary>Authenticated HTTP transport shared by Windows and macOS.</summary>
public static class AesControlTransport
{
    private const int MaximumWireBytes = 56_000_000;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public sealed record Envelope(int Version, string KeyId, string RequestId, long Timestamp,
        string Nonce, string Ciphertext, string Tag);
    public sealed record InnerRequest(string Method, string Path, string Query, string Token, string Body);
    public sealed record InnerResponse(int Status, string Body, Dictionary<string, string> Headers);

    private static byte[] Key(byte[] master, string direction)
        => HKDF.DeriveKey(HashAlgorithmName.SHA256, master, 32,
            Encoding.ASCII.GetBytes("sf-endpointai-transport-v1"), Encoding.ASCII.GetBytes(direction));

    private static byte[] Aad(Envelope value, string direction)
        => Encoding.ASCII.GetBytes(string.Join('\n', "sf-endpointai-transport-v1", direction,
            value.KeyId, value.RequestId, value.Timestamp.ToString(CultureInfo.InvariantCulture), value.Nonce));

    public static Envelope Seal(byte[] master, string keyId, string requestId, byte[] plain, string direction)
    {
        var nonce = RandomNumberGenerator.GetBytes(12);
        var value = new Envelope(1, keyId, requestId, DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            Convert.ToBase64String(nonce), "", "");
        var cipher = new byte[plain.Length];
        var tag = new byte[16];
        var key = Key(master, direction);
        try
        {
            using var aes = new AesGcm(key, 16);
            aes.Encrypt(nonce, plain, cipher, tag, Aad(value, direction));
        }
        finally { CryptographicOperations.ZeroMemory(key); }
        return value with { Ciphertext = Convert.ToBase64String(cipher), Tag = Convert.ToBase64String(tag) };
    }

    public static byte[] Open(byte[] master, string keyId, string requestId, Envelope value, string direction)
    {
        if (value.Version != 1 || value.KeyId != keyId || value.RequestId != requestId
            || !Guid.TryParseExact(value.RequestId, "D", out var id) || id.ToString("D") != value.RequestId
            || value.Timestamp < DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 300
            || value.Timestamp > DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 300)
            throw new CryptographicException("Invalid encrypted control response.");
        var nonce = Convert.FromBase64String(value.Nonce);
        var tag = Convert.FromBase64String(value.Tag);
        var cipher = Convert.FromBase64String(value.Ciphertext);
        if (nonce.Length != 12 || tag.Length != 16 || cipher.Length > 41_000_000
            || Convert.ToBase64String(nonce) != value.Nonce)
            throw new CryptographicException("Invalid encrypted control response.");
        var plain = new byte[cipher.Length];
        var key = Key(master, direction);
        try
        {
            using var aes = new AesGcm(key, 16);
            aes.Decrypt(nonce, cipher, tag, plain, Aad(value, direction));
        }
        finally { CryptographicOperations.ZeroMemory(key); }
        return plain;
    }

    public static async Task<HttpResponseMessage> SendAsync(HttpClient client, RemoteControlOptions options,
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        try { return await SendCoreAsync(client, options, request, cancellationToken); }
        catch (Exception exception) when (exception is JsonException or FormatException or ArgumentException or NullReferenceException)
        {
            throw new CryptographicException("Malformed encrypted control response.");
        }
    }

    private static async Task<HttpResponseMessage> SendCoreAsync(HttpClient client, RemoteControlOptions options,
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var uri = request.RequestUri ?? throw new InvalidOperationException("Missing request URI.");
        var body = request.Content is null ? [] : await request.Content.ReadAsByteArrayAsync(cancellationToken);
        if (body.Length > 30_000_000) throw new InvalidOperationException("Control request is too large.");
        var inner = new InnerRequest(request.Method.Method, uri.AbsolutePath, uri.Query.TrimStart('?'),
            request.Headers.Authorization?.Parameter ?? "", Convert.ToBase64String(body));
        var requestId = Guid.NewGuid().ToString("D");
        var envelope = Seal(options.TransportKey!, options.TransportKeyId, requestId,
            JsonSerializer.SerializeToUtf8Bytes(inner, JsonOptions), "request");
        using var outer = new HttpRequestMessage(HttpMethod.Post, new Uri(options.ServerOrigin, "/api/transport/v1"));
        outer.Content = new ByteArrayContent(JsonSerializer.SerializeToUtf8Bytes(envelope, JsonOptions));
        outer.Content.Headers.ContentType = new("application/json");
        using var received = await client.SendAsync(outer, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        // An unauthenticated outer failure must never be interpreted as a device-token 401.
        if (received.StatusCode != HttpStatusCode.OK)
            throw new HttpRequestException("Encrypted control transport was rejected.");
        var bytes = await ReadBoundedAsync(received.Content, MaximumWireBytes, cancellationToken);
        var incoming = JsonSerializer.Deserialize<Envelope>(bytes, JsonOptions)
            ?? throw new CryptographicException("Missing encrypted response.");
        var decoded = JsonSerializer.Deserialize<InnerResponse>(Open(options.TransportKey!, options.TransportKeyId,
            requestId, incoming, "response"), JsonOptions)
            ?? throw new CryptographicException("Invalid encrypted response.");
        if (decoded.Status is < 200 or > 599) throw new CryptographicException("Invalid business status.");
        var raw = Convert.FromBase64String(decoded.Body);
        if (raw.Length > 30_000_000) throw new CryptographicException("Control response is too large.");
        var result = new HttpResponseMessage((HttpStatusCode)decoded.Status) { Content = new ByteArrayContent(raw) };
        foreach (var (name, value) in decoded.Headers)
        {
            if (name.Equals("Content-Type", StringComparison.OrdinalIgnoreCase))
                result.Content.Headers.TryAddWithoutValidation(name, value);
            else if (name.Equals("X-SF-Policy-Signature", StringComparison.OrdinalIgnoreCase)
                || name.Equals("X-Request-ID", StringComparison.OrdinalIgnoreCase))
                result.Headers.TryAddWithoutValidation(name, value);
        }
        return result;
    }

    private static async Task<byte[]> ReadBoundedAsync(HttpContent content, int limit, CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength > limit) throw new CryptographicException("Control response is too large.");
        await using var stream = await content.ReadAsStreamAsync(cancellationToken);
        using var memory = new MemoryStream();
        var buffer = new byte[81920];
        int count;
        while ((count = await stream.ReadAsync(buffer, cancellationToken)) != 0)
        {
            if (memory.Length + count > limit) throw new CryptographicException("Control response is too large.");
            memory.Write(buffer, 0, count);
        }
        return memory.ToArray();
    }
}
