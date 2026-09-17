using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sf.EndpointAI.Contracts;

namespace Sf.EndpointAI.Client.Core.Policy;

public sealed record RemoteControlOptions(
    Uri ServerOrigin,
    string? ClientToken,
    byte[] PolicyHmacKey,
    string ServerCertificateSpkiSha256,
    byte[]? TransportKey = null,
    string TransportKeyId = "production-2026-01");

public sealed record ReceivedPolicy(EndpointPolicy Policy, string Signature, byte[] RawBody);

public sealed class RemoteControlClient(HttpClient httpClient, RemoteControlOptions options) : IDisposable
{
    private const int MaximumPolicyBytes = 1024 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = CreateJsonOptions();

    public async Task<ReceivedPolicy> FetchPolicyAsync(CancellationToken cancellationToken = default)
        => await FetchPolicyCoreAsync("/api/v1/policy", null, cancellationToken);

    public async Task<ReceivedPolicy> FetchDevicePolicyAsync(
        Guid deviceId,
        string deviceToken,
        CancellationToken cancellationToken = default)
        => await FetchPolicyCoreAsync(
            $"/api/v2/devices/{deviceId:D}/policy",
            deviceToken,
            cancellationToken);

    private async Task<ReceivedPolicy> FetchPolicyCoreAsync(
        string path,
        string? bearerToken,
        CancellationToken cancellationToken)
    {
        using var request = CreateRequest(HttpMethod.Get, path, bearerToken);
        using var response = await SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();
        if (response.Content.Headers.ContentLength is > MaximumPolicyBytes)
        {
            throw new InvalidOperationException("The control policy response is too large.");
        }

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var memory = new MemoryStream();
        await stream.CopyToAsync(memory, cancellationToken);
        if (memory.Length > MaximumPolicyBytes)
        {
            throw new InvalidOperationException("The control policy response is too large.");
        }

        var body = memory.ToArray();
        var signature = response.Headers.TryGetValues("X-SF-Policy-Signature", out var values)
            ? values.SingleOrDefault()
            : null;
        if (signature is null)
        {
            throw new PolicySignatureException("POLICY_SIGNATURE_MISSING", "The policy response has no signature.");
        }

        PolicySignatureVerifier.Verify(body, signature, options.PolicyHmacKey);
        var policy = JsonSerializer.Deserialize<EndpointPolicy>(body, JsonOptions)
            ?? throw new PolicyValidationException("POLICY_BODY_INVALID", "The policy response body is empty.");
        PolicyValidator.Validate(policy);
        return new ReceivedPolicy(policy, signature, body);
    }

    public async Task<HeartbeatResponse> SendHeartbeatAsync(
        HeartbeatRequest heartbeat,
        CancellationToken cancellationToken = default)
    {
        using var request = CreateJsonRequest(HttpMethod.Post, "/api/v1/heartbeat", heartbeat);
        using var response = await SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<HeartbeatResponse>(JsonOptions, cancellationToken)
            ?? throw new InvalidOperationException("The heartbeat response is empty.");
    }

    public async Task<DeviceEnrollmentResponse> EnrollDeviceAsync(
        DeviceEnrollmentRequest enrollment,
        CancellationToken cancellationToken = default)
    {
        using var request = CreateJsonRequest(HttpMethod.Post, "/api/v2/enroll", enrollment);
        using var response = await SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<DeviceEnrollmentResponse>(JsonOptions, cancellationToken)
            ?? throw new InvalidOperationException("The device enrollment response is empty.");
    }

    public async Task<HeartbeatV2Response> SendHeartbeatV2Async(
        HeartbeatV2Request heartbeat,
        string deviceToken,
        CancellationToken cancellationToken = default)
    {
        using var request = CreateJsonRequest(HttpMethod.Post, "/api/v2/heartbeat", heartbeat, deviceToken);
        using var response = await SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();
        var value = await response.Content.ReadFromJsonAsync<HeartbeatV2Response>(JsonOptions, cancellationToken)
            ?? throw new InvalidOperationException("The v2 heartbeat response is empty.");
        if (value.Command is not null)
        {
            VerifyCommand(value.Command);
        }

        return value;
    }

    public async Task SendCommandStatusAsync(
        RemoteCommandStatusUpdate update,
        string deviceToken,
        CancellationToken cancellationToken = default)
    {
        using var request = CreateJsonRequest(
            HttpMethod.Post,
            $"/api/v2/commands/{update.CommandId:D}/status",
            update,
            deviceToken);
        using var response = await SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();
    }

    public async Task<EventBatchResponse> SendEventsAsync(
        EventBatchRequest batch,
        CancellationToken cancellationToken = default)
    {
        using var request = CreateJsonRequest(HttpMethod.Post, "/api/v1/events/batch", batch);
        using var response = await SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<EventBatchResponse>(JsonOptions, cancellationToken)
            ?? throw new InvalidOperationException("The event response is empty.");
    }

    public async Task<EventBatchResponse> SendDeviceEventsAsync(
        EventBatchRequest batch,
        string deviceToken,
        CancellationToken cancellationToken = default)
    {
        using var request = CreateJsonRequest(HttpMethod.Post, "/api/v2/events/batch", batch, deviceToken);
        using var response = await SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<EventBatchResponse>(JsonOptions, cancellationToken)
            ?? throw new InvalidOperationException("The device event response is empty.");
    }

    public static RemoteControlOptions ValidateOptions(RemoteControlOptions value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (!value.ServerOrigin.IsAbsoluteUri
            || !string.Equals(value.ServerOrigin.Scheme, value.TransportKey is null ? Uri.UriSchemeHttps : Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
            || value.ServerOrigin.AbsolutePath != "/"
            || !string.IsNullOrEmpty(value.ServerOrigin.Query)
            || !string.IsNullOrEmpty(value.ServerOrigin.Fragment)
            || !string.IsNullOrEmpty(value.ServerOrigin.UserInfo))
        {
            throw new ArgumentException("The control server must be a valid HTTPS origin.", nameof(value));
        }

        if (value.PolicyHmacKey.Length < 32)
        {
            throw new ArgumentException("A 32-byte HMAC key is required.", nameof(value));
        }

        if (value.TransportKey is null)
            ControlServerCertificateValidator.ParsePin(value.ServerCertificateSpkiSha256);
        else if (value.TransportKey.Length != 32 || !System.Text.RegularExpressions.Regex.IsMatch(value.TransportKeyId, @"\A[A-Za-z0-9_-]{1,64}\z"))
            throw new ArgumentException("A 32-byte transport key and valid key ID are required.", nameof(value));

        return value;
    }

    private HttpRequestMessage CreateRequest(HttpMethod method, string path, string? bearerToken = null)
        => CreateAuthenticatedRequest(method, path, bearerToken);

    private Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        => options.TransportKey is null
            ? httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
            : AesControlTransport.SendAsync(httpClient, options, request, cancellationToken);

    private HttpRequestMessage CreateAuthenticatedRequest(HttpMethod method, string path, string? bearerToken = null)
    {
        var validated = ValidateOptions(options);
        var request = new HttpRequestMessage(method, new Uri(validated.ServerOrigin, path));
        var token = bearerToken ?? validated.ClientToken;
        if (string.IsNullOrWhiteSpace(token))
        {
            request.Dispose();
            throw new InvalidOperationException("CONTROL_ENROLLMENT_TOKEN_MISSING");
        }

        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        return request;
    }

    private HttpRequestMessage CreateJsonRequest<T>(
        HttpMethod method,
        string path,
        T value,
        string? bearerToken = null)
    {
        var request = CreateRequest(method, path, bearerToken);
        request.Content = JsonContent.Create(value, options: JsonOptions);
        return request;
    }

    private void VerifyCommand(SignedRemoteCommand command)
    {
        if (command.Payload.SchemaVersion != 1
            || command.Payload.CommandId == Guid.Empty
            || command.Payload.DeviceId == Guid.Empty
            || command.Payload.Type is not (RemoteCommandType.DisableProxy or RemoteCommandType.EnableProxy)
            || command.Payload.ExpiresAtUtc <= command.Payload.IssuedAtUtc)
        {
            throw new PolicySignatureException("COMMAND_BODY_INVALID", "The remote command body is invalid.");
        }

        var commandKey = HMACSHA256.HashData(options.PolicyHmacKey, Encoding.UTF8.GetBytes("sf-endpoint-ai-command-v1"));
        var body = JsonSerializer.SerializeToUtf8Bytes(command.Payload, JsonOptions);
        PolicySignatureVerifier.Verify(body, command.Signature, commandKey);
    }

    private static JsonSerializerOptions CreateJsonOptions()
    {
        var jsonOptions = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        jsonOptions.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.CamelCase));
        return jsonOptions;
    }

    public void Dispose()
    {
        httpClient.Dispose();
    }
}
