using System.Net;
using System.Net.Http.Json;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Data.Sqlite;
using Sf.EndpointAI.Client.Core.Policy;
using Sf.EndpointAI.Client.Core.Security;
using Sf.EndpointAI.Client.Core.State;
using Sf.EndpointAI.Contracts;

namespace Sf.EndpointAI.UnitTests;

public sealed class PolicyControlTests : IAsyncLifetime
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), $"sf-policy-{Guid.NewGuid():N}");
    private static readonly byte[] HmacKey = Encoding.UTF8.GetBytes("01234567890123456789012345678901");
    private static readonly string CertificatePin = Convert.ToBase64String(SHA256.HashData("test-control-certificate"u8));
    private static readonly JsonSerializerOptions JsonOptions = CreateJsonOptions();

    public ValueTask InitializeAsync()
    {
        Directory.CreateDirectory(_directory);
        return ValueTask.CompletedTask;
    }

    public ValueTask DisposeAsync()
    {
        SqliteConnection.ClearAllPools();
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }

        return ValueTask.CompletedTask;
    }

    [Fact]
    public void Signature_verification_rejects_tampered_policy()
    {
        var body = "{\"policyVersion\":1}"u8.ToArray();
        var signature = PolicySignatureVerifier.Sign(body, HmacKey);

        PolicySignatureVerifier.Verify(body, signature, HmacKey);
        var exception = Assert.Throws<PolicySignatureException>(() =>
            PolicySignatureVerifier.Verify("{\"policyVersion\":2}"u8, signature, HmacKey));

        Assert.Equal("POLICY_SIGNATURE_INVALID", exception.Code);
    }

    [Fact]
    public void Signature_verification_covers_allowlisted_base_urls()
    {
        var policy = CreatePolicy(2) with { AllowlistedBaseUrls = ["https://model-one.internal/v1"] };
        var body = JsonSerializer.SerializeToUtf8Bytes(policy, JsonOptions);
        var signature = PolicySignatureVerifier.Sign(body, HmacKey);
        var tampered = Encoding.UTF8.GetBytes(
            Encoding.UTF8.GetString(body).Replace("model-one.internal", "model-two.internal", StringComparison.Ordinal));

        var exception = Assert.Throws<PolicySignatureException>(() =>
            PolicySignatureVerifier.Verify(tampered, signature, HmacKey));

        Assert.Equal("POLICY_SIGNATURE_INVALID", exception.Code);
    }

    [Fact]
    public void Dynamic_provider_rejects_rollback_and_accepts_newer_policy()
    {
        var first = CreatePolicy(2);
        var provider = new DynamicPolicyProvider(first);

        Assert.False(provider.TryApply(first with { PolicyVersion = 1 }));
        Assert.True(provider.TryApply(first with { PolicyVersion = 3, RouteMode = RouteMode.FixedGateway, GatewayOrigin = "https://gateway.example" }));
        Assert.Equal(3, provider.Current.PolicyVersion);
        Assert.Equal(RouteMode.FixedGateway, provider.Current.RouteMode);
    }

    [Fact]
    public void Http_gateway_requires_explicit_insecure_flag()
    {
        var policy = CreatePolicy(1) with
        {
            RouteMode = RouteMode.FixedGateway,
            GatewayOrigin = "http://10.0.0.8:8080",
        };

        var exception = Assert.Throws<PolicyValidationException>(() => PolicyValidator.Validate(policy));
        Assert.Equal("POLICY_GATEWAY_INVALID", exception.Code);
        PolicyValidator.Validate(policy with { AllowInsecureGateway = true });
    }

    [Theory]
    [InlineData("ftp://model.internal/v1")]
    [InlineData("https://model.internal/v1?target=external")]
    [InlineData("https://user@model.internal/v1")]
    public void Policy_rejects_invalid_allowlisted_base_urls(string value)
    {
        var exception = Assert.Throws<PolicyValidationException>(() =>
            PolicyValidator.Validate(CreatePolicy(1) with { AllowlistedBaseUrls = [value] }));

        Assert.Equal("POLICY_ALLOWLIST_INVALID", exception.Code);
    }

    [Fact]
    public async Task Signed_policy_preserves_explicit_empty_allowlist()
    {
        var policy = CreatePolicy(4) with { AllowlistedBaseUrls = [] };
        var body = JsonSerializer.SerializeToUtf8Bytes(policy, JsonOptions);
        using var handler = new PolicyHandler(body, PolicySignatureVerifier.Sign(body, HmacKey));
        using var client = new RemoteControlClient(
            new HttpClient(handler),
            new RemoteControlOptions(new Uri("https://127.0.0.1:18180"), "client-token", HmacKey, CertificatePin));

        var received = await client.FetchPolicyAsync(TestContext.Current.CancellationToken);

        Assert.NotNull(received.Policy.AllowlistedBaseUrls);
        Assert.Empty(received.Policy.AllowlistedBaseUrls);
    }

    [Fact]
    public async Task Client_state_persists_identity_and_last_valid_policy()
    {
        var store = new SqliteClientStateStore(Path.Combine(_directory, "client.db"));
        await store.InitializeAsync(TestContext.Current.CancellationToken);
        var firstDeviceId = await store.GetOrCreateDeviceIdAsync(TestContext.Current.CancellationToken);
        var secondDeviceId = await store.GetOrCreateDeviceIdAsync(TestContext.Current.CancellationToken);
        var policy = CreatePolicy(7);
        var signature = PolicySignatureVerifier.Sign("policy"u8, HmacKey);
        await store.SavePolicyAsync(policy, signature, DateTimeOffset.UtcNow, TestContext.Current.CancellationToken);

        var cached = await store.LoadPolicyAsync(TestContext.Current.CancellationToken);

        Assert.Equal(firstDeviceId, secondDeviceId);
        Assert.NotNull(cached);
        Assert.Equal(policy, cached.Policy);
        Assert.Equal(signature, cached.Signature);
    }

    [Fact]
    public async Task Remote_client_verifies_signed_raw_body_before_deserializing()
    {
        var policy = CreatePolicy(4);
        var body = JsonSerializer.SerializeToUtf8Bytes(policy, JsonOptions);
        using var handler = new PolicyHandler(body, PolicySignatureVerifier.Sign(body, HmacKey));
        using var client = new RemoteControlClient(
            new HttpClient(handler),
            new RemoteControlOptions(new Uri("https://127.0.0.1:18180"), "client-token", HmacKey, CertificatePin));

        var received = await client.FetchPolicyAsync(TestContext.Current.CancellationToken);

        Assert.Equal(policy, received.Policy);
        Assert.Equal(body, received.RawBody);
    }

    [Fact]
    public async Task Remote_client_uses_persisted_device_token_without_bootstrap_token()
    {
        var policy = CreatePolicy(5);
        var body = JsonSerializer.SerializeToUtf8Bytes(policy, JsonOptions);
        var deviceId = Guid.NewGuid();
        using var handler = new PolicyHandler(
            body,
            PolicySignatureVerifier.Sign(body, HmacKey),
            "device-token",
            $"/api/v2/devices/{deviceId:D}/policy");
        using var client = new RemoteControlClient(
            new HttpClient(handler),
            new RemoteControlOptions(new Uri("https://127.0.0.1:18180"), null, HmacKey, CertificatePin));

        var received = await client.FetchDevicePolicyAsync(
            deviceId,
            "device-token",
            TestContext.Current.CancellationToken);

        Assert.Equal(policy, received.Policy);
    }

    [Fact]
    public async Task Remote_client_accepts_signed_commands_and_rejects_tampering()
    {
        var deviceId = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;
        var payload = new RemoteCommandPayload(
            1,
            Guid.NewGuid(),
            deviceId,
            RemoteCommandType.DisableProxy,
            now,
            now.AddMinutes(10));
        var commandKey = HMACSHA256.HashData(HmacKey, Encoding.UTF8.GetBytes("sf-endpoint-ai-command-v1"));
        var signature = PolicySignatureVerifier.Sign(
            JsonSerializer.SerializeToUtf8Bytes(payload, JsonOptions),
            commandKey);
        var heartbeat = CreateHeartbeatV2(deviceId);
        using var validHandler = new CommandHandler(
            new HeartbeatV2Response(now, 1, 60, new SignedRemoteCommand(payload, signature)));
        using var validClient = new RemoteControlClient(
            new HttpClient(validHandler),
            new RemoteControlOptions(new Uri("https://127.0.0.1:18180"), null, HmacKey, CertificatePin));

        var response = await validClient.SendHeartbeatV2Async(
            heartbeat,
            "device-token",
            TestContext.Current.CancellationToken);

        Assert.Equal(payload.CommandId, response.Command?.Payload.CommandId);

        using var tamperedHandler = new CommandHandler(
            new HeartbeatV2Response(now, 1, 60, new SignedRemoteCommand(payload, signature + "x")));
        using var tamperedClient = new RemoteControlClient(
            new HttpClient(tamperedHandler),
            new RemoteControlOptions(new Uri("https://127.0.0.1:18180"), null, HmacKey, CertificatePin));
        await Assert.ThrowsAsync<PolicySignatureException>(() => tamperedClient.SendHeartbeatV2Async(
            heartbeat,
            "device-token",
            TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Client_state_protects_device_credentials_and_deduplicates_command_receipts()
    {
        var store = new SqliteClientStateStore(Path.Combine(_directory, "protected-client.db"), new TestProtector());
        await store.InitializeAsync(TestContext.Current.CancellationToken);
        var credential = new StoredDeviceCredential(
            "device-token",
            DateTimeOffset.UtcNow,
            "https://127.0.0.1:18180/",
            CertificatePin);
        await store.SaveDeviceCredentialAsync(credential, TestContext.Current.CancellationToken);
        var commandId = Guid.NewGuid();
        await store.SaveCommandReceiptAsync(
            new StoredCommandReceipt(
                commandId,
                RemoteCommandType.DisableProxy,
                RemoteCommandStatus.Executing,
                DateTimeOffset.UtcNow,
                null,
                null,
                null),
            TestContext.Current.CancellationToken);
        await store.SaveCommandReceiptAsync(
            new StoredCommandReceipt(
                commandId,
                RemoteCommandType.DisableProxy,
                RemoteCommandStatus.Succeeded,
                DateTimeOffset.UtcNow,
                DateTimeOffset.UtcNow,
                "PROXY_DISABLED",
                "done"),
            TestContext.Current.CancellationToken);

        Assert.Equal(credential.Token, (await store.LoadDeviceCredentialAsync(TestContext.Current.CancellationToken))?.Token);
        Assert.Equal(credential.ServerOrigin, (await store.LoadDeviceCredentialAsync(TestContext.Current.CancellationToken))?.ServerOrigin);
        var receipt = await store.LoadCommandReceiptAsync(commandId, TestContext.Current.CancellationToken);
        Assert.Equal(RemoteCommandStatus.Succeeded, receipt?.Status);
        Assert.Equal("PROXY_DISABLED", receipt?.ResultCode);
    }

    [Fact]
    public void Control_server_certificate_requires_matching_pin_validity_and_name()
    {
        using var certificate = CreateCertificate(
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddDays(1));
        using var publicKey = certificate.GetRSAPublicKey();
        Assert.NotNull(publicKey);
        var expectedPin = SHA256.HashData(publicKey.ExportSubjectPublicKeyInfo());

        ControlServerCertificateValidator.Validate(
            certificate,
            SslPolicyErrors.RemoteCertificateChainErrors,
            expectedPin,
            DateTimeOffset.UtcNow);

        var mismatch = Assert.Throws<ControlTlsValidationException>(() =>
            ControlServerCertificateValidator.Validate(
                certificate,
                SslPolicyErrors.RemoteCertificateChainErrors,
                SHA256.HashData("different-key"u8),
                DateTimeOffset.UtcNow));
        Assert.Equal("CONTROL_TLS_PIN_MISMATCH", mismatch.Code);

        var wrongName = Assert.Throws<ControlTlsValidationException>(() =>
            ControlServerCertificateValidator.Validate(
                certificate,
                SslPolicyErrors.RemoteCertificateNameMismatch,
                expectedPin,
                DateTimeOffset.UtcNow));
        Assert.Equal("CONTROL_TLS_PIN_MISMATCH", wrongName.Code);

        var missing = Assert.Throws<ControlTlsValidationException>(() =>
            ControlServerCertificateValidator.Validate(
                null,
                SslPolicyErrors.RemoteCertificateNotAvailable,
                expectedPin,
                DateTimeOffset.UtcNow));
        Assert.Equal("CONTROL_TLS_PIN_MISMATCH", missing.Code);
    }

    [Fact]
    public void Control_server_certificate_rejects_expired_certificate()
    {
        using var certificate = CreateCertificate(
            DateTimeOffset.UtcNow.AddDays(-2),
            DateTimeOffset.UtcNow.AddDays(-1));
        using var publicKey = certificate.GetRSAPublicKey();
        Assert.NotNull(publicKey);
        var expectedPin = SHA256.HashData(publicKey.ExportSubjectPublicKeyInfo());

        var exception = Assert.Throws<ControlTlsValidationException>(() =>
            ControlServerCertificateValidator.Validate(
                certificate,
                SslPolicyErrors.RemoteCertificateChainErrors,
                expectedPin,
                DateTimeOffset.UtcNow));

        Assert.Equal("CONTROL_TLS_CERTIFICATE_EXPIRED", exception.Code);
    }

    [Fact]
    public void Remote_control_options_reject_http_and_invalid_pin()
    {
        Assert.Throws<ArgumentException>(() => RemoteControlClient.ValidateOptions(
            new RemoteControlOptions(new Uri("http://127.0.0.1:18443"), "token", HmacKey, CertificatePin)));
        Assert.Throws<ArgumentException>(() => RemoteControlClient.ValidateOptions(
            new RemoteControlOptions(new Uri("https://127.0.0.1:18443"), "token", HmacKey, "invalid")));
    }

    [Fact]
    public async Task Client_state_migrates_legacy_device_credential_without_scope()
    {
        var databasePath = Path.Combine(_directory, "legacy-client.db");
        await using (var connection = new SqliteConnection($"Data Source={databasePath}"))
        {
            await connection.OpenAsync(TestContext.Current.CancellationToken);
            await using var command = connection.CreateCommand();
            command.CommandText = """
                CREATE TABLE device_credential (
                    singleton_id INTEGER PRIMARY KEY CHECK(singleton_id=1),
                    protected_token BLOB NOT NULL,
                    enrolled_at_utc TEXT NOT NULL
                );
                INSERT INTO device_credential (singleton_id, protected_token, enrolled_at_utc)
                VALUES (1, $token, $enrolledAt);
                """;
            command.Parameters.Add("$token", SqliteType.Blob).Value = Encoding.UTF8.GetBytes("protected:legacy-token");
            command.Parameters.AddWithValue("$enrolledAt", DateTimeOffset.UtcNow.ToString("O"));
            await command.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
        }

        var store = new SqliteClientStateStore(databasePath, new TestProtector());
        await store.InitializeAsync(TestContext.Current.CancellationToken);
        var credential = await store.LoadDeviceCredentialAsync(TestContext.Current.CancellationToken);

        Assert.NotNull(credential);
        Assert.Equal("legacy-token", credential.Token);
        Assert.Null(credential.ServerOrigin);
        Assert.Null(credential.ServerCertificateSpkiSha256);
    }

    private static EndpointPolicy CreatePolicy(long version)
    {
        return new EndpointPolicy(
            1,
            Guid.Parse("11111111-1111-1111-1111-111111111111"),
            version,
            true,
            RouteMode.PassthroughOriginal,
            null,
            false,
            60,
            60,
            DateTimeOffset.Parse("2026-08-23T00:00:00Z", System.Globalization.CultureInfo.InvariantCulture));
    }

    private static HeartbeatV2Request CreateHeartbeatV2(Guid deviceId)
    {
        var now = DateTimeOffset.UtcNow;
        return new HeartbeatV2Request(
            2,
            Guid.NewGuid(),
            now,
            new DeviceIdentity(deviceId, "test-host", "Windows", "0.1.12", Guid.NewGuid()),
            new DeviceRuntimeState(now, 0, ClientOperationState.Enabled, true, now, null, null, null),
            new PolicyClientState(1, 1, PolicyApplyStatus.Applied, null, null),
            new ProxyClientState(ProxyState.Listening, "127.0.0.1:18080", 0, AuditState.Healthy),
            [],
            [],
            [],
            []);
    }

    private static X509Certificate2 CreateCertificate(DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=127.0.0.1",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        var san = new SubjectAlternativeNameBuilder();
        san.AddIpAddress(IPAddress.Loopback);
        request.CertificateExtensions.Add(san.Build());
        return request.CreateSelfSigned(notBefore, notAfter);
    }

    private static JsonSerializerOptions CreateJsonOptions()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        options.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.CamelCase));
        return options;
    }

    private sealed class PolicyHandler(
        byte[] body,
        string signature,
        string expectedToken = "client-token",
        string expectedPath = "/api/v1/policy") : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Assert.Equal("Bearer", request.Headers.Authorization?.Scheme);
            Assert.Equal(expectedToken, request.Headers.Authorization?.Parameter);
            Assert.Equal(expectedPath, request.RequestUri?.AbsolutePath);
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(body),
            };
            response.Headers.TryAddWithoutValidation("X-SF-Policy-Signature", signature);
            return Task.FromResult(response);
        }
    }

    private sealed class CommandHandler(HeartbeatV2Response responseValue) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Assert.Equal("Bearer device-token", request.Headers.Authorization?.ToString());
            Assert.Equal("/api/v2/heartbeat", request.RequestUri?.AbsolutePath);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = JsonContent.Create(responseValue, options: JsonOptions),
            });
        }
    }

    private sealed class TestProtector : ITextProtector
    {
        public byte[] Protect(string value) => Encoding.UTF8.GetBytes($"protected:{value}");

        public string Unprotect(byte[] protectedValue)
        {
            var value = Encoding.UTF8.GetString(protectedValue);
            Assert.StartsWith("protected:", value, StringComparison.Ordinal);
            return value["protected:".Length..];
        }
    }
}
