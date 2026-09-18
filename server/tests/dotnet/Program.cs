using System.Security.Cryptography;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sf.EndpointAI.Contracts;
using Sf.EndpointAI.Client.Core.Policy;

var options = new JsonSerializerOptions(JsonSerializerDefaults.Web);
options.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.CamelCase));
var key = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray(); // Synthetic test key.
var when = DateTimeOffset.Parse("2026-09-13T01:02:03.1234000+00:00", CultureInfo.InvariantCulture);
var device = Guid.Parse("10000000-0000-0000-0000-000000000001");
var asset = Guid.Parse("20000000-0000-0000-0000-000000000002");
var command = new RemoteCommandPayload(1, Guid.Parse("30000000-0000-0000-0000-000000000003"),
    device, RemoteCommandType.DisableProxy, when, when.AddMinutes(10));
var commandKey = HMACSHA256.HashData(key, Encoding.UTF8.GetBytes("sf-endpoint-ai-command-v1"));
var policy = new EndpointPolicy(1, Guid.Parse("40000000-0000-0000-0000-000000000004"), 1,
    true, RouteMode.FixedGateway, "http://security-proxy.sf-express.com", true, 60, 60, when,
    [BaseUrlAllowlist.LegacyCcrBaseUrl]);
var heartbeat = new HeartbeatV2Request(2, Guid.Parse("50000000-0000-0000-0000-000000000005"), when,
    new DeviceIdentity(device, "测试终端", "Windows 11", "0.1.19", Guid.Parse("60000000-0000-0000-0000-000000000006")),
    new DeviceRuntimeState(when, 123, ClientOperationState.Enabled, true, when, when, "ok", null),
    new PolicyClientState(1, 1, PolicyApplyStatus.Applied, null, null),
    new ProxyClientState(ProxyState.Listening, "127.0.0.1:18080", 1, AuditState.Healthy),
    [new EndpointUser("S-1-test", "test")],
    [new AgentInventoryItem(Guid.Parse("70000000-0000-0000-0000-000000000007"), "S-1-test",
        AgentType.ClaudeCli, "Claude Code", "1.0", InstallMethod.Npm, 100, true, true,
        null, null, null, RouteStatus.Attached, "https://api.anthropic.com", when)],
    [new AgentEndpointAsset(asset, "S-1-test", "claude", AgentConfigurationSource.Direct,
        null, null, true, "test-model", AgentWireApi.AnthropicMessages, "https://api.anthropic.com",
        "http://127.0.0.1:18080/r/test", "http://127.0.0.1:18080/r/test", false, RouteStatus.Attached, when)],
    [new ProxyActivityAsset(asset, ProxyTrafficState.Succeeded, when, when, null, 200, "ok", null, 12.5, 1, 1, 0)]);
if (args.Length == 0 || args[0] == "fixtures")
{
    var commandBody = JsonSerializer.Serialize(command, options);
    var policyBody = JsonSerializer.Serialize(policy, options);
    var vectors = new[] { 0L, 1000000L, 1234000L, 1234560L }.Select(ticks => {
        var payload = command with { IssuedAtUtc = new DateTimeOffset(2026,9,13,0,0,0,TimeSpan.Zero).AddTicks(ticks) };
        var body = JsonSerializer.Serialize(payload, options);
        return new { body, signature = PolicySignatureVerifier.Sign(Encoding.UTF8.GetBytes(body), commandKey) };
    });
    Console.WriteLine(JsonSerializer.Serialize(new {
        source = "Original 0.1.19 contracts and PolicySignatureVerifier; synthetic data only",
        commandBody, commandSignature = PolicySignatureVerifier.Sign(Encoding.UTF8.GetBytes(commandBody), commandKey),
        policyBody, policySignature = PolicySignatureVerifier.Sign(Encoding.UTF8.GetBytes(policyBody), key),
        heartbeat, commandVectors = vectors,
        enrollment = new DeviceEnrollmentRequest(2, device, "测试终端", "0.1.19")
        , allowlistVectors = new[] {
            " HTTPS://Example.COM:443/api/ ", "http://example.com:80/", "https://example.com/a/../b",
            "http://[::1]:18080/api/", "https://例子.测试/路径", "https://example.com/a/%2e%2e/b",
            "https://example.com/a%2fb", "http://127.1/api", "http://2130706433/api", "https://a_b.example/api",
            "https://exa mple.com", "https://example.com?", "https://example.com#", "https://@example.com",
            "https://example.com/a//b/", "https://example.com/path%zz", "https://example.com/..",
            "https://example.com/a/./", "http://0x7f000001/api"
        }.Select(value => { try { return new { input=value, normalized=(string?)BaseUrlAllowlist.NormalizeEntry(value), valid=true }; }
                           catch (FormatException) { return new { input=value, normalized=(string?)null, valid=false }; } })
    }, options));
    return;
}
if (args[0] == "aes-rejections")
{
    foreach (var scenario in new[] { "plain", "missing", "badbase64", "wrongid", "wrongtag", "outer401", "inner401" })
    {
        using var fake = new FakeControlHandler(async request => {
            if (request.Headers.Authorization is not null || request.RequestUri!.AbsolutePath != "/api/transport/v1")
                throw new InvalidOperationException("Credentials or business path escaped the envelope");
            var text = await request.Content!.ReadAsStringAsync();
            if (text.Contains("synthetic-token", StringComparison.Ordinal)) throw new InvalidOperationException("Token leaked");
            var sent = JsonSerializer.Deserialize<AesControlTransport.Envelope>(text, options)!;
            string answer;
            if (scenario == "plain") answer = "not an encrypted response";
            else if (scenario == "missing") answer = "{}";
            else
            {
                var inner = new AesControlTransport.InnerResponse(401, "", new());
                var encrypted = AesControlTransport.Seal(key, "production-2026-01", sent.RequestId,
                    JsonSerializer.SerializeToUtf8Bytes(inner, options), "response");
                if (scenario == "wrongid") encrypted = encrypted with { RequestId = Guid.NewGuid().ToString("D") };
                if (scenario == "wrongtag") encrypted = encrypted with { Tag = Convert.ToBase64String(new byte[16]) };
                if (scenario == "badbase64") encrypted = encrypted with { Nonce = "!" };
                answer = JsonSerializer.Serialize(encrypted, options);
            }
            return new HttpResponseMessage(scenario == "outer401" ? System.Net.HttpStatusCode.Unauthorized : System.Net.HttpStatusCode.OK)
                { Content = new StringContent(answer) };
        });
        using var http = new HttpClient(fake);
        using var client = new RemoteControlClient(http, new RemoteControlOptions(new Uri("http://127.0.0.1:8080"),
            "synthetic-token", key, "", key));
        try { await client.FetchPolicyAsync(); throw new InvalidOperationException("Expected rejection: " + scenario); }
        catch (CryptographicException) when (scenario != "inner401") { }
        catch (HttpRequestException ex) when (scenario == "outer401" && ex.StatusCode is null) { }
        catch (HttpRequestException ex) when (scenario == "inner401" && ex.StatusCode == System.Net.HttpStatusCode.Unauthorized) { }
    }
    Console.WriteLine("7 encrypted HTTP rejection scenarios passed");
    return;
}
if (args[0] == "aes-seal")
{
    var plain = Encoding.UTF8.GetBytes(Console.In.ReadToEnd());
    Console.WriteLine(JsonSerializer.Serialize(AesControlTransport.Seal(key, "production-2026-01", args[1], plain, args[2]), options));
    return;
}
if (args[0] == "aes-open")
{
    var envelope = JsonSerializer.Deserialize<AesControlTransport.Envelope>(Console.In.ReadToEnd(), options)!;
    Console.Write(Encoding.UTF8.GetString(AesControlTransport.Open(key, "production-2026-01", args[1], envelope, args[2])));
    return;
}
if (args[0] == "verify-command")
{
    var signed = JsonSerializer.Deserialize<SignedRemoteCommand>(File.ReadAllText(args[1]), options)!;
    PolicySignatureVerifier.Verify(JsonSerializer.SerializeToUtf8Bytes(signed.Payload, options), signed.Signature, commandKey);
    Console.WriteLine("Original .NET command verification passed");
    return;
}
if (args[0] == "live" || args[0] == "aes-live")
{
    var origin = new Uri(args[1]);
    var pin = args[2];
    var enrollmentToken = Environment.GetEnvironmentVariable("EAI_INTEROP_CLIENT_TOKEN")
        ?? throw new InvalidOperationException("EAI_INTEROP_CLIENT_TOKEN is required");
    using var handler = new HttpClientHandler { AllowAutoRedirect = false, UseProxy = false,
        ServerCertificateCustomValidationCallback = (_, cert, _, errors) =>
            ControlServerCertificateValidator.ValidateAndReturnTrue(cert, errors,
                ControlServerCertificateValidator.ParsePin(pin), DateTimeOffset.UtcNow)
    };
    using var http = new HttpClient(handler);
    using var client = new RemoteControlClient(http, new RemoteControlOptions(origin, enrollmentToken, key, pin,
        args[0] == "aes-live" ? key : null));
    var enrolled = await client.EnrollDeviceAsync(new DeviceEnrollmentRequest(2, device, "测试终端", "0.1.19"));
    var received = await client.FetchDevicePolicyAsync(device, enrolled.DeviceToken);
    var beat = await client.SendHeartbeatV2Async(heartbeat, enrolled.DeviceToken);
    var events = await client.SendDeviceEventsAsync(new EventBatchRequest(1, Guid.NewGuid(), device,
        [new EndpointEvent(Guid.NewGuid(), when, EventSeverity.Info, "test", "INTEROP", "Synthetic integration event", null, null, null)]),
        enrolled.DeviceToken);
    var adminToken = Environment.GetEnvironmentVariable("EAI_INTEROP_ADMIN_TOKEN")!;
    foreach (var type in new[] { RemoteCommandType.DisableProxy, RemoteCommandType.EnableProxy })
    {
        using var adminRequest = new HttpRequestMessage(HttpMethod.Post, new Uri(origin, $"/admin/v1/devices/{device}/commands"));
        adminRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", adminToken);
        adminRequest.Content = new StringContent(JsonSerializer.Serialize(new { type, reason = "Original client interop", expiresInMinutes = 10 }, options), Encoding.UTF8, "application/json");
        using var adminResponse = await http.SendAsync(adminRequest);
        adminResponse.EnsureSuccessStatusCode();
        var delivered = await client.SendHeartbeatV2Async(heartbeat, enrolled.DeviceToken);
        if (delivered.Command is null || delivered.Command.Payload.Type != type)
            throw new InvalidOperationException("Expected signed command was not delivered");
        foreach (var status in new[] { RemoteCommandStatus.Executing, RemoteCommandStatus.Succeeded })
            await client.SendCommandStatusAsync(new RemoteCommandStatusUpdate(1, device,
                delivered.Command.Payload.CommandId, status, DateTimeOffset.UtcNow, "INTEROP_OK", "Synthetic execution result"), enrolled.DeviceToken);
    }
    Console.WriteLine(JsonSerializer.Serialize(new { received.Policy.PolicyVersion, beat.AcceptedPolicyVersion, events.Accepted }, options));
    return;
}
throw new ArgumentException("Unknown command");

sealed class FakeControlHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> respond) : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        => respond(request);
}
