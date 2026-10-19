using Sf.EndpointAI.Client.Core.Routing;
using Sf.EndpointAI.Client.Core.Security;
using Sf.EndpointAI.Client.Core.State;
using Sf.EndpointAI.Contracts;

if (args.Length != 2) throw new ArgumentException("Expected mode and temporary directory.");
var mode = args[0];
var root = args[1];
var protector = new FileKeyTextProtector(Path.Combine(root, "machine.key"));
var at = DateTimeOffset.Parse("2026-09-13T01:02:03.1234567+00:00");
var commandId = Guid.Parse("30000000-0000-0000-0000-000000000003");
var serverId = Guid.Parse("40000000-0000-0000-0000-000000000004");
var path = Path.Combine(root, mode == "write" ? "dotnet.db" : "go.db");
var store = new SqliteClientStateStore(path, protector);
var routes = new SqliteRouteRegistry(path, protector);
await store.InitializeAsync();
await routes.InitializeAsync();
void Check(bool ok, string field) { if (!ok) throw new InvalidOperationException("Synthetic fixture mismatch: " + field); }
if (mode == "write")
{
    File.WriteAllBytes(Path.Combine(root, "dotnet.blob"), protector.Protect("synthetic-dotnet-protected"));
    var id = await store.GetOrCreateDeviceIdAsync();
    File.WriteAllText(Path.Combine(root, "dotnet-device-id"), id.ToString("D"));
    await store.SaveDeviceCredentialAsync(new StoredDeviceCredential("synthetic-dotnet-token", at, "https://example.invalid/", "synthetic-pin"));
    await store.SavePolicyAsync(new EndpointPolicy(1, serverId, 41, true, RouteMode.PassthroughOriginal, null, false, 60, 60, at, []), "synthetic-signature", at);
    await store.SaveOperationStateAsync(new StoredClientOperationState(ClientOperationState.Disabled, at, "SYNTHETIC_CODE", "Synthetic summary"));
    await store.SaveCommandReceiptAsync(new StoredCommandReceipt(commandId, RemoteCommandType.DisableProxy, RemoteCommandStatus.Executing, at, null, "SYNTHETIC_CODE", "Synthetic summary", id, at, at.AddHours(1)));
    await routes.UpsertAsync(new RouteRecord("interop-route", "synthetic-user", AgentType.ClaudeCli, "direct", new Uri("https://example.invalid/v1"), new Uri("http://127.0.0.1:18080/r/interop-route"), RouteStatus.Attached, at, at));
}
else if (mode == "check")
{
    Check(protector.Unprotect(File.ReadAllBytes(Path.Combine(root, "go.blob"))) == "synthetic-go-protected", "Go AES blob");
    var expectedId = Guid.Parse(File.ReadAllText(Path.Combine(root, "go-device-id")));
    Check(await store.GetOrCreateDeviceIdAsync() == expectedId, "device identity");
    var credential = await store.LoadDeviceCredentialAsync();
    Check(credential is not null && credential.Token == "synthetic-go-token" && credential.EnrolledAtUtc == at && credential.ServerOrigin == "https://example.invalid/" && credential.ServerCertificateSpkiSha256 == "synthetic-pin", "credential");
    var policy = await store.LoadPolicyAsync();
    Check(policy is not null && policy.Policy.PolicyVersion == 42 && policy.Policy.ServerInstanceId == serverId && policy.Policy.RouteMode == RouteMode.PassthroughOriginal && policy.Policy.GatewayOrigin is null && policy.Policy.AllowlistedBaseUrls is { Count: 0 } && policy.Policy.IssuedAtUtc == at && policy.ReceivedAtUtc == at && policy.Signature == "synthetic-signature", "policy");
    var operation = await store.LoadOperationStateAsync();
    Check(operation.State == ClientOperationState.Disabled && operation.UpdatedAtUtc == at && operation.LastErrorCode == "SYNTHETIC_CODE", "operation");
    var receipt = await store.LoadCommandReceiptAsync(commandId);
    Check(receipt is not null && receipt.Type == RemoteCommandType.DisableProxy && receipt.Status == RemoteCommandStatus.Executing && receipt.DeviceId == expectedId && receipt.ReceivedAtUtc == at && receipt.CompletedAtUtc is null && receipt.IssuedAtUtc == at && receipt.ExpiresAtUtc == at.AddHours(1), "receipt");
    var route = await routes.FindAsync("interop-route");
    Check(route is not null && route.UserSid == "synthetic-user" && route.AgentType == AgentType.ClaudeCli && route.ProviderId == "direct" && route.Status == RouteStatus.Attached && route.OriginalBaseUri.AbsoluteUri == "https://example.invalid/v1" && route.InjectedBaseUri.AbsoluteUri == "http://127.0.0.1:18080/r/interop-route" && route.CreatedAtUtc == at && route.UpdatedAtUtc == at, "route");
}
else throw new ArgumentException("Unknown mode.");
