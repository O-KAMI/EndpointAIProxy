using System.Text.Json;
using Sf.EndpointAI.InstallerActions;
var data = new Dictionary<string,string>
{
 ["origin"]="http://control.example.invalid:8080", ["clientToken"]="synthetic_token_12345",
 ["transportKey"]=Convert.ToBase64String(new byte[32]),
 ["policyHmacKey"]=Convert.ToBase64String(new byte[32]), ["keyId"]="test"
};
int passed = 0;
void Check(bool ok) { if (!ok) throw new InvalidOperationException("Check failed."); passed++; }
void Reject(Action action) {
 bool rejected=false;
 try { action(); } catch (Exception ex) when (ex is InvalidDataException or FormatException or ArgumentException) { rejected=true; }
 Check(rejected);
}
Check(InstallerPolicy.Credentials(JsonSerializer.Serialize(data)).Count == 6);
foreach (var key in data.Keys.ToArray()) {
 var copy = new Dictionary<string,string>(data); copy.Remove(key);
 Reject(() => InstallerPolicy.Credentials(JsonSerializer.Serialize(copy)));
}
foreach (var pair in new[] { ("origin","https://wrong.example"), ("transportKey","short"), ("keyId","bad id"), ("clientToken","short"), ("policyHmacKey",Convert.ToBase64String(new byte[1])) }) {
 var copy = new Dictionary<string,string>(data) { [pair.Item1]=pair.Item2 };
 Reject(() => InstallerPolicy.Credentials(JsonSerializer.Serialize(copy)));
}
var extra = new Dictionary<string,string>(data) { ["adminToken"]="must-not-ship" };
Reject(() => InstallerPolicy.Credentials(JsonSerializer.Serialize(extra)));
Check(InstallerPolicy.IsControlOverride("SF_PROXY_CONTROL_TOKEN=synthetic"));
Check(InstallerPolicy.IsControlOverride("sf_proxy_control_transport_key=test"));
Check(!InstallerPolicy.IsControlOverride("SF_PROXY_GATEWAY_HMAC_KEY=preserve"));
Check(!InstallerPolicy.IsControlOverride("PATH=preserve"));
Console.WriteLine($"{passed} installer policy checks passed (synthetic credentials only).");
