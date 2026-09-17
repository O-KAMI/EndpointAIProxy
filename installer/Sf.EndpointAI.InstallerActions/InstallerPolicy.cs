using System.Text.Json;
using System.Text.RegularExpressions;

namespace Sf.EndpointAI.InstallerActions;

public static partial class InstallerPolicy
{
    public static readonly string[] ControlNames =
    [
        "ControlServerOrigin", "ControlEnrollmentToken", "ControlPolicyHmacKey",
        "ControlTransportKey", "ControlTransportKeyId", "ControlServerCertificateSpkiSha256"
    ];

    public static Dictionary<string, string> Credentials(string json)
    {
        var data = JsonSerializer.Deserialize<Dictionary<string, string>>(json) ?? throw new InvalidDataException();
        string[] names = ["origin", "clientToken", "policyHmacKey", "transportKey", "keyId"];
        if (data.Count != names.Length || names.Any(n => !data.ContainsKey(n)))
            throw new InvalidDataException();
        if (data["origin"] != "http://control.example.invalid:8080"
            || !TokenPattern().IsMatch(data["clientToken"])
            || !KeyIdPattern().IsMatch(data["keyId"])
            || Convert.FromBase64String(data["transportKey"]).Length != 32
            || Convert.FromBase64String(data["policyHmacKey"]).Length < 32)
            throw new InvalidDataException();
        return new()
        {
            ["ControlServerOrigin"] = data["origin"],
            ["ControlEnrollmentToken"] = data["clientToken"],
            ["ControlPolicyHmacKey"] = data["policyHmacKey"],
            ["ControlTransportKey"] = data["transportKey"],
            ["ControlTransportKeyId"] = data["keyId"],
            ["ControlServerCertificateSpkiSha256"] = ""
        };
    }

    private static readonly string[] OverrideSuffixes = ["ORIGIN", "TOKEN", "HMAC_KEY", "TRANSPORT_KEY", "TRANSPORT_KEY_ID", "SERVER_CERTIFICATE_SPKI_SHA256"];

    public static bool IsControlOverride(string line)
    {
        var name = line.Split('=', 2)[0];
        return name.Equals("SF_PROXY_ALLOW_INSECURE_CONTROL_SERVER", StringComparison.OrdinalIgnoreCase)
            || OverrideSuffixes
                .Any(suffix => name.Equals("SF_PROXY_CONTROL_" + suffix, StringComparison.OrdinalIgnoreCase));
    }

    [GeneratedRegex("^[A-Za-z0-9_-]{16,}$", RegexOptions.CultureInvariant)]
    private static partial Regex TokenPattern();
    [GeneratedRegex("^[A-Za-z0-9_-]{1,64}$", RegexOptions.CultureInvariant)]
    private static partial Regex KeyIdPattern();
}
