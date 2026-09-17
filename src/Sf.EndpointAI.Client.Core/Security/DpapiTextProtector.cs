using System.Security.Cryptography;
using System.Runtime.Versioning;
using System.Text;

namespace Sf.EndpointAI.Client.Core.Security;

[SupportedOSPlatform("windows")]
public sealed class DpapiTextProtector : ITextProtector
{
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("SF.EndpointAI.Route.v1");

    public byte[] Protect(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        EnsureWindows();
        return ProtectedData.Protect(Encoding.UTF8.GetBytes(value), Entropy, DataProtectionScope.LocalMachine);
    }

    public string Unprotect(byte[] protectedValue)
    {
        ArgumentNullException.ThrowIfNull(protectedValue);
        EnsureWindows();
        var clear = ProtectedData.Unprotect(protectedValue, Entropy, DataProtectionScope.LocalMachine);
        return Encoding.UTF8.GetString(clear);
    }

    private static void EnsureWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Route protection requires Windows DPAPI.");
        }
    }
}
