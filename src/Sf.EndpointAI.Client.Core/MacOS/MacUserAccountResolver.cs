using Sf.EndpointAI.Client.Core.Windows;

namespace Sf.EndpointAI.Client.Core.MacOS;

public sealed class MacUserAccountResolver : IWindowsUserAccountResolver
{
    private const string Prefix = "macos:";

    public WindowsAccountIdentity Resolve(string userSid)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userSid);
        return userSid.StartsWith(Prefix, StringComparison.Ordinal)
            ? new WindowsAccountIdentity(userSid[Prefix.Length..], UsedSidFallback: false)
            : new WindowsAccountIdentity(userSid, UsedSidFallback: true);
    }
}
