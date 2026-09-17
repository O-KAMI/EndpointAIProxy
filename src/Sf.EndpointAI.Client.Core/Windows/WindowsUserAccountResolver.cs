using System.Collections.Concurrent;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace Sf.EndpointAI.Client.Core.Windows;

public sealed record WindowsAccountIdentity(string UserId, bool UsedSidFallback);

public interface IWindowsUserAccountResolver
{
    WindowsAccountIdentity Resolve(string userSid);
}

[SupportedOSPlatform("windows")]
public sealed class WindowsUserAccountResolver : IWindowsUserAccountResolver
{
    private const string SfDomainPrefix = "SF\\";
    private readonly ConcurrentDictionary<string, WindowsAccountIdentity> _cache = new(StringComparer.OrdinalIgnoreCase);

    public WindowsAccountIdentity Resolve(string userSid)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userSid);
        return _cache.GetOrAdd(userSid, static sid =>
        {
            try
            {
                var account = new SecurityIdentifier(sid).Translate(typeof(NTAccount)) as NTAccount;
                return string.IsNullOrWhiteSpace(account?.Value)
                    ? new WindowsAccountIdentity(sid, UsedSidFallback: true)
                    : new WindowsAccountIdentity(NormalizeUserId(account.Value), UsedSidFallback: false);
            }
            catch (Exception exception) when (exception is ArgumentException
                or IdentityNotMappedException
                or PlatformNotSupportedException
                or SystemException)
            {
                return new WindowsAccountIdentity(sid, UsedSidFallback: true);
            }
        });
    }

    public static string NormalizeUserId(string accountName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(accountName);
        if (!accountName.StartsWith(SfDomainPrefix, StringComparison.OrdinalIgnoreCase))
        {
            return accountName;
        }

        var userId = accountName[SfDomainPrefix.Length..];
        return string.IsNullOrWhiteSpace(userId) ? accountName : userId;
    }
}
