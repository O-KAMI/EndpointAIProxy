using System.Collections.Concurrent;

namespace Sf.EndpointAI.Client.Core.Configuration;

public enum CcSwitchOperatingMode
{
    Ordinary,
    LocalProxy,
    Inconsistent,
    Unsupported,
}

public enum CcSwitchAppOwnership
{
    Direct,
    CcSwitch,
    Blocked,
}

public sealed record CcSwitchAppOwnershipStatus(
    string AppType,
    CcSwitchAppOwnership Ownership,
    int ProviderCount,
    int EndpointCount,
    string? ErrorCode);

public sealed record CcSwitchAppModeStatus(
    string AppType,
    CcSwitchOperatingMode Mode,
    Uri? ListenerOrigin,
    bool? ListenerAvailable,
    string? ErrorCode,
    CcSwitchModeEvidence? Evidence = null);

public sealed record CcSwitchModeEvidence(
    bool ProxyEnabled,
    bool AppEnabled,
    bool LiveTakeoverActive,
    bool LivePointsToListener,
    bool HasLiveBackup);

public sealed class CcSwitchModeState
{
    private readonly ConcurrentDictionary<(string UserKey, string AppType), CcSwitchAppModeStatus> _statuses = new();

    public void Update(string userKey, IEnumerable<CcSwitchAppModeStatus> statuses)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userKey);
        ArgumentNullException.ThrowIfNull(statuses);
        foreach (var status in statuses)
        {
            _statuses[(userKey, status.AppType)] = status;
        }
    }

    public CcSwitchAppModeStatus? Get(string userKey, string appType) =>
        _statuses.TryGetValue((userKey, appType), out var status) ? status : null;

    public string? GetReportedMode(string userKey, string? appType = null)
    {
        if (appType is not null)
        {
            return Get(userKey, appType) is { } status ? ToWireValue(status.Mode) : null;
        }

        var modes = _statuses
            .Where(pair => string.Equals(pair.Key.UserKey, userKey, StringComparison.Ordinal))
            .Select(pair => pair.Value.Mode)
            .Distinct()
            .ToArray();
        return modes.Length switch
        {
            0 => null,
            1 => ToWireValue(modes[0]),
            _ => "mixed",
        };
    }

    public static string ToWireValue(CcSwitchOperatingMode mode) => mode switch
    {
        CcSwitchOperatingMode.Ordinary => "ordinary",
        CcSwitchOperatingMode.LocalProxy => "local-proxy",
        CcSwitchOperatingMode.Inconsistent => "inconsistent",
        CcSwitchOperatingMode.Unsupported => "unsupported",
        _ => "unsupported",
    };
}
