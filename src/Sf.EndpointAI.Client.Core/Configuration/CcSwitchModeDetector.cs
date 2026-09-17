using System.Net;
using System.Net.NetworkInformation;

namespace Sf.EndpointAI.Client.Core.Configuration;

public static class CcSwitchModeDetector
{
    public static CcSwitchAppModeStatus Detect(
        string appType,
        CcSwitchDatabaseInspection inspection,
        Uri? liveBaseUri)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(appType);
        ArgumentNullException.ThrowIfNull(inspection);

        if (!inspection.ProviderSchemaSupported
            || !inspection.ProxySchemaSupported
            || !inspection.EndpointSchemaSupported)
        {
            return new CcSwitchAppModeStatus(
                appType,
                CcSwitchOperatingMode.Unsupported,
                null,
                null,
                "CCSWITCH_SCHEMA_UNSUPPORTED");
        }

        if (!inspection.ProxyConfigs.TryGetValue(appType, out var config))
        {
            return new CcSwitchAppModeStatus(
                appType,
                CcSwitchOperatingMode.Ordinary,
                null,
                null,
                null);
        }

        var listenerOrigin = BuildListenerOrigin(config.ListenAddress, config.ListenPort);
        if (listenerOrigin is null)
        {
            return new CcSwitchAppModeStatus(
                appType,
                CcSwitchOperatingMode.Unsupported,
                null,
                null,
                "CCSWITCH_PROXY_LISTENER_INVALID");
        }

        var liveMatches = LivePointsToListener(appType, liveBaseUri, listenerOrigin);
        var listenerAvailable = IsListenerAvailable(listenerOrigin.Port);
        var evidence = new CcSwitchModeEvidence(
            config.ProxyEnabled,
            config.Enabled,
            config.LiveTakeoverActive,
            liveMatches,
            config.HasLiveBackup);
        if (config.Enabled && liveMatches)
        {
            return new CcSwitchAppModeStatus(
                appType,
                CcSwitchOperatingMode.LocalProxy,
                listenerOrigin,
                listenerAvailable,
                listenerAvailable ? null : "CCSWITCH_PROXY_LISTENER_UNAVAILABLE",
                evidence);
        }

        if (!config.Enabled && !liveMatches)
        {
            return new CcSwitchAppModeStatus(
                appType,
                CcSwitchOperatingMode.Ordinary,
                listenerOrigin,
                listenerAvailable,
                config.HasLiveBackup ? "CCSWITCH_STALE_LIVE_BACKUP_IGNORED" : null,
                evidence);
        }

        return new CcSwitchAppModeStatus(
            appType,
            CcSwitchOperatingMode.Inconsistent,
            listenerOrigin,
            listenerAvailable,
            "CCSWITCH_PROXY_STATE_INCONSISTENT",
            evidence);
    }

    internal static Uri? BuildListenerOrigin(string listenAddress, int listenPort)
    {
        if (listenPort is < 1 or > 65535 || string.IsNullOrWhiteSpace(listenAddress))
        {
            return null;
        }

        var connectHost = listenAddress switch
        {
            "0.0.0.0" => "127.0.0.1",
            "::" => "::1",
            _ => listenAddress,
        };
        var host = connectHost.Contains(':', StringComparison.Ordinal) ? $"[{connectHost}]" : connectHost;
        return Uri.TryCreate($"http://{host}:{listenPort}", UriKind.Absolute, out var result)
            ? result
            : null;
    }

    internal static bool LivePointsToListener(string appType, Uri? liveBaseUri, Uri listenerOrigin)
    {
        if (liveBaseUri is null
            || !string.Equals(liveBaseUri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(liveBaseUri.Host, listenerOrigin.Host, StringComparison.OrdinalIgnoreCase)
            || liveBaseUri.Port != listenerOrigin.Port
            || !string.IsNullOrEmpty(liveBaseUri.Query)
            || !string.IsNullOrEmpty(liveBaseUri.Fragment))
        {
            return false;
        }

        var path = liveBaseUri.AbsolutePath.TrimEnd('/');
        return string.Equals(appType, "codex", StringComparison.Ordinal)
            ? path is "" or "/v1"
            : path.Length == 0;
    }

    private static bool IsListenerAvailable(int port)
    {
        try
        {
            return IPGlobalProperties.GetIPGlobalProperties()
                .GetActiveTcpListeners()
                .Any(endpoint => endpoint.Port == port
                    && (IPAddress.IsLoopback(endpoint.Address)
                        || endpoint.Address.Equals(IPAddress.Any)
                        || endpoint.Address.Equals(IPAddress.IPv6Any)));
        }
        catch (NetworkInformationException)
        {
            return false;
        }
    }
}
