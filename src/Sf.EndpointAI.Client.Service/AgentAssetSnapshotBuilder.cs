using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sf.EndpointAI.Client.Core.Configuration;
using Sf.EndpointAI.Client.Core.Diagnostics;
using Sf.EndpointAI.Client.Core.Routing;
using Sf.EndpointAI.Client.Core.Windows;
using Sf.EndpointAI.Contracts;

namespace Sf.EndpointAI.Client.Service;

public sealed class AgentAssetSnapshotBuilder(
    IUserProfileProvider profileProvider,
    CcSwitchModeState ccSwitchModeState,
    BaseUrlBypassPolicy bypassPolicy)
{
    private const string DefaultAnthropicBaseUrl = "https://api.anthropic.com";
    private const string DefaultOpenAiBaseUrl = "https://api.openai.com/v1";
    private static readonly Regex TomlModelPattern = new(
        "^\\s*model\\s*=\\s*\"(?<value>(?:\\\\.|[^\"])*)\"",
        RegexOptions.Multiline | RegexOptions.CultureInvariant);
    private static readonly Regex TomlSectionPattern = new(
        "^\\s*\\[(?<name>[^\\]]+)\\]\\s*(?:#.*)?$",
        RegexOptions.CultureInvariant);
    private static readonly Regex TomlStringAssignmentPattern = new(
        "^\\s*(?<key>[A-Za-z0-9_-]+)\\s*=\\s*\"(?<value>(?:\\\\.|[^\"])*)\"\\s*(?:#.*)?$",
        RegexOptions.CultureInvariant);

    public async Task<IReadOnlyList<AgentEndpointAsset>> BuildAsync(
        IReadOnlyList<RouteRecord> routes,
        DateTimeOffset observedAtUtc,
        CancellationToken cancellationToken = default)
    {
        var profiles = profileProvider.GetProfiles().ToDictionary(profile => profile.Sid, StringComparer.Ordinal);
        var ccSwitchAssets = await InspectCcSwitchProvidersAsync(profiles.Values, cancellationToken);
        var ccSwitchOwnedFamilies = ccSwitchAssets
            .Select(asset => (asset.UserSid, asset.Family))
            .ToHashSet();
        var result = new Dictionary<Guid, AgentEndpointAsset>();
        foreach (var route in routes)
        {
            var family = AgentAssetIdentity.GetFamily(route);
            var source = GetSource(route);
            profiles.TryGetValue(route.UserSid, out var profile);
            var endpointId = GetEndpointId(route.ProviderId);
            var observedCcSwitchAsset = source == AgentConfigurationSource.Direct
                ? null
                : ccSwitchAssets.FirstOrDefault(asset =>
                    asset.UserSid == route.UserSid
                    && asset.Family == family
                    && asset.Source == source
                    && asset.ProviderId == GetCcSwitchProviderId(route.ProviderId)
                    && asset.EndpointId == endpointId);
            var directConfiguration = source == AgentConfigurationSource.Direct && profile is not null
                ? ReadDirectConfiguration(profile, family)
                : null;
            if (source == AgentConfigurationSource.Direct)
            {
                if (ccSwitchOwnedFamilies.Contains((route.UserSid, family))
                    || directConfiguration is not { Exists: true })
                {
                    continue;
                }
            }
            else if (observedCcSwitchAsset is null)
            {
                // A Route Registry row is observation history, not proof that the
                // corresponding Provider or Endpoint still exists in CC Switch.
                continue;
            }

            var model = source == AgentConfigurationSource.Direct
                ? directConfiguration?.Model
                : observedCcSwitchAsset!.Model;
            var localRouteUrl = DiagnosticSanitizer.SanitizeUri(route.InjectedBaseUri.AbsoluteUri);
            var ccSwitchLocalProxy = route.AgentType == AgentType.CcSwitch
                && string.Equals(ccSwitchModeState.GetReportedMode(route.UserSid, family), "local-proxy", StringComparison.Ordinal);
            var observedBaseUri = source == AgentConfigurationSource.Direct
                ? directConfiguration is { Exists: true } ? directConfiguration.BaseUri : null
                : observedCcSwitchAsset?.BaseUri;
            var allowlistBypassed = bypassPolicy.ShouldBypass(route.OriginalBaseUri);
            var configuredMatchesRoute = observedBaseUri is not null
                && SameBaseUri(observedBaseUri, route.InjectedBaseUri);
            var restoredAllowlistedOriginal = source == AgentConfigurationSource.Direct
                && allowlistBypassed
                && observedBaseUri is not null
                && SameBaseUri(observedBaseUri, route.OriginalBaseUri);
            if (source == AgentConfigurationSource.Direct
                && !configuredMatchesRoute
                && !restoredAllowlistedOriginal)
            {
                // Do not combine a current Direct model with an unrelated historical Route.
                continue;
            }

            var effectiveUrl = ccSwitchLocalProxy
                ? family == "codex" ? "http://127.0.0.1:15721/v1" : "http://127.0.0.1:15721"
                : observedBaseUri is null
                    ? localRouteUrl
                    : DiagnosticSanitizer.SanitizeUri(observedBaseUri.AbsoluteUri);
            var isCurrent = source == AgentConfigurationSource.Direct || observedCcSwitchAsset!.IsCurrent;
            var assetId = AgentAssetIdentity.Create(route);
            result[assetId] = new AgentEndpointAsset(
                assetId,
                route.UserSid,
                family,
                source,
                source == AgentConfigurationSource.Direct ? "direct" : GetCcSwitchProviderId(route.ProviderId),
                endpointId,
                isCurrent,
                model,
                family == "claude" ? AgentWireApi.AnthropicMessages : AgentWireApi.OpenAiResponses,
                DiagnosticSanitizer.SanitizeUri(route.OriginalBaseUri.AbsoluteUri),
                effectiveUrl,
                localRouteUrl,
                allowlistBypassed,
                allowlistBypassed
                    ? RouteStatus.Bypassed
                    : configuredMatchesRoute ? route.Status
                    : isCurrent ? RouteStatus.NonCompliant
                    : RouteStatus.Discovered,
                observedAtUtc);
        }

        foreach (var profile in profiles.Values)
        {
            AddDirectConfigurationAsset(
                result,
                profile,
                "claude",
                ccSwitchOwnedFamilies.Contains((profile.Sid, "claude")),
                observedAtUtc);
            AddDirectConfigurationAsset(
                result,
                profile,
                "codex",
                ccSwitchOwnedFamilies.Contains((profile.Sid, "codex")),
                observedAtUtc);
        }

        foreach (var asset in ccSwitchAssets.Where(asset => asset.BaseUri is not null))
        {
            var baseUri = asset.BaseUri!;
            var providerIdentity = asset.Source == AgentConfigurationSource.CcSwitchEndpoint
                ? $"{asset.Family}:{asset.ProviderId}:endpoint:{asset.EndpointId}"
                : $"{asset.Family}:{asset.ProviderId}";
            var assetId = AgentAssetIdentity.Create(
                asset.UserSid,
                asset.Family,
                providerIdentity);
            if (result.ContainsKey(assetId))
            {
                continue;
            }

            var allowlistBypassed = bypassPolicy.ShouldBypass(baseUri);
            var effectiveUrl = string.Equals(ccSwitchModeState.GetReportedMode(asset.UserSid, asset.Family), "local-proxy", StringComparison.Ordinal)
                ? asset.Family == "codex" ? "http://127.0.0.1:15721/v1" : "http://127.0.0.1:15721"
                : DiagnosticSanitizer.SanitizeUri(baseUri.AbsoluteUri);
            result[assetId] = new AgentEndpointAsset(
                assetId,
                asset.UserSid,
                asset.Family,
                asset.Source,
                asset.ProviderId,
                asset.EndpointId,
                asset.IsCurrent,
                asset.Model,
                asset.Family == "claude" ? AgentWireApi.AnthropicMessages : AgentWireApi.OpenAiResponses,
                DiagnosticSanitizer.SanitizeUri(baseUri.AbsoluteUri),
                effectiveUrl,
                null,
                allowlistBypassed,
                allowlistBypassed ? RouteStatus.Bypassed : RouteStatus.Discovered,
                observedAtUtc);
        }

        return result.Values.ToArray();
    }

    private void AddDirectConfigurationAsset(
        Dictionary<Guid, AgentEndpointAsset> result,
        WindowsUserProfile profile,
        string family,
        bool ccSwitchOwned,
        DateTimeOffset observedAtUtc)
    {
        if (ccSwitchOwned)
        {
            return;
        }

        var configuration = ReadDirectConfiguration(profile, family);
        if (!configuration.Exists)
        {
            return;
        }

        var pointsToEndpointProxy = IsEndpointProxyUri(configuration.BaseUri);
        if (pointsToEndpointProxy
            && result.Values.Any(asset =>
                asset.UserSid == profile.Sid
                && asset.AgentFamily == family
                && asset.ConfigurationSource == AgentConfigurationSource.Direct))
        {
            return;
        }

        var assetId = AgentAssetIdentity.Create(
            profile.Sid,
            family,
            "direct");
        if (result.ContainsKey(assetId))
        {
            return;
        }

        var allowlistBypassed = configuration.BaseUri is not null && bypassPolicy.ShouldBypass(configuration.BaseUri);
        var sanitized = configuration.BaseUri is null
            ? null
            : DiagnosticSanitizer.SanitizeUri(configuration.BaseUri.AbsoluteUri);
        result[assetId] = new AgentEndpointAsset(
            assetId,
            profile.Sid,
            family,
            AgentConfigurationSource.Direct,
            "direct",
            null,
            true,
            configuration.Model,
            family == "claude" ? AgentWireApi.AnthropicMessages : AgentWireApi.OpenAiResponses,
            pointsToEndpointProxy ? null : sanitized,
            sanitized,
            pointsToEndpointProxy ? sanitized : null,
            allowlistBypassed,
            allowlistBypassed
                ? RouteStatus.Bypassed
                : pointsToEndpointProxy ? RouteStatus.NonCompliant : RouteStatus.Discovered,
            observedAtUtc);
    }

    private static bool IsEndpointProxyUri(Uri? value) =>
        value is not null
        && value.Port == 18080
        && (string.Equals(value.Host, "127.0.0.1", StringComparison.OrdinalIgnoreCase)
            || string.Equals(value.Host, "localhost", StringComparison.OrdinalIgnoreCase)
            || string.Equals(value.Host, "::1", StringComparison.OrdinalIgnoreCase));

    private static bool SameBaseUri(Uri first, Uri second) =>
        string.Equals(
            first.AbsoluteUri.TrimEnd('/'),
            second.AbsoluteUri.TrimEnd('/'),
            StringComparison.OrdinalIgnoreCase);

    private static AgentConfigurationSource GetSource(RouteRecord route)
    {
        if (route.AgentType != AgentType.CcSwitch)
        {
            return AgentConfigurationSource.Direct;
        }

        return route.ProviderId.Contains(":endpoint:", StringComparison.Ordinal)
            ? AgentConfigurationSource.CcSwitchEndpoint
            : AgentConfigurationSource.CcSwitchProvider;
    }

    private static string GetCcSwitchProviderId(string providerId)
    {
        var value = providerId;
        var firstSeparator = value.IndexOf(':');
        if (firstSeparator >= 0)
        {
            value = value[(firstSeparator + 1)..];
        }

        var endpointSeparator = value.IndexOf(":endpoint:", StringComparison.Ordinal);
        return endpointSeparator < 0 ? value : value[..endpointSeparator];
    }

    private static string? GetEndpointId(string providerId)
    {
        var marker = providerId.IndexOf(":endpoint:", StringComparison.Ordinal);
        return marker < 0 ? null : providerId[(marker + ":endpoint:".Length)..];
    }

    private static DirectConfiguration ReadDirectConfiguration(WindowsUserProfile profile, string family)
    {
        try
        {
            if (family == "claude")
            {
                var claudePath = Path.Combine(profile.ProfilePath, ".claude", "settings.json");
                if (!File.Exists(claudePath))
                {
                    return new DirectConfiguration(false, null, null);
                }

                var root = JsonNode.Parse(File.ReadAllText(claudePath, Encoding.UTF8)) as JsonObject;
                var env = root?["env"] as JsonObject;
                var value = env?["ANTHROPIC_BASE_URL"]?.GetValue<string>();
                return new DirectConfiguration(
                    true,
                    ReadClaudeModel(root?.ToJsonString() ?? "{}"),
                    value is null
                        ? new Uri(DefaultAnthropicBaseUrl)
                        : Uri.TryCreate(value, UriKind.Absolute, out var claudeUri) ? claudeUri : null);
            }

            var codexPath = Path.Combine(profile.ProfilePath, ".codex", "config.toml");
            if (!File.Exists(codexPath))
            {
                return new DirectConfiguration(false, null, null);
            }

            var config = File.ReadAllText(codexPath, Encoding.UTF8);
            return new DirectConfiguration(
                true,
                ReadCodexModel(config),
                ReadCodexBaseUri(config));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException or InvalidOperationException)
        {
            return new DirectConfiguration(false, null, null);
        }
    }

    private static async Task<IReadOnlyList<CcSwitchAssetMetadata>> InspectCcSwitchProvidersAsync(
        IEnumerable<WindowsUserProfile> profiles,
        CancellationToken cancellationToken)
    {
        var result = new List<CcSwitchAssetMetadata>();
        foreach (var profile in profiles)
        {
            var databasePath = Path.Combine(profile.ProfilePath, ".cc-switch", "cc-switch.db");
            if (!File.Exists(databasePath))
            {
                continue;
            }

            try
            {
                var inspection = await CcSwitchDatabaseAdapter.InspectAsync(databasePath, cancellationToken);
                foreach (var provider in inspection.Providers)
                {
                    var model = TryReadProviderModel(provider.AppType, provider.SettingsConfig);
                    result.Add(new CcSwitchAssetMetadata(
                        profile.Sid,
                        provider.AppType,
                        provider.ProviderId,
                        null,
                        AgentConfigurationSource.CcSwitchProvider,
                        model,
                        provider.IsCurrent,
                        provider.OriginalBaseUri));
                }

                foreach (var endpoint in inspection.Endpoints)
                {
                    var provider = result.FirstOrDefault(item =>
                        item.UserSid == profile.Sid
                        && item.Family == endpoint.AppType
                        && item.ProviderId == endpoint.ProviderId
                        && item.Source == AgentConfigurationSource.CcSwitchProvider);
                    result.Add(new CcSwitchAssetMetadata(
                        profile.Sid,
                        endpoint.AppType,
                        endpoint.ProviderId,
                        endpoint.EndpointId.ToString(System.Globalization.CultureInfo.InvariantCulture),
                        AgentConfigurationSource.CcSwitchEndpoint,
                        provider?.Model,
                        provider?.IsCurrent == true,
                        endpoint.OriginalBaseUri));
                }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or Microsoft.Data.Sqlite.SqliteException)
            {
                // Asset collection is read-only and best effort; attachment errors are reported separately.
            }
        }

        return result;
    }

    private static string? ReadClaudeProviderModel(string settingsConfig)
    {
        var root = JsonNode.Parse(settingsConfig) as JsonObject;
        return root?["env"] is JsonObject env ? ReadClaudeModel(env) : null;
    }

    private static string? ReadCodexProviderModel(string settingsConfig)
    {
        var root = JsonNode.Parse(settingsConfig) as JsonObject;
        return root?["config"]?.GetValue<string>() is { } config ? ReadCodexModel(config) : null;
    }

    private static string? TryReadProviderModel(string appType, string settingsConfig)
    {
        try
        {
            return appType == "claude"
                ? ReadClaudeProviderModel(settingsConfig)
                : ReadCodexProviderModel(settingsConfig);
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException)
        {
            return null;
        }
    }

    private static Uri? ReadCodexBaseUri(string config)
    {
        string? section = null;
        string? activeProvider = null;
        string? topLevelBaseUrl = null;
        var providerBaseUrls = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var line in config.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n'))
        {
            var sectionMatch = TomlSectionPattern.Match(line);
            if (sectionMatch.Success)
            {
                section = sectionMatch.Groups["name"].Value.Trim();
                continue;
            }

            var assignment = TomlStringAssignmentPattern.Match(line);
            if (!assignment.Success)
            {
                continue;
            }

            var key = assignment.Groups["key"].Value;
            var value = UnescapeTomlBasicString(assignment.Groups["value"].Value);
            if (section is null && key == "model_provider")
            {
                activeProvider = value;
            }
            else if (section is null && key == "openai_base_url")
            {
                topLevelBaseUrl = value;
            }
            else if (key == "base_url"
                && section is not null
                && section.StartsWith("model_providers.", StringComparison.Ordinal))
            {
                providerBaseUrls[section["model_providers.".Length..]] = value;
            }
        }

        string? selected = activeProvider is not null && activeProvider != "openai"
            ? providerBaseUrls.GetValueOrDefault(activeProvider)
            : topLevelBaseUrl ?? DefaultOpenAiBaseUrl;
        return Uri.TryCreate(selected, UriKind.Absolute, out var uri) ? uri : null;
    }

    private static string? ReadClaudeModel(string settingsJson)
    {
        var root = JsonNode.Parse(settingsJson) as JsonObject;
        if (root?["model"]?.GetValue<string>() is { Length: > 0 } rootModel)
        {
            return rootModel;
        }

        return root?["env"] is JsonObject env ? ReadClaudeModel(env) : null;
    }

    private static string? ReadClaudeModel(JsonObject env)
    {
        string[] keys =
        [
            "ANTHROPIC_MODEL",
            "ANTHROPIC_DEFAULT_SONNET_MODEL",
            "ANTHROPIC_DEFAULT_OPUS_MODEL",
            "ANTHROPIC_DEFAULT_HAIKU_MODEL",
        ];
        return keys.Select(key => env[key]?.GetValue<string>()).FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));
    }

    private static string? ReadCodexModel(string config)
    {
        var match = TomlModelPattern.Match(config);
        return match.Success
            ? match.Groups["value"].Value.Replace("\\\"", "\"", StringComparison.Ordinal).Replace("\\\\", "\\", StringComparison.Ordinal)
            : null;
    }

    private static string UnescapeTomlBasicString(string value) => value
        .Replace("\\\"", "\"", StringComparison.Ordinal)
        .Replace("\\\\", "\\", StringComparison.Ordinal);

    private sealed record DirectConfiguration(bool Exists, string? Model, Uri? BaseUri);

    private sealed record CcSwitchAssetMetadata(
        string UserSid,
        string Family,
        string ProviderId,
        string? EndpointId,
        AgentConfigurationSource Source,
        string? Model,
        bool IsCurrent,
        Uri? BaseUri);
}
