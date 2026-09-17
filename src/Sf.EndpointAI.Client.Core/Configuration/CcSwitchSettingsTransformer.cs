using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Sf.EndpointAI.Client.Core.Configuration;

public sealed record CcSwitchSettingsTransformResult(
    string SettingsConfig,
    Uri OriginalBaseUri,
    string InjectedValue,
    bool Changed);

public static class CcSwitchSettingsTransformer
{
    private static readonly JsonSerializerOptions WriteOptions = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    public static CcSwitchSettingsTransformResult InjectBaseUrl(
        string appType,
        string settingsConfig,
        Uri injectedBaseUri,
        bool allowRemoteBaseUri = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(appType);
        ArgumentNullException.ThrowIfNull(settingsConfig);
        ArgumentNullException.ThrowIfNull(injectedBaseUri);

        JsonObject root;
        try
        {
            root = JsonNode.Parse(settingsConfig) as JsonObject
                ?? throw new ConfigMutationException("CCSWITCH_SETTINGS_ROOT_INVALID", "CC Switch settings_config must be a JSON object.");
        }
        catch (JsonException exception)
        {
            throw new ConfigMutationException("CCSWITCH_SETTINGS_PARSE_FAILED", "CC Switch settings_config contains invalid JSON.", exception);
        }

        string previous;
        string injectedValue;
        bool changed;
        switch (appType)
        {
            case "claude":
                var env = root["env"] as JsonObject
                    ?? throw new ConfigMutationException("CCSWITCH_CLAUDE_ENV_MISSING", "The Claude provider has no env object.");
                previous = env["ANTHROPIC_BASE_URL"]?.GetValue<string>()
                    ?? throw new ConfigMutationException("CCSWITCH_CLAUDE_BASE_URL_MISSING", "The Claude provider has no ANTHROPIC_BASE_URL.");
                injectedValue = injectedBaseUri.AbsoluteUri.TrimEnd('/');
                changed = !string.Equals(previous.TrimEnd('/'), injectedValue, StringComparison.Ordinal);
                if (changed)
                {
                    env["ANTHROPIC_BASE_URL"] = injectedValue;
                }

                break;

            case "codex":
                var config = root["config"]?.GetValue<string>()
                    ?? throw new ConfigMutationException("CCSWITCH_CODEX_CONFIG_MISSING", "The Codex provider has no config TOML string.");
                var transformed = CodexSettingsTransformer.InjectBaseUrl(
                    Encoding.UTF8.GetBytes(config),
                    injectedBaseUri,
                    allowRemoteBaseUri);
                previous = transformed.PreviousValue
                    ?? throw new ConfigMutationException("CCSWITCH_CODEX_BASE_URL_MISSING", "The Codex provider has no BaseURL.");
                injectedValue = transformed.InjectedValue;
                changed = transformed.Changed;
                if (changed)
                {
                    root["config"] = Encoding.UTF8.GetString(transformed.Content);
                }

                break;

            default:
                throw new ConfigMutationException(
                    "CCSWITCH_APP_UNSUPPORTED",
                    $"CC Switch app type '{appType}' is not supported by the prototype.");
        }

        if (!Uri.TryCreate(previous, UriKind.Absolute, out var originalBaseUri))
        {
            throw new ConfigMutationException("CCSWITCH_BASE_URL_INVALID", "The CC Switch provider BaseURL is not an absolute URI.");
        }

        var output = changed ? root.ToJsonString(WriteOptions) : settingsConfig;
        return new CcSwitchSettingsTransformResult(output, originalBaseUri, injectedValue, changed);
    }
}
