using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Sf.EndpointAI.Client.Core.Configuration;

public static class ClaudeSettingsTransformer
{
    private const string BaseUrlKey = "ANTHROPIC_BASE_URL";

    private static readonly JsonSerializerOptions WriteOptions = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    public static ConfigTransformResult InjectBaseUrl(
        ReadOnlySpan<byte> existingContent,
        Uri injectedBaseUri,
        bool allowRemoteBaseUri = false)
    {
        ArgumentNullException.ThrowIfNull(injectedBaseUri);
        if (!injectedBaseUri.IsAbsoluteUri
            || (!string.Equals(injectedBaseUri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
                && !string.Equals(injectedBaseUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            || (!allowRemoteBaseUri
                && (!injectedBaseUri.IsLoopback
                    || !string.Equals(injectedBaseUri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))))
        {
            throw new ConfigMutationException(
                "INJECTED_BASE_URL_INVALID",
                allowRemoteBaseUri
                    ? "Claude direct BaseURL must be an absolute HTTP or HTTPS URI."
                    : "Claude BaseURL must be an absolute HTTP loopback URI.");
        }

        JsonObject root;
        try
        {
            root = existingContent.IsEmpty
                ? new JsonObject()
                : JsonNode.Parse(existingContent) as JsonObject
                    ?? throw new ConfigMutationException("CLAUDE_SETTINGS_ROOT_INVALID", "Claude settings must contain a JSON object.");
        }
        catch (JsonException exception)
        {
            throw new ConfigMutationException("CLAUDE_SETTINGS_PARSE_FAILED", "Claude settings contain invalid JSON.", exception);
        }

        JsonObject env;
        if (root["env"] is null)
        {
            env = new JsonObject();
            root["env"] = env;
        }
        else if (root["env"] is JsonObject existingEnv)
        {
            env = existingEnv;
        }
        else
        {
            throw new ConfigMutationException("CLAUDE_SETTINGS_ENV_INVALID", "Claude settings env must be a JSON object.");
        }

        string? previous = null;
        if (env[BaseUrlKey] is JsonValue previousNode
            && previousNode.TryGetValue<string>(out var previousValue))
        {
            previous = previousValue;
        }
        else if (env[BaseUrlKey] is not null)
        {
            throw new ConfigMutationException("CLAUDE_BASE_URL_TYPE_INVALID", "ANTHROPIC_BASE_URL must be a string.");
        }

        var injectedValue = injectedBaseUri.AbsoluteUri.TrimEnd('/');
        if (string.Equals(previous, injectedValue, StringComparison.Ordinal))
        {
            return new ConfigTransformResult(existingContent.ToArray(), previous, injectedValue, Changed: false);
        }

        env[BaseUrlKey] = injectedValue;
        var json = root.ToJsonString(WriteOptions) + Environment.NewLine;
        return new ConfigTransformResult(Encoding.UTF8.GetBytes(json), previous, injectedValue, Changed: true);
    }
}
