using System.Text;
using System.Text.RegularExpressions;

namespace Sf.EndpointAI.Client.Core.Configuration;

public static partial class CodexSettingsTransformer
{
    private const string DefaultOpenAiBaseUrl = "https://api.openai.com/v1";
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public static ConfigTransformResult InjectBaseUrl(
        ReadOnlySpan<byte> existingContent,
        Uri injectedBaseUri,
        bool allowRemoteBaseUri = false)
    {
        ValidateInjectedBaseUri(injectedBaseUri, allowRemoteBaseUri);

        string content;
        try
        {
            content = StrictUtf8.GetString(existingContent);
        }
        catch (DecoderFallbackException exception)
        {
            throw new ConfigMutationException("CODEX_CONFIG_ENCODING_INVALID", "Codex config must be UTF-8.", exception);
        }

        var newline = content.Contains("\r\n", StringComparison.Ordinal) ? "\r\n" : "\n";
        var hadTrailingNewline = content.EndsWith('\n');
        var lines = content.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n').ToList();
        if (hadTrailingNewline && lines.Count > 0 && lines[^1].Length == 0)
        {
            lines.RemoveAt(lines.Count - 1);
        }

        string? activeProvider = null;
        string? section = null;
        var firstSectionLine = -1;
        var topLevelBaseUrlLine = -1;
        string? topLevelBaseUrl = null;
        var providerBaseUrlLine = -1;
        string? providerBaseUrl = null;
        var activeProviderSectionFound = false;

        for (var index = 0; index < lines.Count; index++)
        {
            var sectionMatch = SectionPattern().Match(lines[index]);
            if (sectionMatch.Success)
            {
                section = sectionMatch.Groups["name"].Value.Trim();
                firstSectionLine = firstSectionLine < 0 ? index : firstSectionLine;
                if (activeProvider is not null
                    && string.Equals(section, $"model_providers.{activeProvider}", StringComparison.Ordinal))
                {
                    activeProviderSectionFound = true;
                }

                continue;
            }

            var assignment = StringAssignmentPattern().Match(lines[index]);
            if (!assignment.Success)
            {
                continue;
            }

            var key = assignment.Groups["key"].Value;
            var value = UnescapeTomlBasicString(assignment.Groups["value"].Value);
            if (section is null && string.Equals(key, "model_provider", StringComparison.Ordinal))
            {
                activeProvider = value;
                continue;
            }

            if (section is null && string.Equals(key, "openai_base_url", StringComparison.Ordinal))
            {
                topLevelBaseUrlLine = index;
                topLevelBaseUrl = value;
                continue;
            }

            if (activeProvider is not null
                && string.Equals(section, $"model_providers.{activeProvider}", StringComparison.Ordinal)
                && string.Equals(key, "base_url", StringComparison.Ordinal))
            {
                providerBaseUrlLine = index;
                providerBaseUrl = value;
            }
        }

        var injectedValue = injectedBaseUri.AbsoluteUri.TrimEnd('/');
        string previous;
        if (activeProvider is not null
            && !string.Equals(activeProvider, "openai", StringComparison.Ordinal))
        {
            if (!activeProviderSectionFound)
            {
                throw new ConfigMutationException(
                    "CODEX_PROVIDER_SECTION_MISSING",
                    $"Codex model provider '{activeProvider}' has no matching configuration section.");
            }

            if (providerBaseUrlLine < 0 || string.IsNullOrWhiteSpace(providerBaseUrl))
            {
                throw new ConfigMutationException(
                    "CODEX_PROVIDER_BASE_URL_MISSING",
                    $"Codex model provider '{activeProvider}' has no BaseURL.");
            }

            previous = providerBaseUrl;
            if (string.Equals(previous.TrimEnd('/'), injectedValue, StringComparison.Ordinal))
            {
                return new ConfigTransformResult(existingContent.ToArray(), previous, injectedValue, Changed: false);
            }

            lines[providerBaseUrlLine] = ReplaceStringAssignment(lines[providerBaseUrlLine], "base_url", injectedValue);
        }
        else
        {
            previous = string.IsNullOrWhiteSpace(topLevelBaseUrl) ? DefaultOpenAiBaseUrl : topLevelBaseUrl;
            if (string.Equals(previous.TrimEnd('/'), injectedValue, StringComparison.Ordinal))
            {
                return new ConfigTransformResult(existingContent.ToArray(), previous, injectedValue, Changed: false);
            }

            if (topLevelBaseUrlLine >= 0)
            {
                lines[topLevelBaseUrlLine] = ReplaceStringAssignment(lines[topLevelBaseUrlLine], "openai_base_url", injectedValue);
            }
            else
            {
                var insertionLine = firstSectionLine < 0 ? lines.Count : firstSectionLine;
                lines.Insert(insertionLine, $"openai_base_url = \"{EscapeTomlBasicString(injectedValue)}\"");
                if (insertionLine + 1 < lines.Count && lines[insertionLine + 1].Length != 0)
                {
                    lines.Insert(insertionLine + 1, string.Empty);
                }
            }
        }

        var transformed = string.Join(newline, lines);
        if (hadTrailingNewline || transformed.Length > 0)
        {
            transformed += newline;
        }

        return new ConfigTransformResult(StrictUtf8.GetBytes(transformed), previous, injectedValue, Changed: true);
    }

    public static bool UsesBuiltInOpenAiProvider(ReadOnlySpan<byte> existingContent)
    {
        string content;
        try
        {
            content = StrictUtf8.GetString(existingContent);
        }
        catch (DecoderFallbackException exception)
        {
            throw new ConfigMutationException("CODEX_CONFIG_ENCODING_INVALID", "Codex config must be UTF-8.", exception);
        }

        string? section = null;
        foreach (var line in content.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n'))
        {
            var sectionMatch = SectionPattern().Match(line);
            if (sectionMatch.Success)
            {
                section = sectionMatch.Groups["name"].Value.Trim();
                continue;
            }

            var assignment = StringAssignmentPattern().Match(line);
            if (section is null
                && assignment.Success
                && string.Equals(assignment.Groups["key"].Value, "model_provider", StringComparison.Ordinal))
            {
                return string.Equals(
                    UnescapeTomlBasicString(assignment.Groups["value"].Value),
                    "openai",
                    StringComparison.Ordinal);
            }
        }

        return true;
    }

    private static string ReplaceStringAssignment(string line, string key, string value)
    {
        var match = StringAssignmentPattern().Match(line);
        var indent = match.Success ? match.Groups["indent"].Value : string.Empty;
        var suffix = match.Success ? match.Groups["suffix"].Value : string.Empty;
        return $"{indent}{key} = \"{EscapeTomlBasicString(value)}\"{suffix}";
    }

    private static string EscapeTomlBasicString(string value) => value
        .Replace("\\", "\\\\", StringComparison.Ordinal)
        .Replace("\"", "\\\"", StringComparison.Ordinal);

    private static string UnescapeTomlBasicString(string value) => value
        .Replace("\\\"", "\"", StringComparison.Ordinal)
        .Replace("\\\\", "\\", StringComparison.Ordinal);

    private static void ValidateInjectedBaseUri(Uri value, bool allowRemoteBaseUri)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (!value.IsAbsoluteUri
            || (!string.Equals(value.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
                && !string.Equals(value.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            || (!allowRemoteBaseUri
                && (!value.IsLoopback
                    || !string.Equals(value.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))))
        {
            throw new ConfigMutationException(
                "INJECTED_BASE_URL_INVALID",
                allowRemoteBaseUri
                    ? "Codex direct BaseURL must be an absolute HTTP or HTTPS URI."
                    : "Codex BaseURL must be an absolute HTTP loopback URI.");
        }
    }

    [GeneratedRegex(@"^\s*\[(?<name>[^\]]+)\]\s*(?:#.*)?$", RegexOptions.CultureInvariant)]
    private static partial Regex SectionPattern();

    [GeneratedRegex("^(?<indent>\\s*)(?<key>[A-Za-z0-9_-]+)\\s*=\\s*\\\"(?<value>(?:\\\\.|[^\\\"])*)\\\"(?<suffix>\\s*(?:#.*)?)$", RegexOptions.CultureInvariant)]
    private static partial Regex StringAssignmentPattern();
}
