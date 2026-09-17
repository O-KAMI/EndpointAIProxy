using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Sf.EndpointAI.Client.Core.Diagnostics;

public static partial class DiagnosticSanitizer
{
    public const string Redacted = "[REDACTED]";

    private static readonly string[] SensitiveNames =
    [
        "authorization",
        "cookie",
        "api-key",
        "apikey",
        "api_key",
        "token",
        "secret",
        "password",
        "credential",
    ];

    public static bool IsSensitiveName(string name) =>
        SensitiveNames.Any(fragment => name.Contains(fragment, StringComparison.OrdinalIgnoreCase));

    public static string HashIdentifier(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return $"sha256:{Convert.ToHexString(digest)[..16].ToLowerInvariant()}";
    }

    public static string SanitizeUri(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
        {
            return SanitizeText(value);
        }

        var builder = new UriBuilder(uri)
        {
            UserName = string.Empty,
            Password = string.Empty,
            Query = string.IsNullOrEmpty(uri.Query) ? string.Empty : "redacted",
            Fragment = string.Empty,
        };
        var segments = builder.Path.Split('/', StringSplitOptions.None);
        for (var index = 0; index < segments.Length; index++)
        {
            if (LooksLikeSecretPathSegment(segments[index]))
            {
                segments[index] = HashIdentifier(segments[index]);
            }
        }

        builder.Path = string.Join('/', segments);
        return builder.Uri.AbsoluteUri.TrimEnd('/');
    }

    public static string SanitizeText(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return value;
        }

        var sanitized = BearerPattern().Replace(value, "$1[REDACTED]");
        sanitized = SecretAssignmentPattern().Replace(sanitized, "$1[REDACTED]");
        sanitized = QuerySecretPattern().Replace(sanitized, "$1=[REDACTED]");
        sanitized = CommonApiTokenPattern().Replace(sanitized, Redacted);
        sanitized = WindowsProfilePathPattern().Replace(sanitized, "$1[USER]");
        sanitized = WindowsSidPattern().Replace(sanitized, match => HashIdentifier(match.Value));
        return sanitized;
    }

    public static string SanitizeJson(string json)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);
        var node = JsonNode.Parse(json) ?? throw new JsonException("JSON content was empty.");
        SanitizeNode(node, null);
        return node.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
    }

    public static string SanitizeConfigText(string content)
    {
        if (string.IsNullOrWhiteSpace(content))
        {
            return content;
        }

        try
        {
            return SanitizeJson(content);
        }
        catch (JsonException)
        {
            var lines = content.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
            for (var index = 0; index < lines.Length; index++)
            {
                var separator = lines[index].IndexOf('=');
                if (separator <= 0)
                {
                    lines[index] = SanitizeText(lines[index]);
                    continue;
                }

                var key = lines[index][..separator].Trim();
                if (IsSensitiveName(key))
                {
                    lines[index] = $"{lines[index][..(separator + 1)]} \"{Redacted}\"";
                    continue;
                }

                if (key.Contains("url", StringComparison.OrdinalIgnoreCase)
                    || key.Contains("uri", StringComparison.OrdinalIgnoreCase))
                {
                    var rawValue = lines[index][(separator + 1)..].Trim();
                    var quote = rawValue.Length > 1 && rawValue[0] is '\"' or '\'' ? rawValue[0] : '\0';
                    var unquoted = quote == '\0' || rawValue[^1] != quote ? rawValue : rawValue[1..^1];
                    var sanitizedUri = SanitizeUri(unquoted);
                    lines[index] = quote == '\0'
                        ? $"{lines[index][..(separator + 1)]} {sanitizedUri}"
                        : $"{lines[index][..(separator + 1)]} {quote}{sanitizedUri}{quote}";
                    continue;
                }

                lines[index] = SanitizeText(lines[index]);
            }

            return string.Join('\n', lines);
        }
    }

    private static void SanitizeNode(JsonNode node, string? propertyName)
    {
        if (node is JsonObject jsonObject)
        {
            foreach (var pair in jsonObject.ToArray())
            {
                if (IsSensitiveName(pair.Key))
                {
                    jsonObject[pair.Key] = Redacted;
                }
                else if (pair.Key.Equals("UserSid", StringComparison.OrdinalIgnoreCase)
                    && pair.Value is JsonValue sidValue
                    && sidValue.TryGetValue<string>(out var sid)
                    && !string.IsNullOrWhiteSpace(sid))
                {
                    jsonObject[pair.Key] = HashIdentifier(sid);
                }
                else if (pair.Value is not null)
                {
                    SanitizeNode(pair.Value, pair.Key);
                }
            }

            return;
        }

        if (node is JsonArray array)
        {
            foreach (var item in array.ToArray())
            {
                if (item is not null)
                {
                    SanitizeNode(item, propertyName);
                }
            }

            return;
        }

        if (node is JsonValue value
            && value.TryGetValue<string>(out var text)
            && !string.IsNullOrEmpty(text))
        {
            var sanitized = propertyName is not null
                && (propertyName.Contains("url", StringComparison.OrdinalIgnoreCase)
                    || propertyName.Contains("uri", StringComparison.OrdinalIgnoreCase))
                ? SanitizeUri(text)
                : SanitizeText(text);
            value.ReplaceWith(JsonValue.Create(sanitized));
        }
    }

    private static bool LooksLikeSecretPathSegment(string segment)
    {
        if (segment.Length < 24 || segment.Equals("chat", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var tokenCharacters = segment.Count(character => char.IsLetterOrDigit(character) || character is '-' or '_');
        return tokenCharacters >= segment.Length * 9 / 10;
    }

    [GeneratedRegex("(?i)(Bearer\\s+)[A-Za-z0-9._~+/=-]+", RegexOptions.CultureInvariant)]
    private static partial Regex BearerPattern();

    [GeneratedRegex("(?i)((?:api[_-]?key|token|secret|password)\\s*[:=]\\s*[\\\"']?)[^\\s,;\\\"']+", RegexOptions.CultureInvariant)]
    private static partial Regex SecretAssignmentPattern();

    [GeneratedRegex("(?i)([?&](?:api[_-]?key|token|secret|signature))=[^&#\\s]+", RegexOptions.CultureInvariant)]
    private static partial Regex QuerySecretPattern();

    [GeneratedRegex("(?i)\\b(?:sk|key|token)-[A-Za-z0-9_-]{16,}\\b", RegexOptions.CultureInvariant)]
    private static partial Regex CommonApiTokenPattern();

    [GeneratedRegex("(?i)([A-Z]:\\\\Users\\\\)[^\\\\/\\s]+", RegexOptions.CultureInvariant)]
    private static partial Regex WindowsProfilePathPattern();

    [GeneratedRegex("S-1-5-21-(?:\\d+-){3}\\d+", RegexOptions.CultureInvariant)]
    private static partial Regex WindowsSidPattern();
}
