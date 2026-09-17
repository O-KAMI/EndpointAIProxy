using System.Text;
using System.Text.Json.Nodes;
using Sf.EndpointAI.Client.Core.Configuration;

namespace Sf.EndpointAI.UnitTests;

public sealed class ClaudeSettingsTransformerTests
{
    [Fact]
    public void Adds_env_and_preserves_unrelated_fields()
    {
        var input = Encoding.UTF8.GetBytes("""
            {
              "model": "claude-sonnet",
              "unknown": { "enabled": true }
            }
            """);

        var result = ClaudeSettingsTransformer.InjectBaseUrl(
            input,
            new Uri("http://127.0.0.1:18080/r/abcdefghijklmnopqrstuv"));

        var root = JsonNode.Parse(result.Content)!.AsObject();
        Assert.True(result.Changed);
        Assert.Equal("claude-sonnet", root["model"]!.GetValue<string>());
        Assert.True(root["unknown"]!["enabled"]!.GetValue<bool>());
        Assert.Equal(
            "http://127.0.0.1:18080/r/abcdefghijklmnopqrstuv",
            root["env"]!["ANTHROPIC_BASE_URL"]!.GetValue<string>());
    }

    [Fact]
    public void Repeated_injection_is_idempotent()
    {
        var uri = new Uri("http://127.0.0.1:18080/r/abcdefghijklmnopqrstuv");
        var first = ClaudeSettingsTransformer.InjectBaseUrl("{}"u8, uri);

        var second = ClaudeSettingsTransformer.InjectBaseUrl(first.Content, uri);

        Assert.False(second.Changed);
        Assert.Equal(first.Content, second.Content);
    }

    [Fact]
    public void Rejects_non_object_env()
    {
        var action = () => ClaudeSettingsTransformer.InjectBaseUrl(
            "{\"env\":[]}"u8,
            new Uri("http://127.0.0.1:18080/r/abcdefghijklmnopqrstuv"));

        var exception = Assert.Throws<ConfigMutationException>(action);
        Assert.Equal("CLAUDE_SETTINGS_ENV_INVALID", exception.Code);
    }
}
