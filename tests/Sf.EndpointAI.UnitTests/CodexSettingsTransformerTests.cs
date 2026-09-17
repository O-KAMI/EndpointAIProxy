using System.Text;
using Sf.EndpointAI.Client.Core.Configuration;

namespace Sf.EndpointAI.UnitTests;

public sealed class CodexSettingsTransformerTests
{
    private static readonly Uri InjectedUri = new("http://127.0.0.1:18080/r/abcdefghijklmnopqrstuv");

    [Fact]
    public void Replaces_only_active_custom_provider_base_url()
    {
        var input = """
            model = "gpt-codex"
            model_provider = "company"

            [model_providers.company]
            name = "Company" # preserved
            base_url = "https://api.openai.com/v1"
            wire_api = "responses"

            [model_providers.other]
            base_url = "https://other.example/v1"
            """;

        var result = CodexSettingsTransformer.InjectBaseUrl(Encoding.UTF8.GetBytes(input), InjectedUri);
        var output = Encoding.UTF8.GetString(result.Content);

        Assert.True(result.Changed);
        Assert.Equal("https://api.openai.com/v1", result.PreviousValue);
        Assert.Contains("model = \"gpt-codex\"", output);
        Assert.Contains("name = \"Company\" # preserved", output);
        Assert.Contains($"base_url = \"{InjectedUri.AbsoluteUri.TrimEnd('/')}\"", output);
        Assert.Contains("base_url = \"https://other.example/v1\"", output);
    }

    [Fact]
    public void Adds_builtin_openai_override_before_sections()
    {
        var input = """
            model = "gpt-codex"

            [sandbox_workspace_write]
            network_access = false
            """;

        var result = CodexSettingsTransformer.InjectBaseUrl(Encoding.UTF8.GetBytes(input), InjectedUri);
        var output = Encoding.UTF8.GetString(result.Content);

        Assert.Equal("https://api.openai.com/v1", result.PreviousValue);
        Assert.True(output.IndexOf("openai_base_url", StringComparison.Ordinal)
            < output.IndexOf("[sandbox_workspace_write]", StringComparison.Ordinal));
    }

    [Fact]
    public void Explicit_builtin_openai_provider_uses_top_level_override()
    {
        var input = """
            model = "gpt-codex"
            model_provider = "openai"

            [sandbox_workspace_write]
            network_access = false
            """;

        var result = CodexSettingsTransformer.InjectBaseUrl(Encoding.UTF8.GetBytes(input), InjectedUri);
        var output = Encoding.UTF8.GetString(result.Content);

        Assert.Equal("https://api.openai.com/v1", result.PreviousValue);
        Assert.Contains("model_provider = \"openai\"", output);
        Assert.Contains($"openai_base_url = \"{InjectedUri.AbsoluteUri.TrimEnd('/')}\"", output);
        Assert.True(output.IndexOf("openai_base_url", StringComparison.Ordinal)
            < output.IndexOf("[sandbox_workspace_write]", StringComparison.Ordinal));
    }

    [Fact]
    public void Repeated_injection_is_idempotent()
    {
        var first = CodexSettingsTransformer.InjectBaseUrl("model = \"gpt-codex\"\n"u8, InjectedUri);
        var second = CodexSettingsTransformer.InjectBaseUrl(first.Content, InjectedUri);

        Assert.False(second.Changed);
        Assert.Equal(first.Content, second.Content);
    }

    [Fact]
    public void Rejects_provider_without_matching_section()
    {
        var action = () => CodexSettingsTransformer.InjectBaseUrl(
            "model_provider = \"missing\"\n"u8,
            InjectedUri);

        var exception = Assert.Throws<ConfigMutationException>(action);
        Assert.Equal("CODEX_PROVIDER_SECTION_MISSING", exception.Code);
    }
}
