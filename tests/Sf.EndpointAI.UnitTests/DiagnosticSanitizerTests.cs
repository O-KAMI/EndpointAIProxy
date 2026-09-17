using Sf.EndpointAI.Client.Core.Diagnostics;

namespace Sf.EndpointAI.UnitTests;

public sealed class DiagnosticSanitizerTests
{
    private const string Canary = "sk-canary-never-leave-the-test-host-123456789";

    [Fact]
    public void Sanitizes_json_credentials_sid_and_uri_secrets()
    {
        var input = $$"""
            {
              "Authorization": "Bearer {{Canary}}",
              "UserSid": "S-1-5-21-111-222-333-1001",
              "BaseUrl": "https://vendor.example/v1/{{Canary}}?token={{Canary}}",
              "model": "safe-model"
            }
            """;

        var result = DiagnosticSanitizer.SanitizeJson(input);

        Assert.DoesNotContain(Canary, result, StringComparison.Ordinal);
        Assert.DoesNotContain("S-1-5-21-111-222-333-1001", result, StringComparison.Ordinal);
        Assert.Contains(DiagnosticSanitizer.Redacted, result, StringComparison.Ordinal);
        Assert.Contains("sha256:", result, StringComparison.Ordinal);
        Assert.Contains("safe-model", result, StringComparison.Ordinal);
    }

    [Fact]
    public void Sanitizes_scalar_and_nested_arrays_without_modifying_the_collection_during_iteration()
    {
        var input = $$"""
            [
              "{{Canary}}",
              ["https://vendor.example/v1/{{Canary}}?token={{Canary}}"],
              {"values":["S-1-5-21-111-222-333-1001", "safe-model"]}
            ]
            """;

        var result = DiagnosticSanitizer.SanitizeJson(input);

        Assert.DoesNotContain(Canary, result, StringComparison.Ordinal);
        Assert.DoesNotContain("S-1-5-21-111-222-333-1001", result, StringComparison.Ordinal);
        Assert.Contains("safe-model", result, StringComparison.Ordinal);
        Assert.Contains("sha256:", result, StringComparison.Ordinal);
    }

    [Fact]
    public void Sanitizes_toml_secrets_without_removing_diagnostic_fields()
    {
        var input = $$"""
            model = "gpt-test"
            base_url = "https://vendor.example/v1/AbCdEfGhIjKlMnOpQrStUvWxYz123456"
            api_key = "{{Canary}}"
            wire_api = "responses"
            """;

        var result = DiagnosticSanitizer.SanitizeConfigText(input);

        Assert.DoesNotContain(Canary, result, StringComparison.Ordinal);
        Assert.Contains("gpt-test", result, StringComparison.Ordinal);
        Assert.Contains("https://vendor.example/v1/sha256:", result, StringComparison.Ordinal);
        Assert.DoesNotContain("AbCdEfGhIjKlMnOpQrStUvWxYz123456", result, StringComparison.Ordinal);
        Assert.Contains("responses", result, StringComparison.Ordinal);
    }

    [Fact]
    public void Sanitizes_bearer_and_query_tokens_in_free_text()
    {
        var input = $"Authorization: Bearer {Canary}; url=https://example.test/v1?token={Canary}";

        var result = DiagnosticSanitizer.SanitizeText(input);

        Assert.DoesNotContain(Canary, result, StringComparison.Ordinal);
        Assert.Contains("[REDACTED]", result, StringComparison.Ordinal);
    }

    [Fact]
    public void Sanitizes_markdown_capture_and_keeps_only_safe_error_fields()
    {
        const string canary = "private prompt text that must not leave";
        const string token = "sk-markdown-canary-123456789012345";
        var markdown = $$"""
            # Capture
            - User SID: `S-1-5-21-111-222-333-1001`
            ## Request body

            ``````
            {"input":"{{canary}}"}
            ``````
            ## Response body

            ``````
            {"error":{"code":"forbidden","type":"access_error","message":"token={{token}}"},"input":"{{canary}}"}
            ``````
            ## Completion

            - Outcome: `GATEWAY_HTTP_ERROR`
            """;

        var result = DiagnosticBundleCollector.SanitizeMarkdownCapture(markdown);

        Assert.DoesNotContain(canary, result, StringComparison.Ordinal);
        Assert.DoesNotContain(token, result, StringComparison.Ordinal);
        Assert.Contains("[OMITTED FROM DIAGNOSTICS]", result, StringComparison.Ordinal);
        Assert.Contains("forbidden", result, StringComparison.Ordinal);
        Assert.Contains("access_error", result, StringComparison.Ordinal);
        Assert.Contains("[REDACTED]", result, StringComparison.Ordinal);
    }
}
