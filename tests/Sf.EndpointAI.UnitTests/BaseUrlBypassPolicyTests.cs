using Sf.EndpointAI.Client.Core.Routing;
using Sf.EndpointAI.Contracts;

namespace Sf.EndpointAI.UnitTests;

public sealed class BaseUrlBypassPolicyTests
{
    private readonly BaseUrlBypassPolicy _policy = new();

    [Theory]
    [InlineData("https://internal.example.invalid/ccr")]
    [InlineData("https://internal.example.invalid/ccr/")]
    [InlineData("https://internal.example.invalid:443/ccr")]
    public void Bypasses_only_normalized_sf_claude_code_gateway(string value)
    {
        Assert.True(_policy.ShouldBypass(new Uri(value)));
    }

    [Theory]
    [InlineData("http://internal.example.invalid/ccr")]
    [InlineData("https://internal.example.invalid:444/ccr")]
    [InlineData("https://internal.example.invalid/ccr/v1")]
    [InlineData("https://internal.example.invalid/ccr?target=external")]
    [InlineData("https://internal.example.invalid/ccr#fragment")]
    [InlineData("https://internal.example.invalid.evil.example/ccr")]
    [InlineData("https://user@internal.example.invalid/ccr")]
    [InlineData("https://@internal.example.invalid/ccr")]
    [InlineData("https://internal.example.invalid/ccr?")]
    [InlineData("https://internal.example.invalid/ccr#")]
    public void Proxies_every_non_matching_base_url(string value)
    {
        Assert.False(_policy.ShouldBypass(new Uri(value)));
    }

    [Fact]
    public void Null_uses_legacy_ccr_but_explicit_empty_list_clears_every_entry()
    {
        Assert.True(_policy.ShouldBypass(new Uri(BaseUrlAllowlist.LegacyCcrBaseUrl)));

        Assert.True(_policy.Replace([]));

        Assert.False(_policy.ShouldBypass(new Uri(BaseUrlAllowlist.LegacyCcrBaseUrl)));
        Assert.Empty(_policy.Snapshot());
        Assert.True(_policy.Replace(null));
        Assert.True(_policy.ShouldBypass(new Uri(BaseUrlAllowlist.LegacyCcrBaseUrl)));
    }

    [Theory]
    [InlineData("http://MODEL.EXAMPLE.INVALID:80/v1/", "http://model.example.invalid/v1")]
    [InlineData("https://model.example.invalid:443/v1///", "https://model.example.invalid/v1")]
    [InlineData("https://model.example.invalid:8443/Api", "https://model.example.invalid:8443/Api")]
    public void Dynamic_entries_are_normalized_and_matched_exactly(string configured, string expected)
    {
        _policy.Replace([configured]);

        Assert.Equal([expected], _policy.Snapshot());
        Assert.True(_policy.ShouldBypass(new Uri(expected)));
        Assert.False(_policy.ShouldBypass(new Uri(expected + "/child")));
    }

    [Theory]
    [InlineData("ftp://model.example.invalid/v1")]
    [InlineData("https://user@model.example.invalid/v1")]
    [InlineData("https://model.example.invalid/v1?key=value")]
    [InlineData("https://model.example.invalid/v1#fragment")]
    public void Invalid_dynamic_entries_are_rejected(string value)
    {
        Assert.Throws<FormatException>(() => _policy.Replace([value]));
    }

    [Fact]
    public void Dynamic_entries_are_deduplicated_after_normalization()
    {
        _policy.Replace([
            "https://MODEL.EXAMPLE.INVALID:443/v1/",
            "https://model.example.invalid/v1",
        ]);

        Assert.Equal(["https://model.example.invalid/v1"], _policy.Snapshot());
    }
}
