using System.Text;
using Sf.EndpointAI.Client.Core.Security;

namespace Sf.EndpointAI.UnitTests;

public sealed class GatewayMetadataSignerTests
{
    [Fact]
    public void Same_metadata_has_stable_signature()
    {
        var signer = new GatewayMetadataSigner(Encoding.UTF8.GetBytes("01234567890123456789012345678901"));
        var metadata = new GatewayMetadata(
            Guid.Parse("11111111-1111-1111-1111-111111111111"),
            "DOMAIN\\user",
            "S-1-5-21-test",
            "Codex",
            "ide",
            "provider-1",
            "https://api.openai.com/v1",
            "api.openai.com",
            Guid.Parse("22222222-2222-2222-2222-222222222222"),
            DateTimeOffset.FromUnixTimeSeconds(1_700_000_000),
            "POST",
            "/v1/responses?stream=true");

        Assert.Equal(signer.Sign(metadata), signer.Sign(metadata));
        Assert.StartsWith("v1:", signer.Sign(metadata), StringComparison.Ordinal);
    }

    [Fact]
    public void Path_change_changes_signature()
    {
        var signer = new GatewayMetadataSigner(Encoding.UTF8.GetBytes("01234567890123456789012345678901"));
        var original = new GatewayMetadata(
            Guid.Empty,
            "DOMAIN\\user",
            "sid",
            "agent",
            "unknown",
            "provider",
            "https://api.openai.com/v1",
            "api.openai.com",
            Guid.Empty,
            DateTimeOffset.UnixEpoch,
            "POST",
            "/v1/responses");

        Assert.NotEqual(signer.Sign(original), signer.Sign(original with { PathAndQuery = "/v1/messages" }));
    }
}
