using Sf.EndpointAI.Client.Core.Windows;

namespace Sf.EndpointAI.UnitTests;

public sealed class WindowsUserAccountResolverTests
{
    [Theory]
    [InlineData("SF\\01443343", "01443343")]
    [InlineData("sf\\01443343", "01443343")]
    [InlineData("DOMAIN\\user", "DOMAIN\\user")]
    [InlineData("01443343", "01443343")]
    [InlineData("SF\\", "SF\\")]
    [InlineData("SF\\   ", "SF\\   ")]
    public void Account_name_is_normalized_without_changing_non_sf_identities(string accountName, string expected)
    {
        Assert.Equal(expected, WindowsUserAccountResolver.NormalizeUserId(accountName));
    }

    [Fact]
    public void Invalid_sid_falls_back_without_throwing()
    {
        var result = new WindowsUserAccountResolver().Resolve("not-a-valid-sid");

        Assert.Equal("not-a-valid-sid", result.UserId);
        Assert.True(result.UsedSidFallback);
    }

    [Fact]
    public void Sid_fallback_is_not_treated_as_an_account_name()
    {
        const string invalidSid = "SF\\01443343";

        var result = new WindowsUserAccountResolver().Resolve(invalidSid);

        Assert.Equal(invalidSid, result.UserId);
        Assert.True(result.UsedSidFallback);
    }
}
