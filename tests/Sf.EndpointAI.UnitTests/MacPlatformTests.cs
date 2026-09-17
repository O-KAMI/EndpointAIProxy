using System.Security.Cryptography;
using Sf.EndpointAI.Client.Core.MacOS;
using Sf.EndpointAI.Client.Core.Security;

namespace Sf.EndpointAI.UnitTests;

public sealed class MacPlatformTests
{
    [Fact]
    public void FileKeyTextProtector_RoundTripsWithoutPersistingPlaintext()
    {
        var root = Path.Combine(Path.GetTempPath(), $"sf-endpointai-key-{Guid.NewGuid():N}");
        var keyPath = Path.Combine(root, "state", "machine.key");
        try
        {
            var protector = new FileKeyTextProtector(keyPath);
            var protectedValue = protector.Protect("https://api.example.test/v1");

            Assert.Equal("https://api.example.test/v1", protector.Unprotect(protectedValue));
            Assert.Equal(-1, protectedValue.AsSpan().IndexOf("api.example.test"u8));
            Assert.Equal(32, File.ReadAllBytes(keyPath).Length);
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    [Fact]
    public void FileKeyTextProtector_RejectsTampering()
    {
        var root = Path.Combine(Path.GetTempPath(), $"sf-endpointai-key-{Guid.NewGuid():N}");
        try
        {
            var protector = new FileKeyTextProtector(Path.Combine(root, "machine.key"));
            var protectedValue = protector.Protect("secret");
            protectedValue[^1] ^= 0xff;

            Assert.ThrowsAny<CryptographicException>(() => protector.Unprotect(protectedValue));
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    [Theory]
    [InlineData("macos:01443343", "01443343", false)]
    [InlineData("unexpected", "unexpected", true)]
    public void MacUserAccountResolver_NormalizesRouteIdentity(
        string routeIdentity,
        string expectedUserId,
        bool expectedFallback)
    {
        var result = new MacUserAccountResolver().Resolve(routeIdentity);

        Assert.Equal(expectedUserId, result.UserId);
        Assert.Equal(expectedFallback, result.UsedSidFallback);
    }
}
