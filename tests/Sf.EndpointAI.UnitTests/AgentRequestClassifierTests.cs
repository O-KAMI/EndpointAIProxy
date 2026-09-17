using Sf.EndpointAI.Client.Core.Routing;
using Sf.EndpointAI.Client.Core.Security;
using Sf.EndpointAI.Contracts;

namespace Sf.EndpointAI.UnitTests;

public sealed class AgentRequestClassifierTests
{
    [Fact]
    public void Cc_switch_provider_identifies_family_and_vscode_surface()
    {
        var now = DateTimeOffset.UtcNow;
        var route = new RouteRecord(
            "abcdefghijklmnopqrstuv",
            "S-1-5-21-test",
            AgentType.CcSwitch,
            "codex:provider",
            new Uri("https://api.openai.com/v1"),
            new Uri("http://127.0.0.1:18080/r/abcdefghijklmnopqrstuv"),
            RouteStatus.Attached,
            now,
            now);

        Assert.Equal("Codex", AgentRequestClassifier.GetFamily(route));
        Assert.Equal("ide", AgentRequestClassifier.GetSurface(route, ["codex_vscode/0.149.0"]));
    }
}
