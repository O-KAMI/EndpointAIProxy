using System.Reflection;
using Sf.EndpointAI.Client.Core.Discovery;
using Sf.EndpointAI.Client.Service;
using Sf.EndpointAI.Contracts;

namespace Sf.EndpointAI.UnitTests;

public sealed class ControlPlaneWorkerTests
{
    [Fact]
    public void Unknown_candidate_display_name_includes_candidate_and_process_name()
    {
        var agent = new AgentIdentityResult(
            "S-1-5-21-test",
            AgentType.UnknownCandidate,
            false,
            30,
            "1.2.3",
            InstallMethod.Unknown,
            [new AgentEvidence(
                "S-1-5-21-test",
                AgentType.CodexCli,
                "running-process",
                EvidenceStrength.Medium,
                @"C:\Users\test\AppData\Roaming\npm\codex.exe (PID 1234)",
                "1.2.3",
                InstallMethod.Unknown,
                DateTimeOffset.UtcNow)]);

        var displayName = InvokeGetDisplayName(agent);

        Assert.Equal("疑似 Codex CLI（识别线索：codex.exe）", displayName);
    }

    [Fact]
    public void Unknown_candidate_display_name_uses_configuration_file_when_process_is_unavailable()
    {
        var agent = new AgentIdentityResult(
            "S-1-5-21-test",
            AgentType.UnknownCandidate,
            false,
            30,
            null,
            InstallMethod.Unknown,
            [new AgentEvidence(
                "S-1-5-21-test",
                AgentType.QoderCli,
                "config-artifact",
                EvidenceStrength.Medium,
                @"C:\Users\test\.qoder\settings.json",
                null,
                InstallMethod.Unknown,
                DateTimeOffset.UtcNow)]);

        var displayName = InvokeGetDisplayName(agent);

        Assert.Equal("疑似 Qoder CLI（识别线索：settings.json）", displayName);
    }

    private static string InvokeGetDisplayName(AgentIdentityResult agent)
    {
        var method = typeof(ControlPlaneWorker)
            .GetMethods(BindingFlags.NonPublic | BindingFlags.Static)
            .Single(candidate =>
                candidate.Name == "GetDisplayName"
                && candidate.GetParameters() is [{ ParameterType: var parameterType }]
                && parameterType == typeof(AgentIdentityResult));
        return Assert.IsType<string>(method.Invoke(null, [agent]));
    }
}
