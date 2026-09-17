using Sf.EndpointAI.Client.Core.Windows;
using Sf.EndpointAI.Contracts;

namespace Sf.EndpointAI.Client.Core.Discovery;

public sealed class RunningProcessCollector(
    IUserProfileProvider profileProvider,
    IRunningProcessSnapshotProvider processSnapshotProvider) : IAgentEvidenceCollector
{
    private static readonly Dictionary<string, AgentType> ProcessNames =
        new Dictionary<string, AgentType>(StringComparer.OrdinalIgnoreCase)
        {
            ["claude"] = AgentType.ClaudeCli,
            ["codex"] = AgentType.CodexCli,
            ["chatgpt"] = AgentType.CodexDesktop,
            ["qoder"] = AgentType.QoderCli,
            ["qodercli"] = AgentType.QoderCli,
            ["cc-switch"] = AgentType.CcSwitch,
            ["cc switch"] = AgentType.CcSwitch,
        };

    public string Name => "running-process";

    public Task<IReadOnlyList<AgentEvidence>> CollectAsync(CancellationToken cancellationToken = default)
    {
        var profiles = profileProvider.GetProfiles();
        var evidence = new List<AgentEvidence>();
        foreach (var process in processSnapshotProvider.GetProcesses(ProcessNames.Keys.ToHashSet(StringComparer.OrdinalIgnoreCase)))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!ProcessNames.TryGetValue(process.ProcessName, out var agentType))
            {
                continue;
            }

            if (process.ExecutablePath is not null && agentType == AgentType.CodexCli)
            {
                agentType = ClassifyCodexSurface(process.ExecutablePath);
            }
            else if (process.ExecutablePath is not null && agentType == AgentType.ClaudeCli)
            {
                agentType = ClassifyClaudeSurface(process.ExecutablePath);
            }

            var profile = profiles.FirstOrDefault(candidate =>
                    string.Equals(candidate.Sid, process.OwnerSid, StringComparison.OrdinalIgnoreCase))
                ?? profiles
                    .Where(candidate => process.ExecutablePath?.StartsWith(
                        candidate.ProfilePath + Path.DirectorySeparatorChar,
                        StringComparison.OrdinalIgnoreCase) == true)
                    .OrderByDescending(candidate => candidate.ProfilePath.Length)
                    .FirstOrDefault();
            if (profile is null)
            {
                continue;
            }

            var artifact = process.ExecutablePath is null
                ? $"process::{process.ProcessName} (PID {process.ProcessId})"
                : $"{process.ExecutablePath} (PID {process.ProcessId})";
            evidence.Add(new AgentEvidence(
                profile.Sid,
                agentType,
                Name,
                EvidenceStrength.Strong,
                artifact,
                process.Version,
                InstallMethod.Unknown,
                DateTimeOffset.UtcNow));
        }

        return Task.FromResult<IReadOnlyList<AgentEvidence>>(evidence);
    }

    private static AgentType ClassifyCodexSurface(string path)
    {
        var normalized = path.Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar);
        if (normalized.Contains(
            $"{Path.DirectorySeparatorChar}extensions{Path.DirectorySeparatorChar}openai.chatgpt-",
            StringComparison.OrdinalIgnoreCase))
        {
            return AgentType.CodexIde;
        }

        if (normalized.Contains(
                $"{Path.DirectorySeparatorChar}AppData{Path.DirectorySeparatorChar}Local{Path.DirectorySeparatorChar}Packages{Path.DirectorySeparatorChar}OpenAI.Codex_",
                StringComparison.OrdinalIgnoreCase)
            || normalized.Contains(
                $"{Path.DirectorySeparatorChar}AppData{Path.DirectorySeparatorChar}Local{Path.DirectorySeparatorChar}Packages{Path.DirectorySeparatorChar}OpenAI.ChatGPT-Desktop_",
                StringComparison.OrdinalIgnoreCase))
        {
            return AgentType.CodexDesktop;
        }

        return AgentType.CodexCli;
    }

    private static AgentType ClassifyClaudeSurface(string path)
    {
        var normalized = path.Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar);
        if (normalized.Contains(
            $"{Path.DirectorySeparatorChar}extensions{Path.DirectorySeparatorChar}anthropic.claude-code-",
            StringComparison.OrdinalIgnoreCase)
            || normalized.Contains(
                $"{Path.DirectorySeparatorChar}plugins{Path.DirectorySeparatorChar}claude-code",
                StringComparison.OrdinalIgnoreCase))
        {
            return AgentType.ClaudeIde;
        }

        if (normalized.Contains(
                $"{Path.DirectorySeparatorChar}AnthropicClaude{Path.DirectorySeparatorChar}",
                StringComparison.OrdinalIgnoreCase)
            || normalized.Contains(
                $"{Path.DirectorySeparatorChar}Packages{Path.DirectorySeparatorChar}Anthropic.Claude_",
                StringComparison.OrdinalIgnoreCase))
        {
            return AgentType.ClaudeDesktop;
        }

        return AgentType.ClaudeCli;
    }
}
