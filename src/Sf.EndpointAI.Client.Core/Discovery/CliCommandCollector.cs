using Sf.EndpointAI.Client.Core.Windows;
using Sf.EndpointAI.Contracts;

namespace Sf.EndpointAI.Client.Core.Discovery;

public sealed class CliCommandCollector(IUserProfileProvider profileProvider) : IAgentEvidenceCollector
{
    private static readonly CommandSignature[] Signatures =
    [
        new(AgentType.ClaudeCli, "claude.cmd", InstallMethod.Npm),
        new(AgentType.ClaudeCli, "claude.ps1", InstallMethod.Npm),
        new(AgentType.ClaudeCli, "claude.exe", InstallMethod.Native),
        new(AgentType.CodexCli, "codex.cmd", InstallMethod.Npm),
        new(AgentType.CodexCli, "codex.ps1", InstallMethod.Npm),
        new(AgentType.CodexCli, "codex.exe", InstallMethod.Native),
        new(AgentType.QoderCli, "qoder.cmd", InstallMethod.Npm),
        new(AgentType.QoderCli, "qoder.ps1", InstallMethod.Npm),
        new(AgentType.QoderCli, "qodercli.cmd", InstallMethod.Npm),
        new(AgentType.QoderCli, "qodercli.ps1", InstallMethod.Npm),
        new(AgentType.QoderCli, "qodercli.exe", InstallMethod.Native),
        new(AgentType.ClaudeCli, "claude", InstallMethod.Native),
        new(AgentType.CodexCli, "codex", InstallMethod.Native),
        new(AgentType.QoderCli, "qoder", InstallMethod.Native),
        new(AgentType.QoderCli, "qodercli", InstallMethod.Native),
    ];

    public string Name => "cli-command";

    public Task<IReadOnlyList<AgentEvidence>> CollectAsync(CancellationToken cancellationToken = default)
    {
        var evidence = new List<AgentEvidence>();
        foreach (var profile in profileProvider.GetProfiles())
        {
            foreach (var root in GetSearchRoots(profile))
            {
                foreach (var signature in Signatures)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var path = Path.GetFullPath(Path.Combine(root, signature.FileName));
                    if (!path.StartsWith(root.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
                        || !File.Exists(path))
                    {
                        continue;
                    }

                    evidence.Add(new AgentEvidence(
                        profile.Sid,
                        signature.AgentType,
                        Name,
                        EvidenceStrength.Medium,
                        path,
                        TryReadFileVersion(path),
                        signature.InstallMethod,
                        DateTimeOffset.UtcNow));
                }
            }

            AddNativeEvidence(
                evidence,
                profile,
                AgentType.ClaudeCli,
                Path.Combine(profile.ProfilePath, ".local", "bin", "claude.exe"));
            AddNativeEvidence(
                evidence,
                profile,
                AgentType.QoderCli,
                Path.Combine(profile.EffectiveLocalAppDataPath, "qodercli", "qodercli.exe"));
            AddNativeEvidence(
                evidence,
                profile,
                AgentType.CcSwitch,
                Path.Combine(profile.EffectiveLocalAppDataPath, "Programs", "CC Switch", "CC Switch.exe"));
            AddNativeEvidence(
                evidence,
                profile,
                AgentType.CcSwitch,
                Path.Combine(profile.EffectiveLocalAppDataPath, "CC Switch", "CC Switch.exe"));
            AddNativeEvidence(
                evidence,
                profile,
                AgentType.ClaudeCli,
                Path.Combine(profile.ProfilePath, ".local", "bin", "claude"));
            AddNativeEvidence(
                evidence,
                profile,
                AgentType.CodexCli,
                Path.Combine(profile.ProfilePath, ".local", "bin", "codex"));
        }

        return Task.FromResult<IReadOnlyList<AgentEvidence>>(evidence);
    }

    private static string[] GetSearchRoots(WindowsUserProfile profile) =>
        profile.EffectiveExecutableSearchPaths
            .Append(Path.Combine(profile.EffectiveRoamingAppDataPath, "npm"))
            .Append(Path.Combine(profile.EffectiveLocalAppDataPath, "npm"))
            .Where(Path.IsPathFullyQualified)
            .Select(Path.GetFullPath)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

    private static void AddNativeEvidence(
        List<AgentEvidence> evidence,
        WindowsUserProfile profile,
        AgentType agentType,
        string path)
    {
        if (!File.Exists(path))
        {
            return;
        }

        evidence.Add(new AgentEvidence(
            profile.Sid,
            agentType,
            "cli-command",
            EvidenceStrength.Medium,
            path,
            TryReadFileVersion(path),
            InstallMethod.Native,
            DateTimeOffset.UtcNow));
    }

    private static string? TryReadFileVersion(string path)
    {
        try
        {
            return System.Diagnostics.FileVersionInfo.GetVersionInfo(path).ProductVersion;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return null;
        }
    }

    private sealed record CommandSignature(AgentType AgentType, string FileName, InstallMethod InstallMethod);
}
