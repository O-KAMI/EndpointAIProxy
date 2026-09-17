using System.Security;
using System.Runtime.Versioning;
using Microsoft.Win32;
using Sf.EndpointAI.Client.Core.Windows;
using Sf.EndpointAI.Contracts;

namespace Sf.EndpointAI.Client.Core.Discovery;

[SupportedOSPlatform("windows")]
public sealed class WindowsInstalledApplicationCollector(IUserProfileProvider profileProvider) : IAgentEvidenceCollector
{
    private const string UninstallPath = @"Software\Microsoft\Windows\CurrentVersion\Uninstall";

    public string Name => "windows-installed-application";

    public Task<IReadOnlyList<AgentEvidence>> CollectAsync(CancellationToken cancellationToken = default)
    {
        var evidence = new List<AgentEvidence>();
        var observedAt = DateTimeOffset.UtcNow;
        foreach (var profile in profileProvider.GetProfiles())
        {
            cancellationToken.ThrowIfCancellationRequested();
            foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                CollectRegistryPath(RegistryHive.Users, $@"{profile.Sid}\{UninstallPath}", view, profile.Sid, evidence, observedAt);
                CollectRegistryPath(RegistryHive.LocalMachine, UninstallPath, view, profile.Sid, evidence, observedAt);
            }
        }

        return Task.FromResult<IReadOnlyList<AgentEvidence>>(evidence);
    }

    private static void CollectRegistryPath(
        RegistryHive hive,
        string keyPath,
        RegistryView view,
        string userSid,
        List<AgentEvidence> evidence,
        DateTimeOffset observedAt)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, view);
            using var uninstall = baseKey.OpenSubKey(keyPath, writable: false);
            if (uninstall is null)
            {
                return;
            }

            foreach (var subKeyName in uninstall.GetSubKeyNames())
            {
                using var product = uninstall.OpenSubKey(subKeyName, writable: false);
                var displayName = product?.GetValue("DisplayName") as string;
                var publisher = product?.GetValue("Publisher") as string;
                var agentType = Classify(displayName, publisher);
                if (agentType is null)
                {
                    continue;
                }

                var artifact = product?.GetValue("DisplayIcon") as string
                    ?? product?.GetValue("InstallLocation") as string
                    ?? $"registry::{hive}\\{keyPath}\\{subKeyName}";
                evidence.Add(new AgentEvidence(
                    userSid,
                    agentType.Value,
                    "windows-installed-application",
                    EvidenceStrength.Strong,
                    artifact,
                    product?.GetValue("DisplayVersion") as string,
                    InstallMethod.Native,
                    observedAt));
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or SecurityException)
        {
            // Registry evidence is best effort; other collectors still identify the installation.
        }
    }

    private static AgentType? Classify(string? displayName, string? publisher)
    {
        if (string.IsNullOrWhiteSpace(displayName))
        {
            return null;
        }

        if (displayName.Contains("CC Switch", StringComparison.OrdinalIgnoreCase))
        {
            return AgentType.CcSwitch;
        }

        if (displayName.Contains("Claude", StringComparison.OrdinalIgnoreCase)
            && (publisher?.Contains("Anthropic", StringComparison.OrdinalIgnoreCase) ?? false))
        {
            return AgentType.ClaudeDesktop;
        }

        if ((displayName.Contains("Codex", StringComparison.OrdinalIgnoreCase)
                || displayName.Contains("ChatGPT", StringComparison.OrdinalIgnoreCase))
            && (publisher?.Contains("OpenAI", StringComparison.OrdinalIgnoreCase) ?? false))
        {
            return AgentType.CodexDesktop;
        }

        return null;
    }
}
