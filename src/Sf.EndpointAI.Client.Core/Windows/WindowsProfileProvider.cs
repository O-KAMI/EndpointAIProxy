using Microsoft.Win32;
using System.Runtime.Versioning;
using System.Security;

namespace Sf.EndpointAI.Client.Core.Windows;

[SupportedOSPlatform("windows")]
public sealed class WindowsProfileProvider : IUserProfileProvider
{
    private const string ProfileListPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
    private const string UserShellFoldersPath = @"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders";
    private const string ShellFoldersPath = @"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders";
    private const string UserEnvironmentPath = @"Environment";
    private const string MachineEnvironmentPath = @"SYSTEM\CurrentControlSet\Control\Session Manager\Environment";

    public IReadOnlyList<WindowsUserProfile> GetProfiles()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Windows profile discovery requires Windows.");
        }

        using var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var profileList = machine.OpenSubKey(ProfileListPath, writable: false);
        if (profileList is null)
        {
            return [];
        }

        var profiles = new List<WindowsUserProfile>();
        foreach (var sid in profileList.GetSubKeyNames())
        {
            if (!sid.StartsWith("S-1-5-21-", StringComparison.Ordinal) || sid.EndsWith(".bak", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            using var profileKey = profileList.OpenSubKey(sid, writable: false);
            var configuredPath = profileKey?.GetValue("ProfileImagePath") as string;
            if (string.IsNullOrWhiteSpace(configuredPath))
            {
                continue;
            }

            var expandedPath = Environment.ExpandEnvironmentVariables(configuredPath);
            if (!Path.IsPathFullyQualified(expandedPath) || !Directory.Exists(expandedPath))
            {
                continue;
            }

            var profilePath = Path.GetFullPath(expandedPath);
            var roamingAppData = ReadKnownFolder(sid, profilePath, "AppData")
                ?? Path.Combine(profilePath, "AppData", "Roaming");
            var localAppData = ReadKnownFolder(sid, profilePath, "Local AppData")
                ?? Path.Combine(profilePath, "AppData", "Local");
            profiles.Add(new WindowsUserProfile(
                sid,
                profilePath,
                roamingAppData,
                localAppData,
                ReadExecutableSearchPaths(sid, profilePath, roamingAppData, localAppData)));
        }

        return profiles
            .DistinctBy(profile => profile.Sid, StringComparer.OrdinalIgnoreCase)
            .OrderBy(profile => profile.Sid, StringComparer.Ordinal)
            .ToArray();
    }

    private static string? ReadKnownFolder(string sid, string profilePath, string valueName)
    {
        try
        {
            foreach (var keyPath in new[] { UserShellFoldersPath, ShellFoldersPath })
            {
                using var users = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Registry64);
                using var key = users.OpenSubKey($@"{sid}\{keyPath}", writable: false);
                var value = key?.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
                var expanded = ExpandUserEnvironment(value, profilePath, null, null);
                if (expanded is not null && Path.IsPathFullyQualified(expanded))
                {
                    return Path.GetFullPath(expanded);
                }
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or SecurityException)
        {
            // Known-folder discovery falls back to the conventional profile layout.
        }

        return null;
    }

    private static string[] ReadExecutableSearchPaths(
        string sid,
        string profilePath,
        string roamingAppData,
        string localAppData)
    {
        var paths = new List<string>
        {
            Path.Combine(roamingAppData, "npm"),
            Path.Combine(localAppData, "npm"),
        };
        try
        {
            using var users = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Registry64);
            using var userEnvironment = users.OpenSubKey($@"{sid}\{UserEnvironmentPath}", writable: false);
            AddPathValue(
                paths,
                userEnvironment?.GetValue("Path", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string,
                profilePath,
                roamingAppData,
                localAppData);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or SecurityException)
        {
            // The known npm roots remain available when a user hive is not loaded.
        }

        try
        {
            using var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var machineEnvironment = machine.OpenSubKey(MachineEnvironmentPath, writable: false);
            AddPathValue(
                paths,
                machineEnvironment?.GetValue("Path", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string,
                profilePath,
                roamingAppData,
                localAppData);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or SecurityException)
        {
            // User-scoped roots are sufficient when the machine PATH is unavailable.
        }

        return paths
            .Where(Path.IsPathFullyQualified)
            .Select(Path.GetFullPath)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static void AddPathValue(
        List<string> paths,
        string? value,
        string profilePath,
        string roamingAppData,
        string localAppData)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        foreach (var item in value.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var expanded = ExpandUserEnvironment(item, profilePath, roamingAppData, localAppData);
            if (!string.IsNullOrWhiteSpace(expanded))
            {
                paths.Add(expanded.Trim().Trim('"'));
            }
        }
    }

    private static string? ExpandUserEnvironment(
        string? value,
        string profilePath,
        string? roamingAppData,
        string? localAppData)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var expanded = value
            .Replace("%USERPROFILE%", profilePath, StringComparison.OrdinalIgnoreCase)
            .Replace("%APPDATA%", roamingAppData ?? Path.Combine(profilePath, "AppData", "Roaming"), StringComparison.OrdinalIgnoreCase)
            .Replace("%LOCALAPPDATA%", localAppData ?? Path.Combine(profilePath, "AppData", "Local"), StringComparison.OrdinalIgnoreCase);
        return Environment.ExpandEnvironmentVariables(expanded);
    }
}
