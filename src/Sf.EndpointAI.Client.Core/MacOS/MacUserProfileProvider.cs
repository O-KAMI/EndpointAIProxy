using Sf.EndpointAI.Client.Core.Windows;

namespace Sf.EndpointAI.Client.Core.MacOS;

public sealed class MacUserProfileProvider(string usersRoot = "/Users") : IUserProfileProvider
{
    private static readonly HashSet<string> ExcludedProfiles = new(StringComparer.OrdinalIgnoreCase)
    {
        "Guest",
        "Shared",
    };

    public IReadOnlyList<WindowsUserProfile> GetProfiles()
    {
        if (!OperatingSystem.IsMacOS())
        {
            throw new PlatformNotSupportedException("macOS profile discovery requires macOS.");
        }

        if (!Directory.Exists(usersRoot))
        {
            return [];
        }

        return Directory.EnumerateDirectories(usersRoot, "*", SearchOption.TopDirectoryOnly)
            .Where(path => !ExcludedProfiles.Contains(Path.GetFileName(path)))
            .Where(path => !Path.GetFileName(path).StartsWith('.'))
            .Select(CreateProfile)
            .OrderBy(profile => profile.Sid, StringComparer.Ordinal)
            .ToArray();
    }

    private static WindowsUserProfile CreateProfile(string profilePath)
    {
        var fullPath = Path.GetFullPath(profilePath);
        var userName = Path.GetFileName(fullPath);
        var executablePaths = new[]
        {
            Path.Combine(fullPath, ".local", "bin"),
            Path.Combine(fullPath, ".npm-global", "bin"),
            Path.Combine(fullPath, ".volta", "bin"),
            Path.Combine(fullPath, ".nvm", "current", "bin"),
            "/opt/homebrew/bin",
            "/usr/local/bin",
            "/usr/bin",
        };
        return new WindowsUserProfile(
            $"macos:{userName}",
            fullPath,
            Path.Combine(fullPath, "Library", "Application Support"),
            Path.Combine(fullPath, "Library", "Caches"),
            executablePaths);
    }
}
