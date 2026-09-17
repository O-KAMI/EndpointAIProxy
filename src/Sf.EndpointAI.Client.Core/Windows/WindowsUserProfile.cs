namespace Sf.EndpointAI.Client.Core.Windows;

public sealed record WindowsUserProfile(
    string Sid,
    string ProfilePath,
    string? RoamingAppDataPath = null,
    string? LocalAppDataPath = null,
    IReadOnlyList<string>? ExecutableSearchPaths = null)
{
    public string EffectiveRoamingAppDataPath =>
        RoamingAppDataPath ?? Path.Combine(ProfilePath, "AppData", "Roaming");

    public string EffectiveLocalAppDataPath =>
        LocalAppDataPath ?? Path.Combine(ProfilePath, "AppData", "Local");

    public IReadOnlyList<string> EffectiveExecutableSearchPaths =>
        ExecutableSearchPaths ??
        [
            Path.Combine(EffectiveRoamingAppDataPath, "npm"),
            Path.Combine(EffectiveLocalAppDataPath, "npm"),
        ];
}

public interface IUserProfileProvider
{
    IReadOnlyList<WindowsUserProfile> GetProfiles();
}
