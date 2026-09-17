using System.Diagnostics;

namespace Sf.EndpointAI.Client.Core.MacOS;

internal static class MacFileOwnership
{
    public static void CopyFrom(string referencePath, string targetPath)
    {
        if (!OperatingSystem.IsMacOS())
        {
            return;
        }

        var owner = Run("/usr/bin/stat", "-f", "%u:%g", referencePath).Trim();
        if (owner.Length == 0 || owner.Any(character => character is not (':' or >= '0' and <= '9')))
        {
            throw new IOException("Could not determine the owner of the existing configuration file.");
        }

        _ = Run("/usr/sbin/chown", owner, targetPath);
    }

    private static string Run(string fileName, params string[] arguments)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = fileName,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = Process.Start(startInfo)
            ?? throw new IOException($"Could not start {Path.GetFileName(fileName)}.");
        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        if (!process.WaitForExit(5000))
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException)
            {
                // The utility exited between the timeout and Kill.
            }

            throw new IOException($"{Path.GetFileName(fileName)} timed out.");
        }

        if (process.ExitCode != 0)
        {
            throw new IOException($"{Path.GetFileName(fileName)} failed: {error.Trim()}");
        }

        return output;
    }
}
