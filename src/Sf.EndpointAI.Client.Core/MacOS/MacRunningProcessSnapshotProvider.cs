using System.ComponentModel;
using System.Diagnostics;
using Sf.EndpointAI.Client.Core.Discovery;

namespace Sf.EndpointAI.Client.Core.MacOS;

public sealed class MacRunningProcessSnapshotProvider : IRunningProcessSnapshotProvider
{
    public IReadOnlyList<RunningProcessSnapshot> GetProcesses(IReadOnlySet<string> processNames)
    {
        ArgumentNullException.ThrowIfNull(processNames);
        if (!OperatingSystem.IsMacOS())
        {
            throw new PlatformNotSupportedException("macOS process discovery requires macOS.");
        }

        var owners = ReadProcessOwners();
        var snapshots = new List<RunningProcessSnapshot>();
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                try
                {
                    if (!processNames.Contains(process.ProcessName))
                    {
                        continue;
                    }

                    var path = TryGetProcessPath(process);
                    snapshots.Add(new RunningProcessSnapshot(
                        process.Id,
                        process.ProcessName,
                        path,
                        TryReadFileVersion(path),
                        owners.TryGetValue(process.Id, out var owner) ? $"macos:{owner}" : null));
                }
                catch (InvalidOperationException)
                {
                    // The process exited while it was being inspected.
                }
                catch (Win32Exception)
                {
                    // Process metadata is best effort.
                }
            }
        }

        return snapshots;
    }

    private static Dictionary<int, string> ReadProcessOwners()
    {
        var result = new Dictionary<int, string>();
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = "/bin/ps",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            ArgumentList = { "-axo", "pid=,user=" },
        });
        if (process is null)
        {
            return result;
        }

        var output = process.StandardOutput.ReadToEnd();
        if (!process.WaitForExit(2000) || process.ExitCode != 0)
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException)
            {
                // The process exited between the timeout and Kill.
            }

            return result;
        }

        foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var fields = line.Split((char[]?)null, 2, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (fields.Length == 2 && int.TryParse(fields[0], out var processId))
            {
                result[processId] = fields[1];
            }
        }

        return result;
    }

    private static string? TryGetProcessPath(Process process)
    {
        try
        {
            return process.MainModule?.FileName;
        }
        catch (Exception exception) when (exception is InvalidOperationException or Win32Exception or NotSupportedException)
        {
            return null;
        }
    }

    private static string? TryReadFileVersion(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        try
        {
            return FileVersionInfo.GetVersionInfo(path).ProductVersion;
        }
        catch (Win32Exception)
        {
            return null;
        }
    }
}
