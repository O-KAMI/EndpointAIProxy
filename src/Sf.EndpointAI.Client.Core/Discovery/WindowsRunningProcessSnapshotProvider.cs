using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace Sf.EndpointAI.Client.Core.Discovery;

public sealed record RunningProcessSnapshot(
    int ProcessId,
    string ProcessName,
    string? ExecutablePath,
    string? Version,
    string? OwnerSid);

public interface IRunningProcessSnapshotProvider
{
    IReadOnlyList<RunningProcessSnapshot> GetProcesses(IReadOnlySet<string> processNames);
}

[SupportedOSPlatform("windows")]
public sealed class WindowsRunningProcessSnapshotProvider : IRunningProcessSnapshotProvider
{
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint TokenQuery = 0x0008;

    public IReadOnlyList<RunningProcessSnapshot> GetProcesses(IReadOnlySet<string> processNames)
    {
        ArgumentNullException.ThrowIfNull(processNames);
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
                        TryGetOwnerSid(process.Id)));
                }
                catch (InvalidOperationException)
                {
                    // The process exited while it was being inspected.
                }
                catch (Win32Exception)
                {
                    // Process metadata is best effort; other processes remain discoverable.
                }
            }
        }

        return snapshots;
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

    private static string? TryGetOwnerSid(int processId)
    {
        using var processHandle = OpenProcess(ProcessQueryLimitedInformation, inheritHandle: false, processId);
        if (processHandle.IsInvalid
            || !OpenProcessToken(processHandle, TokenQuery, out var tokenHandle))
        {
            return null;
        }

        using (tokenHandle)
        using (var identity = new WindowsIdentity(tokenHandle.DangerousGetHandle()))
        {
            return identity.User?.Value;
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern SafeProcessHandle OpenProcess(
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        int processId);

    [DllImport("advapi32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(
        SafeProcessHandle processHandle,
        uint desiredAccess,
        out SafeAccessTokenHandle tokenHandle);
}
