using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text.Json;

namespace Sf.EndpointAI.InstallerActions;

[SupportedOSPlatform("windows")]
internal static class Program
{
    private const string ServiceName = "SfEndpointAIProxy";
    private const string ServiceExe = "Sf.EndpointAI.Client.Service.exe";
    private const string TrayExe = "Sf.EndpointAI.Client.Tray.exe";
    private const string ConfigKey = @"Software\SF\EndpointAIProxy";
    private const string ServiceKey = @"SYSTEM\CurrentControlSet\Services\SfEndpointAIProxy";
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string RunName = "SF Endpoint AI Proxy Tray";
    private static string stage = "arguments";
    private static string mode = "";
    private static string installRoot = "";
    private static string dataRoot = "";
    private static string transactionRoot = "";
    private static string logPath = "";

    private sealed record ValueState(bool Exists, string? Value);
    private sealed record Snapshot(Dictionary<string, ValueState> Values, string? Dacl,
        bool EnvironmentExists, string[] Environment, Dictionary<string, ValueState> Run,
        bool WasRunning, string? OldExecutable);

    public static int Main(string[] args)
    {
        try
        {
            var options = new Dictionary<string, string>(StringComparer.Ordinal);
            if (args.Length != 8) throw new ArgumentException("Invalid installer arguments.", nameof(args));
            for (int i = 0; i < args.Length; i += 2) options.Add(args[i], args[i + 1]);
            mode = options["--mode"];
            if (!new[] { "preflight", "snapshot", "quiesce", "apply", "verify", "rollback", "commit" }.Contains(mode))
                throw new ArgumentException("Invalid installer arguments.", nameof(args));
            installRoot = Path.GetFullPath(options["--install-dir"]).TrimEnd(Path.DirectorySeparatorChar);
            dataRoot = Path.GetFullPath(options["--data-dir"]).TrimEnd(Path.DirectorySeparatorChar);
            var expectedData = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SF", "EndpointAIProxy");
            if (!dataRoot.Equals(expectedData, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException();
            var transaction = Guid.Parse(options["--transaction"]).ToString("N");
            using var identity = WindowsIdentity.GetCurrent();
            if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                throw new UnauthorizedAccessException();
            stage = "initialize_logs";
            SecureDirectory(dataRoot);
            var logs = Path.Combine(dataRoot, "InstallerLogs");
            SecureDirectory(logs);
            var states = Path.Combine(dataRoot, "InstallerState");
            SecureDirectory(states);
            transactionRoot = Path.Combine(states, transaction);
            SecureDirectory(transactionRoot);
            var marker = Path.Combine(transactionRoot, "run-id.txt");
            RejectReparse(marker);
            if (mode == "preflight")
            {
                var runId = DateTime.UtcNow.ToString("yyyyMMddTHHmmssfffffff", System.Globalization.CultureInfo.InvariantCulture) + "-" + Guid.NewGuid().ToString("N");
                File.WriteAllText(marker, runId);
                foreach (var old in Directory.GetFiles(logs, "install-*.jsonl").OrderByDescending(File.GetLastWriteTimeUtc).Skip(19))
                {
                    RejectReparse(old);
                    File.Delete(old);
                }
            }
            var id = File.Exists(marker) ? File.ReadAllText(marker) : Guid.NewGuid().ToString("N");
            if (id.Any(c => !(char.IsAsciiLetterOrDigit(c) || c == '-'))) throw new InvalidDataException();
            logPath = Path.Combine(logs, "install-" + id + ".jsonl");
            RejectReparse(logPath);
            Log("begin", identity.User?.Value, Environment.Is64BitProcess);
            switch (mode)
            {
                case "preflight":
                    stage = "check_pending_transaction";
                    if (File.Exists(BackupPath)) throw new InvalidOperationException();
                    stage = "close_legacy_tray";
                    CloseLegacyTray();
                    break;
                case "snapshot": Capture(); break;
                case "quiesce": QuiesceLegacy(); break;
                case "apply": Apply(); break;
                case "verify": VerifyService(); break;
                case "rollback": Rollback(); break;
                case "commit":
                    stage = "commit_cleanup";
                    DeleteTransaction();
                    break;
            }
            Log("success");
            return 0;
        }
        catch (Exception error)
        {
            // Never serialize Message, Data, arguments, registry values or credential input.
            try
            {
                var frame = new StackTrace(error, true).GetFrames()?.FirstOrDefault();
                Log("failed", errorType: error.GetType().FullName, hresult: error.HResult,
                    member: frame?.GetMethod()?.Name, line: frame?.GetFileLineNumber());
            }
            catch { /* The MSI log still records which custom action failed. */ }
            return 1603;
        }
    }

    private static string BackupPath => Path.Combine(transactionRoot, "rollback.json");

    private static void Log(string outcome, string? identity = null, bool? is64Bit = null,
        string? errorType = null, int? hresult = null, string? member = null, int? line = null)
    {
        if (logPath.Length == 0) return;
        File.AppendAllText(logPath, JsonSerializer.Serialize(new
        {
            timeUtc = DateTime.UtcNow, version = "0.1.22", mode, stage, outcome,
            identity, is64Bit, errorType, hresult, member, line
        }) + Environment.NewLine);
    }

    private static void RejectReparse(string path)
    {
        var current = Path.GetFullPath(path);
        while (!string.IsNullOrEmpty(current))
        {
            if ((File.Exists(current) || Directory.Exists(current))
                && (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new IOException();
            current = Path.GetDirectoryName(current);
        }
    }

    private static void SecureDirectory(string path)
    {
        RejectReparse(path);
        var directory = Directory.CreateDirectory(path);
        var desired = new DirectorySecurity();
        desired.SetAccessRuleProtection(true, false);
        foreach (var sid in new[] { "S-1-5-18", "S-1-5-32-544" })
            desired.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid),
                FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
        var current = directory.GetAccessControl(AccessControlSections.Access);
        if (current.GetSecurityDescriptorSddlForm(AccessControlSections.Access)
            != desired.GetSecurityDescriptorSddlForm(AccessControlSections.Access))
            directory.SetAccessControl(desired); // DACL only; no owner/group/SACL changes.
    }

    private static RegistryKey Machine(RegistryView view = RegistryView.Registry64) =>
        RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);

    private static ValueState ReadValue(RegistryKey? key, string name) =>
        key is not null && key.GetValueNames().Contains(name, StringComparer.OrdinalIgnoreCase)
            ? new(true, key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string
                ?? throw new InvalidDataException())
            : new(false, null);

    private static string? ServiceExecutable()
    {
        using var machine = Machine();
        using var key = machine.OpenSubKey(ServiceKey);
        var raw = key?.GetValue("ImagePath") as string;
        if (raw is null) return null;
        raw = Environment.ExpandEnvironmentVariables(raw).Trim();
        var end = raw.StartsWith('"') ? raw.IndexOf('"', 1) : raw.IndexOf(".exe", StringComparison.OrdinalIgnoreCase) + 4;
        if (end < 1) throw new InvalidDataException();
        var exe = Path.GetFullPath(raw.StartsWith('"') ? raw[1..end] : raw[..end]);
        if (!Path.GetFileName(exe).Equals(ServiceExe, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException();
        return exe;
    }

    private static void CloseLegacyTray()
    {
        var allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            Path.Combine(installRoot, TrayExe)
        };
        var old = ServiceExecutable();
        if (old is not null) allowed.Add(Path.Combine(Path.GetDirectoryName(old)!, TrayExe));
        foreach (var process in Process.GetProcessesByName(Path.GetFileNameWithoutExtension(TrayExe)))
        {
            using (process)
            {
                if (process.HasExited) continue;
                var executable = process.MainModule?.FileName;
                if (executable is null) throw new InvalidOperationException();
                if (!allowed.Contains(Path.GetFullPath(executable))) continue;
                // The same process handle is used for graceful close, bounded wait and termination.
                process.CloseMainWindow();
                if (!process.WaitForExit(5000))
                {
                    process.Kill(entireProcessTree: false);
                    if (!process.WaitForExit(10000)) throw new System.TimeoutException();
                }
            }
        }
    }

    private static void Capture()
    {
        stage = "snapshot_previous_configuration";
        RejectReparse(BackupPath);
        if (File.Exists(BackupPath)) throw new InvalidOperationException();
        using var machine = Machine();
        using var config = machine.OpenSubKey(ConfigKey);
        using var service = machine.OpenSubKey(ServiceKey);
        var values = InstallerPolicy.ControlNames.ToDictionary(n => n, n => ReadValue(config, n));
        var envExists = service?.GetValueNames().Contains("Environment", StringComparer.OrdinalIgnoreCase) == true;
        var environment = envExists ? service!.GetValue("Environment") as string[] ?? throw new InvalidDataException() : [];
        var run = new Dictionary<string, ValueState>();
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            using var hive = Machine(view);
            using var key = hive.OpenSubKey(RunKey);
            run.Add(view.ToString(), ReadValue(key, RunName));
        }
        var wasRunning = false;
        if (service is not null)
        {
            using var controller = new ServiceController(ServiceName);
            wasRunning = controller.Status == ServiceControllerStatus.Running;
        }
        var snapshot = new Snapshot(values, config?.GetAccessControl(AccessControlSections.Access)
            .GetSecurityDescriptorSddlForm(AccessControlSections.Access), envExists, environment, run,
            wasRunning, ServiceExecutable());
        var temporary = BackupPath + ".tmp";
        RejectReparse(temporary);
        File.WriteAllText(temporary, JsonSerializer.Serialize(snapshot));
        File.Move(temporary, BackupPath);
        Log("snapshot_saved");
    }

    private static Snapshot ReadSnapshot()
    {
        RejectReparse(BackupPath);
        return JsonSerializer.Deserialize<Snapshot>(File.ReadAllText(BackupPath)) ?? throw new InvalidDataException();
    }

    private static void QuiesceLegacy()
    {
        _ = ReadSnapshot();
        stage = "remove_legacy_autostart";
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            using var hive = Machine(view);
            using var run = hive.OpenSubKey(RunKey, true);
            run?.DeleteValue(RunName, false);
        }
        stage = "close_legacy_tray";
        CloseLegacyTray();
        stage = "stop_previous_service";
        if (ServiceExecutable() is not null)
        {
            using var controller = new ServiceController(ServiceName);
            if (controller.Status != ServiceControllerStatus.Stopped)
            {
                controller.Stop();
                controller.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(45));
            }
        }
    }

    private static void Apply()
    {
        stage = "validate_credentials";
        _ = ReadSnapshot(); // No mutation without a durable rollback snapshot.
        var credentials = Path.Combine(dataRoot, "client-credentials.json");
        RejectReparse(credentials);
        var values = InstallerPolicy.Credentials(File.ReadAllText(credentials));
        using var machine = Machine();
        using var service = machine.OpenSubKey(ServiceKey, true) ?? throw new InvalidOperationException();
        stage = "verify_service_path";
        if (!string.Equals(ServiceExecutable(), Path.Combine(installRoot, ServiceExe), StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException();
        stage = "protect_registry";
        using var key = machine.CreateSubKey(ConfigKey, true);
        var acl = new RegistrySecurity();
        acl.SetAccessRuleProtection(true, false);
        foreach (var sid in new[] { "S-1-5-18", "S-1-5-32-544" })
            acl.AddAccessRule(new RegistryAccessRule(new SecurityIdentifier(sid),
                RegistryRights.FullControl, InheritanceFlags.ContainerInherit,
                PropagationFlags.None, AccessControlType.Allow));
        key.SetAccessControl(acl);
        stage = "write_control_configuration";
        foreach (var (name, value) in values) key.SetValue(name, value, RegistryValueKind.String);
        key.Flush();
        foreach (var (name, value) in values)
            if (!Equals(key.GetValue(name), value)) throw new IOException();
        stage = "remove_stale_service_overrides";
        var environment = service.GetValue("Environment") as string[] ?? [];
        var retained = environment.Where(line => !InstallerPolicy.IsControlOverride(line)).ToArray();
        if (retained.Length == 0) service.DeleteValue("Environment", false);
        else service.SetValue("Environment", retained, RegistryValueKind.MultiString);
        stage = "remove_legacy_autostart";
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            using var hive = Machine(view);
            using var run = hive.OpenSubKey(RunKey, true);
            run?.DeleteValue(RunName, false);
        }
        stage = "confirm_legacy_tray_closed";
        CloseLegacyTray();
    }

    private static void VerifyService()
    {
        stage = "verify_service_running";
        using var controller = new ServiceController(ServiceName);
        controller.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
        Thread.Sleep(3000);
        controller.Refresh();
        if (controller.Status != ServiceControllerStatus.Running) throw new InvalidOperationException();
    }

    private static void Rollback()
    {
        stage = "rollback_configuration";
        if (!File.Exists(BackupPath)) { Log("no_snapshot"); return; }
        var snapshot = ReadSnapshot();
        using var machine = Machine();
        using var service = machine.OpenSubKey(ServiceKey, true);
        ServiceController? controller = null;
        try
        {
            if (service is not null)
            {
                var exe = ServiceExecutable();
                if (!string.Equals(exe, snapshot.OldExecutable, StringComparison.OrdinalIgnoreCase)
                    && !string.Equals(exe, Path.Combine(installRoot, ServiceExe), StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException();
                controller = new ServiceController(ServiceName);
                if (controller.Status != ServiceControllerStatus.Stopped)
                {
                    controller.Stop();
                    controller.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(45));
                }
            }
            using var config = machine.CreateSubKey(ConfigKey, true);
            foreach (var (name, value) in snapshot.Values)
            {
                if (value.Exists) config.SetValue(name, value.Value!, RegistryValueKind.String);
                else config.DeleteValue(name, false);
            }
            if (snapshot.Dacl is not null)
            {
                var security = new RegistrySecurity();
                security.SetSecurityDescriptorSddlForm(snapshot.Dacl, AccessControlSections.Access);
                config.SetAccessControl(security);
            }
            if (service is not null)
            {
                if (snapshot.EnvironmentExists) service.SetValue("Environment", snapshot.Environment, RegistryValueKind.MultiString);
                else service.DeleteValue("Environment", false);
            }
            foreach (var (view, state) in snapshot.Run)
            {
                using var hive = Machine(Enum.Parse<RegistryView>(view));
                using var run = hive.CreateSubKey(RunKey, true);
                if (state.Exists) run.SetValue(RunName, state.Value!, RegistryValueKind.String);
                else run.DeleteValue(RunName, false);
            }
            if (snapshot.WasRunning && controller is not null)
            {
                stage = "restart_restored_service";
                controller.Start();
                controller.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
            }
            DeleteTransaction();
        }
        finally { controller?.Dispose(); }
    }

    private static void DeleteTransaction()
    {
        foreach (var name in new[] { "rollback.json", "rollback.json.tmp", "run-id.txt" })
        {
            var path = Path.Combine(transactionRoot, name);
            RejectReparse(path);
            File.Delete(path);
        }
        Directory.Delete(transactionRoot);
    }
}
