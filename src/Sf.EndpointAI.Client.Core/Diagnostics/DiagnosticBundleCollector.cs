using System.Diagnostics;
using System.IO.Compression;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Sf.EndpointAI.Client.Core.Configuration;
using Sf.EndpointAI.Client.Core.Discovery;
using Sf.EndpointAI.Client.Core.Routing;
using Sf.EndpointAI.Client.Core.Windows;
using Sf.EndpointAI.Contracts;

namespace Sf.EndpointAI.Client.Core.Diagnostics;

public sealed record DiagnosticCollectionOptions(
    string DataRoot,
    string InstallDirectory,
    string OutputDirectory,
    TimeSpan Since,
    Guid? RequestId = null,
    long MaximumBundleBytes = 100L * 1024L * 1024L,
    long MaximumStagedBytes = 90L * 1024L * 1024L,
    bool EnableActiveProbes = true,
    bool EnableSystemCommands = true,
    IReadOnlyList<string>? InitialErrors = null,
    bool RouteRegistryAvailable = true);

public sealed record DiagnosticCollectionResult(
    string BundlePath,
    string Sha256,
    long Length,
    bool Partial,
    bool Truncated,
    IReadOnlyList<string> Errors);

public sealed record DiagnosticCheck(string Code, string Status, string Summary, string Evidence);
public sealed record DiagnosticSection(string Name, string Status, string Evidence, string? Error);

public sealed class DiagnosticBundleCollector(
    DiagnosticCollectionOptions options,
    IReadOnlyList<WindowsUserProfile> profiles,
    IReadOnlyList<RouteRecord> routes,
    AgentDiscoverySnapshot? discovery,
    IWindowsUserAccountResolver accountResolver)
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };
    private readonly List<string> _errors = options.InitialErrors?.ToList() ?? [];
    private readonly List<DiagnosticCheck> _checks = [];
    private readonly Dictionary<string, DiagnosticSection> _sections = new(StringComparer.OrdinalIgnoreCase);
    private string? _activeSection;
    private long _stagedBytes;
    private bool _truncated;

    public async Task<DiagnosticCollectionResult> CollectAsync(CancellationToken cancellationToken = default)
    {
        ValidateOptions();
        var collectionId = Guid.NewGuid();
        var startedAt = DateTimeOffset.UtcNow;
        var workRoot = Path.Combine(options.DataRoot, "diagnostics", "work", collectionId.ToString("N"));
        Directory.CreateDirectory(workRoot);
        try
        {
            await CollectInstallAsync(workRoot, cancellationToken);
            await CollectSystemAsync(workRoot, cancellationToken);
            ServiceSnapshot? service = null;
            await RunSectionAsync("service", "service/status.json", async () =>
                service = await CollectServiceAsync(workRoot, cancellationToken));
            NetworkSnapshot? network = null;
            await RunSectionAsync("network", "network/connectivity.json", async () =>
                network = await CollectNetworkAsync(workRoot, cancellationToken));
            ConfigurationSnapshot? configuration = null;
            await RunSectionAsync("configuration", "configuration/profiles.json", async () =>
                configuration = await CollectConfigurationAsync(workRoot, cancellationToken));
            await RunSectionAsync("agents", "agents/inventory.json", () => CollectAgentsAsync(workRoot, cancellationToken),
                () => discovery is not null && discovery.Agents.Count == 0);
            await RunSectionAsync("routes", "routes/registry-sanitized.json", async () =>
                {
                    if (!options.RouteRegistryAvailable)
                    {
                        throw new IOException("The route registry could not be loaded.");
                    }

                    await CollectRoutesAsync(workRoot, cancellationToken);
                },
                () => options.RouteRegistryAvailable && routes.Count == 0);
            RequestHistorySnapshot? requests = null;
            await RunSectionAsync("requests", "requests/recent-summary.jsonl", async () =>
                requests = await CollectRequestHistoryAsync(workRoot, startedAt - options.Since, cancellationToken),
                () => requests is not null && requests.TotalCount == 0);
            OperationalEvidence? operational = null;
            await RunSectionAsync("operational-logs", "service/operational-log.jsonl", async () =>
                operational = await CollectOperationalLogsAsync(workRoot, startedAt - options.Since, cancellationToken),
                () => operational is not null && operational.LineCount == 0);
            ClientRuntimeSnapshot? clientRuntime = null;
            await RunSectionAsync("client-runtime", "state/client-runtime.json", async () =>
                clientRuntime = await CollectClientRuntimeAsync(workRoot, service?.Health, cancellationToken));
            await RunSectionAsync("backup-metadata", "configuration/backups-metadata.json", () => CollectBackupMetadataAsync(workRoot, cancellationToken));

            BuildAssessment(service, network, configuration, requests, operational, clientRuntime);
            await WriteJsonAsync(workRoot, "assessment.json", _checks, essential: true, cancellationToken);
            await WriteTextAsync(workRoot, "summary.md", BuildSummary(startedAt), essential: true, cancellationToken);

            var completedAt = DateTimeOffset.UtcNow;
            var manifest = new
            {
                DiagnosticsSchemaVersion = 2,
                CollectionId = collectionId,
                StartedAtUtc = startedAt,
                CompletedAtUtc = completedAt,
                SinceUtc = startedAt - options.Since,
                options.RequestId,
                ClientVersion = typeof(DiagnosticBundleCollector).Assembly.GetName().Version?.ToString() ?? "unknown",
                Partial = _errors.Count > 0 || _truncated,
                Truncated = _truncated,
                Errors = _errors,
                Sections = _sections.Values.OrderBy(section => section.Name, StringComparer.Ordinal).ToArray(),
                Security = new
                {
                    RawRequestBodiesIncluded = false,
                    RawResponseBodiesIncluded = false,
                    RawConfigFilesIncluded = false,
                    RawDatabasesIncluded = false,
                    CredentialsRedacted = true,
                },
            };
            await WriteJsonAsync(workRoot, "manifest.json", manifest, essential: true, cancellationToken);
            await WriteChecksumsAsync(workRoot, cancellationToken);

            Directory.CreateDirectory(options.OutputDirectory);
            var fileName = $"EndpointAIProxy-Diagnostics-{startedAt.UtcDateTime:yyyyMMddTHHmmssZ}-{collectionId:N}";
            var finalPath = Path.Combine(options.OutputDirectory, $"{fileName}.zip");
            var temporaryPath = Path.Combine(options.OutputDirectory, $".{fileName}.tmp");
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }

            ZipFile.CreateFromDirectory(workRoot, temporaryPath, CompressionLevel.Fastest, includeBaseDirectory: false);
            var zipInfo = new FileInfo(temporaryPath);
            if (zipInfo.Length > options.MaximumBundleBytes)
            {
                File.Delete(temporaryPath);
                throw new IOException($"The diagnostic package exceeded {options.MaximumBundleBytes} bytes after compression.");
            }

            File.Move(temporaryPath, finalPath);
            var hash = ComputeFileHash(finalPath);
            await File.WriteAllTextAsync(finalPath + ".sha256", $"{hash}  {Path.GetFileName(finalPath)}\n", new UTF8Encoding(false), cancellationToken);
            return new DiagnosticCollectionResult(
                finalPath,
                hash,
                new FileInfo(finalPath).Length,
                _errors.Count > 0 || _truncated,
                _truncated,
                _errors.ToArray());
        }
        finally
        {
            TryDeleteWorkDirectory(workRoot);
        }
    }

    private async Task CollectInstallAsync(string root, CancellationToken cancellationToken)
    {
        await RunSectionAsync("install", "install/product.json", async () =>
        {
            var files = Directory.Exists(options.InstallDirectory)
                ? Directory.EnumerateFiles(options.InstallDirectory, "*", SearchOption.TopDirectoryOnly)
                    .Where(IsSafeRegularFile)
                    .Select(path =>
                    {
                        var info = new FileInfo(path);
                        return new
                        {
                            File = info.Name,
                            info.Length,
                            info.LastWriteTimeUtc,
                            Version = FileVersionInfo.GetVersionInfo(path).FileVersion,
                            Sha256 = ComputeFileHash(path),
                        };
                    })
                    .ToArray()
                : [];
            await WriteJsonAsync(root, "install/product.json", new
            {
                InstallDirectory = options.InstallDirectory,
                DataRoot = options.DataRoot,
                OsVersion = Environment.OSVersion.VersionString,
                ProcessArchitecture = System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture.ToString(),
                Files = files,
            }, true, cancellationToken);
        });
    }

    private async Task CollectSystemAsync(string root, CancellationToken cancellationToken)
    {
        await RunSectionAsync("system", "system/os.json", async () =>
        {
            var dataDrive = new DriveInfo(Path.GetPathRoot(Path.GetFullPath(options.DataRoot))!);
            await WriteJsonAsync(root, "system/os.json", new
            {
                Environment.OSVersion,
                MachineNameHash = DiagnosticSanitizer.HashIdentifier(Environment.MachineName),
                Environment.SystemDirectory,
                TimeZone = TimeZoneInfo.Local.Id,
                UtcNow = DateTimeOffset.UtcNow,
                LastBootTimeUtc = DateTimeOffset.UtcNow - TimeSpan.FromMilliseconds(Environment.TickCount64),
            }, true, cancellationToken);
            await WriteJsonAsync(root, "system/storage.json", new
            {
                dataDrive.Name,
                dataDrive.DriveFormat,
                dataDrive.TotalSize,
                dataDrive.AvailableFreeSpace,
            }, true, cancellationToken);
            var events = options.EnableSystemCommands
                ? await RunCommandAsync(
                    "wevtutil.exe",
                    "qe System /q:\"*[System[Provider[@Name='Service Control Manager']]] and *[EventData[Data='SfEndpointAIProxy']]\" /c:50 /rd:true /f:text",
                    TimeSpan.FromSeconds(10),
                    cancellationToken)
                : "SKIPPED_BY_TEST_CONFIGURATION";
            await WriteTextAsync(root, "system/event-log.txt", events, false, cancellationToken);
        });
    }

    private async Task<ServiceSnapshot> CollectServiceAsync(string root, CancellationToken cancellationToken)
    {
        var query = options.EnableSystemCommands
            ? await RunCommandAsync("sc.exe", "queryex SfEndpointAIProxy", TimeSpan.FromSeconds(10), cancellationToken)
            : "SKIPPED_BY_TEST_CONFIGURATION";
        var config = options.EnableSystemCommands
            ? await RunCommandAsync("sc.exe", "qc SfEndpointAIProxy", TimeSpan.FromSeconds(10), cancellationToken)
            : "SKIPPED_BY_TEST_CONFIGURATION";
        var recovery = options.EnableSystemCommands
            ? await RunCommandAsync("sc.exe", "qfailure SfEndpointAIProxy", TimeSpan.FromSeconds(10), cancellationToken)
            : "SKIPPED_BY_TEST_CONFIGURATION";
        var running = query.Contains("RUNNING", StringComparison.OrdinalIgnoreCase)
            || query.Contains("运行", StringComparison.OrdinalIgnoreCase);
        var health = options.EnableActiveProbes
            ? await ProbeLocalHealthAsync(cancellationToken)
            : "SKIPPED_BY_TEST_CONFIGURATION";
        var snapshot = new ServiceSnapshot(true, running, query, config, health);
        await WriteJsonAsync(root, "service/status.json", new
        {
            Installed = true,
            Running = running,
            Query = DiagnosticSanitizer.SanitizeText(query),
            Configuration = DiagnosticSanitizer.SanitizeText(config),
            Recovery = DiagnosticSanitizer.SanitizeText(recovery),
            Health = health,
        }, true, cancellationToken);
        return snapshot;
    }

    private async Task<NetworkSnapshot> CollectNetworkAsync(string root, CancellationToken cancellationToken)
    {
        var listeners = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners();
        var port18080 = listeners.Any(endpoint => endpoint.Port == 18080 && IPAddress.IsLoopback(endpoint.Address));
        var port15721 = listeners.Any(endpoint => endpoint.Port == 15721 && IPAddress.IsLoopback(endpoint.Address));
        IPAddress[] addresses = [];
        string? dnsError = null;
        try
        {
            if (options.EnableActiveProbes)
            {
                addresses = await Dns.GetHostAddressesAsync("gateway.example.invalid", cancellationToken);
            }
        }
        catch (Exception exception) when (exception is SocketException or ArgumentException)
        {
            dnsError = exception.Message;
        }

        var tcpConnected = false;
        string? tcpError = null;
        var stopwatch = Stopwatch.StartNew();
        try
        {
            if (options.EnableActiveProbes)
            {
                using var tcp = new TcpClient();
                using var probeTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                probeTimeout.CancelAfter(TimeSpan.FromSeconds(10));
                await tcp.ConnectAsync("gateway.example.invalid", 80, probeTimeout.Token);
                tcpConnected = true;
            }
        }
        catch (Exception exception) when (exception is SocketException or OperationCanceledException)
        {
            tcpError = exception.Message;
        }
        finally
        {
            stopwatch.Stop();
        }

        var snapshot = new NetworkSnapshot(port18080, port15721, addresses.Length > 0, tcpConnected);
        await WriteJsonAsync(root, "network/connectivity.json", new
        {
            Port18080Listening = port18080,
            Port15721Listening = port15721,
            GatewayHost = "gateway.example.invalid",
            GatewayPort = 80,
            DnsAddresses = addresses.Select(address => address.ToString()).ToArray(),
            DnsError = DiagnosticSanitizer.SanitizeText(dnsError ?? string.Empty),
            TcpConnected = tcpConnected,
            TcpElapsedMilliseconds = stopwatch.ElapsedMilliseconds,
            TcpError = DiagnosticSanitizer.SanitizeText(tcpError ?? string.Empty),
        }, true, cancellationToken);
        var netstat = options.EnableSystemCommands
            ? await RunCommandAsync("netstat.exe", "-ano -p tcp", TimeSpan.FromSeconds(10), cancellationToken)
            : "SKIPPED_BY_TEST_CONFIGURATION";
        var ipconfig = options.EnableSystemCommands
            ? await RunCommandAsync("ipconfig.exe", "/all", TimeSpan.FromSeconds(10), cancellationToken)
            : "SKIPPED_BY_TEST_CONFIGURATION";
        var winHttp = options.EnableSystemCommands
            ? await RunCommandAsync("netsh.exe", "winhttp show proxy", TimeSpan.FromSeconds(10), cancellationToken)
            : "SKIPPED_BY_TEST_CONFIGURATION";
        await WriteTextAsync(root, "network/netstat.txt", netstat, false, cancellationToken);
        await WriteTextAsync(root, "network/ipconfig.txt", ipconfig, false, cancellationToken);
        await WriteTextAsync(root, "network/winhttp-proxy.txt", winHttp, false, cancellationToken);
        return snapshot;
    }

    private async Task<ConfigurationSnapshot> CollectConfigurationAsync(string root, CancellationToken cancellationToken)
    {
        var localRouteReferences = 0;
        var staleCcSwitchReferences = 0;
        var externalReferences = 0;
        var ccSwitchSchemaUnsupported = 0;
        var ccSwitchCurrentProviderInvalid = 0;
        var ccSwitchEnabledApps = 0;
        var profileResults = new List<object>();
        foreach (var profile in profiles)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var account = accountResolver.Resolve(profile.Sid);
            var profileAlias = DiagnosticSanitizer.HashIdentifier(profile.Sid).Replace(':', '-');
            var claudePath = Path.Combine(profile.ProfilePath, ".claude", "settings.json");
            var codexPath = Path.Combine(profile.ProfilePath, ".codex", "config.toml");
            var claude = await ReadSanitizedConfigAsync(root, $"configuration/profiles/{profileAlias}/claude.json", claudePath, cancellationToken);
            var codex = await ReadSanitizedConfigAsync(root, $"configuration/profiles/{profileAlias}/codex.toml", codexPath, cancellationToken);
            foreach (var content in new[] { claude.SanitizedContent, codex.SanitizedContent }.Where(value => value is not null))
            {
                if (content!.Contains("127.0.0.1:18080", StringComparison.OrdinalIgnoreCase)) localRouteReferences++;
                else if (content.Contains("127.0.0.1:15721", StringComparison.OrdinalIgnoreCase)) staleCcSwitchReferences++;
                else if (content.Contains("http://", StringComparison.OrdinalIgnoreCase) || content.Contains("https://", StringComparison.OrdinalIgnoreCase)) externalReferences++;
            }

            object? ccSwitch = null;
            var ccSwitchPath = Path.Combine(profile.ProfilePath, ".cc-switch", "cc-switch.db");
            if (File.Exists(ccSwitchPath) && IsSafeRegularFile(ccSwitchPath))
            {
                try
                {
                    var inspection = await CcSwitchDatabaseAdapter.InspectAsync(ccSwitchPath, cancellationToken);
                    if (!inspection.ProviderSchemaSupported || !inspection.ProxySchemaSupported || !inspection.EndpointSchemaSupported)
                    {
                        ccSwitchSchemaUnsupported++;
                    }

                    ccSwitchEnabledApps += inspection.ProxyConfigs.Values.Count(config => config.Enabled);
                    foreach (var appType in new[] { "claude", "codex" })
                    {
                        var appProviders = inspection.Providers.Where(provider => provider.AppType.Equals(appType, StringComparison.Ordinal)).ToArray();
                        if (appProviders.Length > 0 && appProviders.Count(provider => provider.IsCurrent) != 1)
                        {
                            ccSwitchCurrentProviderInvalid++;
                        }
                    }
                    ccSwitch = new
                    {
                        inspection.UserVersion,
                        inspection.ProviderSchemaSupported,
                        inspection.ProxySchemaSupported,
                        inspection.EndpointSchemaSupported,
                        Providers = inspection.Providers.Select(provider => new
                        {
                            provider.ProviderId,
                            provider.AppType,
                            provider.Name,
                            provider.IsCurrent,
                            BaseUrl = provider.OriginalBaseUri is null ? null : DiagnosticSanitizer.SanitizeUri(provider.OriginalBaseUri.AbsoluteUri),
                            provider.ErrorCode,
                        }),
                        Endpoints = inspection.Endpoints.Select(endpoint => new
                        {
                            endpoint.EndpointId,
                            endpoint.ProviderId,
                            endpoint.AppType,
                            Url = DiagnosticSanitizer.SanitizeUri(endpoint.Url),
                            endpoint.ErrorCode,
                        }),
                        inspection.ProxyConfigs,
                    };
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or Microsoft.Data.Sqlite.SqliteException or ConfigMutationException)
                {
                    AddError("configuration.ccswitch", exception);
                }
            }

            profileResults.Add(new
            {
                UserSid = DiagnosticSanitizer.HashIdentifier(profile.Sid),
                account.UserId,
                account.UsedSidFallback,
                ProfilePathHash = DiagnosticSanitizer.HashIdentifier(profile.ProfilePath),
                Claude = claude.Metadata,
                Codex = codex.Metadata,
                CcSwitch = ccSwitch,
            });
        }

        await WriteJsonAsync(root, "configuration/profiles.json", profileResults, true, cancellationToken);
        return new ConfigurationSnapshot(
            localRouteReferences,
            staleCcSwitchReferences,
            externalReferences,
            ccSwitchSchemaUnsupported,
            ccSwitchCurrentProviderInvalid,
            ccSwitchEnabledApps);
    }

    private async Task CollectAgentsAsync(string root, CancellationToken cancellationToken)
    {
        if (discovery is null)
        {
            AddError("agents", new InvalidOperationException("Agent discovery was unavailable."));
            return;
        }

        var sanitized = discovery with
        {
            Agents = discovery.Agents.Select(agent => agent with
            {
                UserSid = DiagnosticSanitizer.HashIdentifier(agent.UserSid),
                Evidence = agent.Evidence.Select(evidence => evidence with
                {
                    UserSid = DiagnosticSanitizer.HashIdentifier(evidence.UserSid),
                    Artifact = DiagnosticSanitizer.SanitizeText(evidence.Artifact),
                }).ToArray(),
            }).ToArray(),
            Evidence = discovery.Evidence.Select(evidence => evidence with
            {
                UserSid = DiagnosticSanitizer.HashIdentifier(evidence.UserSid),
                Artifact = DiagnosticSanitizer.SanitizeText(evidence.Artifact),
            }).ToArray(),
            Failures = discovery.Failures.Select(failure => failure with
            {
                Message = DiagnosticSanitizer.SanitizeText(failure.Message),
            }).ToArray(),
        };
        await WriteJsonAsync(root, "agents/inventory.json", sanitized, true, cancellationToken);
    }

    private async Task CollectRoutesAsync(string root, CancellationToken cancellationToken)
    {
        var sanitized = routes.Select(route => new
        {
            route.RouteId,
            UserSid = DiagnosticSanitizer.HashIdentifier(route.UserSid),
            route.AgentType,
            route.ProviderId,
            OriginalBaseUrl = DiagnosticSanitizer.SanitizeUri(route.OriginalBaseUri.AbsoluteUri),
            InjectedBaseUrl = route.InjectedBaseUri.AbsoluteUri,
            route.Status,
            route.CreatedAtUtc,
            route.UpdatedAtUtc,
        });
        await WriteJsonAsync(root, "routes/registry-sanitized.json", sanitized, true, cancellationToken);
    }

    private async Task<RequestHistorySnapshot> CollectRequestHistoryAsync(string root, DateTimeOffset since, CancellationToken cancellationToken)
    {
        var summaryRoot = Path.Combine(options.DataRoot, "captures", "summary");
        var recent = new List<string>();
        var failures = new List<string>();
        var failedCapturePaths = new List<(Guid RequestId, string Path)>();
        var captureDegraded = false;
        if (Directory.Exists(summaryRoot))
        {
            foreach (var path in Directory.EnumerateFiles(summaryRoot, "*.jsonl", SearchOption.TopDirectoryOnly).OrderByDescending(value => value, StringComparer.Ordinal))
            {
                if (!IsSafeRegularFile(path)) continue;
                IReadOnlyList<string> lines;
                try
                {
                    lines = await ReadAllLinesSharedAsync(path, cancellationToken);
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                {
                    AddError("requests", exception);
                    continue;
                }

                foreach (var line in lines)
                {
                    if (!TrySelectSummary(
                        line,
                        since,
                        options.RequestId,
                        out var sanitized,
                        out var failure,
                        out var degraded,
                        out var observedRequestId,
                        out var markdownPath)) continue;
                    if (recent.Count < 200) recent.Add(sanitized);
                    if (failure && failures.Count < 200) failures.Add(sanitized);
                    if (failure && markdownPath is not null && failedCapturePaths.Count < 50)
                    {
                        failedCapturePaths.Add((observedRequestId, markdownPath));
                    }
                    captureDegraded |= degraded;
                }
            }
        }

        await WriteTextAsync(root, "requests/recent-summary.jsonl", string.Join('\n', recent) + (recent.Count > 0 ? "\n" : string.Empty), false, cancellationToken);
        await WriteTextAsync(root, "requests/failures.jsonl", string.Join('\n', failures) + (failures.Count > 0 ? "\n" : string.Empty), true, cancellationToken);
        var capturesRoot = Path.GetFullPath(Path.Combine(options.DataRoot, "captures")) + Path.DirectorySeparatorChar;
        foreach (var capture in failedCapturePaths.DistinctBy(item => item.RequestId))
        {
            var path = Path.GetFullPath(capture.Path);
            if (!path.StartsWith(capturesRoot, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!File.Exists(path) && File.Exists(path + ".gz"))
            {
                path += ".gz";
            }

            if (!File.Exists(path) || !IsSafeRegularFile(path)) continue;

            string markdown;
            try
            {
                markdown = await ReadAllTextSharedAsync(path, cancellationToken);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                AddError("requests", exception);
                continue;
            }
            await WriteTextAsync(
                root,
                $"requests/sanitized-captures/{capture.RequestId:N}.md",
                SanitizeMarkdownCapture(markdown),
                false,
                cancellationToken);
        }

        return new RequestHistorySnapshot(recent.Count, failures.Count, captureDegraded);
    }

    private async Task<OperationalEvidence> CollectOperationalLogsAsync(string root, DateTimeOffset since, CancellationToken cancellationToken)
    {
        var logRoot = Path.Combine(options.DataRoot, "logs", "service");
        if (!Directory.Exists(logRoot)) return new OperationalEvidence(false, false, false, false, 0);
        var builder = new StringBuilder();
        var lineCount = 0;
        foreach (var path in Directory
            .EnumerateFiles(logRoot, "*", SearchOption.TopDirectoryOnly)
            .Where(path => path.EndsWith(".jsonl", StringComparison.OrdinalIgnoreCase)
                || path.EndsWith(".jsonl.gz", StringComparison.OrdinalIgnoreCase))
            .OrderBy(value => value, StringComparer.Ordinal))
        {
            var info = new FileInfo(path);
            if (!IsSafeRegularFile(path) || info.LastWriteTimeUtc < since.UtcDateTime) continue;
            IReadOnlyList<string> lines;
            try
            {
                lines = await ReadAllLinesSharedAsync(path, cancellationToken);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                AddError("operational-logs", exception);
                continue;
            }

            foreach (var line in lines)
            {
                if (builder.Length >= 20 * 1024 * 1024)
                {
                    MarkActiveSectionTruncated();
                    break;
                }

                try
                {
                    builder.AppendLine(DiagnosticSanitizer.SanitizeJson(line));
                }
                catch (JsonException)
                {
                    builder.AppendLine(DiagnosticSanitizer.SanitizeText(line));
                }
                lineCount++;
            }
        }

        var content = builder.ToString();
        await WriteTextAsync(root, "service/operational-log.jsonl", content, false, cancellationToken);
        return new OperationalEvidence(
            content.Contains("CCSWITCH_PROXY_STATE_INCONSISTENT", StringComparison.Ordinal),
            content.Contains("ROUTE_RETIREMENT_DEFERRED", StringComparison.Ordinal),
            content.Contains("ORIGINAL_BASE_URL_RECOVERY_REQUIRED", StringComparison.Ordinal),
            content.Contains("CCSWITCH_PROXY_LISTENER_UNAVAILABLE", StringComparison.Ordinal),
            lineCount);
    }

    private async Task CollectBackupMetadataAsync(string root, CancellationToken cancellationToken)
    {
        var backupRoot = Path.Combine(options.DataRoot, "config-backups");
        var metadata = Directory.Exists(backupRoot)
            ? Directory.EnumerateFiles(backupRoot, "*", SearchOption.AllDirectories)
                .Where(IsSafeRegularFile)
                .Take(500)
                .Select(path =>
                {
                    var info = new FileInfo(path);
                    return new
                    {
                        RelativePathHash = DiagnosticSanitizer.HashIdentifier(Path.GetRelativePath(backupRoot, path)),
                        info.Length,
                        info.CreationTimeUtc,
                        info.LastWriteTimeUtc,
                        Sha256 = ComputeFileHash(path),
                    };
                }).ToArray()
            : [];
        await WriteJsonAsync(root, "configuration/backups-metadata.json", metadata, false, cancellationToken);
    }

    private async Task<ClientRuntimeSnapshot> CollectClientRuntimeAsync(
        string root,
        string? health,
        CancellationToken cancellationToken)
    {
        var databasePath = Path.Combine(options.DataRoot, "state", "client.db");
        if (!File.Exists(databasePath) || !IsSafeRegularFile(databasePath))
        {
            await WriteJsonAsync(root, "state/client-runtime.json", new { DatabaseExists = false }, true, cancellationToken);
            return new ClientRuntimeSnapshot(null, null, [], null, null);
        }

        var connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadOnly,
            Cache = SqliteCacheMode.Private,
            Pooling = false,
        }.ConnectionString;
        await using var connection = new SqliteConnection(connectionString);
        await connection.OpenAsync(cancellationToken);

        Guid? deviceId = null;
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT device_id FROM client_identity WHERE singleton_id=1;";
            if (await command.ExecuteScalarAsync(cancellationToken) is string value && Guid.TryParse(value, out var parsed))
            {
                deviceId = parsed;
            }
        }

        ClientOperationState? operationState = null;
        DateTimeOffset? operationUpdatedAtUtc = null;
        string? operationErrorCode = null;
        string? operationErrorSummary = null;
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = """
                SELECT operation_state, updated_at_utc, last_error_code, last_error_summary
                FROM client_operation_state WHERE singleton_id=1;
                """;
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (await reader.ReadAsync(cancellationToken))
            {
                operationState = (ClientOperationState)reader.GetInt32(0);
                operationUpdatedAtUtc = DateTimeOffset.Parse(reader.GetString(1), CultureInfo.InvariantCulture);
                operationErrorCode = reader.IsDBNull(2) ? null : reader.GetString(2);
                operationErrorSummary = reader.IsDBNull(3) ? null : DiagnosticSanitizer.SanitizeText(reader.GetString(3));
            }
        }

        object? cachedPolicy = null;
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = """
                SELECT policy_version, server_instance_id, received_at_utc
                FROM cached_policy WHERE singleton_id=1;
                """;
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (await reader.ReadAsync(cancellationToken))
            {
                cachedPolicy = new
                {
                    PolicyVersion = reader.GetInt64(0),
                    ServerInstanceId = reader.GetString(1),
                    ReceivedAtUtc = DateTimeOffset.Parse(reader.GetString(2), CultureInfo.InvariantCulture),
                };
            }
        }

        var receipts = new List<CommandReceiptSnapshot>();
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = """
                SELECT command_id, command_type, status, received_at_utc, completed_at_utc,
                       result_code, result_summary
                FROM remote_command_receipts
                ORDER BY received_at_utc DESC
                LIMIT 50;
                """;
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                receipts.Add(new CommandReceiptSnapshot(
                    Guid.Parse(reader.GetString(0)),
                    (RemoteCommandType)reader.GetInt32(1),
                    (RemoteCommandStatus)reader.GetInt32(2),
                    DateTimeOffset.Parse(reader.GetString(3), CultureInfo.InvariantCulture),
                    reader.IsDBNull(4) ? null : DateTimeOffset.Parse(reader.GetString(4), CultureInfo.InvariantCulture),
                    reader.IsDBNull(5) ? null : reader.GetString(5),
                    reader.IsDBNull(6) ? null : DiagnosticSanitizer.SanitizeText(reader.GetString(6))));
            }
        }

        DateTimeOffset? lastControlSyncAtUtc = null;
        string? lastControlErrorCode = null;
        if (!string.IsNullOrWhiteSpace(health) && health.TrimStart().StartsWith('{'))
        {
            using var document = JsonDocument.Parse(health);
            if (document.RootElement.TryGetProperty("lastControlSyncAtUtc", out var sync)
                && sync.ValueKind == JsonValueKind.String
                && sync.TryGetDateTimeOffset(out var parsedSync))
            {
                lastControlSyncAtUtc = parsedSync;
            }
            if (document.RootElement.TryGetProperty("lastControlErrorCode", out var error)
                && error.ValueKind == JsonValueKind.String)
            {
                lastControlErrorCode = DiagnosticSanitizer.SanitizeText(error.GetString() ?? string.Empty);
            }
        }

        await WriteJsonAsync(root, "state/client-runtime.json", new
        {
            DatabaseExists = true,
            DeviceId = deviceId,
            Operation = new
            {
                State = operationState?.ToString(),
                UpdatedAtUtc = operationUpdatedAtUtc,
                LastErrorCode = operationErrorCode,
                LastErrorSummary = operationErrorSummary,
            },
            CachedPolicy = cachedPolicy,
            LastControlSyncAtUtc = lastControlSyncAtUtc,
            LastControlErrorCode = lastControlErrorCode,
            CommandReceipts = receipts.Select(receipt => new
            {
                receipt.CommandId,
                Type = receipt.Type.ToString(),
                Status = receipt.Status.ToString(),
                receipt.ReceivedAtUtc,
                receipt.CompletedAtUtc,
                receipt.ResultCode,
                receipt.ResultSummary,
            }).ToArray(),
        }, true, cancellationToken);
        return new ClientRuntimeSnapshot(operationState, operationUpdatedAtUtc, receipts, lastControlSyncAtUtc, lastControlErrorCode);
    }

    private void BuildAssessment(
        ServiceSnapshot? service,
        NetworkSnapshot? network,
        ConfigurationSnapshot? configuration,
        RequestHistorySnapshot? requests,
        OperationalEvidence? operational,
        ClientRuntimeSnapshot? clientRuntime)
    {
        if (service is null)
        {
            AddUnknown("SERVICE_NOT_RUNNING", "service/status.json");
            AddUnknown("SERVICE_START_FAILED", "service/status.json");
            AddUnknown("LOCAL_HEALTH_CHECK_FAILED", "service/status.json");
        }
        else
        {
            AddCheck("SERVICE_NOT_RUNNING", service.Running ? "Pass" : "Fail", service.Running ? "Service is running." : "Service is not running.", "service/status.json");
            AddCheck("SERVICE_START_FAILED", !service.Running && service.Query.Contains("FAILED", StringComparison.OrdinalIgnoreCase) ? "Fail" : "Pass", "Service Control Manager query output was inspected.", "service/status.json");
            var healthOk = service.Health.Contains("\"status\":\"ok\"", StringComparison.OrdinalIgnoreCase)
                || service.Health.Contains("\"status\": \"ok\"", StringComparison.OrdinalIgnoreCase);
            AddCheck("LOCAL_HEALTH_CHECK_FAILED", healthOk ? "Pass" : "Warning", "Local health probe result was captured.", "service/status.json");
        }

        if (network is null)
        {
            AddUnknown("LOCAL_PROXY_PORT_NOT_LISTENING", "network/connectivity.json");
            AddUnknown("LOCAL_PROXY_PORT_OCCUPIED", "network/connectivity.json");
            AddUnknown("GATEWAY_DNS_FAILED", "network/connectivity.json");
            AddUnknown("GATEWAY_TCP_CONNECTION_FAILED", "network/connectivity.json");
        }
        else
        {
            var healthOk = service is not null && (service.Health.Contains("\"status\":\"ok\"", StringComparison.OrdinalIgnoreCase)
                || service.Health.Contains("\"status\": \"ok\"", StringComparison.OrdinalIgnoreCase));
            AddCheck("LOCAL_PROXY_PORT_NOT_LISTENING", network.Port18080 ? "Pass" : "Fail", network.Port18080 ? "Port 18080 is listening." : "Port 18080 is not listening.", "network/connectivity.json");
            AddCheck("LOCAL_PROXY_PORT_OCCUPIED", network.Port18080 && !healthOk ? "Warning" : "Pass", network.Port18080 && !healthOk ? "Port 18080 is listening but did not return the EndpointAI health response." : "No conflicting listener evidence was found.", "service/status.json");
            AddCheck("GATEWAY_DNS_FAILED", network.DnsResolved ? "Pass" : "Fail", network.DnsResolved ? "Gateway DNS resolved." : "Gateway DNS resolution failed.", "network/connectivity.json");
            AddCheck("GATEWAY_TCP_CONNECTION_FAILED", network.TcpConnected ? "Pass" : "Fail", network.TcpConnected ? "Gateway TCP connection succeeded." : "Gateway TCP connection failed.", "network/connectivity.json");
        }

        if (configuration is null || network is null || operational is null)
        {
            foreach (var code in new[] { "LIVE_CONFIG_POINTS_TO_STALE_15721", "LIVE_CONFIG_BYPASSES_PROXY", "CCSWITCH_PROXY_LISTENER_UNAVAILABLE", "CCSWITCH_PROXY_STATE_INCONSISTENT", "CCSWITCH_SCHEMA_UNSUPPORTED", "CCSWITCH_CURRENT_PROVIDER_INVALID" })
                AddUnknown(code, "configuration/profiles.json");
        }
        else
        {
            AddCheck("LIVE_CONFIG_POINTS_TO_STALE_15721", configuration.StaleCcSwitchReferences > 0 && !network.Port15721 ? "Fail" : "Pass", $"Found {configuration.StaleCcSwitchReferences} configuration references to port 15721; listener={network.Port15721}.", "configuration/profiles.json");
            AddCheck("LIVE_CONFIG_BYPASSES_PROXY", configuration.ExternalReferences > 0 && configuration.LocalRouteReferences == 0 ? "Warning" : "Pass", $"Local route references={configuration.LocalRouteReferences}, external references={configuration.ExternalReferences}.", "configuration/profiles.json");
            AddCheck("CCSWITCH_PROXY_LISTENER_UNAVAILABLE", (configuration.CcSwitchEnabledApps > 0 && !network.Port15721) || operational.ListenerUnavailable ? "Fail" : "Pass", $"CC Switch enabled applications={configuration.CcSwitchEnabledApps}; listener={network.Port15721}.", "configuration/profiles.json");
            AddCheck("CCSWITCH_PROXY_STATE_INCONSISTENT", operational.CcSwitchInconsistent || (configuration.StaleCcSwitchReferences > 0 && configuration.CcSwitchEnabledApps == 0) ? "Warning" : "Pass", "CC Switch takeover evidence was compared with Live Config.", "service/operational-log.jsonl");
            AddCheck("CCSWITCH_SCHEMA_UNSUPPORTED", configuration.CcSwitchSchemaUnsupported > 0 ? "Fail" : "Pass", $"Unsupported CC Switch schemas={configuration.CcSwitchSchemaUnsupported}.", "configuration/profiles.json");
            AddCheck("CCSWITCH_CURRENT_PROVIDER_INVALID", configuration.CcSwitchCurrentProviderInvalid > 0 ? "Fail" : "Pass", $"Applications without exactly one current provider={configuration.CcSwitchCurrentProviderInvalid}.", "configuration/profiles.json");
        }

        if (!options.RouteRegistryAvailable)
        {
            AddUnknown("ROUTE_NOT_FOUND", "routes/registry-sanitized.json");
            AddUnknown("ROUTE_IDENTITY_MISMATCH", "routes/registry-sanitized.json");
            AddUnknown("ROUTE_REGISTRY_CONFIG_MISMATCH", "routes/registry-sanitized.json");
        }
        else
        {
            AddCheck("ROUTE_NOT_FOUND", routes.Count == 0 ? "Fail" : "Pass", $"Route registry contains {routes.Count} routes.", "routes/registry-sanitized.json");
            var duplicateIdentities = routes.GroupBy(route => (route.UserSid, route.AgentType, route.ProviderId)).Count(group => group.Count() > 1);
            AddCheck("ROUTE_IDENTITY_MISMATCH", duplicateIdentities > 0 ? "Fail" : "Pass", $"Duplicate route identities={duplicateIdentities}.", "routes/registry-sanitized.json");
            if (configuration is null) AddUnknown("ROUTE_REGISTRY_CONFIG_MISMATCH", "configuration/profiles.json");
            else AddCheck("ROUTE_REGISTRY_CONFIG_MISMATCH", configuration.LocalRouteReferences > 0 && routes.Count == 0 ? "Fail" : "Pass", "Live Config local-route references were compared with the Route Registry.", "routes/registry-sanitized.json");
        }

        if (operational is null)
        {
            AddUnknown("ROUTE_RETIREMENT_DEFERRED", "service/operational-log.jsonl");
            AddUnknown("ORIGINAL_BASE_URL_RECOVERY_REQUIRED", "service/operational-log.jsonl");
        }
        else
        {
            AddCheck("ROUTE_RETIREMENT_DEFERRED", operational.RouteRetirementDeferred ? "Warning" : "Pass", "Recent route-retirement evidence was inspected.", "service/operational-log.jsonl");
            AddCheck("ORIGINAL_BASE_URL_RECOVERY_REQUIRED", operational.OriginalBaseUrlRecoveryRequired ? "Fail" : "Pass", "Recent original BaseURL recovery evidence was inspected.", "service/operational-log.jsonl");
        }
        if (!options.RouteRegistryAvailable)
        {
            AddUnknown("CCR_ALLOWLIST_DECISION_MISMATCH", "routes/registry-sanitized.json");
        }
        else
        {
            var bypassPolicy = new BaseUrlBypassPolicy();
            var allowlistedRoutes = routes.Count(route => bypassPolicy.ShouldBypass(route.OriginalBaseUri));
            AddCheck("CCR_ALLOWLIST_DECISION_MISMATCH", allowlistedRoutes > 0 ? "Fail" : "Pass", $"Routes targeting the CCR allowlist={allowlistedRoutes}.", "routes/registry-sanitized.json");
        }
        if (requests is null)
        {
            AddUnknown("RECENT_GATEWAY_HTTP_ERROR", "requests/failures.jsonl");
            AddUnknown("CAPTURE_OR_AUDIT_DEGRADED", "requests/recent-summary.jsonl");
        }
        else
        {
            AddCheck("RECENT_GATEWAY_HTTP_ERROR", requests.FailureCount > 0 ? "Warning" : "Pass", $"Found {requests.FailureCount} recent failed requests.", "requests/failures.jsonl");
            AddCheck("CAPTURE_OR_AUDIT_DEGRADED", requests.CaptureDegraded ? "Warning" : "Pass", "Recent capture degradation flags were inspected.", "requests/recent-summary.jsonl");
        }
        if (discovery is null) AddUnknown("AGENT_NOT_DISCOVERED", "agents/inventory.json");
        else AddCheck("AGENT_NOT_DISCOVERED", discovery.Agents.Count == 0 ? "Warning" : "Pass", $"Discovered Agent inventory items={discovery.Agents.Count}.", "agents/inventory.json");

        if (clientRuntime is null || clientRuntime.OperationState is null)
        {
            AddUnknown("REMOTE_COMMAND_STUCK_EXECUTING", "state/client-runtime.json");
            AddUnknown("RECENT_REMOTE_COMMAND_FAILED", "state/client-runtime.json");
            AddUnknown("OPERATION_ROUTE_STATE_INCONSISTENT", "state/client-runtime.json");
            AddUnknown("CONTROL_SYNC_STALE", "state/client-runtime.json");
        }
        else
        {
            var now = DateTimeOffset.UtcNow;
            var stuck = clientRuntime.CommandReceipts.Count(receipt => receipt.Status == RemoteCommandStatus.Executing && now - receipt.ReceivedAtUtc > TimeSpan.FromMinutes(5));
            var failed = clientRuntime.CommandReceipts.Count(receipt => receipt.Status == RemoteCommandStatus.Failed && now - receipt.ReceivedAtUtc <= TimeSpan.FromDays(7));
            AddCheck("REMOTE_COMMAND_STUCK_EXECUTING", stuck > 0 ? "Warning" : "Pass", $"Command receipts stuck in Executing={stuck}.", "state/client-runtime.json");
            AddCheck("RECENT_REMOTE_COMMAND_FAILED", failed > 0 ? "Warning" : "Pass", $"Failed command receipts in the diagnostic window={failed}.", "state/client-runtime.json");
            if (!options.RouteRegistryAvailable) AddUnknown("OPERATION_ROUTE_STATE_INCONSISTENT", "routes/registry-sanitized.json");
            else
            {
                var inconsistent = clientRuntime.OperationState != ClientOperationState.Enabled && routes.Any(route => route.Status == RouteStatus.Attached);
                AddCheck("OPERATION_ROUTE_STATE_INCONSISTENT", inconsistent ? "Fail" : "Pass", $"Operation state={clientRuntime.OperationState}; attached routes={routes.Count(route => route.Status == RouteStatus.Attached)}.", "state/client-runtime.json");
            }
            if (clientRuntime.LastControlSyncAtUtc is null) AddUnknown("CONTROL_SYNC_STALE", "state/client-runtime.json");
            else AddCheck("CONTROL_SYNC_STALE", now - clientRuntime.LastControlSyncAtUtc > TimeSpan.FromMinutes(5) ? "Warning" : "Pass", $"Last control sync={clientRuntime.LastControlSyncAtUtc:O}; last error={clientRuntime.LastControlErrorCode ?? "none"}.", "state/client-runtime.json");
        }
        if (_errors.Count > 0 || _truncated) AddCheck("DIAGNOSTICS_PARTIAL_COLLECTION", "Warning", $"{_errors.Count} diagnostic errors; truncated={_truncated}.", "manifest.json");
    }

    private string BuildSummary(DateTimeOffset startedAt)
    {
        var builder = new StringBuilder()
            .AppendLine("# EndpointAIProxy diagnostic summary")
            .AppendLine()
            .AppendLine(FormattableString.Invariant($"- Collected at UTC: `{startedAt:O}`"))
            .AppendLine(FormattableString.Invariant($"- Window: `{options.Since.TotalHours:0}` hours"))
            .AppendLine(FormattableString.Invariant($"- Partial: `{_errors.Count > 0 || _truncated}`"))
            .AppendLine(FormattableString.Invariant($"- Truncated: `{_truncated}`"))
            .AppendLine()
            .AppendLine("## Assessment")
            .AppendLine();
        foreach (var check in _checks)
        {
            builder.AppendLine(CultureInfo.InvariantCulture, $"- **{check.Status}** `{check.Code}` — {check.Summary} Evidence: `{check.Evidence}`");
        }

        builder.AppendLine().AppendLine("The package is read-only and excludes raw request/response bodies, raw configuration files, databases and credentials.");
        return builder.ToString();
    }

    private async Task<(object Metadata, string? SanitizedContent)> ReadSanitizedConfigAsync(
        string root,
        string relativeOutput,
        string sourcePath,
        CancellationToken cancellationToken)
    {
        if (!File.Exists(sourcePath) || !IsSafeRegularFile(sourcePath))
        {
            return (new { Exists = false }, null);
        }

        try
        {
            var before = new FileInfo(sourcePath);
            var content = await ReadAllTextSharedAsync(sourcePath, cancellationToken);
            var sanitized = DiagnosticSanitizer.SanitizeConfigText(content);
            var after = new FileInfo(sourcePath);
            await WriteTextAsync(root, relativeOutput, sanitized, true, cancellationToken);
            return (new
            {
                Exists = true,
                before.Length,
                before.LastWriteTimeUtc,
                Sha256 = ComputeFileHash(sourcePath),
                ChangedDuringCollection = before.Length != after.Length || before.LastWriteTimeUtc != after.LastWriteTimeUtc,
            }, sanitized);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            AddError("configuration", exception);
            return (new
            {
                Exists = true,
                Failed = true,
                Error = $"{exception.GetType().Name}: {DiagnosticSanitizer.SanitizeText(exception.Message)}",
            }, null);
        }
    }

    private static async Task<string> ProbeLocalHealthAsync(CancellationToken cancellationToken)
    {
        try
        {
            using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };
            return DiagnosticSanitizer.SanitizeText(await client.GetStringAsync("http://127.0.0.1:18080/healthz", cancellationToken));
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
        {
            return $"ERROR: {exception.GetType().Name}: {DiagnosticSanitizer.SanitizeText(exception.Message)}";
        }
    }

    private async Task RunSectionAsync(
        string section,
        string evidence,
        Func<Task> action,
        Func<bool>? isEmpty = null)
    {
        var previousSection = _activeSection;
        _activeSection = section;
        _sections[section] = new DiagnosticSection(section, "Collected", evidence, null);
        try
        {
            await action();
            if (!_sections.TryGetValue(section, out var existing)
                || (string.Equals(existing.Status, "Collected", StringComparison.Ordinal)
                    && !string.Equals(existing.Status, "Truncated", StringComparison.Ordinal)))
            {
                _sections[section] = new DiagnosticSection(
                    section,
                    isEmpty?.Invoke() == true ? "Empty" : "Collected",
                    evidence,
                    null);
            }
        }
        catch (Exception exception) when (exception is IOException
            or UnauthorizedAccessException
            or InvalidOperationException
            or System.ComponentModel.Win32Exception
            or NetworkInformationException
            or SocketException
            or JsonException)
        {
            AddError(section, exception);
            _sections[section] = new DiagnosticSection(
                section,
                "Failed",
                evidence,
                $"{exception.GetType().Name}: {DiagnosticSanitizer.SanitizeText(exception.Message)}");
        }
        finally
        {
            _activeSection = previousSection;
        }
    }

    private static async Task<string> ReadAllTextSharedAsync(string path, CancellationToken cancellationToken)
    {
        await using var stream = OpenSharedReadStream(path);
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        return await reader.ReadToEndAsync(cancellationToken);
    }

    private static async Task<IReadOnlyList<string>> ReadAllLinesSharedAsync(string path, CancellationToken cancellationToken)
    {
        var result = new List<string>();
        await using var stream = OpenSharedReadStream(path);
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        while (await reader.ReadLineAsync(cancellationToken) is { } line)
        {
            result.Add(line);
        }

        return result;
    }

    private static Stream OpenSharedReadStream(string path)
    {
        var file = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete,
            64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        return path.EndsWith(".gz", StringComparison.OrdinalIgnoreCase)
            ? new GZipStream(file, CompressionMode.Decompress)
            : file;
    }

    private async Task WriteJsonAsync(string root, string relativePath, object value, bool essential, CancellationToken cancellationToken) =>
        await WriteTextAsync(root, relativePath, JsonSerializer.Serialize(value, JsonOptions), essential, cancellationToken);

    private async Task WriteTextAsync(string root, string relativePath, string content, bool essential, CancellationToken cancellationToken)
    {
        var bytes = Encoding.UTF8.GetByteCount(content);
        if (!essential && _stagedBytes + bytes > options.MaximumStagedBytes)
        {
            MarkActiveSectionTruncated();
            return;
        }

        var fullRoot = Path.GetFullPath(root) + Path.DirectorySeparatorChar;
        var path = Path.GetFullPath(Path.Combine(root, relativePath));
        if (!path.StartsWith(fullRoot, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Diagnostic output escaped the staging directory.");
        }

        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        await File.WriteAllTextAsync(path, content, new UTF8Encoding(false), cancellationToken);
        _stagedBytes += bytes;
    }

    private void MarkActiveSectionTruncated()
    {
        _truncated = true;
        if (_activeSection is null || !_sections.TryGetValue(_activeSection, out var section))
        {
            return;
        }

        if (!string.Equals(section.Status, "Failed", StringComparison.Ordinal))
        {
            _sections[_activeSection] = section with { Status = "Truncated" };
        }
    }

    private async Task WriteChecksumsAsync(string root, CancellationToken cancellationToken)
    {
        var builder = new StringBuilder();
        foreach (var path in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories).OrderBy(value => value, StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!IsSafeRegularFile(path) || Path.GetFileName(path).Equals("checksums.sha256", StringComparison.OrdinalIgnoreCase)) continue;
            builder.Append(ComputeFileHash(path)).Append("  ").AppendLine(Path.GetRelativePath(root, path).Replace('\\', '/'));
        }

        await WriteTextAsync(root, "checksums.sha256", builder.ToString(), true, cancellationToken);
    }

    private static async Task<string> RunCommandAsync(string fileName, string arguments, TimeSpan timeout, CancellationToken cancellationToken)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8,
            },
        };
        process.Start();
        var outputTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var errorTask = process.StandardError.ReadToEndAsync(cancellationToken);
        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);
        try
        {
            await process.WaitForExitAsync(timeoutSource.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            process.Kill(entireProcessTree: true);
            return $"COMMAND_TIMEOUT: {fileName}";
        }

        var output = await outputTask;
        var error = await errorTask;
        return DiagnosticSanitizer.SanitizeText($"ExitCode: {process.ExitCode}\n{output}\n{error}");
    }

    private static bool TrySelectSummary(
        string line,
        DateTimeOffset since,
        Guid? requestId,
        out string sanitized,
        out bool failure,
        out bool degraded,
        out Guid observedRequestId,
        out string? markdownPath)
    {
        sanitized = string.Empty;
        failure = false;
        degraded = false;
        observedRequestId = Guid.Empty;
        markdownPath = null;
        try
        {
            using var document = JsonDocument.Parse(line);
            var root = document.RootElement;
            if (!root.TryGetProperty("StartedAtUtc", out var startedElement)
                || !startedElement.TryGetDateTimeOffset(out var started)
                || started < since)
            {
                return false;
            }

            if (!root.TryGetProperty("RequestId", out var requestElement)
                || !requestElement.TryGetGuid(out observedRequestId))
            {
                return false;
            }

            if (requestId is not null && observedRequestId != requestId)
            {
                return false;
            }

            failure = root.TryGetProperty("Outcome", out var outcome)
                && !string.Equals(outcome.GetString(), "SUCCESS", StringComparison.Ordinal);
            degraded = root.TryGetProperty("CaptureDegraded", out var degradedElement)
                && degradedElement.ValueKind == JsonValueKind.True;
            if (root.TryGetProperty("MarkdownPath", out var markdownElement)
                && markdownElement.ValueKind == JsonValueKind.String)
            {
                markdownPath = markdownElement.GetString();
            }
            sanitized = DiagnosticSanitizer.SanitizeJson(line).Replace("\r", string.Empty, StringComparison.Ordinal).Replace("\n", string.Empty, StringComparison.Ordinal);
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    public static string SanitizeMarkdownCapture(string markdown)
    {
        ArgumentNullException.ThrowIfNull(markdown);
        var safeErrorFields = ExtractSafeErrorFields(markdown);
        var lines = markdown.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
        var output = new StringBuilder();
        var omitBody = false;
        foreach (var line in lines)
        {
            if (line.Equals("## Request body", StringComparison.Ordinal)
                || line.Equals("## Response body", StringComparison.Ordinal))
            {
                omitBody = true;
                output.AppendLine(line).AppendLine().AppendLine("[OMITTED FROM DIAGNOSTICS]").AppendLine();
                continue;
            }

            if (omitBody)
            {
                if (!line.StartsWith("## ", StringComparison.Ordinal))
                {
                    continue;
                }

                omitBody = false;
            }

            output.AppendLine(DiagnosticSanitizer.SanitizeText(line));
        }

        if (!string.IsNullOrWhiteSpace(safeErrorFields))
        {
            output.AppendLine().AppendLine("## Safe error fields").AppendLine().AppendLine(safeErrorFields);
        }

        return output.ToString();
    }

    private static string? ExtractSafeErrorFields(string markdown)
    {
        const string heading = "## Response body";
        var headingIndex = markdown.IndexOf(heading, StringComparison.Ordinal);
        if (headingIndex < 0) return null;
        var fenceStart = markdown.IndexOf("``````", headingIndex + heading.Length, StringComparison.Ordinal);
        if (fenceStart < 0) return null;
        fenceStart = markdown.IndexOf('\n', fenceStart);
        if (fenceStart < 0) return null;
        var fenceEnd = markdown.IndexOf("``````", fenceStart + 1, StringComparison.Ordinal);
        if (fenceEnd < 0 || fenceEnd - fenceStart > 64 * 1024) return null;
        var body = markdown[(fenceStart + 1)..fenceEnd].Trim();
        try
        {
            using var document = JsonDocument.Parse(body);
            var fields = new Dictionary<string, string?>(StringComparer.Ordinal);
            AddSafeJsonFields(document.RootElement, string.Empty, fields);
            if (fields.Count == 0) return null;
            var json = JsonSerializer.Serialize(fields, JsonOptions);
            return json.Length <= 8 * 1024 ? DiagnosticSanitizer.SanitizeText(json) : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static void AddSafeJsonFields(
        JsonElement element,
        string prefix,
        IDictionary<string, string?> fields)
    {
        if (element.ValueKind != JsonValueKind.Object) return;
        foreach (var property in element.EnumerateObject())
        {
            var path = string.IsNullOrEmpty(prefix) ? property.Name : $"{prefix}.{property.Name}";
            if (property.Name.Equals("error", StringComparison.OrdinalIgnoreCase)
                && property.Value.ValueKind == JsonValueKind.Object)
            {
                AddSafeJsonFields(property.Value, path, fields);
                continue;
            }

            if (property.Name is not ("code" or "type" or "message" or "request_id" or "requestId" or "status"))
            {
                continue;
            }

            fields[path] = property.Value.ValueKind == JsonValueKind.String
                ? property.Value.GetString()
                : property.Value.GetRawText();
        }
    }

    private void AddError(string section, Exception exception)
    {
        var message = $"{section}: {exception.GetType().Name}: {DiagnosticSanitizer.SanitizeText(exception.Message)}";
        _errors.Add(message);
        var affectedSection = _activeSection ?? section.Split('.', 2)[0];
        if (_sections.TryGetValue(affectedSection, out var current))
        {
            _sections[affectedSection] = current with { Status = "Failed", Error = message };
        }
    }

    private void AddCheck(string code, string status, string summary, string evidence) =>
        _checks.Add(new DiagnosticCheck(code, status, summary, evidence));

    private void AddUnknown(string code, string evidence) =>
        AddCheck(code, "Unknown", "Required diagnostic evidence was unavailable.", evidence);

    private void ValidateOptions()
    {
        if (options.Since < TimeSpan.FromHours(1) || options.Since > TimeSpan.FromDays(7))
            throw new ArgumentOutOfRangeException(nameof(options), "Diagnostic time range must be between 1 hour and 7 days.");
        if (!Path.IsPathFullyQualified(options.DataRoot) || !Path.IsPathFullyQualified(options.OutputDirectory))
            throw new ArgumentException("Diagnostic paths must be fully qualified.", nameof(options));
    }

    private static string ComputeFileHash(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static bool IsSafeRegularFile(string path)
    {
        try
        {
            return !File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static void TryDeleteWorkDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path)) Directory.Delete(path, recursive: true);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // A stale staging directory is safer than deleting outside the known work root.
        }
    }

    private sealed record ServiceSnapshot(bool Installed, bool Running, string Query, string Configuration, string Health);
    private sealed record NetworkSnapshot(bool Port18080, bool Port15721, bool DnsResolved, bool TcpConnected);
    private sealed record ConfigurationSnapshot(
        int LocalRouteReferences,
        int StaleCcSwitchReferences,
        int ExternalReferences,
        int CcSwitchSchemaUnsupported,
        int CcSwitchCurrentProviderInvalid,
        int CcSwitchEnabledApps);
    private sealed record RequestHistorySnapshot(int TotalCount, int FailureCount, bool CaptureDegraded);
    private sealed record CommandReceiptSnapshot(
        Guid CommandId,
        RemoteCommandType Type,
        RemoteCommandStatus Status,
        DateTimeOffset ReceivedAtUtc,
        DateTimeOffset? CompletedAtUtc,
        string? ResultCode,
        string? ResultSummary);
    private sealed record ClientRuntimeSnapshot(
        ClientOperationState? OperationState,
        DateTimeOffset? OperationUpdatedAtUtc,
        IReadOnlyList<CommandReceiptSnapshot> CommandReceipts,
        DateTimeOffset? LastControlSyncAtUtc,
        string? LastControlErrorCode);
    private sealed record OperationalEvidence(
        bool CcSwitchInconsistent,
        bool RouteRetirementDeferred,
        bool OriginalBaseUrlRecoveryRequired,
        bool ListenerUnavailable,
        int LineCount);
}
