using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Win32;
using Sf.EndpointAI.Client.Core.Capture;
using Sf.EndpointAI.Client.Core.Configuration;
using Sf.EndpointAI.Client.Core.Discovery;
using Sf.EndpointAI.Client.Core.Diagnostics;
using Sf.EndpointAI.Client.Core.MacOS;
using Sf.EndpointAI.Client.Core.Policy;
using Sf.EndpointAI.Client.Core.Routing;
using Sf.EndpointAI.Client.Core.Security;
using Sf.EndpointAI.Client.Core.State;
using Sf.EndpointAI.Client.Core.Windows;
using Sf.EndpointAI.Client.Service;
using Sf.EndpointAI.Contracts;

const int ListenPort = 18080;
if (string.Equals(GetCommandLineOption(args, "maintenance"), "collect-diagnostics", StringComparison.OrdinalIgnoreCase))
{
    Environment.ExitCode = await RunDiagnosticMaintenanceAsync(args);
    return;
}

var builder = WebApplication.CreateBuilder(args);
if (OperatingSystem.IsWindows())
{
    builder.Host.UseWindowsService(options => options.ServiceName = "SfEndpointAIProxy");
}
builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenLocalhost(ListenPort, listen => listen.Protocols = HttpProtocols.Http1AndHttp2);
    options.AddServerHeader = false;
});

var dataRoot = Environment.GetEnvironmentVariable("SF_PROXY_DATA_ROOT")
    ?? GetDefaultDataRoot();
var capturesRoot = Path.Combine(dataRoot, "captures");
var databasePath = Path.Combine(dataRoot, "state", "client.db");
var captureOptions = new CaptureOptions(capturesRoot);
var operationalLogOptions = new JsonlFileLoggerOptions(Path.Combine(dataRoot, "logs", "service"));
var compressionQueue = new LogCompressionScheduler();
var operationalLogTracker = new OperationalLogFileTracker();
builder.Logging.AddProvider(new JsonlFileLoggerProvider(
    operationalLogOptions,
    compressionQueue,
    operationalLogTracker));
var managementEnabled = string.Equals(
    Environment.GetEnvironmentVariable("SF_PROXY_ENABLE_MANAGEMENT_API"),
    "true",
    StringComparison.OrdinalIgnoreCase);
var managementToken = Environment.GetEnvironmentVariable("SF_PROXY_MANAGEMENT_TOKEN");
if (managementEnabled && Encoding.UTF8.GetByteCount(managementToken ?? string.Empty) < 32)
{
    throw new InvalidOperationException("SF_PROXY_MANAGEMENT_TOKEN must contain at least 32 UTF-8 bytes when the management API is enabled.");
}

var initialPolicy = BuildPrototypePolicy(builder.Configuration);
var dynamicPolicyProvider = new DynamicPolicyProvider(initialPolicy);
builder.Services.AddSingleton(dynamicPolicyProvider);
builder.Services.AddSingleton<IPolicyProvider>(dynamicPolicyProvider);
if (OperatingSystem.IsWindows())
{
    builder.Services.AddSingleton<ITextProtector, DpapiTextProtector>();
}
else if (OperatingSystem.IsMacOS())
{
    builder.Services.AddSingleton<ITextProtector>(
        new FileKeyTextProtector(Path.Combine(dataRoot, "state", "machine.key")));
}
else
{
    throw new PlatformNotSupportedException("Sf Endpoint AI Proxy supports Windows and macOS.");
}
builder.Services.AddSingleton<IRouteRegistry>(services =>
    new SqliteRouteRegistry(databasePath, services.GetRequiredService<ITextProtector>()));
builder.Services.AddSingleton<RouteTargetResolver>();
var e2eProfileRoot = Environment.GetEnvironmentVariable("SF_PROXY_E2E_PROFILE_ROOT");
if (builder.Environment.IsDevelopment() && !string.IsNullOrWhiteSpace(e2eProfileRoot))
{
    var isolatedProfileRoot = Path.GetFullPath(e2eProfileRoot);
    if (!File.Exists(Path.Combine(isolatedProfileRoot, ".endpointai-e2e-profile")))
    {
        throw new InvalidOperationException("SF_PROXY_E2E_PROFILE_ROOT must contain the E2E profile marker file.");
    }

    builder.Services.AddSingleton<IUserProfileProvider>(
        new IsolatedE2eUserProfileProvider(isolatedProfileRoot));
}
else
{
    if (OperatingSystem.IsWindows())
    {
        builder.Services.AddSingleton<IUserProfileProvider, WindowsProfileProvider>();
    }
    else
    {
        builder.Services.AddSingleton<IUserProfileProvider, MacUserProfileProvider>();
    }
}
builder.Services.AddSingleton<IAgentEvidenceCollector, ConfigArtifactCollector>();
builder.Services.AddSingleton<IAgentEvidenceCollector, PackageManifestCollector>();
builder.Services.AddSingleton<IAgentEvidenceCollector, CliCommandCollector>();
builder.Services.AddSingleton<IAgentEvidenceCollector, ClaudeSurfaceArtifactCollector>();
builder.Services.AddSingleton<IAgentEvidenceCollector, CodexSurfaceArtifactCollector>();
if (OperatingSystem.IsWindows())
{
    builder.Services.AddSingleton<IAgentEvidenceCollector, WindowsInstalledApplicationCollector>();
    builder.Services.AddSingleton<IRunningProcessSnapshotProvider, WindowsRunningProcessSnapshotProvider>();
}
else
{
    builder.Services.AddSingleton<IAgentEvidenceCollector, MacInstalledApplicationCollector>();
    builder.Services.AddSingleton<IRunningProcessSnapshotProvider, MacRunningProcessSnapshotProvider>();
}
builder.Services.AddSingleton<IAgentEvidenceCollector, RunningProcessCollector>();
builder.Services.AddSingleton<AgentDiscoveryEngine>();
builder.Services.AddSingleton<BaseUrlBypassPolicy>();
builder.Services.AddSingleton<CcSwitchModeState>();
builder.Services.AddSingleton(services => new AgentConfigAttachmentCoordinator(
    services.GetRequiredService<IRouteRegistry>(),
    new Uri($"http://127.0.0.1:{ListenPort}"),
    services.GetRequiredService<BaseUrlBypassPolicy>()));
builder.Services.AddSingleton(captureOptions);
builder.Services.AddSingleton<CaptureRetentionManager>();
builder.Services.AddSingleton<JsonlCaptureSummaryWriter>();
builder.Services.AddSingleton(operationalLogOptions);
builder.Services.AddSingleton(compressionQueue);
builder.Services.AddSingleton(operationalLogTracker);
builder.Services.AddSingleton<GzipLogFileCompressor>();
builder.Services.AddSingleton(new OperationalLogRetentionOptions(operationalLogOptions.RootDirectory));
builder.Services.AddSingleton<OperationalLogRetentionManager>();
if (OperatingSystem.IsWindows())
{
    builder.Services.AddSingleton<IWindowsUserAccountResolver, WindowsUserAccountResolver>();
}
else
{
    builder.Services.AddSingleton<IWindowsUserAccountResolver, MacUserAccountResolver>();
}
builder.Services.AddSingleton<AuditHealthState>();
builder.Services.AddSingleton<ProxyActivityTracker>();
builder.Services.AddSingleton<AgentAssetSnapshotBuilder>();
builder.Services.AddSingleton<RouteMutationGate>();
builder.Services.AddSingleton<ClientOperationStateProvider>();
builder.Services.AddSingleton<RouteReconciliationRuntimeState>();
builder.Services.AddSingleton<ControlPlaneRuntimeState>();
builder.Services.AddHostedService<LogStorageMaintenanceWorker>();
builder.Services.AddSingleton(services => new SqliteClientStateStore(
    databasePath,
    services.GetRequiredService<ITextProtector>()));
var autoAttachEnabled = builder.Configuration.GetValue<bool>("auto-attach")
    || string.Equals(
        Environment.GetEnvironmentVariable("SF_PROXY_AUTO_ATTACH"),
        "true",
        StringComparison.OrdinalIgnoreCase);
builder.Services.AddSingleton(new RouteAttachmentOptions(
    Path.Combine(dataRoot, "config-backups"),
    TimeSpan.FromSeconds(60)));
builder.Services.AddSingleton<RouteReconciliationSignals>();
builder.Services.AddSingleton<RemoteOperationCoordinator>();
builder.Services.AddSingleton<IRemoteOperationCoordinator>(services => services.GetRequiredService<RemoteOperationCoordinator>());
if (autoAttachEnabled)
{
    builder.Services.AddHostedService<RouteAttachmentWorker>();
}

var controlServerOriginText = Environment.GetEnvironmentVariable("SF_PROXY_CONTROL_ORIGIN")
    ?? ReadMachineSetting("ControlServerOrigin")
    ?? "http://control.example.invalid:8080";
if (!string.IsNullOrWhiteSpace(controlServerOriginText))
{
    var controlOptions = RemoteControlClient.ValidateOptions(new RemoteControlOptions(
        new Uri(controlServerOriginText, UriKind.Absolute),
        Environment.GetEnvironmentVariable("SF_PROXY_CONTROL_TOKEN")
            ?? ReadMachineSetting("ControlEnrollmentToken"),
        Convert.FromBase64String(Environment.GetEnvironmentVariable("SF_PROXY_CONTROL_HMAC_KEY")
            ?? ReadMachineSetting("ControlPolicyHmacKey")
            ?? throw new InvalidOperationException("SF_PROXY_CONTROL_HMAC_KEY is required when control synchronization is enabled.")),
        Environment.GetEnvironmentVariable("SF_PROXY_CONTROL_SERVER_CERTIFICATE_SPKI_SHA256")
            ?? ReadMachineSetting("ControlServerCertificateSpkiSha256")
            ?? "",
        Convert.FromBase64String(Environment.GetEnvironmentVariable("SF_PROXY_CONTROL_TRANSPORT_KEY")
            ?? ReadMachineSetting("ControlTransportKey")
            ?? throw new InvalidOperationException("SF_PROXY_CONTROL_TRANSPORT_KEY is required.")),
        Environment.GetEnvironmentVariable("SF_PROXY_CONTROL_TRANSPORT_KEY_ID")
            ?? ReadMachineSetting("ControlTransportKeyId") ?? "production-2026-01"));
    builder.Services.AddSingleton(controlOptions);
    builder.Services.AddSingleton(new RemoteControlClient(CreateControlHttpClient(controlOptions), controlOptions));
    builder.Services.AddSingleton<RemoteCommandExecutor>();
    builder.Services.AddHostedService<ControlPlaneWorker>();
}

builder.Services.AddSingleton(CreateForwardingClient());

var gatewayHmac = Environment.GetEnvironmentVariable("SF_PROXY_GATEWAY_HMAC_KEY");
if (!string.IsNullOrWhiteSpace(gatewayHmac))
{
    builder.Services.AddSingleton(new GatewayMetadataSigner(Convert.FromBase64String(gatewayHmac)));
}

var app = builder.Build();
var lifecycleLogger = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Sf.EndpointAI.Client.Service.Lifecycle");
if (lifecycleLogger.IsEnabled(LogLevel.Information))
{
    var serviceVersion = typeof(Program).Assembly.GetName().Version?.ToString() ?? "unknown";
    LifecycleLog.ServiceStarting(
        lifecycleLogger,
        serviceVersion,
        builder.Configuration["route-mode"] ?? "OriginalVendor",
        builder.Configuration["gateway-origin"] ?? string.Empty,
        autoAttachEnabled);
}
var routeRegistry = app.Services.GetRequiredService<IRouteRegistry>();
await routeRegistry.InitializeAsync();
var clientStateStore = app.Services.GetRequiredService<SqliteClientStateStore>();
await clientStateStore.InitializeAsync();
app.Services.GetRequiredService<ClientOperationStateProvider>().Update(
    await clientStateStore.LoadOperationStateAsync());
if (string.Equals(builder.Configuration["maintenance"], "detach-all", StringComparison.OrdinalIgnoreCase))
{
    var profileProvider = app.Services.GetRequiredService<IUserProfileProvider>();
    var coordinator = app.Services.GetRequiredService<AgentConfigAttachmentCoordinator>();
    var results = new List<ProfileAttachmentResult>();
    foreach (var profile in profileProvider.GetProfiles())
    {
        results.Add(await coordinator.DetachAsync(
            profile,
            Path.Combine(dataRoot, "config-backups")));
    }

    Console.WriteLine(JsonSerializer.Serialize(results));
    return;
}

await SeedDevelopmentRouteAsync(app.Environment, routeRegistry, ListenPort);
string[] allForwardedMethods =
[
    HttpMethods.Get,
    HttpMethods.Post,
    HttpMethods.Put,
    HttpMethods.Patch,
    HttpMethods.Delete,
    HttpMethods.Options,
    HttpMethods.Head,
];

app.MapGet("/healthz", async (
    IRouteRegistry registry,
    IPolicyProvider policyProvider,
    AuditHealthState auditHealth,
    ClientOperationStateProvider operationStateProvider,
    ControlPlaneRuntimeState controlPlaneRuntimeState,
    CancellationToken cancellationToken) =>
{
    var routes = await registry.ListAsync(cancellationToken);
    var currentPolicy = policyProvider.Current;
    var operationState = operationStateProvider.Current;
    var controlState = controlPlaneRuntimeState.Current;
    return Results.Ok(new
    {
        status = "ok",
        clientVersion = typeof(ControlPlaneWorker).Assembly.GetName().Version?.ToString(3),
        listenEndpoint = $"127.0.0.1:{ListenPort}",
        routeCount = routes.Count(route => route.Status == RouteStatus.Attached),
        routeMode = currentPolicy.RouteMode.ToString(),
        policyVersion = currentPolicy.PolicyVersion,
        auditState = auditHealth.Current.ToString(),
        operationState = operationState.State.ToString(),
        operationStateUpdatedAtUtc = operationState.UpdatedAtUtc,
        operationState.LastErrorCode,
        operationState.LastErrorSummary,
        controlState.DeviceId,
        controlState.LastControlSyncAtUtc,
        controlState.LastControlErrorCode,
    });
});

if (managementEnabled)
{
    app.MapGet("/management/discovery", async (
        HttpContext context,
        AgentDiscoveryEngine discovery,
        CancellationToken cancellationToken) =>
    {
        if (!HasManagementAccess(context.Request, managementToken!))
        {
            return Results.Unauthorized();
        }

        return Results.Ok(await discovery.DiscoverAsync(cancellationToken));
    });

    app.MapPost("/management/attach", async (
        HttpContext context,
        IUserProfileProvider profileProvider,
        AgentConfigAttachmentCoordinator coordinator,
        CancellationToken cancellationToken) =>
    {
        if (!HasManagementAccess(context.Request, managementToken!))
        {
            return Results.Unauthorized();
        }

        var results = new List<ProfileAttachmentResult>();
        var failures = new List<object>();
        foreach (var profile in profileProvider.GetProfiles())
        {
            try
            {
                results.Add(await coordinator.AttachAsync(
                    profile,
                    Path.Combine(dataRoot, "config-backups"),
                    cancellationToken));
            }
            catch (Exception exception) when (exception is ConfigMutationException or IOException or UnauthorizedAccessException)
            {
                failures.Add(new
                {
                    profile.Sid,
                    errorType = exception.GetType().Name,
                    errorCode = (exception as ConfigMutationException)?.Code,
                    exception.Message,
                });
            }
        }

        return Results.Ok(new { results, failures });
    });

    app.MapPost("/management/detach", async (
        HttpContext context,
        IUserProfileProvider profileProvider,
        AgentConfigAttachmentCoordinator coordinator,
        CancellationToken cancellationToken) =>
    {
        if (!HasManagementAccess(context.Request, managementToken!))
        {
            return Results.Unauthorized();
        }

        var results = new List<ProfileAttachmentResult>();
        var failures = new List<object>();
        foreach (var profile in profileProvider.GetProfiles())
        {
            try
            {
                results.Add(await coordinator.DetachAsync(
                    profile,
                    Path.Combine(dataRoot, "config-backups"),
                    cancellationToken));
            }
            catch (Exception exception) when (exception is ConfigMutationException or IOException or UnauthorizedAccessException)
            {
                failures.Add(new
                {
                    profile.Sid,
                    errorType = exception.GetType().Name,
                    errorCode = (exception as ConfigMutationException)?.Code,
                    exception.Message,
                });
            }
        }

        return Results.Ok(new { results, failures });
    });
}

app.MapMethods("/r/{routeId}/{**remainingPath}", allForwardedMethods, ForwardAsync);
app.MapMethods("/r/{routeId}", allForwardedMethods, ForwardAsync);
app.Run();

static async Task ForwardAsync(
    HttpContext context,
    string routeId,
    RouteTargetResolver resolver,
    HttpClient forwardingClient,
    CaptureOptions captureOptions,
    JsonlCaptureSummaryWriter summaryWriter,
    LogCompressionScheduler compressionQueue,
    IWindowsUserAccountResolver accountResolver,
    AuditHealthState auditHealth,
    BaseUrlBypassPolicy bypassPolicy,
    ProxyActivityTracker activityTracker,
    ILogger<Program> logger)
{
    var requestId = Guid.NewGuid();
    var timing = new ProxyTimingTracker();
    var startedAt = timing.AgentRequestReceivedAtUtc;
    MarkdownCaptureSession? capture = null;
    ResolvedRouteTarget? resolved = null;
    WindowsAccountIdentity? account = null;
    var agent = string.Empty;
    var agentSurface = "unknown";
    var outcome = "PROXY_INTERNAL_ERROR";
    string? errorCode = null;
    string? errorSummary = null;
    try
    {
        var routePrefix = $"/r/{routeId}";
        var requestPath = context.Request.Path.Value ?? string.Empty;
        var suffix = requestPath.StartsWith(routePrefix, StringComparison.Ordinal)
            ? requestPath[routePrefix.Length..]
            : string.Empty;
        resolved = await resolver.ResolveAsync(
            routeId,
            suffix,
            context.Request.QueryString.Value ?? string.Empty,
            context.RequestAborted);
        if (resolved is null)
        {
            await WriteProxyErrorAsync(context, timing, StatusCodes.Status404NotFound, "ROUTE_NOT_FOUND", "The local route was not found.");
            return;
        }

        if (bypassPolicy.ShouldBypass(resolved.Route.OriginalBaseUri))
        {
            outcome = BaseUrlBypassPolicy.BypassCode;
            errorCode = BaseUrlBypassPolicy.BypassCode;
            errorSummary = "The route targets an allowlisted BaseURL and has been retired.";
            ProxyLog.AllowlistedRouteBlocked(logger, routeId, resolved.Route.OriginalBaseUri.AbsoluteUri);
            await WriteProxyErrorAsync(
                context,
                timing,
                StatusCodes.Status409Conflict,
                errorCode,
                "The configured BaseURL must bypass the endpoint proxy.");
            return;
        }

        account = accountResolver.Resolve(resolved.Route.UserSid);
        if (account.UsedSidFallback)
        {
            ProxyLog.UserSidFallback(logger, resolved.Route.UserSid);
        }

        agent = AgentRequestClassifier.GetFamily(resolved.Route);
        agentSurface = AgentRequestClassifier.GetSurface(
            resolved.Route,
            context.Request.Headers.UserAgent.Select(value => value ?? string.Empty));
        capture = await TryCreateCaptureAsync(
            context,
            captureOptions,
            resolved,
            requestId,
            startedAt,
            account,
            agent,
            agentSurface,
            logger);
        if (capture is null)
        {
            auditHealth.MarkDegraded();
        }

        using var outbound = new HttpRequestMessage(new HttpMethod(context.Request.Method), resolved.TargetUri);
        if (context.Features.Get<IHttpRequestBodyDetectionFeature>()?.CanHaveBody == true)
        {
            var body = capture is null
                ? context.Request.Body
                : new CapturingReadStream(context.Request.Body, capture.CaptureRequestBytesAsync);
            outbound.Content = new StreamContent(body);
        }

        CopyRequestHeaders(context.Request, outbound);
        if (resolved.IsSfGateway)
        {
            AddGatewayHeaders(context, outbound, resolved, requestId, account, agent, agentSurface, logger);
        }

        if (capture is not null)
        {
            await capture.WriteInboundHeadersAsync(ToCaptureHeaderDictionary(context.Request.Headers), context.RequestAborted);
            await capture.WriteOutboundHeadersAsync(ToCaptureRequestHeaders(outbound), context.RequestAborted);
        }

        timing.MarkGatewayRequestStarted();
        using var response = await forwardingClient.SendAsync(
            outbound,
            HttpCompletionOption.ResponseHeadersRead,
            context.RequestAborted);
        timing.MarkGatewayResponseHeadersReceived();
        if (capture is not null)
        {
            await capture.BeginResponseAsync(
                (int)response.StatusCode,
                response.ReasonPhrase,
                ToCaptureResponseHeaders(response),
                context.RequestAborted);
        }

        if ((int)response.StatusCode is >= 300 and <= 399)
        {
            await DrainToCaptureAsync(response, capture, context.RequestAborted);
            await WriteProxyErrorAsync(context, timing, StatusCodes.Status502BadGateway, "UPSTREAM_REDIRECT_BLOCKED", "The upstream returned a redirect, which the proxy does not follow.");
            outcome = "UPSTREAM_REDIRECT_BLOCKED";
            errorCode = "UPSTREAM_REDIRECT_BLOCKED";
            errorSummary = response.Headers.Location?.ToString();
            if (capture is not null)
            {
                await capture.CompleteAsync(
                    outcome,
                    errorCode,
                    errorSummary,
                    timing.Snapshot(),
                    context.RequestAborted);
            }

            return;
        }

        context.Response.StatusCode = (int)response.StatusCode;
        CopyResponseHeaders(response, context.Response);
        await CopyResponseBodyAsync(response, context.Response.Body, capture, timing, context.RequestAborted);
        outcome = response.IsSuccessStatusCode ? "SUCCESS" : "GATEWAY_HTTP_ERROR";
        if (!response.IsSuccessStatusCode)
        {
            errorCode = "GATEWAY_HTTP_ERROR";
            errorSummary = $"Gateway returned HTTP {(int)response.StatusCode}.";
        }

        if (capture is not null)
        {
            await capture.CompleteAsync(
                outcome,
                errorCode,
                errorSummary,
                timing.Snapshot(),
                context.RequestAborted);
        }
    }
    catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
    {
        outcome = "CLIENT_CANCELLED";
        errorCode = "CLIENT_CANCELLED";
        if (capture is not null)
        {
            await capture.CompleteAsync(
                outcome,
                errorCode,
                timing: timing.Snapshot(),
                cancellationToken: CancellationToken.None);
        }
    }
    catch (HttpRequestException exception)
    {
        ProxyLog.UpstreamRequestFailed(logger, exception);
        outcome = "GATEWAY_CONNECTION_FAILED";
        errorCode = "GATEWAY_CONNECTION_FAILED";
        errorSummary = exception.Message;
        await WriteProxyErrorAsync(context, timing, StatusCodes.Status502BadGateway, errorCode, "The gateway request failed.");
        if (capture is not null)
        {
            await capture.CompleteAsync(
                outcome,
                errorCode,
                errorSummary,
                timing.Snapshot(),
                CancellationToken.None);
        }
    }
    catch (Exception exception)
    {
        ProxyLog.UnhandledProxyFailure(logger, exception);
        outcome = "PROXY_INTERNAL_ERROR";
        errorCode = "PROXY_INTERNAL_ERROR";
        errorSummary = exception.Message;
        await WriteProxyErrorAsync(context, timing, StatusCodes.Status500InternalServerError, "PROXY_INTERNAL_ERROR", "The local proxy failed.");
        if (capture is not null)
        {
            await capture.CompleteAsync(
                outcome,
                errorCode,
                errorSummary,
                timing.Snapshot(),
                CancellationToken.None);
        }
    }
    finally
    {
        if (resolved is not null)
        {
            var timingSnapshot = timing.Snapshot();
            activityTracker.Record(
                resolved.Route,
                outcome,
                string.Equals(outcome, "CLIENT_CANCELLED", StringComparison.Ordinal)
                    ? null
                    : context.Response.StatusCode,
                errorCode,
                timingSnapshot.GatewayRoundTripMilliseconds);
        }

        if (capture is not null)
        {
            await capture.DisposeAsync();
        }

        if (resolved is not null && account is not null)
        {
            try
            {
                var completedAt = DateTimeOffset.UtcNow;
                var timingSnapshot = timing.Snapshot();
                var markdownPath = capture is not null && File.Exists(capture.CompletedPath)
                    ? capture.CompletedPath
                    : null;
                await summaryWriter.AppendAsync(
                    new CaptureSummary(
                        requestId,
                        startedAt,
                        completedAt,
                        timingSnapshot.AgentRequestReceivedAtUtc,
                        timingSnapshot.GatewayRequestStartedAtUtc,
                        timingSnapshot.GatewayResponseHeadersReceivedAtUtc,
                        timingSnapshot.AgentResponseStartedAtUtc,
                        timingSnapshot.GatewayRoundTripMilliseconds,
                        account.UserId,
                        resolved.Route.UserSid,
                        agent,
                        agentSurface,
                        resolved.Route.ProviderId,
                        resolved.Route.RouteId,
                        resolved.Route.OriginalBaseUri.AbsoluteUri,
                        $"{context.Request.Path}{context.Request.QueryString}",
                        resolved.TargetUri.PathAndQuery,
                        string.Equals(outcome, "CLIENT_CANCELLED", StringComparison.Ordinal)
                            ? null
                            : context.Response.StatusCode,
                        Math.Max(0, (long)(completedAt - startedAt).TotalMilliseconds),
                        outcome,
                        errorCode,
                        errorSummary,
                        capture?.RequestBodyBytes ?? 0,
                        capture?.ResponseBodyBytes ?? 0,
                        capture?.IsTruncated ?? false,
                        capture?.IsDegraded ?? true,
                        markdownPath),
                    CancellationToken.None);
                if (markdownPath is not null)
                {
                    compressionQueue.TryQueue(markdownPath);
                }
                ProxyLog.RequestCompleted(
                    logger,
                    requestId,
                    resolved.Route.RouteId,
                    resolved.Route.ProviderId,
                    outcome,
                    string.Equals(outcome, "CLIENT_CANCELLED", StringComparison.Ordinal)
                        ? null
                        : context.Response.StatusCode,
                    timingSnapshot.GatewayRoundTripMilliseconds,
                    errorCode);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                auditHealth.MarkDegraded();
                ProxyLog.CaptureSummaryFailed(logger, exception);
            }
        }
    }
}

static async Task<MarkdownCaptureSession?> TryCreateCaptureAsync(
    HttpContext context,
    CaptureOptions options,
    ResolvedRouteTarget resolved,
    Guid requestId,
    DateTimeOffset startedAt,
    WindowsAccountIdentity account,
    string agent,
    string agentSurface,
    ILogger logger)
{
    try
    {
        return await MarkdownCaptureSession.CreateAsync(
            options,
            new CaptureMetadata(
                requestId,
                startedAt,
                account.UserId,
                resolved.Route.UserSid,
                agent,
                agentSurface,
                resolved.Route.ProviderId,
                resolved.Route.RouteId,
                resolved.Route.OriginalBaseUri.AbsoluteUri,
                resolved.Route.OriginalBaseUri.Authority,
                context.Request.Method,
                $"{context.Request.Path}{context.Request.QueryString}",
                resolved.TargetUri),
            context.RequestAborted);
    }
    catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
    {
        ProxyLog.CaptureCreateFailed(logger, exception);
        return null;
    }
}

static void CopyRequestHeaders(HttpRequest source, HttpRequestMessage destination)
{
    foreach (var header in source.Headers)
    {
        if (IsHopByHop(header.Key)
            || header.Key.Equals("Host", StringComparison.OrdinalIgnoreCase)
            || header.Key.StartsWith("X-SF-AI-", StringComparison.OrdinalIgnoreCase))
        {
            continue;
        }

        var values = header.Value.ToArray();
        if (!destination.Headers.TryAddWithoutValidation(header.Key, values) && destination.Content is not null)
        {
            destination.Content.Headers.TryAddWithoutValidation(header.Key, values);
        }
    }
}

static void CopyResponseHeaders(HttpResponseMessage source, HttpResponse destination)
{
    foreach (var header in source.Headers.Concat(source.Content.Headers))
    {
        if (!IsHopByHop(header.Key))
        {
            destination.Headers[header.Key] = header.Value.ToArray();
        }
    }

    destination.Headers.Remove("transfer-encoding");
}

static void AddGatewayHeaders(
    HttpContext context,
    HttpRequestMessage outbound,
    ResolvedRouteTarget resolved,
    Guid requestId,
    WindowsAccountIdentity account,
    string agent,
    string agentSurface,
    ILogger logger)
{
    var deviceIdText = Environment.GetEnvironmentVariable("SF_PROXY_DEVICE_ID");
    if (!Guid.TryParse(deviceIdText, out var deviceId))
    {
        ProxyLog.EphemeralDeviceId(logger);
        deviceId = DeviceIdentityHolder.Value;
    }

    var timestamp = DateTimeOffset.UtcNow;
    var metadata = new GatewayMetadata(
        deviceId,
        account.UserId,
        resolved.Route.UserSid,
        agent,
        agentSurface,
        resolved.Route.ProviderId,
        resolved.Route.OriginalBaseUri.AbsoluteUri,
        resolved.Route.OriginalBaseUri.Authority,
        requestId,
        timestamp,
        context.Request.Method,
        resolved.TargetUri.PathAndQuery);
    outbound.Headers.TryAddWithoutValidation("X-SF-AI-Device-Id", deviceId.ToString("D"));
    outbound.Headers.TryAddWithoutValidation("X-SF-AI-User-Id", metadata.UserId);
    outbound.Headers.TryAddWithoutValidation("X-SF-AI-User-Sid", metadata.UserSid);
    outbound.Headers.TryAddWithoutValidation("X-SF-AI-Agent", metadata.Agent);
    outbound.Headers.TryAddWithoutValidation("X-SF-AI-Agent-Surface", metadata.AgentSurface);
    outbound.Headers.TryAddWithoutValidation("X-SF-AI-Provider-Id", metadata.ProviderId);
    outbound.Headers.TryAddWithoutValidation("X-SF-AI-Original-Base-Url", metadata.OriginalBaseUrl);
    outbound.Headers.TryAddWithoutValidation("X-SF-AI-Original-Authority", metadata.OriginalAuthority);
    outbound.Headers.TryAddWithoutValidation("X-SF-AI-Request-Id", requestId.ToString("D"));
    outbound.Headers.TryAddWithoutValidation("X-SF-AI-Timestamp", timestamp.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture));
    var signer = context.RequestServices.GetService<GatewayMetadataSigner>();
    if (signer is not null)
    {
        outbound.Headers.TryAddWithoutValidation("X-SF-AI-Signature", signer.Sign(metadata));
    }
}

static async Task CopyResponseBodyAsync(
    HttpResponseMessage response,
    Stream destination,
    MarkdownCaptureSession? capture,
    ProxyTimingTracker timing,
    CancellationToken cancellationToken)
{
    await using var source = await response.Content.ReadAsStreamAsync(cancellationToken);
    var buffer = new byte[64 * 1024];
    var read = await source.ReadAsync(buffer, cancellationToken);
    timing.MarkAgentResponseStarted();
    while (read > 0)
    {
        await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
        await destination.FlushAsync(cancellationToken);
        if (capture is not null)
        {
            await capture.CaptureResponseBytesAsync(buffer.AsMemory(0, read), cancellationToken);
        }

        read = await source.ReadAsync(buffer, cancellationToken);
    }
}

static async Task DrainToCaptureAsync(
    HttpResponseMessage response,
    MarkdownCaptureSession? capture,
    CancellationToken cancellationToken)
{
    if (capture is null)
    {
        return;
    }

    await using var source = await response.Content.ReadAsStreamAsync(cancellationToken);
    var buffer = new byte[16 * 1024];
    while (true)
    {
        var read = await source.ReadAsync(buffer, cancellationToken);
        if (read == 0)
        {
            return;
        }

        await capture.CaptureResponseBytesAsync(buffer.AsMemory(0, read), cancellationToken);
    }
}

static async Task WriteProxyErrorAsync(
    HttpContext context,
    ProxyTimingTracker timing,
    int statusCode,
    string code,
    string message)
{
    if (context.Response.HasStarted)
    {
        context.Abort();
        return;
    }

    context.Response.Clear();
    context.Response.StatusCode = statusCode;
    context.Response.ContentType = "application/json; charset=utf-8";
    timing.MarkAgentResponseStarted();
    await context.Response.WriteAsJsonAsync(new { error = new { code, message } }, context.RequestAborted);
}

static IEnumerable<KeyValuePair<string, IEnumerable<string>>> ToCaptureHeaderDictionary(IHeaderDictionary headers)
{
    return headers.Select(header =>
        new KeyValuePair<string, IEnumerable<string>>(
            header.Key,
            header.Value.Select(value => value ?? string.Empty).ToArray()));
}

static IEnumerable<KeyValuePair<string, IEnumerable<string>>> ToCaptureRequestHeaders(HttpRequestMessage request)
{
    return request.Headers.Concat(request.Content?.Headers ?? Enumerable.Empty<KeyValuePair<string, IEnumerable<string>>>());
}

static IEnumerable<KeyValuePair<string, IEnumerable<string>>> ToCaptureResponseHeaders(HttpResponseMessage response)
{
    return response.Headers.Concat(response.Content.Headers);
}

static bool IsHopByHop(string headerName)
{
    return headerName.Equals("Connection", StringComparison.OrdinalIgnoreCase)
        || headerName.Equals("Keep-Alive", StringComparison.OrdinalIgnoreCase)
        || headerName.Equals("Proxy-Authenticate", StringComparison.OrdinalIgnoreCase)
        || headerName.Equals("Proxy-Authorization", StringComparison.OrdinalIgnoreCase)
        || headerName.Equals("TE", StringComparison.OrdinalIgnoreCase)
        || headerName.Equals("Trailer", StringComparison.OrdinalIgnoreCase)
        || headerName.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase)
        || headerName.Equals("Upgrade", StringComparison.OrdinalIgnoreCase);
}

static bool HasManagementAccess(HttpRequest request, string expectedToken)
{
    if (!AuthenticationHeaderValue.TryParse(request.Headers.Authorization, out var authorization)
        || !string.Equals(authorization.Scheme, "Bearer", StringComparison.OrdinalIgnoreCase)
        || string.IsNullOrEmpty(authorization.Parameter))
    {
        return false;
    }

    var expected = Encoding.UTF8.GetBytes(expectedToken);
    var actual = Encoding.UTF8.GetBytes(authorization.Parameter);
    return actual.Length == expected.Length && CryptographicOperations.FixedTimeEquals(actual, expected);
}

static EndpointPolicy BuildPrototypePolicy(IConfiguration configuration)
{
    var routeModeText = configuration["route-mode"]
        ?? Environment.GetEnvironmentVariable("SF_PROXY_ROUTE_MODE");
    var gatewayOrigin = configuration["gateway-origin"]
        ?? Environment.GetEnvironmentVariable("SF_PROXY_GATEWAY_ORIGIN");
    var allowInsecureText = configuration["allow-insecure-gateway"]
        ?? Environment.GetEnvironmentVariable("SF_PROXY_ALLOW_INSECURE_GATEWAY");
    var routeMode = Enum.TryParse<RouteMode>(routeModeText, ignoreCase: true, out var parsed)
        ? parsed
        : RouteMode.PassthroughOriginal;
    return new EndpointPolicy(
        1,
        Guid.NewGuid(),
        1,
        true,
        routeMode,
        gatewayOrigin,
        bool.TryParse(allowInsecureText, out var allowInsecureGateway) && allowInsecureGateway,
        60,
        60,
        DateTimeOffset.UtcNow);
}

static HttpClient CreateForwardingClient()
{
    var handler = new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        AutomaticDecompression = DecompressionMethods.None,
        UseCookies = false,
        UseProxy = false,
        ConnectTimeout = TimeSpan.FromSeconds(15),
        PooledConnectionLifetime = TimeSpan.FromMinutes(5),
    };
    return new HttpClient(handler, disposeHandler: true)
    {
        Timeout = Timeout.InfiniteTimeSpan,
    };
}

static HttpClient CreateControlHttpClient(RemoteControlOptions options)
{
    var expectedPin = options.TransportKey is null
        ? ControlServerCertificateValidator.ParsePin(options.ServerCertificateSpkiSha256) : [];
    var handler = new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        AutomaticDecompression = DecompressionMethods.All,
        UseCookies = false,
        UseProxy = false,
        ConnectTimeout = TimeSpan.FromSeconds(10),
        PooledConnectionLifetime = TimeSpan.FromMinutes(5),
    };
    if (options.TransportKey is null)
        handler.SslOptions.RemoteCertificateValidationCallback = (_, certificate, _, errors) =>
    {
        if (certificate is System.Security.Cryptography.X509Certificates.X509Certificate2 certificate2)
        {
            return ControlServerCertificateValidator.ValidateAndReturnTrue(
                certificate2,
                errors,
                expectedPin,
                DateTimeOffset.UtcNow);
        }

        using var converted = certificate is null
            ? null
            : new System.Security.Cryptography.X509Certificates.X509Certificate2(certificate);
        return ControlServerCertificateValidator.ValidateAndReturnTrue(
            converted,
            errors,
            expectedPin,
            DateTimeOffset.UtcNow);
    };
    return new HttpClient(handler, disposeHandler: true)
    {
        Timeout = TimeSpan.FromSeconds(30),
    };
}

static async Task SeedDevelopmentRouteAsync(IHostEnvironment environment, IRouteRegistry registry, int listenPort)
{
    if (!environment.IsDevelopment())
    {
        return;
    }

    var upstream = Environment.GetEnvironmentVariable("SF_PROXY_BOOTSTRAP_UPSTREAM");
    if (!Uri.TryCreate(upstream, UriKind.Absolute, out var originalBaseUri))
    {
        return;
    }

    var routeId = Environment.GetEnvironmentVariable("SF_PROXY_BOOTSTRAP_ROUTE_ID");
    routeId = RouteTargetResolver.IsValidRouteId(routeId ?? string.Empty) ? routeId : RouteIdGenerator.Create();
    var now = DateTimeOffset.UtcNow;
    await registry.UpsertAsync(new RouteRecord(
        routeId!,
        Environment.GetEnvironmentVariable("SF_PROXY_BOOTSTRAP_USER_SID") ?? "S-1-0-0",
        AgentType.ClaudeCode,
        "development",
        originalBaseUri,
        new Uri($"http://127.0.0.1:{listenPort}/r/{routeId}"),
        RouteStatus.Pending,
        now,
        now));
    Console.WriteLine($"Development route: http://127.0.0.1:{listenPort}/r/{routeId}");
}

static string GetDefaultDataRoot()
{
    if (OperatingSystem.IsMacOS())
    {
        return "/Library/Application Support/SF/EndpointAIProxy";
    }

    return Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "SF",
        "EndpointAIProxy");
}

static string? ReadMachineSetting(string name)
{
    if (!OperatingSystem.IsWindows())
    {
        return null;
    }

    using var key = Registry.LocalMachine.OpenSubKey(@"Software\SF\EndpointAIProxy", writable: false);
    return key?.GetValue(name) as string;
}

static string? GetCommandLineOption(string[] arguments, string name)
{
    var prefix = $"--{name}=";
    return arguments
        .FirstOrDefault(argument => argument.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))?
        [prefix.Length..];
}

static async Task<int> RunDiagnosticMaintenanceAsync(string[] arguments)
{
    if (!OperatingSystem.IsWindows() && !OperatingSystem.IsMacOS())
    {
        Console.Error.WriteLine("DIAGNOSTICS_PLATFORM_UNSUPPORTED: Diagnostic collection is supported only on Windows and macOS.");
        return 1;
    }

    if (OperatingSystem.IsWindows())
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
        {
            Console.Error.WriteLine("DIAGNOSTICS_ADMIN_REQUIRED: 请使用管理员身份运行 CMD 后重试。");
            return 5;
        }
    }
    else if (!string.Equals(Environment.UserName, "root", StringComparison.Ordinal))
    {
        Console.Error.WriteLine("DIAGNOSTICS_ROOT_REQUIRED: Run this command with sudo on macOS.");
        return 5;
    }

    var sinceText = GetCommandLineOption(arguments, "diagnostics-since-hours") ?? "72";
    if (!int.TryParse(sinceText, out var sinceHours) || sinceHours is < 1 or > 168)
    {
        Console.Error.WriteLine("DIAGNOSTICS_INVALID_TIME_RANGE: --diagnostics-since-hours must be between 1 and 168.");
        return 1;
    }

    Guid? requestId = null;
    var requestIdText = GetCommandLineOption(arguments, "diagnostics-request-id");
    if (!string.IsNullOrWhiteSpace(requestIdText))
    {
        if (!Guid.TryParse(requestIdText, out var parsedRequestId))
        {
            Console.Error.WriteLine("DIAGNOSTICS_INVALID_REQUEST_ID: --diagnostics-request-id must be a GUID.");
            return 1;
        }

        requestId = parsedRequestId;
    }

    try
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(120));
        var dataRoot = Environment.GetEnvironmentVariable("SF_PROXY_DATA_ROOT")
            ?? GetDefaultDataRoot();
        using var collectionLock = DiagnosticCollectionLock.TryAcquire(dataRoot);
        if (collectionLock is null)
        {
            Console.Error.WriteLine("DIAGNOSTICS_ALREADY_RUNNING: Another diagnostic collection is in progress.");
            return 1;
        }

        var installDirectory = DiagnosticPathResolver.ResolveInstallDirectory(Environment.ProcessPath, AppContext.BaseDirectory);
        var outputDirectory = GetCommandLineOption(arguments, "diagnostics-output")
            ?? Path.Combine(installDirectory, "diagnostics");
        IUserProfileProvider profileProvider = OperatingSystem.IsWindows()
            ? new WindowsProfileProvider()
            : new MacUserProfileProvider();
        var profiles = profileProvider.GetProfiles();

        var routeDatabasePath = Path.Combine(dataRoot, "state", "client.db");
        ITextProtector protector = OperatingSystem.IsWindows()
            ? new DpapiTextProtector()
            : new FileKeyTextProtector(Path.Combine(dataRoot, "state", "machine.key"));
        var registry = new SqliteRouteRegistry(routeDatabasePath, protector);
        IReadOnlyList<RouteRecord> routes = [];
        var routeRegistryAvailable = true;
        var diagnosticReadErrors = new List<string>();
        try
        {
            if (File.Exists(routeDatabasePath))
            {
                routes = await registry.ListReadOnlyAsync(timeout.Token);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or Microsoft.Data.Sqlite.SqliteException or CryptographicException)
        {
            routeRegistryAvailable = false;
            var error = $"ROUTE_REGISTRY_DIAGNOSTIC_READ_FAILED: {exception.GetType().Name}: {DiagnosticSanitizer.SanitizeText(exception.Message)}";
            diagnosticReadErrors.Add(error);
            Console.Error.WriteLine(error);
        }

        var collectors = new List<IAgentEvidenceCollector>
        {
            new ConfigArtifactCollector(profileProvider),
            new PackageManifestCollector(profileProvider),
            new CliCommandCollector(profileProvider),
            new ClaudeSurfaceArtifactCollector(profileProvider),
            new CodexSurfaceArtifactCollector(profileProvider),
        };
        if (OperatingSystem.IsWindows())
        {
            collectors.Add(new WindowsInstalledApplicationCollector(profileProvider));
            collectors.Add(new RunningProcessCollector(profileProvider, new WindowsRunningProcessSnapshotProvider()));
        }
        else
        {
            collectors.Add(new MacInstalledApplicationCollector(profileProvider));
            collectors.Add(new RunningProcessCollector(profileProvider, new MacRunningProcessSnapshotProvider()));
        }
        AgentDiscoverySnapshot? discovery = null;
        try
        {
            discovery = await new AgentDiscoveryEngine(collectors).DiscoverAsync(timeout.Token);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            var error = $"AGENT_DISCOVERY_DIAGNOSTIC_FAILED: {exception.GetType().Name}: {DiagnosticSanitizer.SanitizeText(exception.Message)}";
            diagnosticReadErrors.Add(error);
            Console.Error.WriteLine(error);
        }

        var collector = new DiagnosticBundleCollector(
            new DiagnosticCollectionOptions(
                dataRoot,
                installDirectory,
                Path.GetFullPath(outputDirectory),
                TimeSpan.FromHours(sinceHours),
                requestId,
                InitialErrors: diagnosticReadErrors,
                RouteRegistryAvailable: routeRegistryAvailable),
            profiles,
            routes,
            discovery,
            OperatingSystem.IsWindows()
                ? new WindowsUserAccountResolver()
                : new MacUserAccountResolver());
        var result = await collector.CollectAsync(timeout.Token);
        Console.WriteLine(result.Partial ? "Diagnostic package created with partial results." : "Diagnostic package created successfully.");
        Console.WriteLine($"Path   : {result.BundlePath}");
        Console.WriteLine($"Size   : {result.Length} bytes");
        Console.WriteLine($"SHA256 : {result.Sha256}");
        Console.WriteLine($"Status : {(result.Partial ? "Partial" : "Complete")}");
        return result.Partial ? 2 : 0;
    }
    catch (OperationCanceledException)
    {
        Console.Error.WriteLine("DIAGNOSTICS_TIMEOUT: Diagnostic collection exceeded 120 seconds.");
        return 1;
    }
    catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidOperationException or ArgumentException)
    {
        Console.Error.WriteLine($"DIAGNOSTICS_COLLECTION_FAILED: {exception.GetType().Name}: {DiagnosticSanitizer.SanitizeText(exception.Message)}");
        return 1;
    }
}

static class DeviceIdentityHolder
{
    public static readonly Guid Value = Guid.NewGuid();
}

sealed class IsolatedE2eUserProfileProvider(string profileRoot) : IUserProfileProvider
{
    private readonly IReadOnlyList<WindowsUserProfile> _profiles =
        [new("S-1-5-21-control-e2e", profileRoot)];

    public IReadOnlyList<WindowsUserProfile> GetProfiles() => _profiles;
}
