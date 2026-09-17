using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Win32;
using Sf.EndpointAI.Contracts;
using Sf.EndpointAI.ControlServer;

var builder = WebApplication.CreateBuilder(args);
builder.Host.UseWindowsService(options => options.ServiceName = "SfEndpointAIControl");
var certificatePath = GetControlSetting("SF_CONTROL_CERTIFICATE_PATH", "CertificatePath")
    ?? throw new InvalidOperationException("SF_CONTROL_CERTIFICATE_PATH is required.");
var certificatePassword = GetControlSetting("SF_CONTROL_CERTIFICATE_PASSWORD", "CertificatePassword")
    ?? throw new InvalidOperationException("SF_CONTROL_CERTIFICATE_PASSWORD is required.");
var listenPort = int.TryParse(GetControlSetting("SF_CONTROL_HTTPS_PORT", "HttpsPort"), out var configuredPort)
    && configuredPort is > 0 and <= 65535
        ? configuredPort
        : 18443;
if (!File.Exists(certificatePath))
{
    throw new FileNotFoundException("The control server TLS certificate was not found.", certificatePath);
}

builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenAnyIP(listenPort, listen =>
    {
        listen.Protocols = HttpProtocols.Http1AndHttp2;
        listen.UseHttps(certificatePath, certificatePassword);
    });
    options.AddServerHeader = false;
});
var jsonOptions = new JsonSerializerOptions(JsonSerializerDefaults.Web);
jsonOptions.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.CamelCase));
builder.Services.ConfigureHttpJsonOptions(options =>
    options.SerializerOptions.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.CamelCase)));

var clientToken = GetControlSetting("SF_CONTROL_CLIENT_TOKEN", "EnrollmentToken")
    ?? throw new InvalidOperationException("SF_CONTROL_CLIENT_TOKEN is required.");
var adminToken = GetControlSetting("SF_CONTROL_ADMIN_TOKEN", "AdminToken")
    ?? throw new InvalidOperationException("SF_CONTROL_ADMIN_TOKEN is required.");
var hmacKeyText = GetControlSetting("SF_CONTROL_POLICY_HMAC_KEY", "PolicyHmacKey")
    ?? throw new InvalidOperationException("SF_CONTROL_POLICY_HMAC_KEY is required.");
var hmacKey = Convert.FromBase64String(hmacKeyText);
if (hmacKey.Length < 32)
{
    throw new InvalidOperationException("SF_CONTROL_POLICY_HMAC_KEY must contain at least 32 bytes.");
}
var commandHmacKey = HMACSHA256.HashData(hmacKey, Encoding.UTF8.GetBytes("sf-endpoint-ai-command-v1"));
var dataRoot = GetControlSetting("SF_CONTROL_DATA_ROOT", "DataRoot")
    ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SF", "EndpointAIControl");
var store = new ControlStore(Path.Combine(dataRoot, "control.db"), jsonOptions);
builder.Services.AddSingleton(store);
builder.Services.AddSingleton(new ControlBackupOptions(
    Path.Combine(dataRoot, "backups"),
    7,
    TimeSpan.FromHours(24)));
builder.Services.AddSingleton<ControlBackupState>();
builder.Services.AddHostedService<ControlBackupWorker>();
var app = builder.Build();
await store.InitializeAsync(BuildSeedPolicy(), app.Lifetime.ApplicationStopping);

app.Use(async (context, next) =>
{
    string? expectedToken = null;
    if (context.Request.Path.StartsWithSegments("/api/v1", StringComparison.OrdinalIgnoreCase)
        || string.Equals(context.Request.Path.Value, "/api/v2/enroll", StringComparison.OrdinalIgnoreCase))
    {
        expectedToken = clientToken;
    }
    else if (context.Request.Path.StartsWithSegments("/admin", StringComparison.OrdinalIgnoreCase))
    {
        expectedToken = adminToken;
    }

    if (expectedToken is null)
    {
        await next(context);
        return;
    }

    if (!HasBearerToken(context.Request, expectedToken))
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        return;
    }

    await next(context);
});

app.MapGet("/health/live", () => Results.Ok(new { status = "live" }));
app.MapGet("/health/ready", async (
    ControlStore controlStore,
    ControlBackupState backupState,
    CancellationToken cancellationToken) =>
{
    var current = await controlStore.GetPolicyAsync(cancellationToken);
    return Results.Ok(new
    {
        status = backupState.LastError is null ? "ready" : "degraded",
        policyVersion = current.PolicyVersion,
        backupState.LastSucceededAtUtc,
        backupState.LastError,
    });
});

app.MapGet("/console", (HttpContext context) =>
{
    context.Response.Headers.ContentSecurityPolicy = "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'";
    context.Response.Headers.CacheControl = "no-store";
    context.Response.Headers.XContentTypeOptions = "nosniff";
    return Results.Content(ControlConsolePage.Html, "text/html; charset=utf-8");
});

app.MapGet("/", () => Results.Redirect("/console"));

app.MapGet("/api/v1/policy", async (
    HttpContext context,
    ControlStore controlStore,
    CancellationToken cancellationToken) =>
{
    var policy = await controlStore.GetPolicyAsync(cancellationToken);
    return CreateSignedPolicyResponse(context, policy, jsonOptions, hmacKey);
});

app.MapPost("/api/v1/heartbeat", async (
    HeartbeatRequest heartbeat,
    ControlStore controlStore,
    CancellationToken cancellationToken) =>
{
    if (!IsValidHeartbeat(heartbeat))
    {
        return Results.BadRequest(new ApiErrorEnvelope(new ApiError(
            "HEARTBEAT_INVALID",
            "The heartbeat exceeds the prototype contract limits.")));
    }

    await controlStore.RecordHeartbeatAsync(heartbeat, cancellationToken);
    var policy = await controlStore.GetPolicyAsync(cancellationToken);
    return Results.Ok(new HeartbeatResponse(DateTimeOffset.UtcNow, policy.PolicyVersion, policy.HeartbeatIntervalSeconds));
});

app.MapPost("/api/v1/events/batch", async (
    EventBatchRequest batch,
    ControlStore controlStore,
    CancellationToken cancellationToken) =>
{
    if (batch.SchemaVersion != 1 || batch.DeviceId == Guid.Empty || batch.Events.Count > 100)
    {
        return Results.BadRequest(new ApiErrorEnvelope(new ApiError(
            "EVENT_BATCH_INVALID",
            "The event batch exceeds the prototype contract limits.")));
    }

    var stored = await controlStore.RecordEventsAsync(batch, cancellationToken);
    return Results.Accepted(value: new EventBatchResponse(stored.Accepted, stored.Duplicates, 0, []));
});

app.MapPost("/api/v2/enroll", async (
    HttpContext context,
    DeviceEnrollmentRequest request,
    ControlStore controlStore,
    CancellationToken cancellationToken) =>
{
    if (!context.Request.IsHttps)
    {
        return Results.BadRequest(new ApiErrorEnvelope(new ApiError(
            "DEVICE_CONTROL_HTTPS_REQUIRED",
            "Device enrollment requires HTTPS.")));
    }

    if (request.SchemaVersion != 2
        || request.DeviceId == Guid.Empty
        || string.IsNullOrWhiteSpace(request.Hostname)
        || request.Hostname.Length > 255
        || string.IsNullOrWhiteSpace(request.ServiceVersion)
        || request.ServiceVersion.Length > 64)
    {
        return Results.BadRequest(new ApiErrorEnvelope(new ApiError(
            "DEVICE_ENROLLMENT_INVALID",
            "The enrollment request is invalid.")));
    }

    return Results.Ok(await controlStore.EnrollDeviceAsync(request, cancellationToken));
});

app.MapPost("/api/v2/heartbeat", async (
    HttpContext context,
    HeartbeatV2Request heartbeat,
    ControlStore controlStore,
    CancellationToken cancellationToken) =>
{
    if (!context.Request.IsHttps)
    {
        return Results.BadRequest(new ApiErrorEnvelope(new ApiError(
            "DEVICE_CONTROL_HTTPS_REQUIRED",
            "Device heartbeat requires HTTPS.")));
    }

    if (!IsValidHeartbeatV2(heartbeat))
    {
        return Results.BadRequest(new ApiErrorEnvelope(new ApiError(
            "HEARTBEAT_V2_INVALID",
            "The v2 heartbeat exceeds the accepted contract limits.")));
    }

    var deviceToken = GetBearerToken(context.Request);
    if (deviceToken is null
        || !await controlStore.AuthenticateDeviceAsync(heartbeat.Device.DeviceId, deviceToken, cancellationToken))
    {
        return Results.Unauthorized();
    }

    var policy = await controlStore.GetPolicyAsync(cancellationToken);
    await controlStore.RecordHeartbeatV2Async(
        heartbeat,
        context.Connection.RemoteIpAddress?.ToString(),
        policy.HeartbeatIntervalSeconds,
        cancellationToken);
    SignedRemoteCommand? signedCommand = null;
    if (context.Request.IsHttps)
    {
        var command = await controlStore.LeaseNextCommandAsync(heartbeat.Device.DeviceId, cancellationToken);
        if (command is not null)
        {
            var payload = new RemoteCommandPayload(
                1,
                command.CommandId,
                command.DeviceId,
                command.Type,
                command.CreatedAtUtc,
                command.ExpiresAtUtc);
            signedCommand = new SignedRemoteCommand(payload, SignCommand(payload, commandHmacKey, jsonOptions));
        }
    }

    return Results.Ok(new HeartbeatV2Response(
        DateTimeOffset.UtcNow,
        policy.PolicyVersion,
        policy.HeartbeatIntervalSeconds,
        signedCommand));
});

app.MapGet("/api/v2/devices/{deviceId:guid}/policy", async (
    HttpContext context,
    Guid deviceId,
    ControlStore controlStore,
    CancellationToken cancellationToken) =>
{
    if (!context.Request.IsHttps)
    {
        return Results.BadRequest(new ApiErrorEnvelope(new ApiError(
            "DEVICE_CONTROL_HTTPS_REQUIRED",
            "Device policy synchronization requires HTTPS.")));
    }

    var deviceToken = GetBearerToken(context.Request);
    if (deviceToken is null
        || !await controlStore.AuthenticateDeviceAsync(deviceId, deviceToken, cancellationToken))
    {
        return Results.Unauthorized();
    }

    var policy = await controlStore.GetPolicyAsync(cancellationToken);
    return CreateSignedPolicyResponse(context, policy, jsonOptions, hmacKey);
});

app.MapPost("/api/v2/events/batch", async (
    HttpContext context,
    EventBatchRequest batch,
    ControlStore controlStore,
    CancellationToken cancellationToken) =>
{
    if (!context.Request.IsHttps)
    {
        return Results.BadRequest(new ApiErrorEnvelope(new ApiError(
            "DEVICE_CONTROL_HTTPS_REQUIRED",
            "Device event synchronization requires HTTPS.")));
    }

    if (batch.SchemaVersion != 1 || batch.DeviceId == Guid.Empty || batch.Events.Count > 100)
    {
        return Results.BadRequest(new ApiErrorEnvelope(new ApiError(
            "EVENT_BATCH_INVALID",
            "The event batch exceeds the prototype contract limits.")));
    }

    var deviceToken = GetBearerToken(context.Request);
    if (deviceToken is null
        || !await controlStore.AuthenticateDeviceAsync(batch.DeviceId, deviceToken, cancellationToken))
    {
        return Results.Unauthorized();
    }

    var stored = await controlStore.RecordEventsAsync(batch, cancellationToken);
    return Results.Accepted(value: new EventBatchResponse(stored.Accepted, stored.Duplicates, 0, []));
});

app.MapPost("/api/v2/commands/{commandId:guid}/status", async (
    HttpContext context,
    Guid commandId,
    RemoteCommandStatusUpdate update,
    ControlStore controlStore,
    CancellationToken cancellationToken) =>
{
    if (!context.Request.IsHttps)
    {
        return Results.BadRequest(new ApiErrorEnvelope(new ApiError(
            "DEVICE_CONTROL_HTTPS_REQUIRED",
            "Command status synchronization requires HTTPS.")));
    }

    if (update.SchemaVersion != 1
        || update.CommandId != commandId
        || update.DeviceId == Guid.Empty
        || update.Status is not (RemoteCommandStatus.Executing or RemoteCommandStatus.Succeeded or RemoteCommandStatus.Failed)
        || update.ResultCode?.Length > 128
        || update.ResultSummary?.Length > 512)
    {
        return Results.BadRequest(new ApiErrorEnvelope(new ApiError(
            "COMMAND_STATUS_INVALID",
            "The command status update is invalid.")));
    }

    var deviceToken = GetBearerToken(context.Request);
    if (deviceToken is null
        || !await controlStore.AuthenticateDeviceAsync(update.DeviceId, deviceToken, cancellationToken))
    {
        return Results.Unauthorized();
    }

    return await controlStore.UpdateCommandStatusAsync(update, cancellationToken)
        ? Results.Accepted()
        : Results.Conflict(new ApiErrorEnvelope(new ApiError(
            "COMMAND_STATUS_CONFLICT",
            "The command is terminal, missing, or belongs to another device.")));
});

app.MapGet("/admin/v1/policy", async (ControlStore controlStore, CancellationToken cancellationToken) =>
    Results.Ok(await controlStore.GetPolicyAsync(cancellationToken)));

app.MapPut("/admin/v1/policy", async (
    PolicyUpdateRequest request,
    ControlStore controlStore,
    CancellationToken cancellationToken) =>
{
    var validationError = ValidatePolicyUpdate(request);
    if (validationError is not null)
    {
        return Results.BadRequest(new ApiErrorEnvelope(validationError));
    }

    var updated = await controlStore.TryUpdatePolicyAsync(request, cancellationToken);
    return updated is null
        ? Results.Conflict(new ApiErrorEnvelope(new ApiError(
            "POLICY_VERSION_CONFLICT",
            "The policy changed after it was read; reload and retry.")))
        : Results.Ok(updated);
});

app.MapGet("/admin/v1/devices", async (
    HttpContext context,
    string? search,
    DeviceOnlineState? onlineState,
    int? skip,
    int? take,
    ControlStore controlStore,
    CancellationToken cancellationToken) =>
{
    var now = DateTimeOffset.UtcNow;
    var devices = await controlStore.ListDevicesAsync(cancellationToken);
    var filtered = devices
        .Where(device => string.IsNullOrWhiteSpace(search)
            || device.Hostname.Contains(search, StringComparison.OrdinalIgnoreCase)
            || device.DeviceId.ToString("D").Contains(search, StringComparison.OrdinalIgnoreCase))
        .Where(device => onlineState is null || CalculateOnlineState(device, now) == onlineState)
        .ToArray();
    context.Response.Headers["X-Total-Count"] = filtered.Length.ToString(System.Globalization.CultureInfo.InvariantCulture);
    var page = filtered
        .Skip(Math.Max(0, skip ?? 0))
        .Take(Math.Clamp(take ?? 100, 1, 500));
    return Results.Ok(page.Select(device => new
    {
        device.DeviceId,
        device.LastSeenAtUtc,
        device.Hostname,
        device.OsVersion,
        device.ServiceVersion,
        device.AgentCount,
        device.EndpointCount,
        device.AppliedPolicyVersion,
        device.ProxyState,
        device.OperationState,
        device.SchemaVersion,
        LegacyClient = device.SchemaVersion < 2,
        OnlineState = CalculateOnlineState(device, now),
    }));
});

app.MapGet("/admin/v1/dashboard", async (ControlStore controlStore, CancellationToken cancellationToken) =>
{
    var now = DateTimeOffset.UtcNow;
    var devices = await controlStore.ListDevicesAsync(cancellationToken);
    var states = devices.Select(device => CalculateOnlineState(device, now)).ToArray();
    return Results.Ok(new
    {
        TotalDevices = devices.Count,
        Online = states.Count(state => state == DeviceOnlineState.Online),
        Stale = states.Count(state => state == DeviceOnlineState.Stale),
        Offline = states.Count(state => state == DeviceOnlineState.Offline),
        LegacyClients = devices.Count(device => device.SchemaVersion < 2),
        ProxyDisabled = devices.Count(device => device.OperationState == ClientOperationState.Disabled),
        UpdatedAtUtc = now,
    });
});

app.MapGet("/admin/v1/devices/{deviceId:guid}", async (
    Guid deviceId,
    ControlStore controlStore,
    CancellationToken cancellationToken) =>
{
    var details = await controlStore.GetDeviceDetailsAsync(deviceId, cancellationToken);
    return details is null ? Results.NotFound() : Results.Ok(details);
});

app.MapGet("/admin/v1/devices/{deviceId:guid}/commands", async (
    Guid deviceId,
    ControlStore controlStore,
    CancellationToken cancellationToken) =>
    Results.Ok(await controlStore.ListCommandsAsync(deviceId, cancellationToken)));

app.MapGet("/admin/v1/audit", async (
    Guid? deviceId,
    int? skip,
    int? take,
    ControlStore controlStore,
    CancellationToken cancellationToken) =>
    Results.Ok(await controlStore.ListAdminAuditAsync(
        deviceId,
        Math.Max(0, skip ?? 0),
        Math.Clamp(take ?? 100, 1, 500),
        cancellationToken)));

app.MapPost("/admin/v1/devices/{deviceId:guid}/commands", async (
    HttpContext context,
    Guid deviceId,
    CreateRemoteCommandRequest request,
    ControlStore controlStore,
    CancellationToken cancellationToken) =>
{
    var actor = GetAdminActor(context.Request);
    if (!context.Request.IsHttps
        || request.Type is not (RemoteCommandType.DisableProxy or RemoteCommandType.EnableProxy)
        || string.IsNullOrWhiteSpace(request.Reason)
        || request.Reason.Length > 256
        || request.ExpiresInMinutes is < 1 or > 1440)
    {
        await controlStore.RecordAdminAuditAsync(
            actor,
            "REMOTE_COMMAND_REJECTED",
            deviceId,
            null,
            "REMOTE_COMMAND_INVALID",
            cancellationToken);
        return Results.BadRequest(new ApiErrorEnvelope(new ApiError(
            "REMOTE_COMMAND_INVALID",
            "Remote commands require HTTPS, an allowed type, a reason, and a 1-1440 minute expiry.")));
    }

    try
    {
        var command = await controlStore.CreateRemoteCommandAsync(
            deviceId,
            request,
            actor,
            cancellationToken);
        if (command is not null)
        {
            return Results.Accepted(value: command);
        }

        await controlStore.RecordAdminAuditAsync(
            actor,
            "REMOTE_COMMAND_REJECTED",
            deviceId,
            null,
            "DEVICE_NOT_FOUND",
            cancellationToken);
        return Results.NotFound();
    }
    catch (InvalidOperationException exception) when (exception.Message == "DEVICE_COMMAND_ALREADY_ACTIVE")
    {
        await controlStore.RecordAdminAuditAsync(
            actor,
            "REMOTE_COMMAND_REJECTED",
            deviceId,
            null,
            "DEVICE_COMMAND_ALREADY_ACTIVE",
            cancellationToken);
        return Results.Conflict(new ApiErrorEnvelope(new ApiError(
            "DEVICE_COMMAND_ALREADY_ACTIVE",
            "The device already has an active command.")));
    }
});

app.MapPost("/admin/v1/commands/{commandId:guid}/cancel", async (
    HttpContext context,
    Guid commandId,
    ControlStore controlStore,
    CancellationToken cancellationToken) =>
    await controlStore.CancelCommandAsync(commandId, GetAdminActor(context.Request), cancellationToken)
        ? Results.Ok()
        : Results.Conflict(new ApiErrorEnvelope(new ApiError(
            "COMMAND_NOT_CANCELLABLE",
            "Only a pending command can be cancelled."))));

app.Run();

static EndpointPolicy BuildSeedPolicy()
{
    var mode = Enum.TryParse<RouteMode>(GetControlSetting("SF_CONTROL_ROUTE_MODE", "RouteMode"), true, out var parsed)
        ? parsed
        : RouteMode.FixedGateway;
    var allowInsecureGatewayText = GetControlSetting("SF_CONTROL_ALLOW_INSECURE_GATEWAY", "AllowInsecureGateway");
    var policy = new EndpointPolicy(
        1,
        Guid.TryParse(GetControlSetting("SF_CONTROL_SERVER_ID", "ServerId"), out var serverId) ? serverId : Guid.NewGuid(),
        long.TryParse(GetControlSetting("SF_CONTROL_POLICY_VERSION", "PolicyVersion"), out var version) && version > 0 ? version : 1,
        !string.Equals(GetControlSetting("SF_CONTROL_ENABLED", "Enabled"), "false", StringComparison.OrdinalIgnoreCase),
        mode,
        GetControlSetting("SF_CONTROL_GATEWAY_ORIGIN", "GatewayOrigin")
            ?? "http://gateway.example.invalid",
        allowInsecureGatewayText is null
            || string.Equals(allowInsecureGatewayText, "true", StringComparison.OrdinalIgnoreCase),
        int.TryParse(GetControlSetting("SF_CONTROL_POLL_INTERVAL_SECONDS", "PollIntervalSeconds"), out var pollInterval) ? pollInterval : 60,
        int.TryParse(GetControlSetting("SF_CONTROL_HEARTBEAT_INTERVAL_SECONDS", "HeartbeatIntervalSeconds"), out var heartbeatInterval) ? heartbeatInterval : 60,
        DateTimeOffset.UtcNow,
        [BaseUrlAllowlist.LegacyCcrBaseUrl]);
    var error = ValidatePolicyUpdate(new PolicyUpdateRequest(
        policy.PolicyVersion,
        policy.Enabled,
        policy.RouteMode,
        policy.GatewayOrigin,
        policy.AllowInsecureGateway,
        policy.PollIntervalSeconds,
        policy.HeartbeatIntervalSeconds,
        policy.AllowlistedBaseUrls));
    return error is null
        ? policy
        : throw new InvalidOperationException($"Invalid seed policy: {error.Code}: {error.Message}");
}

static string? GetControlSetting(string environmentVariable, string registryValue)
{
    var environmentValue = Environment.GetEnvironmentVariable(environmentVariable);
    if (!string.IsNullOrWhiteSpace(environmentValue))
    {
        return environmentValue;
    }

    if (!OperatingSystem.IsWindows())
    {
        return null;
    }

    try
    {
        using var key = Registry.LocalMachine.OpenSubKey(@"Software\SF\EndpointAIControl", writable: false);
        return key?.GetValue(registryValue) as string;
    }
    catch (UnauthorizedAccessException)
    {
        return null;
    }
    catch (System.Security.SecurityException)
    {
        return null;
    }
}

static ApiError? ValidatePolicyUpdate(PolicyUpdateRequest request)
{
    if (request.ExpectedVersion < 1
        || request.PollIntervalSeconds is < 15 or > 3600
        || request.HeartbeatIntervalSeconds is < 15 or > 3600)
    {
        return new ApiError("POLICY_FIELDS_INVALID", "Policy version and intervals are outside the accepted range.");
    }

    if (request.AllowlistedBaseUrls is not null)
    {
        try
        {
            BaseUrlAllowlist.Normalize(request.AllowlistedBaseUrls);
        }
        catch (FormatException exception)
        {
            return new ApiError("POLICY_ALLOWLIST_INVALID", exception.Message);
        }
    }

    if (request.RouteMode != RouteMode.FixedGateway)
    {
        return null;
    }

    if (!Uri.TryCreate(request.GatewayOrigin, UriKind.Absolute, out var gateway)
        || (!string.Equals(gateway.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            && !(request.AllowInsecureGateway
                && string.Equals(gateway.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)))
        || !string.IsNullOrEmpty(gateway.UserInfo)
        || gateway.AbsolutePath != "/"
        || !string.IsNullOrEmpty(gateway.Query)
        || !string.IsNullOrEmpty(gateway.Fragment))
    {
        return new ApiError(
            "POLICY_GATEWAY_INVALID",
            "Fixed gateway mode requires a valid origin; HTTP must be explicitly allowed.");
    }

    return null;
}

static bool IsValidHeartbeat(HeartbeatRequest heartbeat)
{
    return heartbeat.SchemaVersion == 1
        && heartbeat.HeartbeatId != Guid.Empty
        && heartbeat.Device.DeviceId != Guid.Empty
        && heartbeat.Agents.Count <= 256
        && heartbeat.Users.Count <= 64
        && heartbeat.Device.Hostname.Length <= 255
        && heartbeat.Agents.All(agent => agent.UserSid.Length <= 184 && agent.DisplayName.Length <= 128);
}

static bool IsValidHeartbeatV2(HeartbeatV2Request heartbeat)
{
    return heartbeat.SchemaVersion == 2
        && heartbeat.HeartbeatId != Guid.Empty
        && heartbeat.Device.DeviceId != Guid.Empty
        && heartbeat.Agents.Count <= 256
        && heartbeat.Users.Count <= 64
        && heartbeat.Endpoints.Count <= 512
        && heartbeat.Activity.Count <= 512
        && heartbeat.Device.Hostname.Length <= 255
        && heartbeat.Device.ServiceVersion.Length <= 64
        && heartbeat.Runtime.UptimeSeconds >= 0
        && heartbeat.Agents.All(agent => agent.UserSid.Length <= 184 && agent.DisplayName.Length <= 128)
        && heartbeat.Endpoints.All(endpoint =>
            endpoint.UserSid.Length <= 184
            && endpoint.AgentFamily.Length is > 0 and <= 32
            && endpoint.ProviderId is null or { Length: <= 256 }
            && endpoint.EndpointId is null or { Length: <= 256 }
            && endpoint.ConfiguredModel is null or { Length: <= 256 }
            && endpoint.OriginalTargetBaseUrl is null or { Length: <= 2048 }
            && endpoint.EffectiveConfiguredBaseUrl is null or { Length: <= 2048 }
            && endpoint.LocalRouteUrl is null or { Length: <= 2048 });
}

static bool HasBearerToken(HttpRequest request, string expectedToken)
{
    if (!AuthenticationHeaderValue.TryParse(request.Headers.Authorization, out var authorization)
        || !string.Equals(authorization.Scheme, "Bearer", StringComparison.OrdinalIgnoreCase)
        || string.IsNullOrEmpty(authorization.Parameter))
    {
        return false;
    }

    return FixedTimeEquals(authorization.Parameter, expectedToken);
}

static string? GetBearerToken(HttpRequest request)
{
    return AuthenticationHeaderValue.TryParse(request.Headers.Authorization, out var authorization)
        && string.Equals(authorization.Scheme, "Bearer", StringComparison.OrdinalIgnoreCase)
        && !string.IsNullOrWhiteSpace(authorization.Parameter)
            ? authorization.Parameter
            : null;
}

static string GetAdminActor(HttpRequest request)
{
    var actor = request.Headers["X-SF-Admin-Actor"].ToString().Trim();
    return actor.Length is > 0 and <= 64 && actor.All(character => char.IsAsciiLetterOrDigit(character) || character is '.' or '-' or '_' or '@')
        ? actor
        : "admin-token";
}

static DeviceOnlineState CalculateOnlineState(StoredDeviceSummary device, DateTimeOffset now)
{
    var elapsed = now - device.LastSeenAtUtc;
    var interval = TimeSpan.FromSeconds(Math.Clamp(device.HeartbeatIntervalSeconds, 15, 3600));
    if (elapsed <= interval + interval + TimeSpan.FromSeconds(30))
    {
        return DeviceOnlineState.Online;
    }

    return elapsed <= interval * 5 + TimeSpan.FromSeconds(30)
        ? DeviceOnlineState.Stale
        : DeviceOnlineState.Offline;
}

static string SignCommand(RemoteCommandPayload payload, byte[] commandKey, JsonSerializerOptions options)
{
    var body = JsonSerializer.SerializeToUtf8Bytes(payload, options);
    return $"v1:{ToBase64Url(HMACSHA256.HashData(commandKey, body))}";
}

static IResult CreateSignedPolicyResponse(
    HttpContext context,
    EndpointPolicy policy,
    JsonSerializerOptions options,
    byte[] hmacKey)
{
    var body = JsonSerializer.SerializeToUtf8Bytes(policy, options);
    using var hmac = new HMACSHA256(hmacKey);
    var signature = ToBase64Url(hmac.ComputeHash(body));
    context.Response.Headers["X-SF-Policy-Version"] = policy.PolicyVersion.ToString(System.Globalization.CultureInfo.InvariantCulture);
    context.Response.Headers["X-SF-Policy-Signature"] = $"v1:{signature}";
    context.Response.Headers.CacheControl = "no-store";
    return Results.Bytes(body, "application/json; charset=utf-8");
}

static bool FixedTimeEquals(string actual, string expected)
{
    var actualBytes = Encoding.UTF8.GetBytes(actual);
    var expectedBytes = Encoding.UTF8.GetBytes(expected);
    return actualBytes.Length == expectedBytes.Length
        && CryptographicOperations.FixedTimeEquals(actualBytes, expectedBytes);
}

static string ToBase64Url(byte[] value)
{
    return Convert.ToBase64String(value)
        .TrimEnd('=')
        .Replace('+', '-')
        .Replace('/', '_');
}
