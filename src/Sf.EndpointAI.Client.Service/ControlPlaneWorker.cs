using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Sf.EndpointAI.Client.Core.Configuration;
using Sf.EndpointAI.Client.Core.Discovery;
using Sf.EndpointAI.Client.Core.Policy;
using Sf.EndpointAI.Client.Core.Routing;
using Sf.EndpointAI.Client.Core.State;
using Sf.EndpointAI.Client.Core.Windows;
using Sf.EndpointAI.Contracts;

namespace Sf.EndpointAI.Client.Service;

public sealed class ControlPlaneWorker(
    RemoteControlClient controlClient,
    RemoteControlOptions controlOptions,
    DynamicPolicyProvider policyProvider,
    BaseUrlBypassPolicy bypassPolicy,
    SqliteClientStateStore stateStore,
    AuditHealthState auditHealth,
    AgentDiscoveryEngine discoveryEngine,
    IUserProfileProvider profileProvider,
    IRouteRegistry routeRegistry,
    CcSwitchModeState ccSwitchModeState,
    AgentAssetSnapshotBuilder assetSnapshotBuilder,
    ProxyActivityTracker activityTracker,
    ClientOperationStateProvider operationStateProvider,
    RouteReconciliationRuntimeState reconciliationRuntimeState,
    RouteReconciliationSignals reconciliationSignals,
    RemoteCommandExecutor remoteCommandExecutor,
    ControlPlaneRuntimeState controlPlaneRuntimeState,
    ILogger<ControlPlaneWorker> logger) : BackgroundService
{
    private readonly Guid _bootId = Guid.NewGuid();
    private readonly DateTimeOffset _serviceStartedAtUtc = DateTimeOffset.UtcNow;
    private readonly List<EndpointEvent> _pendingEvents = [];
    private PolicyClientState _policyState = new(null, null, PolicyApplyStatus.Unknown, null, null);
    private DateTimeOffset? _lastControlSyncAtUtc;
    private DateTimeOffset? _reenrollmentBlockedUntilUtc;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var deviceId = Guid.Empty;
        var cachedPolicyLoaded = false;
        StoredDeviceCredential? credential = null;

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                if (deviceId == Guid.Empty)
                {
                    await stateStore.InitializeAsync(stoppingToken);
                    deviceId = await stateStore.GetOrCreateDeviceIdAsync(stoppingToken);
                    controlPlaneRuntimeState.SetDeviceId(deviceId);
                }

                if (!cachedPolicyLoaded)
                {
                    await ApplyCachedPolicyAsync(stoppingToken);
                    cachedPolicyLoaded = true;
                }

                credential ??= await GetOrEnrollDeviceAsync(deviceId, stoppingToken);
                await remoteCommandExecutor.ResumeExecutingAsync(deviceId, credential.Token, stoppingToken);
                try
                {
                    await SynchronizeOnceAsync(deviceId, credential, stoppingToken);
                }
                catch (HttpRequestException exception) when (exception.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                {
                    credential = await ReenrollDeviceAsync(deviceId, stoppingToken);
                    await SynchronizeOnceAsync(deviceId, credential, stoppingToken);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception) when (exception is HttpRequestException
                or ControlTlsValidationException
                or PolicySignatureException
                or PolicyValidationException
                or InvalidOperationException
                or IOException
                or UnauthorizedAccessException
                or CryptographicException
                or SqliteException
                or JsonException)
            {
                var code = GetErrorCode(exception);
                controlPlaneRuntimeState.RecordFailure(code);
                _policyState = _policyState with
                {
                    ApplyStatus = PolicyApplyStatus.Failed,
                    LastErrorCode = code,
                    LastErrorSummary = exception.Message,
                };
                AddEvent(EventSeverity.Error, "control-plane", code, exception.Message);
                ControlPlaneLog.SynchronizationFailed(logger, code, exception);
            }

            var delaySeconds = Math.Clamp(policyProvider.Current.PollIntervalSeconds, 15, 3600);
            await Task.Delay(TimeSpan.FromSeconds(delaySeconds), stoppingToken);
        }
    }

    private async Task<StoredDeviceCredential> GetOrEnrollDeviceAsync(
        Guid deviceId,
        CancellationToken cancellationToken)
    {
        var existing = await stateStore.LoadDeviceCredentialAsync(cancellationToken);
        if (existing is not null && CredentialMatchesControlServer(existing))
        {
            return existing;
        }

        if (existing is not null)
        {
            AddEvent(
                EventSeverity.Warning,
                "control-plane",
                "CONTROL_DEVICE_CREDENTIAL_SCOPE_MISMATCH",
                "The stored device credential belongs to a different or legacy control server scope.");
        }

        return await EnrollDeviceAsync(deviceId, cancellationToken);
    }

    private async Task<StoredDeviceCredential> ReenrollDeviceAsync(
        Guid deviceId,
        CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        AddEvent(
            EventSeverity.Warning,
            "control-plane",
            "CONTROL_DEVICE_REENROLL_REQUIRED",
            "The control server rejected the stored device credential.");
        if (_reenrollmentBlockedUntilUtc is not null && now < _reenrollmentBlockedUntilUtc)
        {
            throw new ControlSynchronizationException(
                "CONTROL_DEVICE_REENROLL_FAILED",
                "Device re-enrollment is in its five-minute failure cooldown period.");
        }

        try
        {
            var credential = await EnrollDeviceAsync(deviceId, cancellationToken);
            _reenrollmentBlockedUntilUtc = null;
            return credential;
        }
        catch (Exception exception) when (exception is HttpRequestException
            or InvalidOperationException
            or IOException
            or CryptographicException)
        {
            _reenrollmentBlockedUntilUtc = now.AddMinutes(5);
            throw new ControlSynchronizationException(
                "CONTROL_DEVICE_REENROLL_FAILED",
                "Device re-enrollment failed and will not be retried for five minutes.",
                exception);
        }
    }

    private async Task<StoredDeviceCredential> EnrollDeviceAsync(
        Guid deviceId,
        CancellationToken cancellationToken)
    {

        var version = Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "0.0.0";
        var enrolled = await controlClient.EnrollDeviceAsync(
            new DeviceEnrollmentRequest(2, deviceId, Environment.MachineName, version),
            cancellationToken);
        if (enrolled.DeviceId != deviceId)
        {
            throw new InvalidOperationException("The control server enrolled a different device identity.");
        }

        var credential = new StoredDeviceCredential(
            enrolled.DeviceToken,
            enrolled.EnrolledAtUtc,
            controlOptions.ServerOrigin.AbsoluteUri,
            controlOptions.ServerCertificateSpkiSha256);
        await stateStore.SaveDeviceCredentialAsync(credential, cancellationToken);
        return credential;
    }

    private bool CredentialMatchesControlServer(StoredDeviceCredential credential)
    {
        return Uri.TryCreate(credential.ServerOrigin, UriKind.Absolute, out var storedOrigin)
            && storedOrigin == controlOptions.ServerOrigin
            && string.Equals(
                credential.ServerCertificateSpkiSha256,
                controlOptions.ServerCertificateSpkiSha256,
                StringComparison.Ordinal);
    }

    private async Task ApplyCachedPolicyAsync(CancellationToken cancellationToken)
    {
        var cached = await stateStore.LoadPolicyAsync(cancellationToken);
        if (cached is null)
        {
            return;
        }

        try
        {
            PolicyValidator.Validate(cached.Policy);
            ApplyPolicy(cached.Policy);
            _policyState = new PolicyClientState(
                cached.Policy.PolicyVersion,
                cached.Policy.PolicyVersion,
                PolicyApplyStatus.Applied,
                null,
                null);
        }
        catch (PolicyValidationException exception)
        {
            _policyState = new PolicyClientState(
                cached.Policy.PolicyVersion,
                null,
                PolicyApplyStatus.Failed,
                exception.Code,
                exception.Message);
            AddEvent(EventSeverity.Error, "policy", exception.Code, "Cached policy validation failed.");
        }
    }

    private async Task SynchronizeOnceAsync(
        Guid deviceId,
        StoredDeviceCredential credential,
        CancellationToken cancellationToken)
    {
        var received = await controlClient.FetchDevicePolicyAsync(deviceId, credential.Token, cancellationToken);
        _policyState = _policyState with { LastReceivedVersion = received.Policy.PolicyVersion };
        if (ApplyPolicy(received.Policy))
        {
            await stateStore.SavePolicyAsync(received.Policy, received.Signature, DateTimeOffset.UtcNow, cancellationToken);
        }
        _policyState = new PolicyClientState(
            received.Policy.PolicyVersion,
            policyProvider.Current.PolicyVersion,
            PolicyApplyStatus.Applied,
            null,
            null);

        var discovery = await discoveryEngine.DiscoverAsync(cancellationToken);
        foreach (var failure in discovery.Failures)
        {
            AddEvent(
                EventSeverity.Warning,
                "agent-discovery",
                "DISCOVERY_COLLECTOR_FAILED",
                $"Collector '{failure.Collector}' failed with {failure.ErrorType}.");
        }

        var routes = await routeRegistry.ListAsync(cancellationToken);
        var heartbeat = await BuildHeartbeatAsync(deviceId, discovery, routes, cancellationToken);
        var heartbeatResponse = await controlClient.SendHeartbeatV2Async(heartbeat, credential.Token, cancellationToken);
        _lastControlSyncAtUtc = DateTimeOffset.UtcNow;
        controlPlaneRuntimeState.RecordSuccess(_lastControlSyncAtUtc.Value);
        if (heartbeatResponse.Command is not null)
        {
            await remoteCommandExecutor.ExecuteAsync(deviceId, credential.Token, heartbeatResponse.Command, cancellationToken);
        }

        if (_pendingEvents.Count > 0)
        {
            var batchEvents = _pendingEvents.Take(100).ToArray();
            var response = await controlClient.SendDeviceEventsAsync(
                new EventBatchRequest(1, Guid.NewGuid(), deviceId, batchEvents),
                credential.Token,
                cancellationToken);
            if (response.Rejected == 0)
            {
                _pendingEvents.RemoveRange(0, batchEvents.Length);
            }
        }
    }

    private bool ApplyPolicy(EndpointPolicy policy)
    {
        if (!policyProvider.TryApply(policy))
        {
            return false;
        }

        if (bypassPolicy.Replace(policy.AllowlistedBaseUrls))
        {
            reconciliationSignals.Request(null, "policy-allowlist");
        }

        return true;
    }

    private async Task<HeartbeatV2Request> BuildHeartbeatAsync(
        Guid deviceId,
        AgentDiscoverySnapshot discovery,
        IReadOnlyList<RouteRecord> routes,
        CancellationToken cancellationToken)
    {
        var profiles = profileProvider.GetProfiles();
        var users = profiles
            .Select(profile => new EndpointUser(profile.Sid, Path.GetFileName(profile.ProfilePath.TrimEnd(Path.DirectorySeparatorChar))))
            .ToArray();
        var uniqueAgents = discovery.Agents
            .GroupBy(agent => (agent.UserSid, agent.AgentType))
            .Select(group => group.OrderByDescending(agent => agent.Confidence).First())
            .ToArray();
        var inventory = uniqueAgents.Select(agent =>
        {
            var routeAgentType = GetSharedRouteAgentType(agent.AgentType);
            var directRoute = routes.FirstOrDefault(route => route.UserSid == agent.UserSid && route.AgentType == routeAgentType);
            var ccSwitchProviderPrefix = GetCcSwitchProviderPrefix(agent.AgentType);
            var ccSwitchRoute = routes.FirstOrDefault(route =>
                route.UserSid == agent.UserSid
                && route.AgentType == AgentType.CcSwitch
                && (agent.AgentType == AgentType.CcSwitch
                    || (ccSwitchProviderPrefix is not null
                        && route.ProviderId.StartsWith(ccSwitchProviderPrefix, StringComparison.Ordinal))));
            var route = directRoute ?? ccSwitchRoute;
            var running = agent.Evidence.Any(item => string.Equals(item.Collector, "running-process", StringComparison.Ordinal));
            var ccSwitchAppType = GetCcSwitchAppType(agent.AgentType);
            var ccSwitchMode = agent.AgentType == AgentType.CcSwitch
                ? ccSwitchModeState.GetReportedMode(agent.UserSid)
                : ccSwitchAppType is null
                    ? null
                    : ccSwitchModeState.GetReportedMode(agent.UserSid, ccSwitchAppType);
            return new AgentInventoryItem(
                CreateStableInstanceId(deviceId, agent.UserSid, agent.AgentType),
                agent.UserSid,
                agent.AgentType,
                GetDisplayName(agent),
                agent.Version,
                agent.InstallMethod,
                agent.Confidence,
                Installed: true,
                Running: running,
                RouterType: ccSwitchRoute is null
                    ? null
                    : ccSwitchMode == "local-proxy" ? "cc-switch-local-proxy" : "cc-switch",
                CcSwitchVersion: agent.AgentType == AgentType.CcSwitch ? agent.Version : null,
                CcSwitchMode: ccSwitchMode,
                RouteStatus: route?.Status ?? (agent.AgentType is AgentType.QoderCli or AgentType.QoderIde
                    ? RouteStatus.Unsupported
                    : RouteStatus.Discovered),
                ObservedTargetOrigin: route?.OriginalBaseUri.GetLeftPart(UriPartial.Authority),
                LastSeenAtUtc: discovery.CompletedAtUtc);
        }).ToArray();
        var current = policyProvider.Current;
        var operationState = operationStateProvider.Current;
        var reconciliationState = reconciliationRuntimeState.Current;
        var endpoints = await assetSnapshotBuilder.BuildAsync(
            routes,
            discovery.CompletedAtUtc,
            cancellationToken);
        var activity = activityTracker.Snapshot(endpoints).ToList();
        var trackedAssetIds = activity.Select(item => item.AssetId).ToHashSet();
        activity.AddRange(endpoints
            .Where(endpoint => !trackedAssetIds.Contains(endpoint.AssetId))
            .Select(endpoint => new ProxyActivityAsset(
                endpoint.AssetId,
                endpoint.AllowlistBypassed
                    ? ProxyTrafficState.AllowlistBypassed
                    : ProxyTrafficState.NeverObserved,
                null,
                null,
                null,
                null,
                endpoint.AllowlistBypassed ? BaseUrlBypassPolicy.BypassCode : null,
                null,
                null,
                0,
                0,
                0)));
        return new HeartbeatV2Request(
            2,
            Guid.NewGuid(),
            DateTimeOffset.UtcNow,
            new DeviceIdentity(
                deviceId,
                Environment.MachineName,
                Environment.OSVersion.VersionString,
                Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "0.0.0",
                _bootId),
            new DeviceRuntimeState(
                _serviceStartedAtUtc,
                Math.Max(0, (long)(DateTimeOffset.UtcNow - _serviceStartedAtUtc).TotalSeconds),
                operationState.State,
                true,
                _lastControlSyncAtUtc,
                reconciliationState.LastReconcileAtUtc,
                reconciliationState.LastReconcileResult,
                reconciliationState.LastReconcileErrorCode),
            _policyState,
            new ProxyClientState(
                ProxyState.Listening,
                "127.0.0.1:18080",
                routes.Count(route => route.Status == RouteStatus.Attached),
                auditHealth.Current),
            users,
            inventory,
            endpoints,
            activity);
    }

    private void AddEvent(EventSeverity severity, string type, string code, string summary)
    {
        if (_pendingEvents.Count >= 1000)
        {
            _pendingEvents.RemoveAt(0);
        }

        _pendingEvents.Add(new EndpointEvent(
            Guid.NewGuid(),
            DateTimeOffset.UtcNow,
            severity,
            type,
            code,
            summary.Length > 512 ? summary[..512] : summary,
            null,
            null,
            null));
    }

    private static Guid CreateStableInstanceId(Guid deviceId, string userSid, AgentType agentType)
    {
        var input = Encoding.UTF8.GetBytes($"{deviceId:D}|{userSid}|{agentType}");
        var hash = SHA256.HashData(input);
        return new Guid(hash.AsSpan(0, 16));
    }

    private static string GetDisplayName(AgentIdentityResult agent)
    {
        if (agent.AgentType != AgentType.UnknownCandidate)
        {
            return GetDisplayName(agent.AgentType);
        }

        var candidateType = agent.Evidence
            .Select(item => (AgentType?)item.CandidateType)
            .FirstOrDefault(type => type != AgentType.UnknownCandidate);
        var candidateName = candidateType is null ? "AI Agent" : GetDisplayName(candidateType.Value);
        var evidenceName = agent.Evidence
            .OrderByDescending(item => string.Equals(item.Collector, "running-process", StringComparison.Ordinal))
            .Select(item => GetEvidenceName(item.Artifact))
            .FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));
        return evidenceName is null
            ? $"疑似 {candidateName}"
            : $"疑似 {candidateName}（识别线索：{evidenceName}）";
    }

    private static string? GetEvidenceName(string artifact)
    {
        if (string.IsNullOrWhiteSpace(artifact)
            || artifact.StartsWith("registry::", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var value = artifact.Trim();
        var pidMarker = value.LastIndexOf(" (PID ", StringComparison.Ordinal);
        if (pidMarker > 0 && value.EndsWith(')'))
        {
            value = value[..pidMarker];
        }

        var fileName = Path.GetFileName(value.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        return string.IsNullOrWhiteSpace(fileName) ? null : fileName;
    }

    private static string GetDisplayName(AgentType agentType) => agentType switch
    {
        AgentType.ClaudeCode => "Claude Code",
        AgentType.ClaudeCli => "Claude Code CLI",
        AgentType.ClaudeIde => "Claude Code IDE Extension",
        AgentType.ClaudeDesktop => "Claude Code Desktop",
        AgentType.CodexCli => "Codex CLI",
        AgentType.CodexIde => "Codex IDE Extension",
        AgentType.CodexDesktop => "Codex Desktop",
        AgentType.QoderCli => "Qoder CLI",
        AgentType.QoderIde => "Qoder IDE",
        AgentType.CcSwitch => "CC Switch",
        _ => "Unknown AI Agent",
    };

    private static bool IsCodexAgent(AgentType agentType) => agentType is
        AgentType.CodexCli or AgentType.CodexIde or AgentType.CodexDesktop;

    private static bool IsClaudeAgent(AgentType agentType) => agentType is
        AgentType.ClaudeCode or AgentType.ClaudeCli or AgentType.ClaudeIde or AgentType.ClaudeDesktop;

    private static AgentType GetSharedRouteAgentType(AgentType agentType)
    {
        if (IsCodexAgent(agentType))
        {
            return AgentType.CodexCli;
        }

        return IsClaudeAgent(agentType) ? AgentType.ClaudeCode : agentType;
    }

    private static string? GetCcSwitchProviderPrefix(AgentType agentType)
    {
        if (IsCodexAgent(agentType))
        {
            return "codex:";
        }

        return IsClaudeAgent(agentType) ? "claude:" : null;
    }

    private static string? GetCcSwitchAppType(AgentType agentType)
    {
        if (IsCodexAgent(agentType))
        {
            return "codex";
        }

        return IsClaudeAgent(agentType) ? "claude" : null;
    }

    private static string GetErrorCode(Exception exception) => exception switch
    {
        ControlSynchronizationException synchronization => synchronization.Code,
        ControlTlsValidationException tls => tls.Code,
        PolicySignatureException signature => signature.Code,
        PolicyValidationException validation => validation.Code,
        HttpRequestException http when FindControlTlsException(http) is { } tls => tls.Code,
        HttpRequestException => "CONTROL_HTTP_FAILED",
        IOException => "CONTROL_IO_FAILED",
        _ => "CONTROL_SYNC_FAILED",
    };

    private static ControlTlsValidationException? FindControlTlsException(Exception exception)
    {
        for (var current = exception; current is not null; current = current.InnerException!)
        {
            if (current is ControlTlsValidationException tls)
            {
                return tls;
            }
        }

        return null;
    }
}

internal sealed class ControlSynchronizationException : InvalidOperationException
{
    public ControlSynchronizationException(string code, string message, Exception? innerException = null)
        : base(message, innerException)
    {
        Code = code;
    }

    public string Code { get; }
}

internal static partial class ControlPlaneLog
{
    [LoggerMessage(EventId = 2001, Level = LogLevel.Warning, Message = "Control-plane synchronization failed with {ErrorCode}.")]
    public static partial void SynchronizationFailed(ILogger logger, string errorCode, Exception exception);
}
