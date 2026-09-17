using Microsoft.Data.Sqlite;
using Sf.EndpointAI.Client.Core.Routing;
using Sf.EndpointAI.Client.Core.Windows;
using Sf.EndpointAI.Contracts;

namespace Sf.EndpointAI.Client.Core.Configuration;

public sealed record AgentConfigAttachmentItem(
    AgentType AgentType,
    string ProviderId,
    string ConfigPath,
    RouteStatus Status,
    Uri? OriginalBaseUri,
    Uri? InjectedBaseUri,
    string? BackupPath,
    string? ErrorCode,
    string? Message);

public sealed record ProfileAttachmentResult(
    string UserSid,
    bool CcSwitchManaged,
    IReadOnlyList<AgentConfigAttachmentItem> Items,
    IReadOnlyList<CcSwitchAppModeStatus>? CcSwitchApps = null,
    IReadOnlyList<CcSwitchAppOwnershipStatus>? CcSwitchOwnership = null);

public sealed class AgentConfigAttachmentCoordinator
{
    private static readonly string[] SupportedAppTypes = ["claude", "codex"];
    private static readonly Uri InspectionUri = new("http://127.0.0.1:18080/r/config-inspection");
    private static readonly Uri PrototypeDirectGatewayUri = new("http://192.0.2.2:8080");
    private readonly IRouteRegistry _routeRegistry;
    private readonly RouteProvisioner _routeProvisioner;
    private readonly BaseUrlBypassPolicy _bypassPolicy;

    public AgentConfigAttachmentCoordinator(
        IRouteRegistry routeRegistry,
        Uri localProxyOrigin,
        BaseUrlBypassPolicy? bypassPolicy = null)
    {
        _routeRegistry = routeRegistry;
        _routeProvisioner = new RouteProvisioner(routeRegistry, localProxyOrigin);
        _bypassPolicy = bypassPolicy ?? new BaseUrlBypassPolicy();
    }

    public async Task<ProfileAttachmentResult> AttachAsync(
        WindowsUserProfile profile,
        string backupRoot,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentException.ThrowIfNullOrWhiteSpace(backupRoot);
        var ccSwitchDatabase = Path.Combine(profile.ProfilePath, ".cc-switch", "cc-switch.db");
        if (File.Exists(ccSwitchDatabase))
        {
            return await AttachMixedProfileAsync(profile, ccSwitchDatabase, backupRoot, cancellationToken);
        }

        var items = new List<AgentConfigAttachmentItem>();
        var claudeSettings = Path.Combine(profile.ProfilePath, ".claude", "settings.json");
        if (File.Exists(claudeSettings))
        {
            items.Add(await AttachDirectFileAsync(
                profile,
                AgentType.ClaudeCode,
                "direct",
                claudeSettings,
                backupRoot,
                (content, uri) => ClaudeSettingsTransformer.InjectBaseUrl(content.Span, uri),
                new Uri("https://api.anthropic.com"),
                cancellationToken));
        }

        var codexConfig = Path.Combine(profile.ProfilePath, ".codex", "config.toml");
        if (File.Exists(codexConfig))
        {
            items.Add(await AttachDirectFileAsync(
                profile,
                AgentType.CodexCli,
                "direct",
                codexConfig,
                backupRoot,
                (content, uri) => CodexSettingsTransformer.InjectBaseUrl(content.Span, uri),
                new Uri("https://api.openai.com/v1"),
                cancellationToken));
        }

        var qoderSettings = Path.Combine(profile.ProfilePath, ".qoder", "settings.json");
        if (File.Exists(qoderSettings))
        {
            items.Add(new AgentConfigAttachmentItem(
                AgentType.QoderCli,
                "byok",
                qoderSettings,
                RouteStatus.Unsupported,
                null,
                null,
                null,
                "QODER_PRIVATE_CONFIG_UNSUPPORTED",
                "Qoder BYOK configuration is managed by its built-in wizard and is not mutated by the prototype."));
        }

        return new ProfileAttachmentResult(profile.Sid, CcSwitchManaged: false, items);
    }

    public async Task<ProfileAttachmentResult> DetachAsync(
        WindowsUserProfile profile,
        string backupRoot,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentException.ThrowIfNullOrWhiteSpace(backupRoot);
        var routes = (await _routeRegistry.ListAsync(cancellationToken))
            .Where(route => string.Equals(route.UserSid, profile.Sid, StringComparison.Ordinal))
            .ToArray();
        var ccSwitchDatabase = Path.Combine(profile.ProfilePath, ".cc-switch", "cc-switch.db");
        if (File.Exists(ccSwitchDatabase))
        {
            return await DetachMixedProfileAsync(
                profile,
                ccSwitchDatabase,
                routes,
                backupRoot,
                cancellationToken);
        }

        var items = new List<AgentConfigAttachmentItem>();
        foreach (var route in routes.Where(route => route.ProviderId == "direct"))
        {
            var path = route.AgentType switch
            {
                AgentType.ClaudeCode => Path.Combine(profile.ProfilePath, ".claude", "settings.json"),
                AgentType.CodexCli => Path.Combine(profile.ProfilePath, ".codex", "config.toml"),
                _ => null,
            };
            if (path is null || !File.Exists(path))
            {
                continue;
            }

            var update = await RestoreFileIfOwnedAsync(route, path, backupRoot, cancellationToken);
            await _routeRegistry.DeleteByIdentityAsync(route.UserSid, route.AgentType, route.ProviderId, cancellationToken);
            items.Add(new AgentConfigAttachmentItem(
                route.AgentType,
                route.ProviderId,
                path,
                RouteStatus.Discovered,
                route.OriginalBaseUri,
                route.InjectedBaseUri,
                update?.BackupPath,
                null,
                "BaseURL detached."));
        }

        return new ProfileAttachmentResult(profile.Sid, CcSwitchManaged: false, items);
    }

    private async Task<ProfileAttachmentResult> AttachMixedProfileAsync(
        WindowsUserProfile profile,
        string databasePath,
        string backupRoot,
        CancellationToken cancellationToken)
    {
        var inspection = await CcSwitchDatabaseAdapter.InspectAsync(databasePath, cancellationToken);
        var modes = await DetectCcSwitchModesAsync(profile, inspection, cancellationToken);
        if (!inspection.ProviderSchemaSupported
            || !inspection.ProxySchemaSupported
            || !inspection.EndpointSchemaSupported)
        {
            var unsupportedModes = SupportedAppTypes
                .Select(appType => new CcSwitchAppModeStatus(
                    appType,
                    CcSwitchOperatingMode.Unsupported,
                    null,
                    null,
                    "CCSWITCH_SCHEMA_UNSUPPORTED"))
                .ToArray();
            var blockedItems = SupportedAppTypes
                .Select(appType => CreateAppBlockedItem(
                    databasePath,
                    appType,
                    "CCSWITCH_SCHEMA_UNSUPPORTED"))
                .ToArray();
            var blockedOwnership = SupportedAppTypes
                .Select(appType => new CcSwitchAppOwnershipStatus(
                    appType,
                    CcSwitchAppOwnership.Blocked,
                    0,
                    0,
                    "CCSWITCH_SCHEMA_UNSUPPORTED"))
                .ToArray();
            return new ProfileAttachmentResult(
                profile.Sid,
                CcSwitchManaged: false,
                blockedItems,
                unsupportedModes,
                blockedOwnership);
        }

        var items = new List<AgentConfigAttachmentItem>();
        var ownership = new List<CcSwitchAppOwnershipStatus>();
        var modeByApp = modes.ToDictionary(item => item.AppType, StringComparer.Ordinal);
        var ccSwitchManaged = false;
        foreach (var appType in SupportedAppTypes)
        {
            var hasMappings = inspection.Providers.Any(item => item.AppType == appType)
                || inspection.Endpoints.Any(item => item.AppType == appType);
            var mode = modeByApp.GetValueOrDefault(appType)
                ?? CcSwitchModeDetector.Detect(
                    appType,
                    inspection,
                    await InspectLiveBaseUriAsync(profile, appType, cancellationToken));
            if (hasMappings)
            {
                ccSwitchManaged = true;
                ownership.Add(new CcSwitchAppOwnershipStatus(
                    appType,
                    CcSwitchAppOwnership.CcSwitch,
                    inspection.Providers.Count(item => item.AppType == appType),
                    inspection.Endpoints.Count(item => item.AppType == appType),
                    null));
                try
                {
                    var result = await AttachCcSwitchAppAsync(
                        profile,
                        databasePath,
                        backupRoot,
                        inspection,
                        mode,
                        cancellationToken);
                    items.AddRange(result.Items);
                    var appErrorCode = result.Items
                        .FirstOrDefault(item => item.Status is RouteStatus.Error or RouteStatus.Unsupported)
                        ?.ErrorCode;
                    if (appErrorCode is not null)
                    {
                        ownership[^1] = ownership[^1] with { ErrorCode = appErrorCode };
                    }
                }
                catch (Exception exception) when (exception is ConfigMutationException
                    or IOException
                    or UnauthorizedAccessException
                    or SqliteException)
                {
                    items.Add(CreateAppErrorItem(databasePath, appType, exception));
                    ownership[^1] = ownership[^1] with
                    {
                        ErrorCode = exception is ConfigMutationException mutation
                            ? mutation.Code
                            : "CCSWITCH_APP_RECONCILE_FAILED",
                    };
                }

                continue;
            }

            if (mode.Mode != CcSwitchOperatingMode.Ordinary)
            {
                ownership.Add(new CcSwitchAppOwnershipStatus(
                    appType,
                    CcSwitchAppOwnership.Blocked,
                    0,
                    0,
                    mode.ErrorCode ?? "CCSWITCH_PROXY_STATE_INCONSISTENT"));
                items.Add(CreateAppBlockedItem(
                    databasePath,
                    appType,
                    mode.ErrorCode ?? "CCSWITCH_PROXY_STATE_INCONSISTENT"));
                continue;
            }

            ownership.Add(new CcSwitchAppOwnershipStatus(
                appType,
                CcSwitchAppOwnership.Direct,
                0,
                0,
                null));

            try
            {
                var direct = await AttachDirectAppIfPresentAsync(
                    profile,
                    appType,
                    backupRoot,
                    cancellationToken);
                if (direct is not null)
                {
                    items.Add(direct with
                    {
                        Message = direct.Message == "Already attached."
                            ? direct.Message
                            : "CCSWITCH_APP_DIRECT_FALLBACK_ATTACHED: " + direct.Message,
                    });
                    var staleCcSwitchRoutes = (await _routeRegistry.ListAsync(cancellationToken))
                        .Where(route => string.Equals(route.UserSid, profile.Sid, StringComparison.Ordinal)
                            && route.AgentType == AgentType.CcSwitch
                            && route.ProviderId.StartsWith($"{appType}:", StringComparison.Ordinal))
                        .ToArray();
                    foreach (var staleRoute in staleCcSwitchRoutes)
                    {
                        if (!await TryRetireRouteIfUnreferencedAsync(
                                profile,
                                staleRoute,
                                databasePath,
                                cancellationToken))
                        {
                            items.Add(CreateRetirementDeferredItem(databasePath, staleRoute));
                        }
                    }
                }
            }
            catch (Exception exception) when (exception is ConfigMutationException
                or IOException
                or UnauthorizedAccessException)
            {
                items.Add(CreateAppErrorItem(databasePath, appType, exception));
            }
        }

        return new ProfileAttachmentResult(profile.Sid, ccSwitchManaged, items, modes, ownership);
    }

    private async Task<AgentConfigAttachmentItem?> AttachDirectAppIfPresentAsync(
        WindowsUserProfile profile,
        string appType,
        string backupRoot,
        CancellationToken cancellationToken)
    {
        var configPath = appType == "claude"
            ? Path.Combine(profile.ProfilePath, ".claude", "settings.json")
            : Path.Combine(profile.ProfilePath, ".codex", "config.toml");
        if (!File.Exists(configPath))
        {
            return null;
        }

        return appType == "claude"
            ? await AttachDirectFileAsync(
                profile,
                AgentType.ClaudeCode,
                "direct",
                configPath,
                backupRoot,
                (content, uri) => ClaudeSettingsTransformer.InjectBaseUrl(content.Span, uri),
                new Uri("https://api.anthropic.com"),
                cancellationToken)
            : await AttachDirectFileAsync(
                profile,
                AgentType.CodexCli,
                "direct",
                configPath,
                backupRoot,
                (content, uri) => CodexSettingsTransformer.InjectBaseUrl(content.Span, uri),
                new Uri("https://api.openai.com/v1"),
                cancellationToken);
    }

    private static AgentConfigAttachmentItem CreateAppBlockedItem(
        string databasePath,
        string appType,
        string errorCode) =>
        new(
            AgentType.CcSwitch,
            $"{appType}:ownership",
            databasePath,
            errorCode == "CCSWITCH_SCHEMA_UNSUPPORTED" ? RouteStatus.Unsupported : RouteStatus.Error,
            null,
            null,
            null,
            errorCode,
            $"CC Switch ownership for {appType} could not be reconciled safely.");

    private static AgentConfigAttachmentItem CreateAppErrorItem(
        string databasePath,
        string appType,
        Exception exception) =>
        new(
            AgentType.CcSwitch,
            $"{appType}:ownership",
            databasePath,
            RouteStatus.Error,
            null,
            null,
            null,
            exception is ConfigMutationException mutation ? mutation.Code : "CCSWITCH_APP_RECONCILE_FAILED",
            $"CCSWITCH_APP_RECONCILE_FAILED: {exception.Message}");

    private async Task<ProfileAttachmentResult> AttachCcSwitchAppAsync(
        WindowsUserProfile profile,
        string databasePath,
        string backupRoot,
        CcSwitchDatabaseInspection inspection,
        CcSwitchAppModeStatus appMode,
        CancellationToken cancellationToken)
    {
        var items = new List<AgentConfigAttachmentItem>();
        var fileUpdates = new List<ConfigFileUpdateResult>();
        CcSwitchDatabaseUpdateResult? databaseUpdate = null;
        var modes = new[] { appMode };
        var modeByApp = modes.ToDictionary(item => item.AppType, StringComparer.Ordinal);
        var providerTargets = new Dictionary<(string AppType, string ProviderId), Uri>();
        var managedRoutes = new Dictionary<string, RouteRecord>(StringComparer.Ordinal);
        var routesToDelete = new Dictionary<string, RouteRecord>(StringComparer.Ordinal);
        var routeSnapshots = new Dictionary<RouteIdentity, RouteRecord?>();
        var providerMutations = new List<CcSwitchProviderMutation>();
        var endpointMutations = new List<CcSwitchEndpointMutation>();

        var appProviders = inspection.Providers.Where(item => item.AppType == appMode.AppType).ToArray();
        var appEndpoints = inspection.Endpoints.Where(item => item.AppType == appMode.AppType).ToArray();
        if (appMode.Mode == CcSwitchOperatingMode.Ordinary)
        {
            var currentProviders = appProviders.Where(item => item.IsCurrent).ToArray();
            if (currentProviders.Length != 1 || currentProviders[0].OriginalBaseUri is null)
            {
                items.Add(CreateAppBlockedItem(
                    databasePath,
                    appMode.AppType,
                    "CCSWITCH_CURRENT_PROVIDER_INVALID"));
                return new ProfileAttachmentResult(profile.Sid, CcSwitchManaged: true, items, modes);
            }
        }

        foreach (var provider in appProviders)
        {
            var identity = $"{provider.AppType}:{provider.ProviderId}";
            if (!CanMutate(modeByApp, provider.AppType))
            {
                items.Add(CreateModeBlockedItem(databasePath, identity, modeByApp.GetValueOrDefault(provider.AppType)));
                continue;
            }

            if (provider.OriginalBaseUri is null)
            {
                items.Add(new AgentConfigAttachmentItem(
                    AgentType.CcSwitch,
                    identity,
                    databasePath,
                    RouteStatus.Unsupported,
                    null,
                    null,
                    null,
                    provider.ErrorCode,
                    "The provider configuration format is unsupported and was not changed."));
                continue;
            }

            var decision = await ResolveRoutingDecisionAsync(
                profile.Sid,
                identity,
                provider.OriginalBaseUri,
                routeSnapshots,
                cancellationToken);
            providerTargets[(provider.AppType, provider.ProviderId)] = decision.TargetBaseUri;
            TrackRouteDecision(decision, managedRoutes, routesToDelete);

            if (!decision.Bypassed || decision.RouteToDelete is not null)
            {
                var transformed = CcSwitchSettingsTransformer.InjectBaseUrl(
                    provider.AppType,
                    provider.SettingsConfig,
                    decision.TargetBaseUri,
                    allowRemoteBaseUri: decision.Bypassed);
                if (transformed.Changed)
                {
                    providerMutations.Add(new CcSwitchProviderMutation(
                        provider.ProviderId,
                        provider.AppType,
                        provider.SettingsConfig,
                        transformed.SettingsConfig));
                }
            }

            if (decision.Bypassed)
            {
                items.Add(CreateBypassedItem(identity, databasePath, decision.OriginalBaseUri));
            }
        }

        foreach (var endpoint in appEndpoints)
        {
            var identity = $"{endpoint.AppType}:{endpoint.ProviderId}:endpoint:{endpoint.EndpointId}";
            if (!CanMutate(modeByApp, endpoint.AppType))
            {
                items.Add(CreateModeBlockedItem(databasePath, identity, modeByApp.GetValueOrDefault(endpoint.AppType)));
                continue;
            }

            if (endpoint.OriginalBaseUri is null)
            {
                items.Add(new AgentConfigAttachmentItem(
                    AgentType.CcSwitch,
                    identity,
                    databasePath,
                    RouteStatus.Unsupported,
                    null,
                    null,
                    null,
                    endpoint.ErrorCode,
                    "The provider endpoint URL is unsupported and was not changed."));
                continue;
            }

            var decision = await ResolveRoutingDecisionAsync(
                profile.Sid,
                identity,
                endpoint.OriginalBaseUri,
                routeSnapshots,
                cancellationToken);
            TrackRouteDecision(decision, managedRoutes, routesToDelete);
            var target = decision.TargetBaseUri.AbsoluteUri.TrimEnd('/');
            if (!string.Equals(endpoint.Url.TrimEnd('/'), target, StringComparison.Ordinal))
            {
                endpointMutations.Add(new CcSwitchEndpointMutation(
                    endpoint.EndpointId,
                    endpoint.ProviderId,
                    endpoint.AppType,
                    endpoint.Url,
                    target));
            }

            if (decision.Bypassed)
            {
                items.Add(CreateBypassedItem(identity, databasePath, decision.OriginalBaseUri));
            }
        }

        try
        {
            if (providerMutations.Count > 0 || endpointMutations.Count > 0)
            {
                databaseUpdate = await CcSwitchDatabaseAdapter.ApplyAsync(
                    databasePath,
                    providerMutations,
                    endpointMutations,
                    Path.Combine(backupRoot, profile.Sid, "cc-switch"),
                    cancellationToken);
            }

            foreach (var provider in appProviders.Where(item => item.IsCurrent && item.OriginalBaseUri is not null))
            {
                if (!modeByApp.TryGetValue(provider.AppType, out var mode)
                    || mode.Mode != CcSwitchOperatingMode.Ordinary
                    || !providerTargets.TryGetValue((provider.AppType, provider.ProviderId), out var target))
                {
                    continue;
                }

                var liveUpdate = await SyncCurrentProviderAsync(
                    profile,
                    provider.AppType,
                    target,
                    backupRoot,
                    allowRemoteBaseUri: _bypassPolicy.ShouldBypass(target),
                    cancellationToken);
                if (liveUpdate is not null)
                {
                    fileUpdates.Add(liveUpdate);
                }
            }

            foreach (var route in managedRoutes.Values)
            {
                var attached = route with { Status = RouteStatus.Attached, UpdatedAtUtc = DateTimeOffset.UtcNow };
                await _routeRegistry.UpsertAsync(attached, cancellationToken);
                items.Add(new AgentConfigAttachmentItem(
                    AgentType.CcSwitch,
                    attached.ProviderId,
                    databasePath,
                    RouteStatus.Attached,
                    attached.OriginalBaseUri,
                    attached.InjectedBaseUri,
                    databaseUpdate?.BackupPath,
                    null,
                    "CC Switch mapping attached."));
            }

            foreach (var route in routesToDelete.Values)
            {
                if (!await TryRetireRouteIfUnreferencedAsync(profile, route, databasePath, cancellationToken))
                {
                    items.Add(CreateRetirementDeferredItem(databasePath, route));
                }
            }

            var configurationIdentities = appProviders
                .Select(provider => $"{provider.AppType}:{provider.ProviderId}")
                .Concat(appEndpoints.Select(endpoint =>
                    $"{endpoint.AppType}:{endpoint.ProviderId}:endpoint:{endpoint.EndpointId}"))
                .ToHashSet(StringComparer.Ordinal);
            var directAgentType = appMode.AppType == "claude"
                ? AgentType.ClaudeCode
                : AgentType.CodexCli;
            var orphanRoutes = (await _routeRegistry.ListAsync(cancellationToken))
                .Where(route => string.Equals(route.UserSid, profile.Sid, StringComparison.Ordinal)
                    && ((route.AgentType == AgentType.CcSwitch
                            && route.ProviderId.StartsWith($"{appMode.AppType}:", StringComparison.Ordinal)
                            && !configurationIdentities.Contains(route.ProviderId))
                        || (route.AgentType == directAgentType
                            && string.Equals(route.ProviderId, "direct", StringComparison.Ordinal))))
                .ToArray();
            foreach (var orphanRoute in orphanRoutes)
            {
                if (!await TryRetireRouteIfUnreferencedAsync(
                        profile,
                        orphanRoute,
                        databasePath,
                        cancellationToken,
                        requireMissingConfigurationIdentity: orphanRoute.AgentType == AgentType.CcSwitch))
                {
                    items.Add(CreateOrphanRetirementDeferredItem(databasePath, orphanRoute));
                }
            }
        }
        catch
        {
            RestoreFileUpdates(fileUpdates);
            if (databaseUpdate is not null)
            {
                await CcSwitchDatabaseAdapter.RestoreAsync(databasePath, databaseUpdate.BackupPath, CancellationToken.None);
            }

            await RestoreRouteSnapshotsAsync(routeSnapshots, CancellationToken.None);

            throw;
        }

        return new ProfileAttachmentResult(profile.Sid, CcSwitchManaged: true, items, modes);
    }

    private async Task<ProfileAttachmentResult> DetachMixedProfileAsync(
        WindowsUserProfile profile,
        string databasePath,
        IReadOnlyList<RouteRecord> routes,
        string backupRoot,
        CancellationToken cancellationToken)
    {
        var inspection = await CcSwitchDatabaseAdapter.InspectAsync(databasePath, cancellationToken);
        if (!inspection.ProviderSchemaSupported
            || !inspection.ProxySchemaSupported
            || !inspection.EndpointSchemaSupported)
        {
            throw new ConfigMutationException(
                "CCSWITCH_SCHEMA_UNSUPPORTED",
                "CC Switch configuration cannot be detached because its database schema is unsupported.");
        }

        var modes = await DetectCcSwitchModesAsync(profile, inspection, cancellationToken);
        var modeByApp = modes.ToDictionary(item => item.AppType, StringComparer.Ordinal);
        var items = new List<AgentConfigAttachmentItem>();
        var errors = new List<Exception>();
        var ccSwitchManaged = false;
        foreach (var appType in SupportedAppTypes)
        {
            var hasMappings = inspection.Providers.Any(item => item.AppType == appType)
                || inspection.Endpoints.Any(item => item.AppType == appType);
            if (!hasMappings)
            {
                continue;
            }

            ccSwitchManaged = true;
            var directAgentType = appType == "claude" ? AgentType.ClaudeCode : AgentType.CodexCli;
            var appRoutes = routes
                .Where(route => (route.AgentType == AgentType.CcSwitch
                        && route.ProviderId.StartsWith($"{appType}:", StringComparison.Ordinal))
                    || (route.AgentType == directAgentType && route.ProviderId == "direct"))
                .ToArray();
            if (appRoutes.Length == 0)
            {
                continue;
            }

            var mode = modeByApp.GetValueOrDefault(appType)
                ?? CcSwitchModeDetector.Detect(
                    appType,
                    inspection,
                    await InspectLiveBaseUriAsync(profile, appType, cancellationToken));
            try
            {
                var result = await DetachCcSwitchAppAsync(
                    profile,
                    databasePath,
                    appRoutes,
                    backupRoot,
                    inspection,
                    mode,
                    cancellationToken);
                items.AddRange(result.Items);
            }
            catch (Exception exception) when (exception is ConfigMutationException
                or IOException
                or UnauthorizedAccessException
                or SqliteException)
            {
                errors.Add(exception);
            }
        }

        foreach (var route in routes.Where(route => route.ProviderId == "direct"))
        {
            var appType = route.AgentType == AgentType.ClaudeCode ? "claude" : "codex";
            var path = appType == "claude"
                ? Path.Combine(profile.ProfilePath, ".claude", "settings.json")
                : Path.Combine(profile.ProfilePath, ".codex", "config.toml");
            try
            {
                var live = await TryInspectLiveBaseUriAsync(profile, appType, cancellationToken);
                ConfigFileUpdateResult? update = null;
                if (live.Success && live.BaseUri is not null && SameBaseUri(live.BaseUri, route.InjectedBaseUri))
                {
                    update = await RestoreFileIfOwnedAsync(route, path, backupRoot, cancellationToken);
                    await _routeRegistry.DeleteByIdentityAsync(
                        route.UserSid,
                        route.AgentType,
                        route.ProviderId,
                        cancellationToken);
                }
                else if (!live.Success
                    || !await TryRetireRouteIfUnreferencedAsync(profile, route, databasePath, cancellationToken))
                {
                    throw new ConfigMutationException(
                        "ROUTE_RETIREMENT_DEFERRED",
                        $"Direct Route '{route.ProviderId}' is no longer owned by a safely inspectable Live Config.");
                }

                items.Add(new AgentConfigAttachmentItem(
                    route.AgentType,
                    route.ProviderId,
                    path,
                    RouteStatus.Discovered,
                    route.OriginalBaseUri,
                    route.InjectedBaseUri,
                    update?.BackupPath,
                    null,
                    update is null ? "Stale direct Route detached." : "BaseURL detached."));
            }
            catch (Exception exception) when (exception is ConfigMutationException
                or IOException
                or UnauthorizedAccessException)
            {
                errors.Add(exception);
            }
        }

        if (errors.Count > 0)
        {
            throw new ConfigMutationException(
                "DETACH_PARTIAL_FAILURE",
                $"Detach completed with {errors.Count} application error(s): {string.Join("; ", errors.Select(item => item.Message))}",
                new AggregateException(errors));
        }

        return new ProfileAttachmentResult(
            profile.Sid,
            CcSwitchManaged: ccSwitchManaged,
            items,
            modes);
    }

    private async Task<ProfileAttachmentResult> DetachCcSwitchAppAsync(
        WindowsUserProfile profile,
        string databasePath,
        IReadOnlyList<RouteRecord> routes,
        string backupRoot,
        CcSwitchDatabaseInspection inspection,
        CcSwitchAppModeStatus appMode,
        CancellationToken cancellationToken)
    {
        var modes = new[] { appMode };
        var modeByApp = modes.ToDictionary(item => item.AppType, StringComparer.Ordinal);
        if (appMode.Mode is CcSwitchOperatingMode.Inconsistent or CcSwitchOperatingMode.Unsupported)
        {
            throw new ConfigMutationException(
                "CCSWITCH_PROXY_STATE_INCONSISTENT",
                "CC Switch configuration cannot be detached while its proxy state is inconsistent or unsupported.");
        }

        var providerMutations = new List<CcSwitchProviderMutation>();
        var endpointMutations = new List<CcSwitchEndpointMutation>();
        var restoredRoutes = new Dictionary<string, RouteRecord>(StringComparer.Ordinal);
        var appProviders = inspection.Providers.Where(item => item.AppType == appMode.AppType).ToArray();
        var appEndpoints = inspection.Endpoints.Where(item => item.AppType == appMode.AppType).ToArray();
        foreach (var provider in appProviders.Where(item => item.OriginalBaseUri is not null))
        {
            var identity = $"{provider.AppType}:{provider.ProviderId}";
            var route = routes.FirstOrDefault(candidate =>
                    candidate.AgentType == AgentType.CcSwitch
                    && string.Equals(candidate.ProviderId, identity, StringComparison.Ordinal))
                ?? routes.FirstOrDefault(candidate => SameBaseUri(provider.OriginalBaseUri!, candidate.InjectedBaseUri));
            if (route is null || !SameBaseUri(provider.OriginalBaseUri!, route.InjectedBaseUri))
            {
                continue;
            }

            var transformed = CcSwitchSettingsTransformer.InjectBaseUrl(
                provider.AppType,
                provider.SettingsConfig,
                route.OriginalBaseUri,
                allowRemoteBaseUri: true);
            if (transformed.Changed)
            {
                providerMutations.Add(new CcSwitchProviderMutation(
                    provider.ProviderId,
                    provider.AppType,
                    provider.SettingsConfig,
                    transformed.SettingsConfig));
            }

            restoredRoutes[identity] = route;
        }

        foreach (var endpoint in appEndpoints.Where(item => item.OriginalBaseUri is not null))
        {
            var identity = $"{endpoint.AppType}:{endpoint.ProviderId}:endpoint:{endpoint.EndpointId}";
            var route = routes.FirstOrDefault(candidate =>
                    candidate.AgentType == AgentType.CcSwitch
                    && string.Equals(candidate.ProviderId, identity, StringComparison.Ordinal))
                ?? routes.FirstOrDefault(candidate => SameBaseUri(endpoint.OriginalBaseUri!, candidate.InjectedBaseUri));
            if (route is null || !SameBaseUri(endpoint.OriginalBaseUri!, route.InjectedBaseUri))
            {
                continue;
            }

            endpointMutations.Add(new CcSwitchEndpointMutation(
                endpoint.EndpointId,
                endpoint.ProviderId,
                endpoint.AppType,
                endpoint.Url,
                route.OriginalBaseUri.AbsoluteUri.TrimEnd('/')));
            restoredRoutes[identity] = route;
        }

        CcSwitchDatabaseUpdateResult? databaseUpdate = null;
        var fileUpdates = new List<ConfigFileUpdateResult>();
        try
        {
            if (providerMutations.Count > 0 || endpointMutations.Count > 0)
            {
                databaseUpdate = await CcSwitchDatabaseAdapter.ApplyAsync(
                    databasePath,
                    providerMutations,
                    endpointMutations,
                    Path.Combine(backupRoot, profile.Sid, "cc-switch-detach"),
                    cancellationToken);
            }

            foreach (var provider in appProviders.Where(item => item.IsCurrent))
            {
                if (!modeByApp.TryGetValue(provider.AppType, out var mode)
                    || mode.Mode != CcSwitchOperatingMode.Ordinary
                    || !restoredRoutes.TryGetValue($"{provider.AppType}:{provider.ProviderId}", out var route))
                {
                    continue;
                }

                var update = await SyncCurrentProviderAsync(
                    profile,
                    provider.AppType,
                    route.OriginalBaseUri,
                    backupRoot,
                    allowRemoteBaseUri: true,
                    cancellationToken);
                if (update is not null)
                {
                    fileUpdates.Add(update);
                }
            }

            foreach (var route in restoredRoutes.Values.DistinctBy(item => item.RouteId))
            {
                if (!await TryRetireRouteIfUnreferencedAsync(profile, route, databasePath, cancellationToken))
                {
                    throw new ConfigMutationException(
                        "ROUTE_RETIREMENT_DEFERRED",
                        $"CC Switch Route '{route.ProviderId}' is still referenced or could not be inspected safely.");
                }
            }
        }
        catch
        {
            RestoreFileUpdates(fileUpdates);
            if (databaseUpdate is not null)
            {
                await CcSwitchDatabaseAdapter.RestoreAsync(databasePath, databaseUpdate.BackupPath, CancellationToken.None);
            }

            var routeSnapshots = restoredRoutes.Values.DistinctBy(item => item.RouteId).ToDictionary(
                route => new RouteIdentity(route.UserSid, route.AgentType, route.ProviderId),
                route => (RouteRecord?)route);
            await RestoreRouteSnapshotsAsync(routeSnapshots, CancellationToken.None);

            throw;
        }

        var items = restoredRoutes.Values.DistinctBy(item => item.RouteId).Select(route => new AgentConfigAttachmentItem(
            AgentType.CcSwitch,
            route.ProviderId,
            databasePath,
            RouteStatus.Discovered,
            route.OriginalBaseUri,
            route.InjectedBaseUri,
            databaseUpdate?.BackupPath,
            null,
            "CC Switch mapping detached."))
            .ToArray();
        return new ProfileAttachmentResult(profile.Sid, CcSwitchManaged: true, items, modes);
    }

    private async Task<AgentConfigAttachmentItem> AttachDirectFileAsync(
        WindowsUserProfile profile,
        AgentType agentType,
        string providerId,
        string configPath,
        string backupRoot,
        Func<ReadOnlyMemory<byte>, Uri, ConfigTransformResult> transform,
        Uri defaultOriginalBaseUri,
        CancellationToken cancellationToken)
    {
        var existingContent = await File.ReadAllBytesAsync(configPath, cancellationToken);
        var inspection = transform(existingContent, InspectionUri);
        var configuredBaseUri = string.IsNullOrWhiteSpace(inspection.PreviousValue)
            ? defaultOriginalBaseUri
            : new Uri(inspection.PreviousValue, UriKind.Absolute);
        if (IsPrototypeDirectGateway(configuredBaseUri))
        {
            configuredBaseUri = await RecoverOriginalBaseUriAsync(
                profile,
                agentType,
                backupRoot,
                transform,
                cancellationToken)
                ?? (agentType == AgentType.ClaudeCode
                    || (agentType == AgentType.CodexCli && CodexSettingsTransformer.UsesBuiltInOpenAiProvider(existingContent.AsSpan()))
                        ? defaultOriginalBaseUri
                        : throw new ConfigMutationException(
                            "ORIGINAL_BASE_URL_RECOVERY_REQUIRED",
                            "The original Codex custom Provider BaseURL could not be recovered from the 0.1.3 backup."));
        }

        var referencedRoute = await TryResolveExistingLocalRouteAsync(configuredBaseUri, cancellationToken);
        var originalBaseUri = referencedRoute?.OriginalBaseUri ?? configuredBaseUri;
        if (_bypassPolicy.ShouldBypass(originalBaseUri))
        {
            ConfigFileUpdateResult? bypassUpdate = null;
            if (referencedRoute is not null)
            {
                var restored = agentType == AgentType.ClaudeCode
                    ? ClaudeSettingsTransformer.InjectBaseUrl(existingContent.AsSpan(), originalBaseUri, allowRemoteBaseUri: true)
                    : CodexSettingsTransformer.InjectBaseUrl(existingContent.AsSpan(), originalBaseUri, allowRemoteBaseUri: true);
                if (restored.Changed)
                {
                    bypassUpdate = await AtomicConfigFileUpdater.ApplyAsync(
                        configPath,
                        existingContent,
                        restored.Content,
                        Path.Combine(backupRoot, profile.Sid, $"{agentType}-allowlist"),
                        cancellationToken);
                }

                await TryRetireRouteIfUnreferencedAsync(profile, referencedRoute, null, cancellationToken);
            }

            return new AgentConfigAttachmentItem(
                agentType,
                providerId,
                configPath,
                RouteStatus.Bypassed,
                originalBaseUri,
                null,
                bypassUpdate?.BackupPath,
                BaseUrlBypassPolicy.BypassCode,
                "BaseURL is allowlisted and bypasses the endpoint proxy.");
        }

        var routeSnapshots = new Dictionary<RouteIdentity, RouteRecord?>();
        await CaptureRouteSnapshotAsync(
            routeSnapshots,
            profile.Sid,
            agentType,
            providerId,
            cancellationToken);
        ConfigFileUpdateResult? update = null;
        try
        {
            var route = referencedRoute is not null
                && SameRouteIdentity(referencedRoute, profile.Sid, agentType, providerId)
                    ? referencedRoute
                    : await _routeProvisioner.EnsureAsync(
                        profile.Sid,
                        agentType,
                        providerId,
                        originalBaseUri,
                        cancellationToken);
            var transformed = transform(existingContent, route.InjectedBaseUri);
            if (transformed.Changed)
            {
                update = await AtomicConfigFileUpdater.ApplyAsync(
                    configPath,
                    existingContent,
                    transformed.Content,
                    Path.Combine(backupRoot, profile.Sid, agentType.ToString()),
                    cancellationToken);
            }

            var attached = route with { Status = RouteStatus.Attached, UpdatedAtUtc = DateTimeOffset.UtcNow };
            await _routeRegistry.UpsertAsync(attached, cancellationToken);
            var retirementDeferred = referencedRoute is not null
                && !SameRouteIdentity(referencedRoute, profile.Sid, agentType, providerId)
                && !await TryRetireRouteIfUnreferencedAsync(profile, referencedRoute, null, cancellationToken);
            return new AgentConfigAttachmentItem(
                agentType,
                providerId,
                configPath,
                RouteStatus.Attached,
                attached.OriginalBaseUri,
                attached.InjectedBaseUri,
                update?.BackupPath,
                retirementDeferred ? "ROUTE_RETIREMENT_DEFERRED" : null,
                retirementDeferred
                    ? "BaseURL attached; the previous Route is still referenced or could not be inspected safely."
                    : referencedRoute is not null && !SameRouteIdentity(referencedRoute, profile.Sid, agentType, providerId)
                        ? "ROUTE_OWNERSHIP_HANDOFF_COMPLETED: BaseURL attached to the direct Route identity."
                        : transformed.Changed ? "BaseURL attached." : "Already attached.");
        }
        catch
        {
            if (update is not null)
            {
                RestoreFileUpdates([update]);
            }

            await RestoreRouteSnapshotsAsync(routeSnapshots, CancellationToken.None);
            throw;
        }
    }

    private async Task<RoutingDecision> ResolveRoutingDecisionAsync(
        string userSid,
        string identity,
        Uri configuredBaseUri,
        Dictionary<RouteIdentity, RouteRecord?> routeSnapshots,
        CancellationToken cancellationToken)
    {
        var existingRoute = await TryResolveExistingLocalRouteAsync(configuredBaseUri, cancellationToken);
        var originalBaseUri = existingRoute?.OriginalBaseUri ?? configuredBaseUri;
        if (_bypassPolicy.ShouldBypass(originalBaseUri))
        {
            return new RoutingDecision(originalBaseUri, originalBaseUri, null, existingRoute, Bypassed: true);
        }

        await CaptureRouteSnapshotAsync(
            routeSnapshots,
            userSid,
            AgentType.CcSwitch,
            identity,
            cancellationToken);
        var route = existingRoute is not null
            && SameRouteIdentity(existingRoute, userSid, AgentType.CcSwitch, identity)
                ? existingRoute
                : await _routeProvisioner.EnsureAsync(
                    userSid,
                    AgentType.CcSwitch,
                    identity,
                    originalBaseUri,
                    cancellationToken);
        var routeToDelete = existingRoute is not null
            && !SameRouteIdentity(existingRoute, userSid, AgentType.CcSwitch, identity)
                ? existingRoute
                : null;
        return new RoutingDecision(originalBaseUri, route.InjectedBaseUri, route, routeToDelete, Bypassed: false);
    }

    private async Task CaptureRouteSnapshotAsync(
        Dictionary<RouteIdentity, RouteRecord?> snapshots,
        string userSid,
        AgentType agentType,
        string providerId,
        CancellationToken cancellationToken)
    {
        var identity = new RouteIdentity(userSid, agentType, providerId);
        if (!snapshots.ContainsKey(identity))
        {
            snapshots[identity] = await _routeRegistry.FindByIdentityAsync(
                userSid,
                agentType,
                providerId,
                cancellationToken);
        }
    }

    private async Task RestoreRouteSnapshotsAsync(
        IReadOnlyDictionary<RouteIdentity, RouteRecord?> snapshots,
        CancellationToken cancellationToken)
    {
        try
        {
            foreach (var snapshot in snapshots.Reverse())
            {
                if (snapshot.Value is null)
                {
                    await _routeRegistry.DeleteByIdentityAsync(
                        snapshot.Key.UserSid,
                        snapshot.Key.AgentType,
                        snapshot.Key.ProviderId,
                        cancellationToken);
                }
                else
                {
                    await _routeRegistry.UpsertAsync(snapshot.Value, cancellationToken);
                }
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or SqliteException)
        {
            throw new ConfigMutationException(
                "ROUTE_REGISTRY_ROLLBACK_FAILED",
                "Route Registry rollback failed after an application reconciliation error.",
                exception);
        }
    }

    private static void TrackRouteDecision(
        RoutingDecision decision,
        Dictionary<string, RouteRecord> managedRoutes,
        Dictionary<string, RouteRecord> routesToDelete)
    {
        if (decision.ManagedRoute is not null)
        {
            managedRoutes[decision.ManagedRoute.ProviderId] = decision.ManagedRoute;
        }

        if (decision.RouteToDelete is not null)
        {
            routesToDelete[decision.RouteToDelete.RouteId] = decision.RouteToDelete;
        }
    }

    private static bool CanMutate(
        Dictionary<string, CcSwitchAppModeStatus> modes,
        string appType) =>
        modes.TryGetValue(appType, out var mode)
        && mode.Mode is CcSwitchOperatingMode.Ordinary or CcSwitchOperatingMode.LocalProxy;

    private static AgentConfigAttachmentItem CreateModeBlockedItem(
        string databasePath,
        string identity,
        CcSwitchAppModeStatus? mode) =>
        new(
            AgentType.CcSwitch,
            identity,
            databasePath,
            mode?.Mode == CcSwitchOperatingMode.Unsupported ? RouteStatus.Unsupported : RouteStatus.Error,
            null,
            null,
            null,
            mode?.ErrorCode ?? "CCSWITCH_PROXY_STATE_INCONSISTENT",
            "The CC Switch application mode is not safe to mutate.");

    private static AgentConfigAttachmentItem CreateBypassedItem(
        string identity,
        string databasePath,
        Uri originalBaseUri) =>
        new(
            AgentType.CcSwitch,
            identity,
            databasePath,
            RouteStatus.Bypassed,
            originalBaseUri,
            null,
            null,
            BaseUrlBypassPolicy.BypassCode,
            "CC Switch address is allowlisted and was not proxied.");

    private static AgentConfigAttachmentItem CreateRetirementDeferredItem(
        string configPath,
        RouteRecord route) =>
        new(
            route.AgentType,
            route.ProviderId,
            configPath,
            RouteStatus.Pending,
            route.OriginalBaseUri,
            route.InjectedBaseUri,
            null,
            "ROUTE_RETIREMENT_DEFERRED",
            "The previous Route is still referenced or its references could not be inspected safely.");

    private static AgentConfigAttachmentItem CreateOrphanRetirementDeferredItem(
        string configPath,
        RouteRecord route) =>
        new(
            route.AgentType,
            route.ProviderId,
            configPath,
            RouteStatus.Pending,
            route.OriginalBaseUri,
            route.InjectedBaseUri,
            null,
            "ORPHAN_ROUTE_RETIREMENT_DEFERRED",
            "The orphan Route is hidden from inventory but remains referenced or could not be verified safely.");

    private static async Task<IReadOnlyList<CcSwitchAppModeStatus>> DetectCcSwitchModesAsync(
        WindowsUserProfile profile,
        CcSwitchDatabaseInspection inspection,
        CancellationToken cancellationToken)
    {
        var appTypes = inspection.Providers.Select(item => item.AppType)
            .Concat(inspection.Endpoints.Select(item => item.AppType))
            .Concat(inspection.ProxyConfigs.Keys)
            .Where(item => item is "claude" or "codex")
            .Distinct(StringComparer.Ordinal)
            .OrderBy(item => item, StringComparer.Ordinal)
            .ToArray();
        var result = new List<CcSwitchAppModeStatus>(appTypes.Length);
        foreach (var appType in appTypes)
        {
            var liveBaseUri = await InspectLiveBaseUriAsync(profile, appType, cancellationToken);
            result.Add(CcSwitchModeDetector.Detect(appType, inspection, liveBaseUri));
        }

        return result;
    }

    private static async Task<Uri?> InspectLiveBaseUriAsync(
        WindowsUserProfile profile,
        string appType,
        CancellationToken cancellationToken)
    {
        var path = appType switch
        {
            "claude" => Path.Combine(profile.ProfilePath, ".claude", "settings.json"),
            "codex" => Path.Combine(profile.ProfilePath, ".codex", "config.toml"),
            _ => null,
        };
        if (path is null || !File.Exists(path))
        {
            return null;
        }

        try
        {
            var content = await File.ReadAllBytesAsync(path, cancellationToken);
            var inspected = appType == "claude"
                ? ClaudeSettingsTransformer.InjectBaseUrl(content, InspectionUri)
                : CodexSettingsTransformer.InjectBaseUrl(content, InspectionUri);
            return Uri.TryCreate(inspected.PreviousValue, UriKind.Absolute, out var value) ? value : null;
        }
        catch (ConfigMutationException)
        {
            return null;
        }
    }

    private async Task<bool> TryRetireRouteIfUnreferencedAsync(
        WindowsUserProfile profile,
        RouteRecord route,
        string? databasePath,
        CancellationToken cancellationToken,
        bool requireMissingConfigurationIdentity = false)
    {
        try
        {
            var ownerAppType = route.AgentType switch
            {
                AgentType.ClaudeCode => "claude",
                AgentType.CodexCli => "codex",
                AgentType.CcSwitch => route.ProviderId.Split(':', 2)[0],
                _ => null,
            };
            if (ownerAppType is not "claude" and not "codex")
            {
                return false;
            }

            var ownerInspected = false;
            foreach (var appType in SupportedAppTypes)
            {
                var path = appType == "claude"
                    ? Path.Combine(profile.ProfilePath, ".claude", "settings.json")
                    : Path.Combine(profile.ProfilePath, ".codex", "config.toml");
                if (!File.Exists(path))
                {
                    continue;
                }

                var live = await TryInspectLiveBaseUriAsync(profile, appType, cancellationToken);
                if (!live.Success)
                {
                    return false;
                }

                ownerInspected |= appType == ownerAppType;
                if (live.BaseUri is not null && SameBaseUri(live.BaseUri, route.InjectedBaseUri))
                {
                    return false;
                }
            }

            if (!ownerInspected)
            {
                return false;
            }

            var resolvedDatabasePath = databasePath
                ?? Path.Combine(profile.ProfilePath, ".cc-switch", "cc-switch.db");
            if (File.Exists(resolvedDatabasePath))
            {
                var inspection = await CcSwitchDatabaseAdapter.InspectAsync(resolvedDatabasePath, cancellationToken);
                if (!inspection.ProviderSchemaSupported
                    || !inspection.ProxySchemaSupported
                    || !inspection.EndpointSchemaSupported)
                {
                    return false;
                }

                if (requireMissingConfigurationIdentity
                    && CcSwitchConfigurationIdentityExists(inspection, route.ProviderId))
                {
                    return false;
                }

                if (inspection.Providers.Any(item => item.OriginalBaseUri is not null
                        && SameBaseUri(item.OriginalBaseUri, route.InjectedBaseUri))
                    || inspection.Endpoints.Any(item => item.OriginalBaseUri is not null
                        && SameBaseUri(item.OriginalBaseUri, route.InjectedBaseUri)))
                {
                    return false;
                }
            }

            await _routeRegistry.DeleteByIdentityAsync(
                route.UserSid,
                route.AgentType,
                route.ProviderId,
                cancellationToken);
            return true;
        }
        catch (Exception exception) when (exception is ConfigMutationException
            or IOException
            or UnauthorizedAccessException
            or SqliteException)
        {
            return false;
        }
    }

    private static bool CcSwitchConfigurationIdentityExists(
        CcSwitchDatabaseInspection inspection,
        string routeProviderId)
    {
        var segments = routeProviderId.Split(':');
        if (segments.Length < 2)
        {
            return true;
        }

        var appType = segments[0];
        var providerId = segments[1];
        if (segments.Length >= 4 && string.Equals(segments[2], "endpoint", StringComparison.Ordinal))
        {
            return long.TryParse(
                    segments[3],
                    System.Globalization.NumberStyles.None,
                    System.Globalization.CultureInfo.InvariantCulture,
                    out var endpointId)
                && inspection.Endpoints.Any(item => item.AppType == appType
                    && item.ProviderId == providerId
                    && item.EndpointId == endpointId);
        }

        return inspection.Providers.Any(item => item.AppType == appType
            && item.ProviderId == providerId);
    }

    private static async Task<LiveBaseUriInspection> TryInspectLiveBaseUriAsync(
        WindowsUserProfile profile,
        string appType,
        CancellationToken cancellationToken)
    {
        var path = appType == "claude"
            ? Path.Combine(profile.ProfilePath, ".claude", "settings.json")
            : Path.Combine(profile.ProfilePath, ".codex", "config.toml");
        if (!File.Exists(path))
        {
            return new LiveBaseUriInspection(false, null);
        }

        try
        {
            var content = await File.ReadAllBytesAsync(path, cancellationToken);
            var inspected = appType == "claude"
                ? ClaudeSettingsTransformer.InjectBaseUrl(content, InspectionUri)
                : CodexSettingsTransformer.InjectBaseUrl(content, InspectionUri);
            return Uri.TryCreate(inspected.PreviousValue, UriKind.Absolute, out var value)
                ? new LiveBaseUriInspection(true, value)
                : new LiveBaseUriInspection(false, null);
        }
        catch (ConfigMutationException)
        {
            return new LiveBaseUriInspection(false, null);
        }
    }

    private static async Task<ConfigFileUpdateResult?> SyncCurrentProviderAsync(
        WindowsUserProfile profile,
        string appType,
        Uri targetBaseUri,
        string backupRoot,
        bool allowRemoteBaseUri,
        CancellationToken cancellationToken)
    {
        string path;
        Func<ReadOnlyMemory<byte>, ConfigTransformResult> transform;
        switch (appType)
        {
            case "claude":
                path = Path.Combine(profile.ProfilePath, ".claude", "settings.json");
                transform = content => ClaudeSettingsTransformer.InjectBaseUrl(
                    content.Span,
                    targetBaseUri,
                    allowRemoteBaseUri);
                break;
            case "codex":
                path = Path.Combine(profile.ProfilePath, ".codex", "config.toml");
                transform = content => CodexSettingsTransformer.InjectBaseUrl(
                    content.Span,
                    targetBaseUri,
                    allowRemoteBaseUri);
                break;
            default:
                return null;
        }

        var existing = File.Exists(path)
            ? await File.ReadAllBytesAsync(path, cancellationToken)
            : [];
        var current = appType == "claude"
            ? ClaudeSettingsTransformer.InjectBaseUrl(existing.AsSpan(), InspectionUri)
            : CodexSettingsTransformer.InjectBaseUrl(existing.AsSpan(), InspectionUri);
        if (Uri.TryCreate(current.PreviousValue, UriKind.Absolute, out var currentBaseUri)
            && SameBaseUri(currentBaseUri, targetBaseUri))
        {
            return null;
        }

        var transformed = transform(existing);
        if (!transformed.Changed)
        {
            return null;
        }

        return await AtomicConfigFileUpdater.ApplyAsync(
            path,
            existing,
            transformed.Content,
            Path.Combine(backupRoot, profile.Sid, "cc-switch-live"),
            cancellationToken);
    }

    private async Task<RouteRecord?> TryResolveExistingLocalRouteAsync(
        Uri configuredBaseUri,
        CancellationToken cancellationToken)
    {
        if (!configuredBaseUri.IsLoopback
            || !string.Equals(configuredBaseUri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var segments = configuredBaseUri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length != 2 || !string.Equals(segments[0], "r", StringComparison.Ordinal))
        {
            throw new ConfigMutationException(
                "LOCAL_ROUTE_UNRECOGNIZED",
                "The existing loopback BaseURL is not owned by this endpoint proxy.");
        }

        return await _routeRegistry.FindAsync(segments[1], cancellationToken)
            ?? throw new ConfigMutationException(
                "ORIGINAL_BASE_URL_RECOVERY_REQUIRED",
                "The existing local route is missing from the route registry, so its original BaseURL cannot be recovered.");
    }

    private static async Task<ConfigFileUpdateResult?> RestoreFileIfOwnedAsync(
        RouteRecord route,
        string configPath,
        string backupRoot,
        CancellationToken cancellationToken)
    {
        var content = await File.ReadAllBytesAsync(configPath, cancellationToken);
        ConfigTransformResult inspection;
        ConfigTransformResult restored;
        if (route.AgentType == AgentType.ClaudeCode)
        {
            inspection = ClaudeSettingsTransformer.InjectBaseUrl(content, InspectionUri);
            restored = ClaudeSettingsTransformer.InjectBaseUrl(content, route.OriginalBaseUri, allowRemoteBaseUri: true);
        }
        else
        {
            inspection = CodexSettingsTransformer.InjectBaseUrl(content, InspectionUri);
            restored = CodexSettingsTransformer.InjectBaseUrl(content, route.OriginalBaseUri, allowRemoteBaseUri: true);
        }

        if (!Uri.TryCreate(inspection.PreviousValue, UriKind.Absolute, out var current)
            || !SameBaseUri(current, route.InjectedBaseUri))
        {
            throw new ConfigMutationException(
                "DETACH_CONFIG_CHANGED",
                $"Configuration '{configPath}' no longer points to its managed local route.");
        }

        return restored.Changed
            ? await AtomicConfigFileUpdater.ApplyAsync(
                configPath,
                content,
                restored.Content,
                Path.Combine(backupRoot, route.UserSid, "detach"),
                cancellationToken)
            : null;
    }

    private static void RestoreFileUpdates(IEnumerable<ConfigFileUpdateResult> updates)
    {
        foreach (var update in updates.Reverse())
        {
            if (update.Created)
            {
                File.Delete(update.TargetPath);
            }
            else if (update.BackupPath is not null)
            {
                AtomicConfigFileUpdater.Restore(update.TargetPath, update.BackupPath);
            }
        }
    }

    private static bool SameBaseUri(Uri left, Uri right) => string.Equals(
        left.AbsoluteUri.TrimEnd('/'),
        right.AbsoluteUri.TrimEnd('/'),
        StringComparison.Ordinal);

    private static bool SameRouteIdentity(
        RouteRecord route,
        string userSid,
        AgentType agentType,
        string providerId) =>
        string.Equals(route.UserSid, userSid, StringComparison.Ordinal)
        && route.AgentType == agentType
        && string.Equals(route.ProviderId, providerId, StringComparison.Ordinal);

    private static bool IsPrototypeDirectGateway(Uri value) => string.Equals(
        value.AbsoluteUri.TrimEnd('/'),
        PrototypeDirectGatewayUri.AbsoluteUri.TrimEnd('/'),
        StringComparison.OrdinalIgnoreCase);

    private static async Task<Uri?> RecoverOriginalBaseUriAsync(
        WindowsUserProfile profile,
        AgentType agentType,
        string backupRoot,
        Func<ReadOnlyMemory<byte>, Uri, ConfigTransformResult> transform,
        CancellationToken cancellationToken)
    {
        var directory = Path.Combine(backupRoot, profile.Sid, $"{agentType}-direct-gateway");
        if (!Directory.Exists(directory))
        {
            return null;
        }

        foreach (var backupPath in Directory
            .EnumerateFiles(directory, "*.bak", SearchOption.TopDirectoryOnly)
            .OrderByDescending(File.GetLastWriteTimeUtc))
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var content = await File.ReadAllBytesAsync(backupPath, cancellationToken);
                var inspection = transform(content, InspectionUri);
                if (Uri.TryCreate(inspection.PreviousValue, UriKind.Absolute, out var recovered)
                    && !IsPrototypeDirectGateway(recovered))
                {
                    return recovered;
                }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ConfigMutationException)
            {
                // Try the next older atomic backup.
            }
        }

        return null;
    }

    private sealed record RoutingDecision(
        Uri OriginalBaseUri,
        Uri TargetBaseUri,
        RouteRecord? ManagedRoute,
        RouteRecord? RouteToDelete,
        bool Bypassed);

    private sealed record LiveBaseUriInspection(bool Success, Uri? BaseUri);

    private sealed record RouteIdentity(string UserSid, AgentType AgentType, string ProviderId);
}
