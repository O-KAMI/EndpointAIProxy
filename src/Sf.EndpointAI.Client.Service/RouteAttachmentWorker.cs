using Microsoft.Data.Sqlite;
using Sf.EndpointAI.Client.Core.Configuration;
using Sf.EndpointAI.Client.Core.Policy;
using Sf.EndpointAI.Client.Core.State;
using Sf.EndpointAI.Client.Core.Windows;
using Sf.EndpointAI.Contracts;

namespace Sf.EndpointAI.Client.Service;

public sealed record RouteAttachmentOptions(string BackupRoot, TimeSpan ReconcileInterval);

public sealed class RouteAttachmentWorker(
    IUserProfileProvider profileProvider,
    AgentConfigAttachmentCoordinator coordinator,
    CcSwitchModeState ccSwitchModeState,
    IPolicyProvider policyProvider,
    ClientOperationStateProvider operationStateProvider,
    RouteMutationGate mutationGate,
    RouteAttachmentOptions options,
    RouteReconciliationSignals reconciliationSignals,
    RouteReconciliationRuntimeState reconciliationRuntimeState,
    ILogger<RouteAttachmentWorker> logger) : BackgroundService
{
    private const int TransitionRereadCount = 3;
    private static readonly TimeSpan EventDebounce = TimeSpan.FromMilliseconds(500);
    private readonly Dictionary<string, FileSystemWatcher> _watchers = new(StringComparer.OrdinalIgnoreCase);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        EnsureWatchers();
        reconciliationSignals.Request(null, "startup");
        var periodicPump = PumpPeriodicSignalsAsync(stoppingToken);
        try
        {
            await foreach (var first in reconciliationSignals.Reader.ReadAllAsync(stoppingToken))
            {
                var batch = await ReadDebouncedBatchAsync(first, stoppingToken);
                EnsureWatchers();
                if (policyProvider.Current.Enabled
                    && operationStateProvider.Current.State == ClientOperationState.Enabled)
                {
                    await ReconcileAsync(batch, stoppingToken);
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Normal service shutdown.
        }
        finally
        {
            reconciliationSignals.Complete();
            foreach (var watcher in _watchers.Values)
            {
                watcher.Dispose();
            }

            _watchers.Clear();
            try
            {
                await periodicPump;
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                // Normal service shutdown.
            }
        }
    }

    public override void Dispose()
    {
        foreach (var watcher in _watchers.Values)
        {
            watcher.Dispose();
        }

        _watchers.Clear();
        base.Dispose();
    }

    private async Task PumpPeriodicSignalsAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(options.ReconcileInterval);
        while (await timer.WaitForNextTickAsync(cancellationToken))
        {
            reconciliationSignals.Request(null, "periodic");
        }
    }

    private async Task<IReadOnlyList<RouteReconciliationSignal>> ReadDebouncedBatchAsync(
        RouteReconciliationSignal first,
        CancellationToken cancellationToken)
    {
        var result = new List<RouteReconciliationSignal> { first };
        if (!string.Equals(first.Source, "startup", StringComparison.Ordinal))
        {
            await Task.Delay(EventDebounce, cancellationToken);
        }

        while (reconciliationSignals.Reader.TryRead(out var signal))
        {
            result.Add(signal);
        }

        return result;
    }

    private async Task ReconcileAsync(
        IReadOnlyList<RouteReconciliationSignal> signals,
        CancellationToken cancellationToken)
    {
        using (await mutationGate.EnterAsync(cancellationToken))
        {
            string? reconcileErrorCode = null;
            var reconcileAll = signals.Any(signal => signal.UserSid is null);
            var userSids = signals
                .Where(signal => signal.UserSid is not null)
                .Select(signal => signal.UserSid!)
                .ToHashSet(StringComparer.Ordinal);
            var trigger = string.Join(
                ',',
                signals.Select(signal => signal.Source).Distinct(StringComparer.Ordinal).OrderBy(value => value, StringComparer.Ordinal));

            foreach (var profile in profileProvider.GetProfiles())
            {
                if (!reconcileAll && !userSids.Contains(profile.Sid))
                {
                    continue;
                }

                try
                {
                    var (result, rereadCount) = await AttachWithTransitionRetryAsync(
                        profile,
                        trigger,
                        cancellationToken);
                    var previousModes = (result.CcSwitchApps ?? [])
                        .ToDictionary(
                            status => status.AppType,
                            status => ccSwitchModeState.Get(profile.Sid, status.AppType),
                            StringComparer.Ordinal);
                    ccSwitchModeState.Update(profile.Sid, result.CcSwitchApps ?? []);
                    LogResult(profile, result, previousModes, trigger, rereadCount);
                    reconcileErrorCode ??= result.Items
                        .FirstOrDefault(item => item.Status is RouteStatus.Error or RouteStatus.Pending)
                        ?.ErrorCode;
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception exception) when (exception is ConfigMutationException
                    or IOException
                    or UnauthorizedAccessException
                    or SqliteException)
                {
                    reconcileErrorCode ??= (exception as ConfigMutationException)?.Code
                        ?? exception.GetType().Name;
                    RouteAttachmentLog.ProfileReconciliationFailed(
                        logger,
                        profile.Sid,
                        (exception as ConfigMutationException)?.Code ?? exception.GetType().Name,
                        exception);
                }
            }

            reconciliationRuntimeState.Record(reconcileErrorCode);
        }
    }

    private async Task<(ProfileAttachmentResult Result, int RereadCount)> AttachWithTransitionRetryAsync(
        WindowsUserProfile profile,
        string trigger,
        CancellationToken cancellationToken)
    {
        for (var rereadCount = 0; ; rereadCount++)
        {
            try
            {
                var result = await coordinator.AttachAsync(profile, options.BackupRoot, cancellationToken);
                var inconsistentApps = (result.CcSwitchApps ?? [])
                    .Where(status => status.Mode == CcSwitchOperatingMode.Inconsistent)
                    .Select(status => status.AppType)
                    .ToArray();
                if (inconsistentApps.Length == 0)
                {
                    return (result, rereadCount);
                }

                if (rereadCount >= TransitionRereadCount)
                {
                    RouteAttachmentLog.ReconcileRetryExhausted(
                        logger,
                        profile.Sid,
                        string.Join(',', inconsistentApps),
                        trigger,
                        rereadCount);
                    return (result, rereadCount);
                }

                if (logger.IsEnabled(LogLevel.Information))
                {
                    var appTypes = string.Join(',', inconsistentApps);
                    RouteAttachmentLog.ModeTransitionDetected(
                        logger,
                        profile.Sid,
                        appTypes,
                        trigger,
                        rereadCount + 1);
                }
            }
            catch (Exception exception) when (IsTransientReconcileFailure(exception))
            {
                if (rereadCount >= TransitionRereadCount)
                {
                    throw new ConfigMutationException(
                        "CCSWITCH_RECONCILE_RETRY_EXHAUSTED",
                        "CC Switch configuration kept changing or remained locked during reconciliation.",
                        exception);
                }

                RouteAttachmentLog.ModeTransitionDetected(
                    logger,
                    profile.Sid,
                    "database-or-live-config",
                    trigger,
                    rereadCount + 1);
            }

            await Task.Delay(EventDebounce, cancellationToken);
        }
    }

    private void LogResult(
        WindowsUserProfile profile,
        ProfileAttachmentResult result,
        IReadOnlyDictionary<string, CcSwitchAppModeStatus?> previousModes,
        string trigger,
        int rereadCount)
    {
        var attachedCount = result.Items.Count(item => item.Status == RouteStatus.Attached);
        var bypassedCount = result.Items.Count(item => item.Status == RouteStatus.Bypassed);
        if (attachedCount > 0 || bypassedCount > 0)
        {
            RouteAttachmentLog.ProfileReconciled(
                logger,
                profile.Sid,
                attachedCount,
                bypassedCount,
                result.CcSwitchManaged);
        }

        foreach (var status in result.CcSwitchApps ?? [])
        {
            var previous = previousModes.GetValueOrDefault(status.AppType);
            var evidence = status.Evidence;
            if (logger.IsEnabled(LogLevel.Information))
            {
                var previousMode = previous is null ? null : CcSwitchModeState.ToWireValue(previous.Mode);
                var mode = CcSwitchModeState.ToWireValue(status.Mode);
                RouteAttachmentLog.CcSwitchModeObserved(
                    logger,
                    profile.Sid,
                    status.AppType,
                    previousMode,
                    mode,
                    status.ListenerOrigin?.AbsoluteUri,
                    status.ListenerAvailable,
                    evidence?.ProxyEnabled,
                    evidence?.AppEnabled,
                    evidence?.LiveTakeoverActive,
                    evidence?.LivePointsToListener,
                    evidence?.HasLiveBackup,
                    trigger,
                    rereadCount,
                    status.ErrorCode);
            }

            if (status.ErrorCode is not null)
            {
                RouteAttachmentLog.CcSwitchModeWarning(
                    logger,
                    profile.Sid,
                    status.AppType,
                    CcSwitchModeState.ToWireValue(status.Mode),
                    status.ErrorCode);
            }

            if (previous?.Mode == CcSwitchOperatingMode.LocalProxy
                && status.Mode == CcSwitchOperatingMode.Ordinary
                && result.Items.Any(item => item.AgentType == AgentType.CcSwitch
                    && item.Status == RouteStatus.Attached
                    && item.ProviderId.StartsWith($"{status.AppType}:", StringComparison.Ordinal)))
            {
                RouteAttachmentLog.OrdinaryRouteReattached(logger, profile.Sid, status.AppType, trigger);
            }
        }

        if (logger.IsEnabled(LogLevel.Information))
        {
            foreach (var status in result.CcSwitchOwnership ?? [])
            {
                var ownership = status.Ownership.ToString();
                RouteAttachmentLog.CcSwitchOwnershipObserved(
                    logger,
                    profile.Sid,
                    status.AppType,
                    ownership,
                    status.ProviderCount,
                    status.EndpointCount,
                    trigger,
                    status.ErrorCode);
            }
        }

        if (logger.IsEnabled(LogLevel.Information))
        {
            foreach (var item in result.Items)
            {
                var identity = ParseIdentity(item);
                var decision = item.Status.ToString();
                RouteAttachmentLog.RouteDecisionObserved(
                    logger,
                    profile.Sid,
                    identity.AppType,
                    identity.ProviderId,
                    identity.EndpointId,
                    item.OriginalBaseUri?.AbsoluteUri,
                    decision,
                    item.ErrorCode,
                    item.Message);
            }
        }
    }

    private void EnsureWatchers()
    {
        foreach (var entry in _watchers
                     .Where(entry => !Directory.Exists(entry.Value.Path))
                     .ToArray())
        {
            entry.Value.Dispose();
            _watchers.Remove(entry.Key);
        }

        foreach (var profile in profileProvider.GetProfiles())
        {
            AddWatcher(
                profile.Sid,
                Path.Combine(profile.ProfilePath, ".cc-switch"),
                "cc-switch.db*",
                fileName => fileName?.EndsWith("-wal", StringComparison.OrdinalIgnoreCase) == true
                    ? "ccswitch-wal"
                    : fileName?.EndsWith("-shm", StringComparison.OrdinalIgnoreCase) == true
                        ? "ccswitch-shm"
                        : "ccswitch-database");
            AddWatcher(
                profile.Sid,
                Path.Combine(profile.ProfilePath, ".codex"),
                "config.toml",
                _ => "codex-live-config");
            AddWatcher(
                profile.Sid,
                Path.Combine(profile.ProfilePath, ".claude"),
                "settings.json",
                _ => "claude-live-config");
        }
    }

    private void AddWatcher(
        string userSid,
        string directory,
        string filter,
        Func<string?, string> sourceSelector)
    {
        if (!Directory.Exists(directory))
        {
            return;
        }

        var fullDirectory = Path.GetFullPath(directory);
        var key = $"{userSid}|{fullDirectory}|{filter}";
        if (_watchers.ContainsKey(key))
        {
            return;
        }

        var watcher = new FileSystemWatcher(fullDirectory, filter)
        {
            IncludeSubdirectories = false,
            NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
        };
        FileSystemEventHandler changed = (_, args) =>
            reconciliationSignals.Request(userSid, sourceSelector(args.Name));
        RenamedEventHandler renamed = (_, args) =>
            reconciliationSignals.Request(userSid, sourceSelector(args.Name));
        watcher.Changed += changed;
        watcher.Created += changed;
        watcher.Deleted += changed;
        watcher.Renamed += renamed;
        watcher.Error += (_, args) =>
        {
            RouteAttachmentLog.WatcherFailed(logger, userSid, fullDirectory, args.GetException());
            reconciliationSignals.Request(userSid, "watcher-error");
        };

        try
        {
            watcher.EnableRaisingEvents = true;
            _watchers.Add(key, watcher);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            watcher.Dispose();
            RouteAttachmentLog.WatcherFailed(logger, userSid, fullDirectory, exception);
        }
    }

    private static bool IsTransientReconcileFailure(Exception exception) => exception switch
    {
        SqliteException sqlite => sqlite.SqliteErrorCode is 5 or 6,
        ConfigMutationException mutation => mutation.Code is
            "CCSWITCH_DB_CHANGED_CONCURRENTLY" or
            "CONFIG_CHANGED_CONCURRENTLY",
        _ => false,
    };

    private static (string AppType, string ProviderId, string? EndpointId) ParseIdentity(
        AgentConfigAttachmentItem item)
    {
        if (item.AgentType != AgentType.CcSwitch)
        {
            return (item.AgentType.ToString(), item.ProviderId, null);
        }

        var segments = item.ProviderId.Split(':');
        return segments.Length >= 4 && string.Equals(segments[2], "endpoint", StringComparison.Ordinal)
            ? (segments[0], segments[1], segments[3])
            : (segments.ElementAtOrDefault(0) ?? "unknown", segments.ElementAtOrDefault(1) ?? item.ProviderId, null);
    }

}

internal static partial class RouteAttachmentLog
{
    [LoggerMessage(
        EventId = 3001,
        Level = LogLevel.Information,
        Message = "Route reconciliation completed for profile {UserSid}: {AttachedCount} attached route(s), {BypassedCount} allowlisted item(s), CC Switch managed: {CcSwitchManaged}.")]
    public static partial void ProfileReconciled(
        ILogger logger,
        string userSid,
        int attachedCount,
        int bypassedCount,
        bool ccSwitchManaged);

    [LoggerMessage(
        EventId = 3002,
        Level = LogLevel.Warning,
        Message = "Route reconciliation failed for profile {UserSid} with {ErrorCode}.")]
    public static partial void ProfileReconciliationFailed(ILogger logger, string userSid, string errorCode, Exception exception);

    [LoggerMessage(
        EventId = 3003,
        Level = LogLevel.Warning,
        Message = "CC Switch mode for profile {UserSid}, app {AppType} is {Mode}: {ErrorCode}.")]
    public static partial void CcSwitchModeWarning(
        ILogger logger,
        string userSid,
        string appType,
        string mode,
        string errorCode);

    [LoggerMessage(
        EventId = 3004,
        Level = LogLevel.Information,
        SkipEnabledCheck = true,
        Message = "CC Switch mode observed for profile {UserSid}, app {AppType}: previous={PreviousMode}, mode={Mode}, listener={ListenerOrigin}, available={ListenerAvailable}, proxyEnabled={ProxyEnabled}, appEnabled={AppEnabled}, liveTakeoverActive={LiveTakeoverActive}, livePointsToListener={LivePointsToListener}, hasLiveBackup={HasLiveBackup}, trigger={Trigger}, rereads={RereadCount}, error={ErrorCode}.")]
    public static partial void CcSwitchModeObserved(
        ILogger logger,
        string userSid,
        string appType,
        string? previousMode,
        string mode,
        string? listenerOrigin,
        bool? listenerAvailable,
        bool? proxyEnabled,
        bool? appEnabled,
        bool? liveTakeoverActive,
        bool? livePointsToListener,
        bool? hasLiveBackup,
        string trigger,
        int rereadCount,
        string? errorCode);

    [LoggerMessage(
        EventId = 3005,
        Level = LogLevel.Information,
        SkipEnabledCheck = true,
        Message = "BaseURL route decision for profile {UserSid}, app {AppType}, provider {ProviderId}, endpoint {EndpointId}: original={OriginalBaseUrl}, decision={Decision}, error={ErrorCode}, result={ResultMessage}.")]
    public static partial void RouteDecisionObserved(
        ILogger logger,
        string userSid,
        string appType,
        string providerId,
        string? endpointId,
        string? originalBaseUrl,
        string decision,
        string? errorCode,
        string? resultMessage);

    [LoggerMessage(
        EventId = 3006,
        Level = LogLevel.Information,
        Message = "CCSWITCH_MODE_TRANSITION_DETECTED for profile {UserSid}, app(s) {AppTypes}, trigger={Trigger}; scheduling reread {RereadCount}.")]
    public static partial void ModeTransitionDetected(
        ILogger logger,
        string userSid,
        string appTypes,
        string trigger,
        int rereadCount);

    [LoggerMessage(
        EventId = 3007,
        Level = LogLevel.Warning,
        Message = "CCSWITCH_RECONCILE_RETRY_EXHAUSTED for profile {UserSid}, app(s) {AppTypes}, trigger={Trigger}, rereads={RereadCount}.")]
    public static partial void ReconcileRetryExhausted(
        ILogger logger,
        string userSid,
        string appTypes,
        string trigger,
        int rereadCount);

    [LoggerMessage(
        EventId = 3008,
        Level = LogLevel.Information,
        Message = "CCSWITCH_ORDINARY_ROUTE_REATTACHED for profile {UserSid}, app {AppType}, trigger={Trigger}.")]
    public static partial void OrdinaryRouteReattached(ILogger logger, string userSid, string appType, string trigger);

    [LoggerMessage(
        EventId = 3009,
        Level = LogLevel.Warning,
        Message = "Configuration watcher failed for profile {UserSid}, directory {Directory}.")]
    public static partial void WatcherFailed(ILogger logger, string userSid, string directory, Exception exception);

    [LoggerMessage(
        EventId = 3010,
        Level = LogLevel.Information,
        SkipEnabledCheck = true,
        Message = "CC Switch ownership for profile {UserSid}, app {AppType}: ownership={Ownership}, providers={ProviderCount}, endpoints={EndpointCount}, trigger={Trigger}, error={ErrorCode}.")]
    public static partial void CcSwitchOwnershipObserved(
        ILogger logger,
        string userSid,
        string appType,
        string ownership,
        int providerCount,
        int endpointCount,
        string trigger,
        string? errorCode);
}
