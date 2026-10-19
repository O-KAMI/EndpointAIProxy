package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"endpointai/client/internal/audit"
	"endpointai/client/internal/configuration"
	"endpointai/client/internal/contracts"
	"endpointai/client/internal/control"
	"endpointai/client/internal/discovery"
	"endpointai/client/internal/installguard"
	"endpointai/client/internal/observability"
	"endpointai/client/internal/platform"
	"endpointai/client/internal/protocol"
	"endpointai/client/internal/proxy"
	"endpointai/client/internal/state"
)

type Options struct {
	Version, Listen, DataRoot string
	Policy                    contracts.Policy
	AutoAttach                bool
	EnableDSH                 bool
	DSHHomes                  []string
	Control                   *control.Options
	GatewayKey                []byte
	GatewayDeviceID           string
}
type App struct {
	Options                                                   Options
	Store                                                     *state.Store
	Audit                                                     *audit.Store
	Profiles                                                  func(context.Context) ([]platform.Profile, error)
	Client                                                    *control.Client
	mu                                                        sync.RWMutex
	mutation                                                  sync.Mutex
	command                                                   sync.Mutex
	syncControl                                               sync.Mutex
	policy                                                    contracts.Policy
	allowlist                                                 map[string]struct{}
	operation                                                 state.OperationState
	policyState                                               contracts.PolicyClientState
	deviceID, bootID                                          string
	started                                                   time.Time
	lastControl, lastReconcile                                *time.Time
	lastControlError, lastReconcileError, lastReconcileResult *string
	activity                                                  map[string]contracts.ProxyActivityAsset
	events                                                    []contracts.EndpointEvent
	reconcile                                                 chan struct{}
	credential                                                *state.Credential
	reenrollBlocked                                           time.Time
	nextPolicy, nextHeartbeat, nextEvents, nextReceipts       time.Time
	controlFailures                                           map[string]controlFailure
	controlTrace                                              map[string]observability.Detail
	controlDurations                                          map[string]float64
	pendingReceipts                                           map[string]state.CommandReceipt
}

type controlFailure struct {
	Count               int
	First, Last, Logged time.Time
	Detail              observability.Detail
}

func New(ctx context.Context, opts Options, store *state.Store, logs *audit.Store, profiles func(context.Context) ([]platform.Profile, error)) (*App, error) {
	if e := protocol.ValidatePolicy(opts.Policy); e != nil {
		return nil, e
	}
	opts.Policy.AllowlistedBaseURLs = appendNullable(opts.Policy.AllowlistedBaseURLs)
	if opts.Policy.GatewayOrigin != nil {
		opts.Policy.GatewayOrigin = ptr(*opts.Policy.GatewayOrigin)
	}
	id, e := store.GetOrCreateDeviceID(ctx)
	if e != nil {
		return nil, e
	}
	op, e := store.LoadOperationState(ctx)
	if e != nil {
		return nil, e
	}
	a := &App{Options: opts, Store: store, Audit: logs, Profiles: profiles, policy: opts.Policy, operation: op, deviceID: id, bootID: proxy.UUID(), started: time.Now().UTC(), activity: make(map[string]contracts.ProxyActivityAsset), events: []contracts.EndpointEvent{}, reconcile: make(chan struct{}, 1), controlFailures: map[string]controlFailure{}, controlTrace: map[string]observability.Detail{}, controlDurations: map[string]float64{}, pendingReceipts: map[string]state.CommandReceipt{}}
	if opts.Control != nil {
		a.Client, e = control.New(*opts.Control)
		if e != nil {
			return nil, e
		}
		a.Client.Observe = func(stage string, d observability.Detail, elapsed time.Duration) {
			a.mu.Lock()
			a.controlTrace[stage] = d
			a.controlDurations[stage] = float64(elapsed) / float64(time.Millisecond)
			a.mu.Unlock()
		}
		cached, e := store.LoadPolicy(ctx)
		if e != nil {
			return nil, e
		}
		if cached != nil {
			if e = protocol.ValidatePolicy(cached.Policy); e == nil {
				a.policy = cached.Policy
				version := cached.Policy.PolicyVersion
				a.policyState = contracts.PolicyClientState{LastReceivedVersion: &version, AppliedVersion: &version, ApplyStatus: contracts.PolicyApplyStatusApplied}
			} else {
				a.AddEvent("POLICY_CACHE_INVALID", "Cached policy validation failed.")
			}
		}
	}
	a.allowlist = compileAllowlist(a.policy)
	return a, nil
}

func ptr[T any](v T) *T { return &v }
func (a *App) Policy() contracts.Policy {
	a.mu.RLock()
	defer a.mu.RUnlock()
	p := a.policy
	p.AllowlistedBaseURLs = appendNullable(p.AllowlistedBaseURLs)
	if p.GatewayOrigin != nil {
		p.GatewayOrigin = ptr(*p.GatewayOrigin)
	}
	return p
}
func appendNullable(v []string) []string {
	if v == nil {
		return nil
	}
	return append([]string{}, v...)
}
func (a *App) Enabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.operation.State == contracts.ClientOperationStateEnabled
}
func (a *App) DeviceID() string { return a.deviceID }
func compileAllowlist(p contracts.Policy) map[string]struct{} {
	values := p.AllowlistedBaseURLs
	if values == nil {
		values = []string{"https://internal.example.invalid/ccr"}
	}
	entries, _ := protocol.NormalizeAllowlist(values)
	out := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		out[entry] = struct{}{}
	}
	return out
}
func (a *App) proxyPolicy() (contracts.Policy, map[string]struct{}) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.policy, a.allowlist
}
func (a *App) Bypass(value string) bool {
	target, e := protocol.NormalizeBaseURL(value)
	if e != nil {
		return false
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	_, ok := a.allowlist[target]
	return ok
}
func (a *App) RequestReconcile() {
	select {
	case a.reconcile <- struct{}{}:
	default:
	}
}

func (a *App) ApplyPolicy(ctx context.Context, p contracts.Policy, sig string) error {
	if e := protocol.ValidatePolicy(p); e != nil {
		return e
	}
	a.mutation.Lock()
	defer a.mutation.Unlock()
	current := a.Policy()
	if p.PolicyVersion < current.PolicyVersion || (p.PolicyVersion == current.PolicyVersion && p.ServerInstanceID == current.ServerInstanceID) {
		return nil
	}
	if e := a.Store.SavePolicy(ctx, p, sig, time.Now().UTC()); e != nil {
		return e
	}
	a.mu.Lock()
	p.AllowlistedBaseURLs = appendNullable(p.AllowlistedBaseURLs)
	if p.GatewayOrigin != nil {
		p.GatewayOrigin = ptr(*p.GatewayOrigin)
	}
	a.policy = p
	a.allowlist = compileAllowlist(p)
	version := p.PolicyVersion
	a.policyState = contracts.PolicyClientState{LastReceivedVersion: &version, AppliedVersion: &version, ApplyStatus: contracts.PolicyApplyStatusApplied}
	a.mu.Unlock()
	a.Audit.Log("POLICY_APPLIED", map[string]any{"policyVersion": p.PolicyVersion, "operation": "policy"})
	a.RequestReconcile()
	return nil
}

func (a *App) manager() *configuration.Manager {
	return &configuration.Manager{Store: a.Store, Origin: "http://" + a.Options.Listen, BackupRoot: filepath.Join(a.Options.DataRoot, "config-backups"), Allowlisted: a.Bypass, EnableDSH: a.Options.EnableDSH}
}

// PrepareConfigurationProfiles restores trusted recovery roots before inspecting
// live launch overlays. Maintenance must use this even when new DSH attachment
// is disabled, because existing routes can still be referenced by a process.
func PrepareConfigurationProfiles(ctx context.Context, m *configuration.Manager, profiles []platform.Profile, homes []string, inspectDSH bool) ([]configuration.Profile, error) {
	out := make([]configuration.Profile, 0, len(profiles))
	for _, p := range profiles {
		out = append(out, configuration.Profile{SID: p.SID, Home: p.Home, Roaming: p.Roaming, Local: p.Local, SearchPaths: p.SearchPaths, DSHHomes: homes})
	}
	if !inspectDSH {
		return out, nil
	}
	out, err := m.DSHRecoveryProfiles(ctx, out)
	if err != nil {
		return nil, err
	}
	roots := make(map[string][]string, len(out))
	for _, p := range out {
		roots[p.SID] = p.DSHHomes
	}
	metadata := discovery.DSHProfileMetadata(ctx, profiles, roots)
	for i := range out {
		meta, ok := metadata[out[i].SID]
		out[i].DSHVersion = meta.Version
		out[i].DSHPiAIVersion = meta.DSHPiAIVersion
		out[i].DSHOverlaysUnknown = !ok || meta.OverlaysUnknown
	}
	return out, nil
}
func (a *App) configProfiles(ctx context.Context, profiles []platform.Profile) []configuration.Profile {
	inspect := a.Options.EnableDSH
	routes, err := a.Store.ListRoutes(ctx)
	if err != nil {
		inspect = true
	}
	for _, route := range routes {
		if route.AgentType == int(contracts.AgentTypeDeepSeekHarness) {
			inspect = true
			break
		}
	}
	out, prepErr := PrepareConfigurationProfiles(ctx, a.manager(), profiles, a.Options.DSHHomes, inspect)
	if prepErr != nil {
		a.logConfigFailure("dsh_recovery_metadata", prepErr)
		// Keep every route when metadata cannot be prepared. The manager also
		// validates its journal before any mutation.
		out, _ = PrepareConfigurationProfiles(ctx, a.manager(), profiles, a.Options.DSHHomes, false)
		for i := range out {
			out[i].DSHOverlaysUnknown = true
		}
	}
	if err != nil {
		for i := range out {
			out[i].DSHOverlaysUnknown = true
		}
	}
	return out
}

func (a *App) Reconcile(ctx context.Context) error {
	if installguard.Pending(a.Options.DataRoot) {
		return nil
	}
	a.mutation.Lock()
	defer a.mutation.Unlock()
	if !a.Options.AutoAttach || !a.Policy().Enabled || !a.Enabled() {
		return nil
	}
	profiles, e := a.Profiles(ctx)
	if e != nil {
		a.logConfigFailure("profile_discovery", e)
		return e
	}
	var results []configuration.Result
	for attempt := 0; attempt < 4; attempt++ {
		results, e = a.manager().Reconcile(ctx, a.configProfiles(ctx, profiles))
		retry := false
		for _, r := range results {
			if r.ErrorCode == "CCSWITCH_RECONCILE_RETRY_EXHAUSTED" || r.ErrorCode == "CCSWITCH_DB_CHANGED_CONCURRENTLY" || r.ErrorCode == "CONFIG_CHANGED_CONCURRENTLY" || r.Mode == "inconsistent" {
				retry = true
			}
		}
		if !retry || attempt == 3 {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	failed := e != nil
	for _, r := range results {
		if r.ErrorCode != "" && r.Status != int(contracts.RouteStatusUnsupported) {
			failed = true
		}
	}
	now := time.Now().UTC()
	a.mu.Lock()
	a.lastReconcile = &now
	a.lastReconcileResult = ptr("completed")
	a.lastReconcileError = nil
	if failed {
		a.lastReconcileError = ptr("RECONCILE_FAILED")
		a.lastReconcileResult = ptr("failed")
	}
	a.mu.Unlock()
	a.logConfigResults("reconcile", results)
	if e != nil {
		a.logConfigFailure("reconcile", e)
	}
	a.Audit.Log("RECONCILE_COMPLETED", map[string]any{"items": len(results), "failed": failed})
	if failed {
		a.AddEvent("RECONCILE_FAILED", "One or more Agent configurations could not be reconciled.")
		if e == nil {
			e = errors.New("RECONCILE_FAILED")
		}
	}
	return e
}

func (a *App) RunReconcile(ctx context.Context) {
	a.RequestReconcile()
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	lastPeriodic := time.Time{}
	lastFingerprint := ""
	for {
		select {
		case <-ctx.Done():
			return
		case <-a.reconcile:
			_ = a.Reconcile(ctx)
		case now := <-tick.C:
			if !a.Options.AutoAttach {
				continue
			}
			profiles, e := a.Profiles(ctx)
			if e != nil {
				continue
			}
			var b strings.Builder
			for _, p := range profiles {
				for _, rel := range []string{".claude/settings.json", ".codex/config.toml", ".cc-switch/cc-switch.db", ".cc-switch/cc-switch.db-wal", ".cc-switch/cc-switch.db-shm"} {
					path := filepath.Join(p.Home, filepath.FromSlash(rel))
					info, e := os.Stat(path)
					if e == nil {
						fmt.Fprintf(&b, "%s|%d|%d;", path, info.ModTime().UnixNano(), info.Size())
					}
				}
			}
			fingerprint := b.String()
			if fingerprint != lastFingerprint || now.Sub(lastPeriodic) >= time.Minute {
				lastFingerprint = fingerprint
				lastPeriodic = now
				_ = a.Reconcile(ctx)
			}
		}
	}
}

func (a *App) operationOnce(ctx context.Context, kind contracts.RemoteCommandType) (state.OperationState, string, error) {
	if installguard.Pending(a.Options.DataRoot) {
		return state.OperationState{}, "INSTALLATION_PENDING", errors.New("INSTALLATION_PENDING")
	}
	a.mutation.Lock()
	defer a.mutation.Unlock()
	if kind == contracts.RemoteCommandTypeDisableProxy {
		blocked := state.OperationState{State: contracts.ClientOperationStateDisabled, UpdatedAtUTC: time.Now().UTC()}
		if e := a.Store.SaveOperationState(ctx, blocked); e != nil {
			return blocked, "PROXY_DISABLE_FAILED", e
		}
		a.mu.Lock()
		a.operation = blocked
		a.mu.Unlock()
	}
	profiles, e := a.Profiles(ctx)
	var results []configuration.Result
	if e == nil {
		if kind == contracts.RemoteCommandTypeDisableProxy {
			results, e = a.manager().DetachAll(ctx, a.configProfiles(ctx, profiles))
		} else {
			results, e = a.manager().Reconcile(ctx, a.configProfiles(ctx, profiles))
		}
	}
	a.logConfigResults("operation", results)
	if e != nil {
		a.logConfigFailure("operation", e)
	}
	failed := e != nil
	for _, r := range results {
		if r.Status == int(contracts.RouteStatusError) || r.Status == int(contracts.RouteStatusNonCompliant) {
			failed = true
		}
	}
	op := state.OperationState{State: contracts.ClientOperationStateEnabled, UpdatedAtUTC: time.Now().UTC()}
	code := "PROXY_ENABLED"
	if kind == contracts.RemoteCommandTypeDisableProxy {
		op.State = contracts.ClientOperationStateDisabled
		code = "PROXY_DISABLED"
	}
	if failed {
		if kind == contracts.RemoteCommandTypeDisableProxy {
			op.State = contracts.ClientOperationStateDisableFailed
			code = "PROXY_DISABLE_FAILED"
		} else {
			op.State = contracts.ClientOperationStateEnableFailed
			code = "PROXY_ENABLE_FAILED"
		}
		op.LastErrorCode = &code
		op.LastErrorSummary = ptr("One or more managed configurations could not be updated.")
		if e == nil {
			e = errors.New(code)
		}
	}
	if saveErr := a.Store.SaveOperationState(ctx, op); saveErr != nil {
		return op, code, saveErr
	}
	a.mu.Lock()
	a.operation = op
	a.mu.Unlock()
	return op, code, e
}

func (a *App) ApplyCommand(ctx context.Context, cmd contracts.SignedRemoteCommand, token string) error {
	a.command.Lock()
	defer a.command.Unlock()
	if a.Client == nil {
		return errors.New("CONTROL_DISABLED")
	}
	if e := protocol.VerifyCommand(cmd, a.Client.Options.PolicyKey); e != nil {
		return e
	}
	p := cmd.Payload
	if p.DeviceID != a.deviceID {
		return errors.New("COMMAND_DEVICE_MISMATCH")
	}
	receipt, e := a.Store.LoadCommandReceipt(ctx, p.CommandID)
	if e != nil {
		return e
	}
	if receipt != nil && receipt.Type != p.Type {
		return errors.New("COMMAND_TYPE_MISMATCH")
	}
	if receipt != nil && (receipt.Status == contracts.RemoteCommandStatusSucceeded || receipt.Status == contracts.RemoteCommandStatusFailed) {
		_ = a.reportCommand(ctx, *receipt, token)
		return nil
	}
	if receipt == nil {
		receipt = &state.CommandReceipt{CommandID: p.CommandID, Type: p.Type, Status: contracts.RemoteCommandStatusExecuting, ReceivedAtUTC: time.Now().UTC(), DeviceID: ptr(a.deviceID), IssuedAtUTC: ptr(p.IssuedAtUTC), ExpiresAtUTC: ptr(p.ExpiresAtUTC)}
		if !p.ExpiresAtUTC.After(receipt.ReceivedAtUTC) {
			receipt.Status = contracts.RemoteCommandStatusFailed
			receipt.CompletedAtUTC = ptr(receipt.ReceivedAtUTC)
			receipt.ResultCode = ptr("COMMAND_EXPIRED")
			receipt.ResultSummary = ptr("The command expired before local execution.")
			if e = a.Store.SaveCommandReceipt(ctx, *receipt); e != nil {
				return e
			}
			_ = a.reportCommand(ctx, *receipt, token)
			return nil
		}
	}
	if e = a.Store.SaveCommandReceipt(ctx, *receipt); e != nil {
		return e
	}
	_ = a.reportCommand(ctx, *receipt, token)
	return a.finishCommand(ctx, *receipt, token)
}

func (a *App) finishCommand(ctx context.Context, receipt state.CommandReceipt, token string) error {
	_, code, e := a.operationOnce(ctx, receipt.Type)
	receipt.Status = contracts.RemoteCommandStatusSucceeded
	if e != nil {
		receipt.Status = contracts.RemoteCommandStatusFailed
	}
	receipt.CompletedAtUTC = ptr(time.Now().UTC())
	receipt.ResultCode = &code
	receipt.ResultSummary = ptr(code)
	if e = a.Store.SaveCommandReceipt(ctx, receipt); e != nil {
		return e
	}
	a.Audit.Log("COMMAND_COMPLETED", map[string]any{"commandId": observability.SafeID(receipt.CommandID), "commandType": int(receipt.Type), "status": int(receipt.Status), "resultCode": code})
	_ = a.reportCommand(ctx, receipt, token)
	return nil
}
func (a *App) reportCommand(ctx context.Context, r state.CommandReceipt, token string) error {
	observed := r.ReceivedAtUTC
	if r.CompletedAtUTC != nil {
		observed = *r.CompletedAtUTC
	}
	e := a.Client.CommandStatus(ctx, contracts.RemoteCommandStatusUpdate{SchemaVersion: 1, DeviceID: a.deviceID, CommandID: r.CommandID, Status: r.Status, ObservedAtUTC: observed, ResultCode: r.ResultCode, ResultSummary: r.ResultSummary}, token)
	var businessError *control.HTTPError
	if errors.As(e, &businessError) && businessError.Status == http.StatusConflict {
		delete(a.pendingReceipts, r.CommandID)
		a.Audit.Log("COMMAND_RECEIPT_CONFLICT", map[string]any{"commandId": observability.SafeID(r.CommandID), "status": int(r.Status), "errorCode": "COMMAND_STATUS_CONFLICT"})
		a.AddEvent("COMMAND_RECEIPT_CONFLICT", "Command receipt conflicts with server state; automatic retry stopped.")
		a.controlResult("command_receipt", nil)
		return nil
	}
	a.controlResult("command_receipt", e)
	if e != nil {
		if len(a.pendingReceipts) < 1000 || a.pendingReceipts[r.CommandID].CommandID != "" {
			a.pendingReceipts[r.CommandID] = r
		} else {
			a.Audit.Log("COMMAND_RECEIPT_QUEUE_FULL", map[string]any{"items": len(a.pendingReceipts)})
		}
	} else {
		delete(a.pendingReceipts, r.CommandID)
	}
	return e
}

func (a *App) enroll(ctx context.Context) (*state.Credential, error) {
	hostname, _ := os.Hostname()
	out, e := a.Client.Enroll(ctx, contracts.DeviceEnrollmentRequest{SchemaVersion: 2, DeviceID: a.deviceID, Hostname: hostname, ServiceVersion: a.Options.Version})
	if e != nil {
		return nil, e
	}
	c := state.Credential{Token: out.DeviceToken, EnrolledAtUTC: out.EnrolledAtUTC, ServerOrigin: ptr(a.Client.Options.Origin), ServerCertificateSPKISHA256: ptr(a.Client.Options.CertificatePin)}
	if e = a.Store.SaveCredential(ctx, c); e != nil {
		return nil, e
	}
	return &c, nil
}

func (a *App) Sync(ctx context.Context) error {
	if installguard.Pending(a.Options.DataRoot) {
		return nil
	}
	a.syncControl.Lock()
	defer a.syncControl.Unlock()
	if a.Client == nil {
		return nil
	}
	now := time.Now().UTC()
	if a.credential == nil {
		cached, e := a.Store.LoadCredential(ctx)
		if e != nil {
			a.controlResult("credential", e)
			return e
		}
		a.controlResult("credential", nil)
		if cached != nil && cached.ServerOrigin != nil && strings.TrimRight(*cached.ServerOrigin, "/") == strings.TrimRight(a.Client.Options.Origin, "/") && cached.ServerCertificateSPKISHA256 != nil && *cached.ServerCertificateSPKISHA256 == a.Client.Options.CertificatePin {
			a.credential = cached
		} else {
			a.credential, e = a.enroll(ctx)
			a.controlResult("enroll", e)
			if e != nil {
				return e
			}
		}
	}
	// Each stage owns its deadline and backoff. Failure never suppresses a different due stage.
	var first error
	synchronized := false
	record := func(stage string, e error) {
		a.controlResult(stage, e)
		if e != nil {
			e = a.rejected(ctx, e)
			if first == nil {
				first = e
			}
		}
	}
	if !now.Before(a.nextHeartbeat) {
		a.nextHeartbeat = now.Add(15 * time.Second)
		heartbeat, e := a.Heartbeat(ctx)
		if e == nil {
			var response contracts.HeartbeatV2Response
			response, e = a.Client.Heartbeat(ctx, heartbeat, a.credential.Token)
			if e == nil {
				interval := a.Policy().HeartbeatIntervalSeconds
				if response.NextHeartbeatSeconds >= 15 && response.NextHeartbeatSeconds <= 3600 {
					interval = response.NextHeartbeatSeconds
				}
				a.nextHeartbeat = now.Add(time.Duration(interval) * time.Second)
				synchronized = true
				if response.Command != nil {
					commandErr := a.ApplyCommand(ctx, *response.Command, a.credential.Token)
					record("command", commandErr)
				}
			}
		}
		if e != nil {
			a.nextHeartbeat = time.Now().Add(15 * time.Second)
		}
		record("heartbeat", e)
	}
	if !now.Before(a.nextPolicy) {
		a.nextPolicy = now.Add(15 * time.Second)
		p, sig, e := a.Client.Policy(ctx, a.deviceID, a.credential.Token)
		if e == nil {
			e = a.ApplyPolicy(ctx, p, sig)
		}
		if e == nil {
			a.mu.Lock()
			a.policyState.LastReceivedVersion = ptr(p.PolicyVersion)
			a.mu.Unlock()
			a.nextPolicy = now.Add(time.Duration(p.PollIntervalSeconds) * time.Second)
			synchronized = true
		}
		if e != nil {
			a.nextPolicy = time.Now().Add(15 * time.Second)
		}
		record("policy", e)
	}
	if !now.Before(a.nextReceipts) {
		a.nextReceipts = now.Add(15 * time.Second)
		a.command.Lock()
		resume, e := a.Store.ListExecutingReceipts(ctx, a.deviceID)
		if e != nil {
			a.controlResult("command_receipt", e)
		}
		if e == nil {
			for _, r := range resume {
				_ = a.reportCommand(ctx, r, a.credential.Token)
				if err := a.finishCommand(ctx, r, a.credential.Token); err != nil && e == nil {
					e = err
				}
			}
			pending := make([]state.CommandReceipt, 0, len(a.pendingReceipts))
			for _, r := range a.pendingReceipts {
				pending = append(pending, r)
			}
			for _, r := range pending {
				if err := a.reportCommand(ctx, r, a.credential.Token); err != nil && e == nil {
					e = err
				}
			}
		}
		a.command.Unlock()
		if e != nil {
			a.nextReceipts = time.Now().Add(15 * time.Second)
			if first == nil {
				first = a.rejected(ctx, e)
			}
		}
	}
	if !now.Before(a.nextEvents) {
		a.mu.RLock()
		events := append([]contracts.EndpointEvent{}, a.events...)
		a.mu.RUnlock()
		if len(events) > 100 {
			events = events[:100]
		}
		if len(events) > 0 {
			a.nextEvents = now.Add(15 * time.Second)
			out, e := a.Client.Events(ctx, contracts.EventBatchRequest{SchemaVersion: 1, BatchID: proxy.UUID(), DeviceID: a.deviceID, Events: events}, a.credential.Token)
			if e == nil && out.Rejected > 0 {
				e = observability.Wrap("events_validate", "CONTROL_EVENTS_REJECTED", nil)
			}
			if e == nil {
				sent := map[string]bool{}
				for _, event := range events {
					sent[event.EventID] = true
				}
				a.mu.Lock()
				keep := a.events[:0]
				for _, event := range a.events {
					if !sent[event.EventID] {
						keep = append(keep, event)
					}
				}
				a.events = keep
				a.mu.Unlock()
				a.nextEvents = time.Time{}
			}
			if e != nil {
				a.nextEvents = time.Now().Add(15 * time.Second)
			}
			record("events", e)
		}
	}
	if synchronized {
		a.mu.Lock()
		a.lastControl = ptr(now)
		a.mu.Unlock()
	}
	a.mu.Lock()
	if first == nil && len(a.controlFailures) == 0 {
		a.lastControlError = nil
	} else {
		a.lastControlError = ptr("CONTROL_SYNC_FAILED")
	}
	a.mu.Unlock()
	return first
}

// controlResult emits only transitions and one bounded summary per minute, never raw errors.
func (a *App) controlResult(stage string, err error) {
	now := time.Now().UTC()
	a.mu.Lock()
	previous, failed := a.controlFailures[stage]
	duration := a.controlDurations[stage]
	if err == nil {
		delete(a.controlFailures, stage)
		d := a.controlTrace[stage]
		a.mu.Unlock()
		if failed {
			fields := observability.Fields(d)
			fields["operation"] = stage
			fields["failureCount"] = previous.Count
			fields["durationMilliseconds"] = duration
			a.Audit.Log("CONTROL_RECOVERED", fields)
		}
		return
	}
	d := observability.Classify(err)
	if d.Stage == "" {
		d.Stage = stage
	}
	if d.Code == "" {
		d.Code = "CONTROL_OPERATION_FAILED"
	}
	changed := previous.Detail.Class != d.Class || previous.Detail.Stage != d.Stage || previous.Detail.Code != d.Code || previous.Detail.HTTPStatus != d.HTTPStatus
	previous.Count++
	previous.Last = now
	previous.Detail = d
	if !failed {
		previous.First = now
	}
	emit := !failed || changed || now.Sub(previous.Logged) >= time.Minute
	if emit {
		previous.Logged = now
	}
	a.controlFailures[stage] = previous
	a.mu.Unlock()
	if emit {
		fields := observability.Fields(d)
		fields["operation"] = stage
		fields["failureCount"] = previous.Count
		fields["firstFailureAtUtc"] = previous.First
		fields["lastFailureAtUtc"] = previous.Last
		fields["durationMilliseconds"] = duration
		a.Audit.Log("CONTROL_FAILED", fields)
		a.AddEvent("CONTROL_SYNC_FAILED", "Control synchronization failed; cached state remains active.")
	}
}

func (a *App) logConfigFailure(operation string, err error) {
	d := observability.Classify(err)
	d.Stage = "configuration"
	d.Code = "CONFIG_OPERATION_FAILED"
	fields := observability.Fields(d)
	fields["operation"] = operation
	a.Audit.Log("CONFIG_FAILED", fields)
}

func (a *App) logConfigResults(operation string, results []configuration.Result) {
	for _, r := range results {
		if !r.Changed && r.ErrorCode == "" {
			continue
		}
		fields := map[string]any{"operation": operation, "userHash": stable(r.SID), "pathHash": stable(r.Path), "providerHash": stable(r.ProviderID), "routeId": r.RouteID, "agentType": r.AgentType, "status": r.Status, "changed": r.Changed, "failed": r.ErrorCode != "" && r.Status != int(contracts.RouteStatusUnsupported), "mode": r.Mode, "ownership": r.Ownership, "errorCode": r.ErrorCode}
		a.Audit.Log("CONFIG_RESULT", fields)
	}
}

func (a *App) rejected(ctx context.Context, e error) error {
	var httpErr *control.HTTPError
	if errors.As(e, &httpErr) && httpErr.Status == 401 {
		if time.Now().Before(a.reenrollBlocked) {
			return errors.New("CONTROL_DEVICE_REENROLL_COOLDOWN")
		}
		fresh, enrollErr := a.enroll(ctx)
		a.controlResult("enroll", enrollErr)
		if enrollErr != nil {
			a.reenrollBlocked = time.Now().Add(5 * time.Minute)
			return observability.Wrap("enroll", "CONTROL_DEVICE_REENROLL_FAILED", enrollErr)
		}
		a.credential = fresh
		a.reenrollBlocked = time.Time{}
		a.nextPolicy = time.Time{}
		a.nextHeartbeat = time.Time{}
		return errors.New("CONTROL_DEVICE_REENROLLED")
	}
	return e
}

func (a *App) RunControl(ctx context.Context) {
	if a.Client == nil {
		return
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	next := time.Time{}
	for {
		if !time.Now().Before(next) {
			if e := a.Sync(ctx); e != nil {
				if ctx.Err() != nil {
					return
				}
				a.mu.Lock()
				a.lastControlError = ptr("CONTROL_SYNC_FAILED")
				a.mu.Unlock()
				if a.credential == nil {
					next = time.Now().Add(15 * time.Second)
				} else {
					next = time.Now().Add(time.Second)
				}
			} else {
				next = time.Now().Add(time.Second)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (a *App) AddEvent(code, summary string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.events) >= 1000 {
		a.events = a.events[1:]
	}
	a.events = append(a.events, contracts.EndpointEvent{EventID: proxy.UUID(), OccurredAtUTC: time.Now().UTC(), Severity: contracts.EventSeverityWarning, Type: "client", Code: code, Summary: summary})
}

func (a *App) Handler() http.Handler {
	gatewayID := func() string {
		if a.Options.GatewayDeviceID != "" {
			return a.Options.GatewayDeviceID
		}
		return a.DeviceID()
	}
	forward := &proxy.Handler{Store: a.Store, Policy: a.Policy, Snapshot: a.proxyPolicy, Enabled: a.Enabled, Bypass: a.Bypass, DeviceID: gatewayID, UserID: platform.ResolveUserID, GatewayKey: a.Options.GatewayKey, Transport: proxy.ForwardTransport(), StartCapture: a.Audit.Start, Observe: a.Observe}
	mux := http.NewServeMux()
	mux.Handle("/r/", forward)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(405)
			return
		}
		routes, e := a.Store.ListRoutes(r.Context())
		if e != nil {
			w.WriteHeader(503)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "degraded"})
			return
		}
		count := 0
		for _, route := range routes {
			if !a.Options.EnableDSH && route.AgentType == int(contracts.AgentTypeDeepSeekHarness) {
				continue
			}
			if route.Status == int(contracts.RouteStatusAttached) {
				count++
			}
		}
		p := a.Policy()
		a.mu.RLock()
		op := a.operation
		health := map[string]any{"status": "ok", "clientVersion": a.Options.Version, "implementation": "go", "listenEndpoint": a.Options.Listen, "routeCount": count, "routeMode": pascal(p.RouteMode), "policyVersion": p.PolicyVersion, "auditState": "Healthy", "operationState": enumName(contracts.ClientOperationStateNames, int(op.State)), "operationStateUpdatedAtUtc": op.UpdatedAtUTC, "lastErrorCode": op.LastErrorCode, "lastErrorSummary": op.LastErrorSummary, "deviceId": a.deviceID, "lastControlSyncAtUtc": a.lastControl, "lastControlErrorCode": a.lastControlError}
		a.mu.RUnlock()
		health["installationPending"] = installguard.Pending(a.Options.DataRoot)
		health["auditDiagnostics"] = a.Audit.Snapshot()
		if a.Audit.Degraded() {
			health["auditState"] = "Degraded"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(health)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.EscapedPath(), "/r/") {
			forward.ServeHTTP(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func pascal(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
func enumName(names []string, n int) string {
	if n < 0 || n >= len(names) {
		return "Unknown"
	}
	return pascal(names[n])
}

// .NET Guid(byte[]) uses little-endian first fields; UUID v5 is not compatible.
func stable(value string) string {
	b := sha256.Sum256([]byte(value))
	h := []byte{b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]}
	s := hex.EncodeToString(h)
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:]
}
func family(route contracts.Route) string {
	agent, _ := proxy.Classify(route, "")
	if route.AgentType == int(contracts.AgentTypeDeepSeekHarness) {
		return "deepseekHarness"
	}
	if agent == "ClaudeCode" {
		return "claude"
	}
	return "codex"
}
func assetID(route contracts.Route) string {
	return stable(route.UserSID + "|" + family(route) + "|" + route.ProviderID)
}
func (a *App) Observe(rec proxy.Record, status int, outcome string, d time.Duration) {
	if rec.Preflight {
		a.logRequest(rec, status, outcome, d)
		return
	}
	id := assetID(rec.Route)
	now := time.Now().UTC()
	a.mu.Lock()
	item := a.activity[id]
	item.AssetID = id
	item.LastRequestAtUTC = &now
	item.LastHttpStatusCode = ptr(status)
	item.LastOutcome = &outcome
	item.LastGatewayRoundTripMilliseconds = rec.GatewayRoundTripMilliseconds
	item.RequestCountSinceBoot++
	if outcome == "SUCCESS" {
		item.State = contracts.ProxyTrafficStateSucceeded
		item.LastSuccessAtUTC = &now
		item.SuccessCountSinceBoot++
		item.LastErrorCode = nil
	} else {
		item.FailureCountSinceBoot++
		item.LastFailureAtUTC = &now
		item.LastErrorCode = &outcome
		item.State = contracts.ProxyTrafficStateRouteFailed
		if outcome == "GATEWAY_HTTP_ERROR" {
			item.State = contracts.ProxyTrafficStateGatewayReachedWithError
		}
		if outcome == "GATEWAY_CONNECTION_FAILED" {
			item.State = contracts.ProxyTrafficStateConnectionFailed
		}
	}
	a.activity[id] = item
	a.mu.Unlock()
	a.logRequest(rec, status, outcome, d)
}

func (a *App) logRequest(rec proxy.Record, status int, outcome string, d time.Duration) {
	fields := observability.Fields(rec.Failure)
	fields["requestId"] = rec.RequestID
	fields["routeId"] = rec.Route.RouteID
	fields["status"] = status
	fields["outcome"] = outcome
	fields["durationMilliseconds"] = d.Milliseconds()
	fields["captureFinalizeMilliseconds"] = rec.CaptureFinalizeMilliseconds
	a.Audit.Log("REQUEST_COMPLETED", fields)
}

func (a *App) Heartbeat(ctx context.Context) (contracts.HeartbeatV2Request, error) {
	profiles, e := a.Profiles(ctx)
	if e != nil {
		return contracts.HeartbeatV2Request{}, e
	}
	agents, e := discovery.Discover(ctx, profiles)
	if e != nil {
		a.AddEvent("DISCOVERY_COLLECTOR_FAILED", "Agent discovery was partially unavailable.")
	}
	routes, e := a.Store.ListRoutes(ctx)
	if e != nil {
		return contracts.HeartbeatV2Request{}, e
	}
	endpoints, e := a.manager().Inspect(ctx, a.configProfiles(ctx, profiles))
	if e != nil {
		a.AddEvent("ASSET_INSPECTION_FAILED", "Endpoint metadata was partially unavailable.")
	}
	now := time.Now().UTC()
	hostname, _ := os.Hostname()
	p := a.Policy()
	a.mu.RLock()
	op := a.operation
	ps := a.policyState
	lastControl, lastReconcile, lastResult, lastError := a.lastControl, a.lastReconcile, a.lastReconcileResult, a.lastReconcileError
	a.mu.RUnlock()
	out := contracts.HeartbeatV2Request{SchemaVersion: 2, HeartbeatID: proxy.UUID(), ObservedAtUTC: now, Device: contracts.DeviceIdentity{DeviceID: a.deviceID, Hostname: hostname, OSVersion: runtime.GOOS + "/" + runtime.GOARCH, ServiceVersion: a.Options.Version, BootID: a.bootID}, Runtime: contracts.DeviceRuntimeState{ServiceStartedAtUTC: a.started, UptimeSeconds: int64(time.Since(a.started).Seconds()), OperationState: op.State, ProxyListenerAvailable: true, LastControlSyncAtUTC: lastControl, LastReconcileAtUTC: lastReconcile, LastReconcileResult: lastResult, LastReconcileErrorCode: lastError}, Policy: ps, Proxy: contracts.ProxyClientState{State: contracts.ProxyStateListening, ListenEndpoint: a.Options.Listen, AuditState: contracts.AuditStateHealthy}, Users: []contracts.EndpointUser{}, Agents: []contracts.AgentInventoryItem{}, Endpoints: []contracts.AgentEndpointAsset{}, Activity: []contracts.ProxyActivityAsset{}}
	if a.Audit.Degraded() {
		out.Proxy.AuditState = contracts.AuditStateDegraded
	}
	for _, r := range routes {
		if !a.Options.EnableDSH && r.AgentType == int(contracts.AgentTypeDeepSeekHarness) {
			continue
		}
		if r.Status == int(contracts.RouteStatusAttached) {
			out.Proxy.ActiveRouteCount++
		}
	}
	if out.Policy.AppliedVersion == nil && a.Client != nil {
		out.Policy.AppliedVersion = ptr(p.PolicyVersion)
	}
	for _, profile := range profiles {
		out.Users = append(out.Users, contracts.EndpointUser{SID: profile.SID, AccountName: platform.ResolveUserID(profile.SID)})
	}
	modes := map[string]string{}
	for _, ep := range endpoints {
		if ep.Mode != "" {
			modes[ep.SID+"|"+ep.Family] = ep.Mode
		}
	}
	for _, agent := range agents {
		if !agent.Confirmed || (!a.Options.EnableDSH && agent.AgentType == int(contracts.AgentTypeDeepSeekHarness)) {
			continue
		}
		typ := agent.AgentType
		shared := typ
		if typ == 8 || typ == 9 || typ == 10 {
			shared = 0
		}
		if typ == 6 || typ == 7 {
			shared = 1
		}
		var route *contracts.Route
		for i := range routes {
			r := &routes[i]
			if r.UserSID == agent.UserSID && r.AgentType == shared {
				route = r
				break
			}
		}
		if route == nil {
			for i := range routes {
				r := &routes[i]
				if r.UserSID == agent.UserSID && r.AgentType == 4 && (typ == 4 || (shared == 0 && strings.HasPrefix(r.ProviderID, "claude:")) || (shared == 1 && strings.HasPrefix(r.ProviderID, "codex:"))) {
					route = r
					break
				}
			}
		}
		name := enumName(contracts.AgentTypeNames, typ)
		item := contracts.AgentInventoryItem{InstanceID: stable(a.deviceID + "|" + agent.UserSID + "|" + name), UserSID: agent.UserSID, AgentType: contracts.AgentType(typ), DisplayName: name, InstallMethod: contracts.InstallMethod(agent.InstallMethod), DiscoveryConfidence: agent.Confidence, Installed: true, LastSeenAtUTC: now}
		if typ == int(contracts.AgentTypeDeepSeekHarness) {
			item.DisplayName = "DSH"
		}
		if agent.Version != "" {
			item.Version = ptr(agent.Version)
		}
		for _, ev := range agent.Evidence {
			if ev.Collector == "running-process" {
				item.Running = true
			}
		}
		if typ == 2 || typ == 3 {
			item.RouteStatus = contracts.RouteStatusUnsupported
		}
		if route != nil {
			item.RouteStatus = contracts.RouteStatus(route.Status)
			if u, err := url.Parse(route.OriginalBaseURL); err == nil {
				item.ObservedTargetOrigin = ptr(u.Scheme + "://" + u.Host)
			}
			if route.AgentType == 4 {
				item.RouterType = ptr("cc-switch")
				mode := modes[route.UserSID+"|"+family(*route)]
				if mode != "" {
					item.CcSwitchMode = &mode
				}
				if mode == "local-proxy" {
					item.RouterType = ptr("cc-switch-local-proxy")
				}
			}
		}
		out.Agents = append(out.Agents, item)
	}
	for _, ep := range endpoints {
		if ep.Family == "deepseekHarness" && !a.Options.EnableDSH {
			continue
		}
		identity := ep.ProviderID
		id := stable(ep.SID + "|" + ep.Family + "|" + identity)
		provider, endpoint := identity, ep.EndpointID
		if ep.Source != 1 && ep.Family != "deepseekHarness" {
			parts := strings.Split(identity, ":")
			if len(parts) > 1 {
				provider = parts[1]
			}
		}
		item := contracts.AgentEndpointAsset{AssetID: id, UserSID: ep.SID, AgentFamily: ep.Family, ConfigurationSource: contracts.AgentConfigurationSource(ep.Source), ProviderID: ptr(provider), IsCurrent: ep.Current, OriginalTargetBaseURL: ptr(audit.RedactURL(ep.OriginalBaseURL)), EffectiveConfiguredBaseURL: ptr(audit.RedactURL(ep.EffectiveBaseURL)), AllowlistBypassed: ep.Bypassed, RouteStatus: contracts.RouteStatus(ep.RouteStatus), ObservedAtUTC: now, WireAPI: endpointWireAPI(ep.Family, ep.ProviderID)}
		if endpoint != "" {
			item.EndpointID = &endpoint
		}
		if ep.Model != "" {
			item.ConfiguredModel = ptr(ep.Model)
		}
		if ep.LocalRouteURL != "" {
			item.LocalRouteURL = ptr(ep.LocalRouteURL)
		}
		out.Endpoints = append(out.Endpoints, item)
		a.mu.RLock()
		activity, ok := a.activity[id]
		a.mu.RUnlock()
		if !ok {
			activity = contracts.ProxyActivityAsset{AssetID: id, State: contracts.ProxyTrafficStateNeverObserved}
			if ep.Bypassed {
				activity.State = contracts.ProxyTrafficStateAllowlistBypassed
				activity.LastOutcome = ptr("BASE_URL_ALLOWLIST_BYPASS")
			}
		}
		out.Activity = append(out.Activity, activity)
	}
	return out, nil
}

// User/account resolution is independent of model request threads and service
// readiness. Domain lookup failures retain the existing SID fallback.
func (a *App) RunUserIDRefresh(ctx context.Context) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		profiles, err := a.Profiles(ctx)
		if err == nil {
			sids := make([]string, 0, len(profiles))
			for _, p := range profiles {
				sids = append(sids, p.SID)
			}
			if routes, e := a.Store.ListRoutes(ctx); e == nil {
				for _, r := range routes {
					sids = append(sids, r.UserSID)
				}
			}
			platform.RefreshUserIDs(ctx, sids)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
