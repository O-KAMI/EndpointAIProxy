package app

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
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
	ExcludeCodex              bool
	DSHHomes                  []string
	Control                   *control.Options
	GatewayKey                []byte
	GatewayDeviceID           string
}
type App struct {
	Options                                                       Options
	Store                                                         *state.Store
	Audit                                                         *audit.Store
	Profiles                                                      func(context.Context) ([]platform.Profile, error)
	Client                                                        *control.Client
	accountListeners                                              *proxy.AccountListeners
	proxySlots                                                    chan struct{}
	mu                                                            sync.RWMutex
	mutation                                                      sync.Mutex
	eventMu                                                       sync.Mutex
	command                                                       sync.Mutex
	syncControl                                                   sync.Mutex
	policy                                                        contracts.Policy
	allowlist                                                     map[string]struct{}
	operation                                                     state.OperationState
	policyState                                                   contracts.PolicyClientState
	deviceID, bootID                                              string
	started                                                       time.Time
	lastControl, lastReconcile                                    *time.Time
	lastControlError, lastReconcileError, lastReconcileResult     *string
	activity                                                      map[string]contracts.ProxyActivityAsset
	events                                                        []contracts.EndpointEvent
	eventsLoaded                                                  bool
	reconcile                                                     chan struct{}
	credential                                                    *state.Credential
	reenrollBlocked                                               time.Time
	rotationPending                                               bool
	nextCredentialRotation                                        time.Time
	credentialRotationRetries                                     int
	statelessPolicyVersions                                       bool
	lightweightInventory                                          bool
	compactInventory                                              bool
	lastFullInventory                                             *contracts.HeartbeatV2Request
	nextFullInventory                                             time.Time
	nextInventoryScan                                             time.Time
	lastInventoryDigest                                           [32]byte
	inventoryGeneration                                           atomic.Uint64
	lastInventoryGeneration                                       uint64
	policyReceiptPending, policyReceiptWake                       atomic.Bool
	nextPolicy, nextHeartbeat, nextEvents, nextReceipts           time.Time
	heartbeatRetries, policyRetries, eventRetries, receiptRetries int
	controlFailures                                               map[string]controlFailure
	controlTrace                                                  map[string]observability.Detail
	controlDurations                                              map[string]float64
	pendingReceipts                                               map[string]state.CommandReceipt
}

type controlFailure struct {
	Count               int
	First, Last, Logged time.Time
	Detail              observability.Detail
}

func controlRetryDelay(failures int) time.Duration {
	if failures < 1 {
		failures = 1
	}
	if failures > 6 {
		failures = 6
	}
	limit := 15 * time.Second * time.Duration(1<<(failures-1))
	if limit > 5*time.Minute {
		limit = 5 * time.Minute
	}
	return limit/2 + time.Duration(rand.Int64N(int64(limit/2)+1))
}

func controlRetryDelayFor(failures int, err error) time.Duration {
	delay := controlRetryDelay(failures)
	var response *control.HTTPError
	if errors.As(err, &response) && (response.Status == http.StatusTooManyRequests || response.Status == http.StatusServiceUnavailable) && response.RetryAfter > delay {
		return response.RetryAfter
	}
	return delay
}

func controlInterval(seconds int) time.Duration {
	interval := time.Duration(seconds) * time.Second
	spread := interval / 10
	return interval - spread + time.Duration(rand.Int64N(int64(2*spread)+1))
}

func New(ctx context.Context, opts Options, store *state.Store, logs *audit.Store, profiles func(context.Context) ([]platform.Profile, error)) (*App, error) {
	if e := protocol.ValidatePolicy(opts.Policy); e != nil {
		return nil, e
	}
	opts.Policy = clonePolicyRules(opts.Policy)
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
	if err := a.restorePendingEvents(ctx); err != nil {
		logs.Log("EVENT_QUEUE_READ_FAILED", map[string]any{"errorCode": "EVENT_QUEUE_UNAVAILABLE"})
	}
	a.proxySlots = make(chan struct{}, 64)
	if opts.Control != nil {
		a.Client, e = control.New(*opts.Control)
		if e != nil {
			return nil, e
		}
		if e = a.Client.AttachDeviceTransportStore(ctx, store); e != nil {
			logs.Log("CONTROL_DEVICE_STORE_UNAVAILABLE", map[string]any{"errorCode": "CONTROL_DEVICE_STORE_UNAVAILABLE"})
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
			if len(a.Client.Options.PolicyPublicKey) > 0 && strings.HasPrefix(cached.Signature, "ed25519-v1:") {
				e = protocol.VerifyEd25519(cached.RawPolicy, cached.Signature, a.Client.Options.PolicyPublicKey, "policy")
			} else if len(a.Client.Options.PolicyPublicKey) > 0 && !strings.HasPrefix(cached.Signature, "v1:") {
				e = errors.New("POLICY_CACHE_SIGNATURE_INVALID")
			}
			if e == nil {
				e = protocol.ValidatePolicy(cached.Policy)
			}
			if e == nil {
				a.policy = cached.Policy
				version := cached.Policy.PolicyVersion
				a.policyState = contracts.PolicyClientState{LastReceivedVersion: &version, AppliedVersion: &version, ApplyStatus: contracts.PolicyApplyStatusApplied}
			} else {
				a.AddEvent("POLICY_CACHE_INVALID", "Cached policy validation failed.")
			}
		}
	}
	a.allowlist = compileAllowlist(a.policy)
	a.accountListeners = proxy.NewAccountListeners(a.Handler())
	return a, nil
}

func ptr[T any](v T) *T { return &v }
func (a *App) Policy() contracts.Policy {
	a.mu.RLock()
	defer a.mu.RUnlock()
	p := a.policy
	p = clonePolicyRules(p)
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

func clonePolicyRules(p contracts.Policy) contracts.Policy {
	p.AllowlistedDomains = appendNullable(p.AllowlistedDomains)
	if p.RoutingRules != nil {
		p.RoutingRules = append([]contracts.RoutingRule{}, p.RoutingRules...)
		for i := range p.RoutingRules {
			if p.RoutingRules[i].GatewayOrigin != nil {
				p.RoutingRules[i].GatewayOrigin = ptr(*p.RoutingRules[i].GatewayOrigin)
			}
		}
	}
	return p
}
func (a *App) Enabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.operation.State == contracts.ClientOperationStateEnabled
}
func (a *App) DeviceID() string { return a.deviceID }
func compileAllowlist(p contracts.Policy) map[string]struct{} {
	if p.SchemaVersion == 2 {
		out := make(map[string]struct{}, len(p.AllowlistedDomains))
		for _, domain := range p.AllowlistedDomains {
			if normalized, err := protocol.NormalizeDomain(domain); err == nil {
				out[normalized] = struct{}{}
			}
		}
		return out
	}
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
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.policy.SchemaVersion == 2 {
		return protocol.DomainAllowed(value, a.allowlist)
	}
	target, e := protocol.NormalizeBaseURL(value)
	if e != nil {
		return false
	}
	_, ok := a.allowlist[target]
	return ok
}
func (a *App) RequestReconcile() {
	a.inventoryGeneration.Add(1)
	select {
	case a.reconcile <- struct{}{}:
	default:
	}
}

func (a *App) ApplyPolicy(ctx context.Context, p contracts.Policy, sig string, authenticatedRaw ...[]byte) error {
	if e := protocol.ValidatePolicy(p); e != nil {
		return e
	}
	a.mutation.Lock()
	defer a.mutation.Unlock()
	current := a.Policy()
	if p.PolicyVersion < current.PolicyVersion || (p.PolicyVersion == current.PolicyVersion && p.ServerInstanceID == current.ServerInstanceID && p.SchemaVersion <= current.SchemaVersion) {
		// A signed response for an unchanged policy can upgrade the offline cache
		// without changing the effective policy or its version.
		if p.PolicyVersion == current.PolicyVersion && p.ServerInstanceID == current.ServerInstanceID && p.SchemaVersion == current.SchemaVersion && len(authenticatedRaw) > 0 && len(authenticatedRaw[0]) > 0 {
			oldBody, oldErr := json.Marshal(current)
			newBody, newErr := json.Marshal(p)
			if oldErr == nil && newErr == nil && string(oldBody) == string(newBody) {
				cached, err := a.Store.LoadPolicy(ctx)
				if err != nil {
					return err
				}
				if cached != nil && cached.Signature == sig && string(cached.RawPolicy) == string(authenticatedRaw[0]) {
					return nil
				}
				return a.Store.SavePolicy(ctx, p, sig, time.Now().UTC(), authenticatedRaw[0])
			}
		}
		return nil
	}
	if e := a.Store.SavePolicy(ctx, p, sig, time.Now().UTC(), authenticatedRaw...); e != nil {
		return e
	}
	a.mu.Lock()
	p = clonePolicyRules(p)
	p.AllowlistedBaseURLs = appendNullable(p.AllowlistedBaseURLs)
	if p.GatewayOrigin != nil {
		p.GatewayOrigin = ptr(*p.GatewayOrigin)
	}
	a.policy = p
	a.allowlist = compileAllowlist(p)
	version := p.PolicyVersion
	a.policyState = contracts.PolicyClientState{AppliedSchemaVersion: p.SchemaVersion, LastReceivedVersion: &version, AppliedVersion: &version, ApplyStatus: contracts.PolicyApplyStatusApplied}
	// A successful reconciliation for the previous policy is not evidence for this version.
	a.lastReconcile, a.lastReconcileResult, a.lastReconcileError = nil, nil, nil
	a.mu.Unlock()
	a.Audit.Log("POLICY_APPLIED", map[string]any{"policyVersion": p.PolicyVersion, "operation": "policy"})
	a.policyReceiptPending.Store(true)
	a.RequestReconcile()
	return nil
}

func (a *App) manager() *configuration.Manager {
	return &configuration.Manager{Store: a.Store, Origin: "http://" + a.Options.Listen, BackupRoot: filepath.Join(a.Options.DataRoot, "config-backups"), Allowlisted: a.Bypass, EnableDSH: a.Options.EnableDSH, ExcludeCodex: a.Options.ExcludeCodex, AccountOrigin: a.accountListeners.Ensure, PruneAccountOrigins: a.accountListeners.Prune}
}

func (a *App) StartAccountListeners(ctx context.Context) error {
	routes, err := a.Store.ListRoutes(ctx)
	if err != nil {
		return err
	}
	for _, route := range routes {
		if strings.HasPrefix(route.ProviderID, "dsh:messages:account:") {
			if _, err := a.accountListeners.Ensure(route.RouteID, route.InjectedBaseURL); err != nil {
				return err
			}
		}
	}
	return nil
}

func (a *App) CloseAccountListeners() { a.accountListeners.Close() }

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
		out[i].DSHDesktopAccountVerified = meta.DesktopAccountVerified
		out[i].DSHDesktopReferencesVerified = meta.DesktopReferencesVerified
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
	defer func() {
		if a.policyReceiptPending.Swap(false) {
			a.policyReceiptWake.Store(true)
		}
	}()
	if !a.Options.AutoAttach || !a.Policy().Enabled || !a.Enabled() {
		return nil
	}
	profiles, e := a.Profiles(ctx)
	if e != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		now := time.Now().UTC()
		a.mu.Lock()
		a.lastReconcile = &now
		a.lastReconcileResult = ptr("failed")
		a.lastReconcileError = ptr("PROFILE_DISCOVERY_FAILED")
		a.mu.Unlock()
		a.logConfigFailure("profile_discovery", e)
		a.AddEvent("RECONCILE_FAILED", "User profiles could not be discovered for reconciliation.")
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
	tick := time.NewTicker(5 * time.Second)
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
			if fingerprint != lastFingerprint {
				a.inventoryGeneration.Add(1)
			}
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
	defer a.inventoryGeneration.Add(1)
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
	if e := a.Client.VerifyCommand(cmd); e != nil {
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
	if receipt != nil && (receipt.ExpiresAtUTC == nil || !receipt.ExpiresAtUTC.After(time.Now().UTC())) {
		// The interrupted operation may already have taken effect. Do not rerun it
		// after expiry; the server's result-unknown workflow requires human review.
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
	if receipt.ExpiresAtUTC == nil || !receipt.ExpiresAtUTC.After(time.Now().UTC()) {
		return nil
	}
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
	request := contracts.DeviceEnrollmentRequest{SchemaVersion: 2, DeviceID: a.deviceID, Hostname: hostname, ServiceVersion: a.Options.Version}
	if a.credential != nil {
		request.PreviousDeviceToken = a.credential.Token
	} else {
		// Bind pending state to the control identity; never send it to a new origin.
		type pendingEnrollment struct{ Device, Origin, Pin, Token string }
		value, err := a.Store.LoadPendingEnrollment(ctx)
		if err != nil {
			return nil, errors.New("CONTROL_PENDING_ENROLLMENT_READ_FAILED")
		}
		var pending pendingEnrollment
		if value == "" {
			var random [32]byte
			if _, err = cryptorand.Read(random[:]); err != nil {
				return nil, errors.New("CONTROL_PENDING_ENROLLMENT_RANDOM_FAILED")
			}
			pending = pendingEnrollment{Device: a.deviceID, Origin: a.Client.Options.Origin, Pin: a.Client.Options.CertificatePin, Token: base64.StdEncoding.EncodeToString(random[:])}
			clear(random[:])
			data, err := json.Marshal(pending)
			if err != nil {
				return nil, errors.New("CONTROL_PENDING_ENROLLMENT_INVALID")
			}
			err = a.Store.SavePendingEnrollment(ctx, string(data))
			clear(data)
			if err != nil {
				return nil, errors.New("CONTROL_PENDING_ENROLLMENT_WRITE_FAILED")
			}
		} else if json.Unmarshal([]byte(value), &pending) != nil || pending.Device != a.deviceID || pending.Origin != a.Client.Options.Origin || pending.Pin != a.Client.Options.CertificatePin {
			return nil, errors.New("CONTROL_PENDING_ENROLLMENT_INVALID")
		}
		decoded, err := base64.StdEncoding.Strict().DecodeString(pending.Token)
		if err != nil || len(decoded) != 32 || base64.StdEncoding.EncodeToString(decoded) != pending.Token {
			return nil, errors.New("CONTROL_PENDING_ENROLLMENT_INVALID")
		}
		clear(decoded)
		request.InitialDeviceToken = pending.Token
	}
	out, e := a.Client.Enroll(ctx, request)
	if e != nil {
		return nil, e
	}
	c := state.Credential{Token: out.DeviceToken, EnrolledAtUTC: out.EnrolledAtUTC, ServerOrigin: ptr(a.Client.Options.Origin), ServerCertificateSPKISHA256: ptr(a.Client.Options.CertificatePin)}
	if e = a.Store.CommitEnrollment(ctx, c); e != nil {
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
	if a.policyReceiptWake.Swap(false) && a.heartbeatRetries == 0 {
		due := now.Add(time.Duration(rand.Int64N(int64(5*time.Second) + 1)))
		if a.nextHeartbeat.After(due) {
			a.nextHeartbeat = due
		}
	}
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
	first := a.rotateCredential(ctx, nil)
	if a.credential == nil {
		return first
	}
	synchronized := false
	record := func(stage string, e error) {
		a.controlResult(stage, e)
		if e != nil {
			if !a.rotationPending {
				e = a.rejected(ctx, e)
			}
			if first == nil {
				first = e
			}
		}
	}
	if !now.Before(a.nextHeartbeat) {
		a.nextHeartbeat = now.Add(15 * time.Second)
		var heartbeat contracts.HeartbeatV2Request
		var e error
		generation := a.inventoryGeneration.Load()
		scanned := false
		var scannedInventory contracts.HeartbeatV2Request
		var digest [32]byte
		if a.lightweightInventory && a.lastFullInventory != nil && now.Before(a.nextInventoryScan) && now.Before(a.nextFullInventory) && generation == a.lastInventoryGeneration {
			heartbeat, e = a.lightHeartbeat(ctx, *a.lastFullInventory)
		} else {
			heartbeat, e = a.Heartbeat(ctx)
			if e != nil && a.lightweightInventory && a.lastFullInventory != nil && ctx.Err() == nil {
				record("inventory", e)
				heartbeat, e = a.lightHeartbeat(ctx, *a.lastFullInventory)
			} else if e == nil {
				record("inventory", nil)
				scanned = true
				scannedInventory = heartbeat
				digest, e = inventoryDigest(heartbeat)
				if e == nil && a.lightweightInventory && a.lastFullInventory != nil && now.Before(a.nextFullInventory) && digest == a.lastInventoryDigest {
					heartbeat.InventoryUnchanged = true
					heartbeat.Endpoints = []contracts.AgentEndpointAsset{}
				}
			}
		}
		if e == nil {
			heartbeat.StatelessPolicyVersions = a.statelessPolicyVersions
			if heartbeat.InventoryUnchanged && a.compactInventory {
				heartbeat.CompactInventory = true
				heartbeat.Users = []contracts.EndpointUser{}
				heartbeat.Agents = []contracts.AgentInventoryItem{}
			}
			var response contracts.HeartbeatV2Response
			response, e = a.Client.Heartbeat(ctx, heartbeat, a.credential.Token)
			var status *control.HTTPError
			detail := observability.Classify(e)
			unavailable := errors.As(e, &status) && status.Status == http.StatusNotFound
			// Older device-bound servers reject unknown routes at the outer
			// envelope; retry a full heartbeat using the same transport key.
			if heartbeat.CompactInventory && detail.Stage == "transport_http" && detail.HTTPStatus == http.StatusBadRequest {
				unavailable = true
			}
			if heartbeat.InventoryUnchanged && unavailable {
				// An older server cannot safely interpret omitted inventory. Retry
				// the original full endpoint after an authenticated 404.
				a.lightweightInventory = false
				a.compactInventory = false
				a.lastFullInventory = nil
				heartbeat, e = a.Heartbeat(ctx)
				if e == nil {
					scanned = true
					scannedInventory = heartbeat
					digest, e = inventoryDigest(heartbeat)
				}
				if e == nil {
					heartbeat.StatelessPolicyVersions = a.statelessPolicyVersions
					response, e = a.Client.Heartbeat(ctx, heartbeat, a.credential.Token)
				}
			}
			if e == nil {
				a.statelessPolicyVersions = response.StatelessPolicyVersions
				a.lightweightInventory = response.LightweightInventory
				a.compactInventory = response.LightweightInventory && response.CompactInventory
				if scanned && response.LightweightInventory {
					cached := scannedInventory
					a.lastFullInventory = &cached
					a.lastInventoryGeneration = generation
					a.lastInventoryDigest = digest
					a.nextInventoryScan = time.Now().Add(controlInterval(300))
					if !heartbeat.InventoryUnchanged {
						a.nextFullInventory = time.Now().Add(controlInterval(3600))
					}
				}
				if !response.LightweightInventory {
					a.lastFullInventory = nil
				}
				interval := a.Policy().HeartbeatIntervalSeconds
				if response.NextHeartbeatSeconds >= 15 && response.NextHeartbeatSeconds <= 3600 {
					interval = response.NextHeartbeatSeconds
				}
				a.heartbeatRetries = 0
				a.nextHeartbeat = time.Now().Add(controlInterval(interval))
				if a.policyRetries == 0 && response.AcceptedPolicyVersion != a.Policy().PolicyVersion && a.nextPolicy.After(time.Now()) {
					a.nextPolicy = time.Time{}
				}
				synchronized = true
				if rotationErr := a.rotateCredential(ctx, &response); rotationErr != nil {
					if a.credential == nil {
						return rotationErr
					}
					if first == nil {
						first = rotationErr
					}
				}
				if response.Command != nil {
					commandErr := a.ApplyCommand(ctx, *response.Command, a.credential.Token)
					record("command", commandErr)
				}
			}
		}
		if e != nil {
			a.heartbeatRetries++
			a.nextHeartbeat = time.Now().Add(controlRetryDelayFor(a.heartbeatRetries, e))
		}
		record("heartbeat", e)
	}
	if !now.Before(a.nextPolicy) {
		a.nextPolicy = now.Add(15 * time.Second)
		p, sig, raw, e := a.Client.PolicyRaw(ctx, a.deviceID, a.credential.Token, a.statelessPolicyVersions)
		if e == nil {
			e = a.ApplyPolicy(ctx, p, sig, raw)
		}
		if e == nil {
			a.mu.Lock()
			a.policyState.LastReceivedVersion = ptr(p.PolicyVersion)
			a.mu.Unlock()
			a.policyRetries = 0
			interval := p.PollIntervalSeconds
			if interval < 600 {
				interval = 600
			}
			a.nextPolicy = time.Now().Add(controlInterval(interval))
			synchronized = true
		}
		if e != nil {
			a.policyRetries++
			a.nextPolicy = time.Now().Add(controlRetryDelayFor(a.policyRetries, e))
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
				if r.ExpiresAtUTC == nil || !r.ExpiresAtUTC.After(time.Now().UTC()) {
					continue
				}
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
			a.receiptRetries++
			a.nextReceipts = time.Now().Add(controlRetryDelayFor(a.receiptRetries, e))
			if first == nil {
				first = a.rejected(ctx, e)
			}
		} else {
			a.receiptRetries = 0
		}
	}
	if !now.Before(a.nextEvents) {
		if e := a.restorePendingEvents(ctx); e != nil {
			a.eventRetries++
			a.nextEvents = time.Now().Add(controlRetryDelayFor(a.eventRetries, e))
			record("events", observability.Wrap("events_read", "EVENT_QUEUE_UNAVAILABLE", e))
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
			if e == nil && (out.Rejected > 0 || out.Accepted+out.Duplicates != len(events)) {
				e = observability.Wrap("events_validate", "CONTROL_EVENTS_REJECTED", nil)
			}
			if e == nil {
				a.eventMu.Lock()
				e = a.Store.DeletePendingEvents(ctx, events)
				if e != nil {
					a.eventMu.Unlock()
				} else {
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
					a.eventMu.Unlock()
					a.nextEvents = time.Time{}
					a.eventRetries = 0
				}
			}
			if e != nil {
				a.eventRetries++
				a.nextEvents = time.Now().Add(controlRetryDelayFor(a.eventRetries, e))
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
	next := time.Now().Add(time.Duration(rand.Int64N(int64(30*time.Second) + 1)))
	enrollRetries := 0
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
					enrollRetries++
					next = time.Now().Add(controlRetryDelayFor(enrollRetries, e))
				} else {
					next = time.Now().Add(time.Second)
				}
			} else {
				enrollRetries = 0
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

func (a *App) restorePendingEvents(ctx context.Context) error {
	a.eventMu.Lock()
	defer a.eventMu.Unlock()
	if a.eventsLoaded {
		return nil
	}
	pending, err := a.Store.PendingEvents(ctx)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	seen := make(map[string]bool, len(pending))
	for _, event := range pending {
		seen[event.EventID] = true
	}
	for _, event := range a.events {
		if !seen[event.EventID] {
			pending = append(pending, event)
			seen[event.EventID] = true
		}
	}
	a.events = pending
	a.eventsLoaded = true
	return nil
}

func (a *App) AddEvent(code, summary string) {
	event := contracts.EndpointEvent{EventID: proxy.UUID(), OccurredAtUTC: time.Now().UTC(), Severity: contracts.EventSeverityWarning, Type: "client", Code: code, Summary: summary}
	a.eventMu.Lock()
	defer a.eventMu.Unlock()
	dropped, err := a.Store.EnqueueEvent(context.Background(), event)
	if err != nil {
		a.Audit.Log("EVENT_QUEUE_WRITE_FAILED", map[string]any{"errorCode": "EVENT_QUEUE_UNAVAILABLE"})
	} else if dropped > 0 {
		a.Audit.Log("EVENT_QUEUE_OVERFLOW", map[string]any{"droppedCount": dropped})
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.events) >= state.PendingEventLimit {
		a.events = a.events[1:]
	}
	a.events = append(a.events, event)
}

func (a *App) Handler() http.Handler {
	gatewayID := func() string {
		if a.Options.GatewayDeviceID != "" {
			return a.Options.GatewayDeviceID
		}
		return a.DeviceID()
	}
	forward := &proxy.Handler{Store: a.Store, Policy: a.Policy, Snapshot: a.proxyPolicy, Enabled: a.Enabled, Bypass: a.Bypass, DeviceID: gatewayID, UserID: platform.ResolveUserID, GatewayKey: a.Options.GatewayKey, Transport: proxy.ForwardTransport(), StartCapture: a.Audit.Start, Observe: a.Observe, Slots: a.proxySlots}
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
		queue := map[string]any{"memoryDepth": len(a.events), "memoryBaselineLoaded": a.eventsLoaded, "capacity": state.PendingEventLimit, "persistedDepth": nil, "persistedReadStatus": "unavailable"}
		a.mu.RUnlock()
		queueCtx, cancel := context.WithTimeout(r.Context(), time.Second)
		persisted, queueErr := a.Store.PendingEventCount(queueCtx)
		cancel()
		if queueErr == nil {
			queue["persistedDepth"], queue["persistedReadStatus"] = persisted, "available"
		} else {
			health["status"] = "degraded"
		}
		health["controlEventQueue"] = queue
		health["installationPending"] = installguard.Pending(a.Options.DataRoot)
		health["gatewayOrigin"] = p.GatewayOrigin
		health["auditDiagnostics"] = a.Audit.Snapshot()
		if a.Audit.Degraded() {
			health["auditState"] = "Degraded"
		}
		w.Header().Set("Content-Type", "application/json")
		if queueErr != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
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
	out.Runtime.SupportedPolicySchemaVersion = 2
	out.Policy.AppliedSchemaVersion = p.SchemaVersion
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

// lightHeartbeat retains the last acknowledged inventory while sending current
// runtime and proxy activity. A periodic full scan repairs missed changes.
func (a *App) lightHeartbeat(ctx context.Context, cached contracts.HeartbeatV2Request) (contracts.HeartbeatV2Request, error) {
	routes, err := a.Store.ListRoutes(ctx)
	if err != nil {
		return contracts.HeartbeatV2Request{}, err
	}
	out := cached
	out.HeartbeatID = proxy.UUID()
	out.ObservedAtUTC = time.Now().UTC()
	out.InventoryUnchanged = true
	out.Endpoints = []contracts.AgentEndpointAsset{}
	out.Proxy.ActiveRouteCount = 0
	for _, route := range routes {
		if (a.Options.EnableDSH || route.AgentType != int(contracts.AgentTypeDeepSeekHarness)) && route.Status == int(contracts.RouteStatusAttached) {
			out.Proxy.ActiveRouteCount++
		}
	}
	a.mu.RLock()
	out.Runtime.UptimeSeconds = int64(time.Since(a.started).Seconds())
	out.Runtime.OperationState = a.operation.State
	out.Runtime.LastControlSyncAtUTC = a.lastControl
	out.Runtime.LastReconcileAtUTC = a.lastReconcile
	out.Runtime.LastReconcileResult = a.lastReconcileResult
	out.Runtime.LastReconcileErrorCode = a.lastReconcileError
	out.Policy = a.policyState
	out.Policy.AppliedSchemaVersion = a.policy.SchemaVersion
	out.Activity = append(make([]contracts.ProxyActivityAsset, 0, len(cached.Activity)), cached.Activity...)
	for i, item := range out.Activity {
		if activity, ok := a.activity[item.AssetID]; ok {
			out.Activity[i] = activity
		}
	}
	a.mu.RUnlock()
	if out.Policy.AppliedVersion == nil && a.Client != nil {
		out.Policy.AppliedVersion = ptr(a.Policy().PolicyVersion)
	}
	if a.Audit.Degraded() {
		out.Proxy.AuditState = contracts.AuditStateDegraded
	} else {
		out.Proxy.AuditState = contracts.AuditStateHealthy
	}
	return out, nil
}

func inventoryDigest(h contracts.HeartbeatV2Request) ([32]byte, error) {
	agents := append([]contracts.AgentInventoryItem(nil), h.Agents...)
	for i := range agents {
		agents[i].LastSeenAtUTC = time.Time{}
	}
	endpoints := append([]contracts.AgentEndpointAsset(nil), h.Endpoints...)
	for i := range endpoints {
		endpoints[i].ObservedAtUTC = time.Time{}
	}
	encoded, err := json.Marshal(struct {
		Users     []contracts.EndpointUser
		Agents    []contracts.AgentInventoryItem
		Endpoints []contracts.AgentEndpointAsset
	}{h.Users, agents, endpoints})
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
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
