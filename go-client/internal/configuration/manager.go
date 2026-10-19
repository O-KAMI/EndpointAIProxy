package configuration

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"endpointai/client/internal/contracts"
	"endpointai/client/internal/protocol"
	"endpointai/client/internal/state"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Profile struct {
	SID, Home, Roaming, Local string
	SearchPaths               []string
	DSHHomes                  []string
	DSHOverlaysUnknown        bool
	DSHVersion                string
	DSHPiAIVersion            string
}
type Result struct {
	SID, Path, ProviderID, RouteID, Mode, Ownership, ErrorCode string
	AgentType, Status                                          int
	Changed                                                    bool
}
type Manager struct {
	Store              *state.Store
	Origin, BackupRoot string
	Allowlisted        func(string) bool
	EnableDSH          bool
	mu                 sync.Mutex
}
type decision struct {
	target     string
	route      *contracts.Route
	before     *contracts.Route
	bypass     bool
	referenced *contracts.Route
}

func configPath(p Profile, app string) string {
	if app == "claude" {
		return filepath.Join(p.Home, ".claude", "settings.json")
	}
	return filepath.Join(p.Home, ".codex", "config.toml")
}
func errorCode(e error) string {
	var m *MutationError
	if errors.As(e, &m) {
		return m.Code
	}
	return "CONFIG_OPERATION_FAILED"
}
func (m *Manager) validate() error {
	if m.Store == nil {
		return fmt.Errorf("configuration store is required")
	}
	if m.BackupRoot == "" {
		return fmt.Errorf("configuration backup root is required")
	}
	return validateTarget(m.Origin, false)
}
func (m *Manager) resolve(ctx context.Context, p Profile, agent int, identity, current string, detach bool) (decision, error) {
	routes, e := m.Store.ListRoutes(ctx)
	if e != nil {
		return decision{}, e
	}
	var old *contracts.Route
	for _, r := range routes {
		if r.UserSID == p.SID && r.AgentType == agent && r.ProviderID == identity {
			copy := r
			old = &copy
			break
		}
	}
	var referenced *contracts.Route
	if u, err := url.Parse(current); err == nil && u.Scheme == "http" && (net.ParseIP(u.Hostname()).IsLoopback() || strings.EqualFold(u.Hostname(), "localhost")) {
		for _, candidate := range routes {
			if sameURL(candidate.InjectedBaseURL, current) && candidate.UserSID == p.SID {
				copy := candidate
				referenced = &copy
				break
			}
		}
	}
	if detach {
		if old == nil {
			if referenced == nil {
				return decision{target: current}, nil
			}
			old = referenced
		}
		if !sameURL(current, old.InjectedBaseURL) {
			return decision{}, problem("DETACH_CONFIG_CHANGED")
		}
		return decision{target: old.OriginalBaseURL, before: old, bypass: true, referenced: referenced}, nil
	}
	original := current
	if original == "" {
		original = "https://api.anthropic.com"
	}
	u, e := url.Parse(original)
	if e != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return decision{}, problem("ORIGINAL_BASE_URL_INVALID")
	}
	ip := net.ParseIP(u.Hostname())
	if ip != nil && ip.IsLoopback() || strings.EqualFold(u.Hostname(), "localhost") || agent == dshAgent && dshIsLoopback(u.Hostname()) {
		if referenced == nil && !(agent == dshAgent && m.dshLocalUpstreamAllowed(u)) {
			return decision{}, problem("ORIGINAL_BASE_URL_RECOVERY_REQUIRED")
		}
		if referenced != nil {
			original = referenced.OriginalBaseURL
		}
	}
	if m.Allowlisted != nil && m.Allowlisted(original) {
		return decision{target: original, before: old, bypass: true, referenced: referenced}, nil
	}
	now := time.Now().UTC()
	var routeRandom [16]byte
	if _, e = rand.Read(routeRandom[:]); e != nil {
		return decision{}, e
	}
	r := contracts.Route{RouteID: base64.RawURLEncoding.EncodeToString(routeRandom[:]), UserSID: p.SID, AgentType: agent, ProviderID: identity, OriginalBaseURL: original, Status: 1, CreatedAtUTC: now, UpdatedAtUTC: now}
	if old != nil {
		r.RouteID = old.RouteID
		r.CreatedAtUTC = old.CreatedAtUTC
	}
	r.InjectedBaseURL = strings.TrimRight(m.Origin, "/") + "/r/" + r.RouteID
	return decision{target: r.InjectedBaseURL, route: &r, before: old, referenced: referenced}, nil
}
func sameURL(a, b string) bool {
	na, ea := protocol.NormalizeBaseURL(a)
	nb, eb := protocol.NormalizeBaseURL(b)
	if ea == nil && eb == nil {
		return na == nb
	}
	return strings.TrimRight(a, "/") == strings.TrimRight(b, "/")
}
func (m *Manager) save(ctx context.Context, d decision) error {
	if d.route != nil {
		return m.Store.UpsertRoute(ctx, *d.route)
	}
	return nil
}
func (m *Manager) finish(ctx context.Context, d decision) error {
	if d.route != nil {
		attached := *d.route
		attached.Status = 3
		attached.UpdatedAtUTC = time.Now().UTC()
		return m.Store.UpsertRoute(ctx, attached)
	}
	return nil
}
func (m *Manager) undoRoute(ctx context.Context, d decision) error {
	if d.before != nil {
		return m.Store.UpsertRoute(ctx, *d.before)
	}
	if d.route != nil {
		return m.Store.DeleteRoute(ctx, d.route.RouteID)
	}
	return nil
}
func makeResult(p Profile, path, id string, agent int, d decision) Result {
	r := Result{SID: p.SID, Path: path, ProviderID: id, AgentType: agent, Status: 2, Mode: "ordinary", Ownership: "direct"}
	if d.route != nil {
		r.RouteID = d.route.RouteID
	}
	if d.bypass {
		r.Status = 7
	}
	return r
}
func (m *Manager) direct(ctx context.Context, p Profile, app string, detach bool) (Result, error) {
	path := configPath(p, app)
	agent := 0
	if app == "codex" {
		agent = 1
	}
	r := Result{SID: p.SID, Path: path, ProviderID: "direct", AgentType: agent, Ownership: "direct", Mode: "ordinary"}
	info, e := os.Lstat(path)
	if os.IsNotExist(e) {
		return r, nil
	}
	if e != nil {
		return r, e
	}
	if !info.Mode().IsRegular() {
		return r, problem("CONFIG_NOT_REGULAR")
	}
	content, e := os.ReadFile(path)
	if e != nil {
		return r, e
	}
	inspect, e := transform(app, content, "http://127.0.0.1:18080/r/inspection", false)
	if e != nil {
		return r, e
	}
	d, e := m.resolve(ctx, p, agent, "direct", inspect.Previous, detach)
	if e != nil {
		return r, e
	}
	if detach && d.before == nil {
		return r, nil
	}
	r = makeResult(p, path, "direct", agent, d)
	t, e := transform(app, content, d.target, d.bypass)
	if e != nil {
		return r, e
	}
	if e = m.save(ctx, d); e != nil {
		return r, e
	}
	var update FileUpdate
	if t.Changed {
		update, e = applyProfileFile(ctx, p, path, content, t.Content, m.BackupRoot)
		if e != nil {
			if update.Replaced {
				if rollback := update.Rollback(context.Background(), m.BackupRoot); rollback != nil {
					return r, errors.Join(e, rollback)
				}
			}
			return r, errors.Join(e, m.undoRoute(context.Background(), d))
		}
		r.Changed = true
	}
	if e = m.finish(ctx, d); e != nil {
		var rollback error
		if t.Changed {
			rollback = update.Rollback(context.Background(), m.BackupRoot)
		}
		if rollback != nil {
			return r, errors.Join(e, rollback)
		}
		return r, errors.Join(e, rollback, m.undoRoute(context.Background(), d))
	}
	_ = m.retireUnused(ctx, p)
	if d.route != nil {
		r.Status = 3
	}
	return r, nil
}
func (m *Manager) Reconcile(ctx context.Context, profiles []Profile) ([]Result, error) {
	return m.run(ctx, profiles, false)
}
func (m *Manager) DetachAll(ctx context.Context, profiles []Profile) ([]Result, error) {
	return m.run(ctx, profiles, true)
}
func (m *Manager) run(ctx context.Context, profiles []Profile, detach bool) ([]Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e := m.validate(); e != nil {
		return nil, e
	}
	var results []Result
	var errs []error
	for _, p := range profiles {
		if e := ctx.Err(); e != nil {
			return results, e
		}
		ccPath := filepath.Join(p.Home, ".cc-switch", "cc-switch.db")
		_, statErr := os.Lstat(ccPath)
		var cc CCInspection
		var ccErr error
		hasCC := statErr == nil
		if hasCC {
			cc, ccErr = InspectCC(ctx, ccPath)
		} else if !os.IsNotExist(statErr) {
			ccErr = statErr
		}
		for _, app := range []string{"claude", "codex"} {
			var rs []Result
			var e error
			if ccErr != nil {
				e = ccErr
				rs = []Result{{SID: p.SID, Path: ccPath, ProviderID: app, AgentType: 4, Ownership: "blocked", Mode: "unsupported"}}
			} else if hasCC {
				rs, e = m.ccApp(ctx, p, ccPath, app, cc, detach)
			} else {
				r, err := m.direct(ctx, p, app, detach)
				rs, e = []Result{r}, err
			}
			if e != nil {
				errs = append(errs, e)
				for i := range rs {
					rs[i].Status = 6
					rs[i].ErrorCode = errorCode(e)
				}
			}
			results = append(results, rs...)
		}
		if m.EnableDSH || detach {
			rs, e := m.dshProfile(ctx, p, detach)
			results = append(results, rs...)
			if e != nil {
				errs = append(errs, e)
			}
		}
	}
	if detach {
		routes, e := m.Store.ListRoutes(ctx)
		if e != nil {
			errs = append(errs, e)
		} else {
			for _, route := range routes {
				if route.AgentType == dshAgent {
					errs = append(errs, problem("DSH_DETACH_RECOVERY_REQUIRED"))
					break
				}
			}
		}
	}
	return results, errors.Join(errs...)
}

type ccPlanned struct {
	decision decision
	result   Result
}

func (m *Manager) ccApp(ctx context.Context, p Profile, path, app string, cc CCInspection, detach bool) ([]Result, error) {
	var providers []CCProvider
	var endpoints []CCEndpoint
	for _, v := range cc.Providers {
		if v.App == app {
			providers = append(providers, v)
		}
	}
	for _, v := range cc.Endpoints {
		if v.App == app {
			endpoints = append(endpoints, v)
		}
	}
	livePath := configPath(p, app)
	live, e := readOptional(livePath)
	if e != nil {
		return nil, e
	}
	lt, e := transform(app, live, "http://127.0.0.1:18080/r/inspection", false)
	if e != nil {
		return nil, e
	}
	proxy, present := cc.Proxies[app]
	mode, _ := DetectCCMode(app, proxy, present, lt.Previous)
	blocked := Result{SID: p.SID, Path: path, ProviderID: app, AgentType: 4, Mode: mode, Ownership: "blocked", Status: 5}
	if mode == "unsupported" || mode == "inconsistent" {
		return []Result{blocked}, problem("CCSWITCH_PROXY_STATE_INCONSISTENT")
	}
	if len(providers)+len(endpoints) == 0 {
		r, e := m.direct(ctx, p, app, detach)
		return []Result{r}, e
	}
	currentCount := 0
	for _, v := range providers {
		if v.Current {
			currentCount++
		}
	}
	if mode == "ordinary" && currentCount != 1 {
		return []Result{blocked}, problem("CCSWITCH_CURRENT_PROVIDER_INVALID")
	}
	var planned []ccPlanned
	var skipped []Result
	var mutations []CCMutation
	var targetCurrent string
	for _, v := range providers {
		inspect, e := ccTransform(app, v.Settings, "http://127.0.0.1:18080/r/inspection", false)
		if e != nil {
			if !v.Current {
				blockedItem := blocked
				blockedItem.ProviderID = ccIdentity(v)
				blockedItem.ErrorCode = errorCode(e)
				skipped = append(skipped, blockedItem)
				continue
			}
			return []Result{blocked}, e
		}
		d, e := m.resolve(ctx, p, 4, ccIdentity(v), inspect.Previous, detach)
		if e != nil {
			if !v.Current {
				item := blocked
				item.ProviderID = ccIdentity(v)
				item.ErrorCode = errorCode(e)
				skipped = append(skipped, item)
				continue
			}
			return []Result{blocked}, e
		}
		t, e := ccTransform(app, v.Settings, d.target, d.bypass)
		if e != nil {
			return []Result{blocked}, e
		}
		r := makeResult(p, path, ccIdentity(v), 4, d)
		r.Mode, r.Ownership, r.Changed = mode, "cc-switch", t.Changed
		planned = append(planned, ccPlanned{d, r})
		if t.Changed {
			mutations = append(mutations, CCMutation{App: app, ProviderID: v.ID, Expected: v.Settings, Updated: string(t.Content)})
		}
		if v.Current {
			targetCurrent = d.target
		}
	}
	for _, v := range endpoints {
		d, e := m.resolve(ctx, p, 4, endpointIdentity(v), v.URL, detach)
		if e != nil {
			item := blocked
			item.ProviderID = endpointIdentity(v)
			item.ErrorCode = errorCode(e)
			skipped = append(skipped, item)
			continue
		}
		r := makeResult(p, path, endpointIdentity(v), 4, d)
		r.Mode, r.Ownership, r.Changed = mode, "cc-switch", !sameURL(v.URL, d.target)
		planned = append(planned, ccPlanned{d, r})
		if r.Changed {
			id := v.ID
			mutations = append(mutations, CCMutation{App: app, ProviderID: v.ProviderID, EndpointID: &id, Expected: v.URL, Updated: d.target})
		}
	}
	var results []Result
	for _, v := range planned {
		results = append(results, v.result)
	}
	// Persist routes first, so a crash never leaves an injected URL without its origin.
	saved := 0
	undo := func() error {
		var es []error
		for i := saved - 1; i >= 0; i-- {
			es = append(es, m.undoRoute(context.Background(), planned[i].decision))
		}
		return errors.Join(es...)
	}
	for _, v := range planned {
		if e = m.save(ctx, v.decision); e != nil {
			return results, errors.Join(e, undo())
		}
		saved++
	}
	_, e = ApplyCC(ctx, path, m.BackupRoot, mutations)
	if e != nil {
		// Commit failures can be ambiguous. Only discard new origin records when
		// current live/database inspection proves none of their URLs was published.
		refs, inspectErr := m.references(ctx, p)
		if inspectErr != nil {
			return results, errors.Join(e, inspectErr)
		}
		for _, v := range planned {
			if v.decision.route != nil && referenced(refs, v.decision.route.InjectedBaseURL) {
				return results, e
			}
		}
		return results, errors.Join(e, undo())
	}
	var liveUpdate FileUpdate
	liveChanged := false
	if mode == "ordinary" && targetCurrent != "" {
		if detach {
			owned := false
			for _, v := range planned {
				if v.decision.before != nil && sameURL(lt.Previous, v.decision.before.InjectedBaseURL) {
					owned = true
				}
			}
			if !owned && !sameURL(lt.Previous, targetCurrent) {
				e = problem("DETACH_CONFIG_CHANGED")
			}
		}
		if e == nil {
			var t Transform
			t, e = transform(app, live, targetCurrent, true)
			if e == nil && t.Changed {
				liveUpdate, e = applyProfileFile(ctx, p, livePath, live, t.Content, m.BackupRoot)
				liveChanged = liveUpdate.Replaced
			}
		}
	}
	if e == nil {
		for _, v := range planned {
			if e = m.finish(ctx, v.decision); e != nil {
				break
			}
		}
	}
	if e != nil {
		var rollback []error
		var liveErr error
		if liveChanged {
			liveErr = liveUpdate.Rollback(context.Background(), m.BackupRoot)
			rollback = append(rollback, liveErr)
		}
		_, dbErr := ApplyCC(context.Background(), path, m.BackupRoot, reverseCC(mutations))
		rollback = append(rollback, dbErr)
		// If compensation lost a CAS race, retain origin records for any local
		// URLs still referenced by the database rather than creating dead routes.
		if dbErr == nil && liveErr == nil {
			rollback = append(rollback, undo())
		}
		return results, errors.Join(append([]error{e}, rollback...)...)
	}
	for i, v := range planned {
		if v.decision.route != nil {
			results[i].Status = 3
		}
	}
	_ = m.retireUnused(ctx, p)
	return append(results, skipped...), nil
}

func referenced(values []string, target string) bool {
	for _, value := range values {
		if sameURL(value, target) {
			return true
		}
	}
	return false
}

// references inspects every supported surface before allowing origin retirement.
// Any unreadable or unsupported surface makes retirement conservative.
func (m *Manager) referencesBase(ctx context.Context, p Profile) ([]string, error) {
	var refs []string
	for _, app := range []string{"claude", "codex"} {
		b, e := os.ReadFile(configPath(p, app))
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return nil, e
		}
		t, e := transform(app, b, "http://127.0.0.1:18080/r/inspection", false)
		if e != nil {
			return nil, e
		}
		refs = append(refs, t.Previous)
	}
	path := filepath.Join(p.Home, ".cc-switch", "cc-switch.db")
	if _, e := os.Lstat(path); e == nil {
		cc, e := InspectCC(ctx, path)
		if e != nil {
			return nil, e
		}
		for _, provider := range cc.Providers {
			t, e := ccTransform(provider.App, provider.Settings, "http://127.0.0.1:18080/r/inspection", false)
			if e != nil {
				return nil, e
			}
			refs = append(refs, t.Previous)
		}
		for _, endpoint := range cc.Endpoints {
			refs = append(refs, endpoint.URL)
		}
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	return refs, nil
}

func (m *Manager) references(ctx context.Context, p Profile) ([]string, error) {
	refs, e := m.referencesBase(ctx, p)
	if e != nil {
		return nil, e
	}
	roots, e := m.dshSavedRoots(p)
	if e != nil {
		return nil, e
	}
	if m.EnableDSH || len(roots) > 0 {
		if p.DSHOverlaysUnknown {
			return nil, problem("DSH_ROUTE_REFERENCES_UNVERIFIED")
		}
		p.DSHHomes = append(p.DSHHomes, roots...)
		docs, e := dshDocuments(p)
		if e != nil {
			return nil, e
		}
		for _, doc := range docs {
			if doc.issue != "" || doc.referencesUnknown {
				return nil, problem("DSH_ROUTE_REFERENCES_UNVERIFIED")
			}
			for _, candidate := range doc.candidates {
				refs = append(refs, candidate.current)
			}
		}
	}
	return refs, nil
}

func (m *Manager) retireUnused(ctx context.Context, p Profile) error {
	refs, e := m.references(ctx, p)
	if e != nil {
		return e
	}
	routes, e := m.Store.ListRoutes(ctx)
	if e != nil {
		return e
	}
	for _, route := range routes {
		if route.UserSID != p.SID || referenced(refs, route.InjectedBaseURL) {
			continue
		}
		app := ""
		switch route.AgentType {
		case 0:
			app = "claude"
		case 1:
			app = "codex"
		case 4:
			app = strings.Split(route.ProviderID, ":")[0]
		}
		if app != "claude" && app != "codex" {
			continue
		}
		if _, e := os.Stat(configPath(p, app)); e != nil {
			continue
		}
		if e = m.Store.DeleteRoute(ctx, route.RouteID); e != nil {
			return e
		}
	}
	return nil
}
