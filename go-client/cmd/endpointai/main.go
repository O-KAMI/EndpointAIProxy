package main

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"endpointai/client/internal/app"
	"endpointai/client/internal/audit"
	"endpointai/client/internal/configuration"
	"endpointai/client/internal/contracts"
	"endpointai/client/internal/control"
	"endpointai/client/internal/diagnostics"
	"endpointai/client/internal/discovery"
	"endpointai/client/internal/instance"
	"endpointai/client/internal/observability"
	"endpointai/client/internal/platform"
	"endpointai/client/internal/protect"
	"endpointai/client/internal/protocol"
	"endpointai/client/internal/proxy"
	"endpointai/client/internal/state"
)

var version = "0.2.2"

type options struct {
	app                                                  app.Options
	maintenance, diagnosticsOutput, diagnosticsRequestID string
	diagnosticsSince                                     time.Duration
	profileRoot                                          string
	development                                          bool
	management                                           bool
	managementToken                                      string
}

func parse(args []string) (options, error) {
	cli := map[string]string{}
	known := map[string]bool{"auto-attach": true, "enable-dsh": true, "dsh-homes": true, "route-mode": true, "gateway-origin": true, "allow-insecure-gateway": true, "maintenance": true, "diagnostics-output": true, "diagnostics-since-hours": true, "diagnostics-request-id": true}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "--") {
			return options{}, errors.New("ARGUMENT_INVALID")
		}
		name, value, has := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
		name = strings.ToLower(name)
		if !known[name] {
			return options{}, errors.New("ARGUMENT_UNKNOWN")
		}
		if !has {
			if i+1 >= len(args) {
				return options{}, errors.New("ARGUMENT_VALUE_MISSING")
			}
			i++
			value = args[i]
		}
		cli[name] = value
	}
	get := func(flag, env, fallback string) string {
		if v, ok := cli[flag]; ok {
			return v
		}
		if v, ok := os.LookupEnv(env); ok {
			return v
		}
		return fallback
	}
	root := os.Getenv("SF_PROXY_DATA_ROOT")
	if root == "" {
		root = platform.DefaultDataRoot()
	}
	abs, e := filepath.Abs(root)
	if e != nil {
		return options{}, errors.New("DATA_ROOT_INVALID")
	}
	opts := options{app: app.Options{Version: version, Listen: "127.0.0.1:18080", DataRoot: abs}, maintenance: cli["maintenance"], diagnosticsOutput: cli["diagnostics-output"], diagnosticsRequestID: cli["diagnostics-request-id"], diagnosticsSince: 72 * time.Hour, profileRoot: os.Getenv("SF_PROXY_E2E_PROFILE_ROOT")}
	if opts.maintenance != "" && opts.maintenance != "detach-all" && opts.maintenance != "collect-diagnostics" {
		return opts, errors.New("MAINTENANCE_MODE_UNSUPPORTED")
	}
	if text := cli["diagnostics-since-hours"]; text != "" {
		hours, e := strconv.Atoi(text)
		if e != nil || hours < 1 || hours > 168 {
			return opts, errors.New("DIAGNOSTICS_INVALID_TIME_RANGE")
		}
		opts.diagnosticsSince = time.Duration(hours) * time.Hour
	}
	opts.development = strings.EqualFold(os.Getenv("DOTNET_ENVIRONMENT"), "Development") || strings.EqualFold(os.Getenv("ASPNETCORE_ENVIRONMENT"), "Development") || strings.EqualFold(os.Getenv("SF_PROXY_ENVIRONMENT"), "Development")
	if opts.profileRoot != "" {
		if !opts.development {
			return opts, errors.New("E2E_PROFILE_REQUIRES_DEVELOPMENT")
		}
		opts.profileRoot, e = filepath.Abs(opts.profileRoot)
		if e != nil {
			return opts, errors.New("E2E_PROFILE_INVALID")
		}
		if _, e = os.Stat(filepath.Join(opts.profileRoot, ".endpointai-e2e-profile")); e != nil {
			return opts, errors.New("E2E_PROFILE_MARKER_REQUIRED")
		}
	}
	opts.app.AutoAttach, e = strconv.ParseBool(get("auto-attach", "SF_PROXY_AUTO_ATTACH", "false"))
	if e != nil {
		return opts, errors.New("AUTO_ATTACH_INVALID")
	}
	opts.app.EnableDSH, e = strconv.ParseBool(get("enable-dsh", "SF_PROXY_ENABLE_DSH", "false"))
	if e != nil {
		return opts, errors.New("DSH_ENABLE_INVALID")
	}
	if value := get("dsh-homes", "SF_PROXY_DSH_HOMES", ""); value != "" {
		if !strings.HasPrefix(strings.TrimSpace(value), "[") || len(value) > 64<<10 || json.Unmarshal([]byte(value), &opts.app.DSHHomes) != nil || len(opts.app.DSHHomes) > 32 {
			return opts, errors.New("DSH_HOMES_INVALID")
		}
		for _, home := range opts.app.DSHHomes {
			if home == "" || !filepath.IsAbs(home) {
				return opts, errors.New("DSH_HOMES_INVALID")
			}
		}
	}
	mode := get("route-mode", "SF_PROXY_ROUTE_MODE", "passthroughOriginal")
	switch strings.ToLower(mode) {
	case "passthroughoriginal":
		mode = "passthroughOriginal"
	case "fixedgateway":
		mode = "fixedGateway"
	default:
		return opts, errors.New("ROUTE_MODE_INVALID")
	}
	gateway := get("gateway-origin", "SF_PROXY_GATEWAY_ORIGIN", "")
	var gatewayPtr *string
	if gateway != "" {
		gatewayPtr = &gateway
	}
	allow, e := strconv.ParseBool(get("allow-insecure-gateway", "SF_PROXY_ALLOW_INSECURE_GATEWAY", "false"))
	if e != nil {
		return opts, errors.New("GATEWAY_CONFIGURATION_INVALID")
	}
	opts.app.Policy = contracts.Policy{SchemaVersion: 1, ServerInstanceID: proxy.UUID(), PolicyVersion: 1, Enabled: true, RouteMode: mode, GatewayOrigin: gatewayPtr, AllowInsecureGateway: allow, PollIntervalSeconds: 60, HeartbeatIntervalSeconds: 60, IssuedAtUTC: time.Now().UTC()}
	if e = protocol.ValidatePolicy(opts.app.Policy); e != nil {
		return opts, errors.New("POLICY_CONFIGURATION_INVALID")
	}
	opts.management = strings.EqualFold(os.Getenv("SF_PROXY_ENABLE_MANAGEMENT_API"), "true")
	opts.managementToken = os.Getenv("SF_PROXY_MANAGEMENT_TOKEN")
	if id, e := uuid.Parse(os.Getenv("SF_PROXY_DEVICE_ID")); e == nil {
		opts.app.GatewayDeviceID = id.String()
	}
	if opts.management && len([]byte(opts.managementToken)) < 32 {
		return opts, errors.New("MANAGEMENT_TOKEN_INVALID")
	}
	if key := os.Getenv("SF_PROXY_GATEWAY_HMAC_KEY"); key != "" {
		opts.app.GatewayKey, e = base64.StdEncoding.DecodeString(key)
		if e != nil || len(opts.app.GatewayKey) < 32 {
			return opts, errors.New("GATEWAY_KEY_INVALID")
		}
	}
	if opts.maintenance != "" {
		return opts, nil
	}
	setting := func(env, name, fallback string) (string, error) {
		if v, ok := os.LookupEnv(env); ok {
			return v, nil
		}
		v, e := platform.ReadMachineSetting(name)
		if e != nil {
			return "", errors.New("MACHINE_CONFIGURATION_UNREADABLE")
		}
		if v == "" {
			v = fallback
		}
		return v, nil
	}
	origin, e := setting("SF_PROXY_CONTROL_ORIGIN", "ControlServerOrigin", "http://control.example.invalid:8080")
	if e != nil {
		return opts, e
	}
	if origin != "" {
		read := func(env, name string) (string, error) { return setting(env, name, "") }
		token, e := read("SF_PROXY_CONTROL_TOKEN", "ControlEnrollmentToken")
		if e != nil {
			return opts, e
		}
		hmac, e := read("SF_PROXY_CONTROL_HMAC_KEY", "ControlPolicyHmacKey")
		if e != nil {
			return opts, e
		}
		transport, e := read("SF_PROXY_CONTROL_TRANSPORT_KEY", "ControlTransportKey")
		if e != nil {
			return opts, e
		}
		pin, e := read("SF_PROXY_CONTROL_SERVER_CERTIFICATE_SPKI_SHA256", "ControlServerCertificateSpkiSha256")
		if e != nil {
			return opts, e
		}
		id, e := setting("SF_PROXY_CONTROL_TRANSPORT_KEY_ID", "ControlTransportKeyId", "production-2026-01")
		if e != nil {
			return opts, e
		}
		policyKey, e := base64.StdEncoding.DecodeString(hmac)
		if e != nil {
			return opts, errors.New("CONTROL_POLICY_KEY_INVALID")
		}
		var transportKey []byte
		if transport != "" {
			transportKey, e = base64.StdEncoding.DecodeString(transport)
			if e != nil {
				return opts, errors.New("CONTROL_TRANSPORT_KEY_INVALID")
			}
		}
		co := control.Options{Origin: origin, EnrollmentToken: token, CertificatePin: pin, PolicyKey: policyKey, TransportKey: transportKey, TransportKeyID: id}
		if _, e = control.New(co); e != nil {
			return opts, e
		}
		opts.app.Control = &co
	}
	return opts, nil
}

func profiles(opts options) func(context.Context) ([]platform.Profile, error) {
	if opts.profileRoot != "" {
		p := platform.Profile{SID: "S-1-5-21-control-e2e", Home: opts.profileRoot, Roaming: filepath.Join(opts.profileRoot, "AppData", "Roaming"), Local: filepath.Join(opts.profileRoot, "AppData", "Local"), SearchPaths: []string{filepath.Join(opts.profileRoot, ".local", "bin")}}
		return func(context.Context) ([]platform.Profile, error) { return []platform.Profile{p}, nil }
	}
	return platform.Profiles
}

func protector(root string) (state.Protector, error) {
	if runtime.GOOS == "windows" {
		return protect.NewDPAPI()
	}
	key := filepath.Join(root, "state", "machine.key")
	if info, e := os.Stat(filepath.Join(root, "state", "client.db")); e == nil && info.Size() > 0 {
		if _, e = os.Stat(key); os.IsNotExist(e) {
			return nil, errors.New("MACHINE_KEY_MISSING")
		}
	}
	return protect.NewFileKey(key)
}

func run(ctx context.Context, opts options) error {
	// Claim the legacy endpoint before opening/migrating state or touching Agent configs.
	// The .NET service has no Go file lock, so the listener is the cross-implementation guard.
	listener, e := net.Listen("tcp4", opts.app.Listen)
	if e != nil {
		return observability.Wrap("listener", "CLIENT_ENDPOINT_IN_USE", e)
	}
	defer listener.Close()
	if e = os.MkdirAll(opts.app.DataRoot, 0700); e != nil {
		return observability.Wrap("data_root", "DATA_ROOT_UNAVAILABLE", e)
	}
	lock, e := instance.Acquire(filepath.Join(opts.app.DataRoot, "client.lock"))
	if e != nil {
		return observability.Wrap("instance", "CLIENT_INSTANCE_LOCKED", e)
	}
	defer lock.Close()
	p, e := protector(opts.app.DataRoot)
	if e != nil {
		code := "MACHINE_KEY_UNAVAILABLE"
		if e.Error() == "MACHINE_KEY_MISSING" {
			code = "MACHINE_KEY_MISSING"
		}
		return observability.Wrap("machine_key", code, e)
	}
	store, e := state.Open(filepath.Join(opts.app.DataRoot, "state", "client.db"), p)
	if e != nil {
		return observability.Wrap("state_open", "CLIENT_STATE_UNAVAILABLE", e)
	}
	defer store.Close()
	logs := audit.New(opts.app.DataRoot)
	service, e := app.New(ctx, opts.app, store, logs, profiles(opts))
	if e != nil {
		return observability.Wrap("initialize", "CLIENT_INITIALIZATION_FAILED", e)
	}
	if opts.development && os.Getenv("SF_PROXY_BOOTSTRAP_UPSTREAM") != "" {
		original := os.Getenv("SF_PROXY_BOOTSTRAP_UPSTREAM")
		if _, e = protocol.NormalizeBaseURL(original); e != nil {
			return errors.New("BOOTSTRAP_UPSTREAM_INVALID")
		}
		id := os.Getenv("SF_PROXY_BOOTSTRAP_ROUTE_ID")
		if !proxy.ValidRouteID(id) {
			var b [16]byte
			hash := sha256.Sum256([]byte(proxy.UUID()))
			copy(b[:], hash[:16])
			id = base64.RawURLEncoding.EncodeToString(b[:])
		}
		now := time.Now().UTC()
		sid := os.Getenv("SF_PROXY_BOOTSTRAP_USER_SID")
		if sid == "" {
			sid = "S-1-0-0"
		}
		if e = store.UpsertRoute(ctx, contracts.Route{RouteID: id, UserSID: sid, AgentType: 0, ProviderID: "development", OriginalBaseURL: original, InjectedBaseURL: "http://" + opts.app.Listen + "/r/" + id, Status: 1, CreatedAtUTC: now, UpdatedAtUTC: now}); e != nil {
			return e
		}
	}
	gate := newDrainGate(service.HandlerWithManagement(opts.management, opts.managementToken))
	requestCtx, cancelRequests := context.WithCancel(context.Background())
	defer cancelRequests()
	server := &http.Server{Handler: gate, BaseContext: func(net.Listener) context.Context { return requestCtx }, ReadHeaderTimeout: 15 * time.Second, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 64 << 10}
	workersCtx, cancelWorkers := context.WithCancel(ctx)
	defer cancelWorkers()
	var workers sync.WaitGroup
	for _, worker := range []func(context.Context){service.RunControl, service.RunReconcile, service.RunUserIDRefresh} {
		workers.Add(1)
		go func(fn func(context.Context)) { defer workers.Done(); fn(workersCtx) }(worker)
	}
	// Audit outlives every producer, including HTTP handler completion.
	auditCtx, cancelAudit := context.WithCancel(context.Background())
	auditDone := make(chan struct{})
	go func() { defer close(auditDone); logs.Run(auditCtx) }()
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	logs.Log("SERVICE_STARTED", map[string]any{"version": opts.app.Version, "implementation": "go", "runId": proxy.UUID()})
	var serveError error
	select {
	case e = <-done:
		if !errors.Is(e, http.ErrServerClosed) {
			serveError = observability.Wrap("listener", "CLIENT_LISTENER_FAILED", e)
		}
	case <-ctx.Done():
	}
	cancelWorkers()
	handlersDone := gate.stop()
	shutdown, stop := context.WithTimeout(context.Background(), 10*time.Second)
	if e = server.Shutdown(shutdown); e != nil {
		_ = server.Close()
	}
	stop()
	cancelRequests()
	<-handlersDone
	workers.Wait()
	logs.Log("SERVICE_STOPPED", map[string]any{"graceful": e == nil})
	cancelAudit()
	<-auditDone
	return serveError
}

// Admission closes before waiting, avoiding a concurrent Add/Wait race.
type drainGate struct {
	handler  http.Handler
	mu       sync.Mutex
	active   int
	stopping bool
	done     chan struct{}
}

func newDrainGate(h http.Handler) *drainGate {
	return &drainGate{handler: h, done: make(chan struct{})}
}
func (g *drainGate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	if g.stopping {
		g.mu.Unlock()
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	g.active++
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		defer g.mu.Unlock()
		g.active--
		if g.stopping && g.active == 0 {
			close(g.done)
		}
	}()
	g.handler.ServeHTTP(w, r)
}
func (g *drainGate) stop() <-chan struct{} {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.stopping {
		g.stopping = true
		if g.active == 0 {
			close(g.done)
		}
	}
	return g.done
}
func startupFailure(err error) map[string]any {
	d := observability.Classify(err)
	if d.Code == "" {
		d.Code = "CLIENT_START_FAILED"
	}
	if d.Stage == "" {
		d.Stage = "startup"
	}
	return observability.Fields(d)
}

func maintenance(opts options) int {
	admin, e := platform.IsElevated()
	if e != nil || !admin {
		fmt.Fprintln(os.Stderr, "MAINTENANCE_ADMIN_REQUIRED")
		return 5
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	if opts.maintenance == "collect-diagnostics" {
		ps, e := profiles(opts)(ctx)
		if e != nil {
			ps = nil
		}
		agents, _ := discovery.Discover(ctx, ps)
		output := ""
		if opts.diagnosticsOutput != "" {
			output = filepath.Join(opts.diagnosticsOutput, "EndpointAIProxy-Diagnostics-"+proxy.UUID()+".zip")
		}
		diagnosticOptions := diagnostics.Options{ClientVersion: version, DataRoot: opts.app.DataRoot, OutputPath: output, Since: opts.diagnosticsSince, RequestID: opts.diagnosticsRequestID, Profiles: ps, Agents: agents}
		keyExists := runtime.GOOS == "windows"
		if _, err := os.Stat(filepath.Join(opts.app.DataRoot, "state", "machine.key")); err == nil {
			keyExists = true
		}
		if keyExists {
			if p, err := protector(opts.app.DataRoot); err == nil {
				if snapshot, err := state.OpenReadOnly(filepath.Join(opts.app.DataRoot, "state", "client.db"), p); err == nil {
					diagnosticOptions.Routes, _ = snapshot.ListRoutes(ctx)
					manager := configuration.Manager{Store: snapshot}
					cp := make([]configuration.Profile, 0, len(ps))
					for _, p := range ps {
						cp = append(cp, configuration.Profile{SID: p.SID, Home: p.Home, Roaming: p.Roaming, Local: p.Local, SearchPaths: p.SearchPaths, DSHHomes: opts.app.DSHHomes})
					}
					diagnosticOptions.Endpoints, _ = manager.Inspect(ctx, cp)
					snapshot.Close()
				}
			}
		}
		path, e := diagnostics.Collect(ctx, diagnosticOptions)
		if e != nil {
			fmt.Fprintln(os.Stderr, "DIAGNOSTICS_COLLECTION_FAILED")
			return 1
		}
		f, e := os.Open(path)
		if e != nil {
			return 1
		}
		h := sha256.New()
		length, e := io.Copy(h, f)
		f.Close()
		if e != nil {
			return 1
		}
		partial := false
		z, e := zip.OpenReader(path)
		if e == nil {
			for _, entry := range z.File {
				if entry.Name == "manifest.json" {
					r, e := entry.Open()
					if e == nil {
						var manifest struct{ Partial bool }
						_ = json.NewDecoder(r).Decode(&manifest)
						partial = manifest.Partial
						r.Close()
					}
				}
			}
			z.Close()
		}
		fmt.Printf("Diagnostic package created.\nPath   : %s\nSize   : %d bytes\nSHA256 : %x\n", path, length, h.Sum(nil))
		if partial {
			fmt.Println("Status : Partial")
			return 2
		}
		fmt.Println("Status : Complete")
		return 0
	}
	l, e := net.Listen("tcp4", opts.app.Listen)
	if e != nil {
		fmt.Fprintln(os.Stderr, "CLIENT_MUST_BE_STOPPED")
		return 1
	}
	defer l.Close()
	if _, e = os.Stat(filepath.Join(opts.app.DataRoot, "state", "client.db")); os.IsNotExist(e) {
		return 0
	}
	lock, e := instance.Acquire(filepath.Join(opts.app.DataRoot, "client.lock"))
	if e != nil {
		return 1
	}
	defer lock.Close()
	p, e := protector(opts.app.DataRoot)
	if e != nil {
		return 1
	}
	store, e := state.Open(filepath.Join(opts.app.DataRoot, "state", "client.db"), p)
	if e != nil {
		return 1
	}
	defer store.Close()
	ps, e := profiles(opts)(ctx)
	if e != nil {
		return 1
	}
	m := configuration.Manager{Store: store, Origin: "http://" + opts.app.Listen, BackupRoot: filepath.Join(opts.app.DataRoot, "config-backups")}
	cp, e := app.PrepareConfigurationProfiles(ctx, &m, ps, opts.app.DSHHomes, true)
	if e != nil {
		return 1
	}
	results, e := m.DetachAll(ctx, cp)
	if e != nil {
		return 1
	}
	for _, r := range results {
		if r.ErrorCode != "" && r.Status != int(contracts.RouteStatusUnsupported) {
			return 1
		}
	}
	return 0
}

func main() {
	if len(os.Args) == 2 && (os.Args[1] == "--version" || os.Args[1] == "-version") {
		fmt.Println(version)
		return
	}
	opts, e := parse(os.Args[1:])
	if e != nil {
		fmt.Fprintln(os.Stderr, "CLIENT_CONFIGURATION_INVALID")
		os.Exit(2)
	}
	if opts.maintenance != "" {
		os.Exit(maintenance(opts))
	}
	if runtime.GOOS != "windows" && runtime.GOOS != "darwin" {
		fmt.Fprintln(os.Stderr, "CLIENT_PLATFORM_UNSUPPORTED")
		os.Exit(1)
	}
	if e = platform.RunService("SfEndpointAIProxy", func(ctx context.Context) error { return run(ctx, opts) }); e != nil {
		_ = json.NewEncoder(os.Stderr).Encode(startupFailure(e))
		os.Exit(1)
	}
}
