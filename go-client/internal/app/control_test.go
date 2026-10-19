package app

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"endpointai/client/internal/audit"
	"endpointai/client/internal/contracts"
	"endpointai/client/internal/control"
	"endpointai/client/internal/installguard"
	"endpointai/client/internal/observability"
	"endpointai/client/internal/platform"
	"endpointai/client/internal/protect"
	"endpointai/client/internal/protocol"
	"endpointai/client/internal/state"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeControl struct {
	mu                 sync.Mutex
	server             *httptest.Server
	key                []byte
	policy             contracts.Policy
	counts             map[string]int
	outer401, inner401 bool
	badPolicySignature bool
	receiptConflict    bool
	command            *contracts.SignedRemoteCommand
	deviceIDs          []string
}

func testPolicy(version int64) contracts.Policy {
	return contracts.Policy{SchemaVersion: 1, ServerInstanceID: "40000000-0000-0000-0000-000000000004", PolicyVersion: version, Enabled: true, RouteMode: "passthroughOriginal", PollIntervalSeconds: 60, HeartbeatIntervalSeconds: 60, IssuedAtUTC: time.Now().UTC(), AllowlistedBaseURLs: []string{}}
}
func newFakeControl(t *testing.T) *fakeControl {
	t.Helper()
	f := &fakeControl{key: make([]byte, 32), policy: testPolicy(2), counts: map[string]int{}}
	for i := range f.key {
		f.key[i] = byte(i)
	}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}
func (f *fakeControl) options() control.Options {
	return control.Options{Origin: f.server.URL, EnrollmentToken: "synthetic-enrollment", PolicyKey: f.key, TransportKey: f.key, TransportKeyID: "test"}
}
func (f *fakeControl) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.outer401 {
		w.WriteHeader(401)
		return
	}
	var e protocol.Envelope
	if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
		w.WriteHeader(400)
		return
	}
	b, err := protocol.Open(f.key, "test", e.RequestID, e, "request")
	if err != nil {
		w.WriteHeader(400)
		return
	}
	var in protocol.InnerRequest
	if json.Unmarshal(b, &in) != nil {
		w.WriteHeader(400)
		return
	}
	raw, _ := base64.StdEncoding.DecodeString(in.Body)
	status := 200
	headers := map[string]string{"X-Request-ID": uuid.NewString()}
	var response any
	kind := "unknown"
	switch {
	case in.Path == "/api/v2/enroll":
		kind = "enroll"
		var request contracts.DeviceEnrollmentRequest
		json.Unmarshal(raw, &request)
		f.deviceIDs = append(f.deviceIDs, request.DeviceID)
		response = contracts.DeviceEnrollmentResponse{DeviceID: request.DeviceID, DeviceToken: fmt.Sprintf("synthetic-token-%d", len(f.deviceIDs)), EnrolledAtUTC: time.Now().UTC()}
	case strings.HasSuffix(in.Path, "/policy"):
		kind = "policy"
		if f.inner401 {
			status = 401
			f.inner401 = false
			response = map[string]string{"error": "expired"}
		} else {
			response = f.policy
		}
	case in.Path == "/api/v2/heartbeat":
		kind = "heartbeat"
		response = contracts.HeartbeatV2Response{ServerTimeUTC: time.Now().UTC(), AcceptedPolicyVersion: f.policy.PolicyVersion, NextHeartbeatSeconds: 60, Command: f.command}
	case in.Path == "/api/v2/events/batch":
		kind = "events"
		var request contracts.EventBatchRequest
		json.Unmarshal(raw, &request)
		response = contracts.EventBatchResponse{Accepted: len(request.Events), Errors: []contracts.ApiError{}}
	case strings.HasSuffix(in.Path, "/status"):
		kind = "status"
		if f.receiptConflict {
			status = 409
		}
		response = map[string]bool{"ok": true}
	default:
		status = 404
		response = map[string]string{"error": "unknown"}
	}
	f.counts[kind]++
	b, _ = json.Marshal(response)
	if kind == "policy" && status == 200 {
		headers["X-SF-Policy-Signature"], _ = protocol.Sign(b, f.key)
		if f.badPolicySignature {
			headers["X-SF-Policy-Signature"] = "v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		}
	}
	inner, _ := json.Marshal(protocol.InnerResponse{Status: status, Body: base64.StdEncoding.EncodeToString(b), Headers: headers})
	out, err := protocol.Seal(f.key, "test", e.RequestID, inner, "response")
	if err != nil {
		w.WriteHeader(500)
		return
	}
	json.NewEncoder(w).Encode(out)
}
func (f *fakeControl) count(key string) int { f.mu.Lock(); defer f.mu.Unlock(); return f.counts[key] }
func newControlApp(t *testing.T, f *fakeControl) *App {
	t.Helper()
	dir := t.TempDir()
	p, e := protect.NewFileKey(filepath.Join(dir, "key"))
	if e != nil {
		t.Fatal(e)
	}
	store, e := state.Open(filepath.Join(dir, "state.db"), p)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { store.Close() })
	opts := f.options()
	a, e := New(context.Background(), Options{Version: "test", Listen: "127.0.0.1:18080", DataRoot: dir, Policy: testPolicy(1), Control: &opts}, store, audit.New(filepath.Join(dir, "logs")), func(context.Context) ([]platform.Profile, error) { return []platform.Profile{}, nil })
	if e != nil {
		t.Fatal(e)
	}
	return a
}
func signedCommand(t *testing.T, a *App, kind contracts.RemoteCommandType) contracts.SignedRemoteCommand {
	t.Helper()
	p := contracts.RemoteCommandPayload{SchemaVersion: 1, CommandID: uuid.NewString(), DeviceID: a.DeviceID(), Type: kind, IssuedAtUTC: time.Now().UTC().Add(-time.Second), ExpiresAtUTC: time.Now().UTC().Add(time.Hour)}
	return signPayload(t, a, p)
}
func signPayload(t *testing.T, a *App, p contracts.RemoteCommandPayload) contracts.SignedRemoteCommand {
	t.Helper()
	b, e := protocol.CommandBody(p)
	if e != nil {
		t.Fatal(e)
	}
	h := hmac.New(sha256.New, a.Client.Options.PolicyKey)
	h.Write([]byte("sf-endpoint-ai-command-v1"))
	sig, e := protocol.Sign(b, h.Sum(nil))
	if e != nil {
		t.Fatal(e)
	}
	return contracts.SignedRemoteCommand{Payload: p, Signature: sig}
}

func TestAESControlSyncCadenceEventsAndReenrollment(t *testing.T) {
	f := newFakeControl(t)
	a := newControlApp(t, f)
	ctx := context.Background()
	a.AddEvent("SYNTHETIC", "Synthetic integration event.")
	if e := a.Sync(ctx); e != nil {
		t.Fatal(e)
	}
	id := a.DeviceID()
	if f.count("enroll") != 1 || f.count("policy") != 1 || f.count("heartbeat") != 1 || f.count("events") != 1 || a.Policy().PolicyVersion != 2 {
		t.Fatal("initial enrollment/sync incomplete")
	}
	a.mu.RLock()
	lastSuccess := *a.lastControl
	a.mu.RUnlock()
	for i := 0; i < 3; i++ {
		if e := a.Sync(ctx); e != nil {
			t.Fatal(e)
		}
	}
	if f.count("policy") != 1 || f.count("heartbeat") != 1 || f.count("events") != 1 {
		t.Fatal("Sync ignored next-policy/heartbeat/event cadence")
	}
	a.mu.RLock()
	noNetworkSuccess := *a.lastControl
	a.mu.RUnlock()
	if !noNetworkSuccess.Equal(lastSuccess) {
		t.Error("no-network Sync advanced last successful control timestamp")
	}
	f.mu.Lock()
	f.outer401 = true
	f.mu.Unlock()
	a.nextPolicy = time.Time{}
	if e := a.Sync(ctx); e == nil {
		t.Fatal("outer unauthorized accepted")
	}
	if f.count("enroll") != 1 {
		t.Fatal("outer unauthorized triggered enrollment")
	}
	f.mu.Lock()
	f.outer401 = false
	f.inner401 = true
	f.mu.Unlock()
	a.nextPolicy = time.Time{}
	if e := a.Sync(ctx); e == nil || e.Error() != "CONTROL_DEVICE_REENROLLED" {
		t.Fatalf("authenticated unauthorized not reenrolled: %v", e)
	}
	if f.count("enroll") != 2 || a.DeviceID() != id {
		t.Fatal("reenrollment changed device identity")
	}
	f.mu.Lock()
	if f.deviceIDs[0] != f.deviceIDs[1] {
		t.Fatal("server observed changed identity")
	}
	f.mu.Unlock()
	if e := a.Sync(ctx); e != nil {
		t.Fatal(e)
	}
}
func TestRemoteDisableEnableAndReplay(t *testing.T) {
	f := newFakeControl(t)
	a := newControlApp(t, f)
	ctx := context.Background()
	if e := a.Sync(ctx); e != nil {
		t.Fatal(e)
	}
	disable := signedCommand(t, a, contracts.RemoteCommandTypeDisableProxy)
	f.mu.Lock()
	f.command = &disable
	f.mu.Unlock()
	a.nextHeartbeat = time.Time{}
	if e := a.Sync(ctx); e != nil {
		t.Fatal(e)
	}
	if a.Enabled() {
		t.Fatal("disable did not persist operation")
	}
	receipt, e := a.Store.LoadCommandReceipt(ctx, disable.Payload.CommandID)
	if e != nil || receipt.Status != contracts.RemoteCommandStatusSucceeded {
		t.Fatalf("receipt %+v %v", receipt, e)
	}
	var profiles atomic.Int32
	a.Profiles = func(context.Context) ([]platform.Profile, error) { profiles.Add(1); return []platform.Profile{}, nil }
	if e = a.ApplyCommand(ctx, disable, a.credential.Token); e != nil {
		t.Fatal(e)
	}
	if profiles.Load() != 0 {
		t.Fatal("terminal replay executed operation")
	}
	enable := signedCommand(t, a, contracts.RemoteCommandTypeEnableProxy)
	if e = a.ApplyCommand(ctx, enable, a.credential.Token); e != nil {
		t.Fatal(e)
	}
	if !a.Enabled() {
		t.Fatal("enable did not persist operation")
	}
}
func TestOfflinePolicyCacheAndRollback(t *testing.T) {
	f := newFakeControl(t)
	a := newControlApp(t, f)
	ctx := context.Background()
	if e := a.Sync(ctx); e != nil {
		t.Fatal(e)
	}
	old := a.Policy()
	if e := a.ApplyPolicy(ctx, testPolicy(1), "ignored"); e != nil {
		t.Fatal(e)
	}
	if a.Policy().PolicyVersion != old.PolicyVersion {
		t.Fatal("policy rollback accepted")
	}
	opts := a.Options
	offline, e := New(ctx, opts, a.Store, a.Audit, a.Profiles)
	if e != nil {
		t.Fatal(e)
	}
	if offline.DeviceID() != a.DeviceID() || offline.Policy().PolicyVersion != 2 {
		t.Fatal("restart lost cached state")
	}
	f.server.Close()
	if e = offline.Sync(ctx); e == nil {
		t.Fatal("offline sync unexpectedly succeeded")
	}
	if offline.Policy().PolicyVersion != 2 {
		t.Fatal("offline failure discarded cached policy")
	}
}
func TestConcurrentExecutingCommandReplayRunsOnce(t *testing.T) {
	f := newFakeControl(t)
	a := newControlApp(t, f)
	command := signedCommand(t, a, contracts.RemoteCommandTypeDisableProxy)
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	a.Profiles = func(context.Context) ([]platform.Profile, error) {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
		}
		return []platform.Profile{}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errorsOut := make(chan error, 2)
	go func() { errorsOut <- a.ApplyCommand(ctx, command, "synthetic") }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("first command did not execute")
	}
	started := make(chan struct{})
	go func() { close(started); errorsOut <- a.ApplyCommand(ctx, command, "synthetic") }()
	<-started
	time.Sleep(50 * time.Millisecond)
	close(release)
	for i := 0; i < 2; i++ {
		if e := <-errorsOut; e != nil && !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("same executing command ran %d times", calls.Load())
	}
}

func TestCommandExpiryDeviceBindingAndRecovery(t *testing.T) {
	f := newFakeControl(t)
	a := newControlApp(t, f)
	ctx := context.Background()
	var calls atomic.Int32
	a.Profiles = func(context.Context) ([]platform.Profile, error) { calls.Add(1); return []platform.Profile{}, nil }
	wrong := signedCommand(t, a, contracts.RemoteCommandTypeDisableProxy)
	wrong.Payload.DeviceID = uuid.NewString()
	wrong = signPayload(t, a, wrong.Payload)
	if e := a.ApplyCommand(ctx, wrong, "synthetic"); e == nil || e.Error() != "COMMAND_DEVICE_MISMATCH" {
		t.Fatalf("wrong-device command: %v", e)
	}
	if calls.Load() != 0 {
		t.Fatal("wrong-device operation executed")
	}
	expired := signedCommand(t, a, contracts.RemoteCommandTypeDisableProxy)
	expired.Payload.IssuedAtUTC = time.Now().UTC().Add(-time.Hour)
	expired.Payload.ExpiresAtUTC = time.Now().UTC().Add(-time.Minute)
	expired = signPayload(t, a, expired.Payload)
	if e := a.ApplyCommand(ctx, expired, "synthetic"); e != nil {
		t.Fatal(e)
	}
	r, e := a.Store.LoadCommandReceipt(ctx, expired.Payload.CommandID)
	if e != nil || r.Status != contracts.RemoteCommandStatusFailed || r.ResultCode == nil || *r.ResultCode != "COMMAND_EXPIRED" {
		t.Fatalf("expired receipt %+v %v", r, e)
	}
	if calls.Load() != 0 {
		t.Fatal("expired operation executed")
	}
	// A command interrupted after persisting Executing resumes even if its original expiry passes.
	now := time.Now().UTC()
	device := a.DeviceID()
	pending := state.CommandReceipt{CommandID: uuid.NewString(), DeviceID: &device, Type: contracts.RemoteCommandTypeDisableProxy, Status: contracts.RemoteCommandStatusExecuting, ReceivedAtUTC: now.Add(-time.Hour), IssuedAtUTC: &expired.Payload.IssuedAtUTC, ExpiresAtUTC: &expired.Payload.ExpiresAtUTC}
	if e = a.Store.SaveCommandReceipt(ctx, pending); e != nil {
		t.Fatal(e)
	}
	if e = a.Sync(ctx); e != nil {
		t.Fatal(e)
	}
	r, e = a.Store.LoadCommandReceipt(ctx, pending.CommandID)
	if e != nil || r.Status != contracts.RemoteCommandStatusSucceeded || a.Enabled() {
		t.Fatalf("interrupted command did not resume: %+v %v", r, e)
	}
}

func TestConcurrentSyncEnrollsOnce(t *testing.T) {
	f := newFakeControl(t)
	a := newControlApp(t, f)
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() { results <- a.Sync(context.Background()) }()
	}
	for i := 0; i < 2; i++ {
		if e := <-results; e != nil {
			t.Fatal(e)
		}
	}
	if f.count("enroll") != 1 || f.count("policy") != 1 || f.count("heartbeat") != 1 {
		t.Fatal("concurrent Sync duplicated control exchanges")
	}
}
func TestTamperedPolicyAndCommandDoNotChangeState(t *testing.T) {
	f := newFakeControl(t)
	a := newControlApp(t, f)
	ctx := context.Background()
	if e := a.Sync(ctx); e != nil {
		t.Fatal(e)
	}
	f.mu.Lock()
	f.policy = testPolicy(3)
	f.badPolicySignature = true
	f.mu.Unlock()
	a.nextPolicy = time.Time{}
	if e := a.Sync(ctx); e == nil {
		t.Fatal("tampered policy accepted")
	}
	if a.Policy().PolicyVersion != 2 {
		t.Fatal("invalid policy replaced cached version")
	}
	cmd := signedCommand(t, a, contracts.RemoteCommandTypeDisableProxy)
	cmd.Signature = "v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	f.mu.Lock()
	f.badPolicySignature = false
	f.policy = testPolicy(2)
	f.command = &cmd
	f.mu.Unlock()
	a.nextHeartbeat = time.Time{}
	if e := a.Sync(ctx); e == nil {
		t.Fatal("tampered command accepted")
	}
	if !a.Enabled() {
		t.Fatal("tampered command disabled proxy")
	}
	if r, e := a.Store.LoadCommandReceipt(ctx, cmd.Payload.CommandID); e != nil || r != nil {
		t.Fatalf("tampered command created receipt %+v %v", r, e)
	}
}

func TestPolicyFailureDoesNotSuppressHeartbeatCommandsOrEvents(t *testing.T) {
	f := newFakeControl(t)
	a := newControlApp(t, f)
	ctx := context.Background()
	if err := a.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	cmd := signedCommand(t, a, contracts.RemoteCommandTypeDisableProxy)
	f.mu.Lock()
	f.badPolicySignature = true
	f.policy = testPolicy(3)
	f.command = &cmd
	f.mu.Unlock()
	a.nextPolicy = time.Time{}
	a.nextHeartbeat = time.Time{}
	a.AddEvent("SYNTHETIC", "Synthetic event.")
	if err := a.Sync(ctx); err == nil {
		t.Fatal("invalid signed policy accepted")
	}
	if a.Policy().PolicyVersion != 2 {
		t.Fatal("invalid policy applied")
	}
	if a.Enabled() || f.count("heartbeat") != 2 || f.count("events") == 0 {
		t.Fatal("policy failure starved healthy stages/command")
	}
	if a.nextPolicy.Before(time.Now()) {
		t.Fatal("failed policy missing bounded retry")
	}
	// Heartbeat has its own deadline, unaffected by the policy backoff.
	a.nextHeartbeat = time.Time{}
	if err := a.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if f.count("heartbeat") != 3 || f.count("policy") != 2 {
		t.Fatal("stage deadlines not independent")
	}
}

func TestEventAndReceiptFailuresDoNotSuppressHeartbeat(t *testing.T) {
	f := newFakeControl(t)
	a := newControlApp(t, f)
	ctx := context.Background()
	if err := a.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	original := a.Client.HTTP.Transport
	a.Client.HTTP.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		// Inspect only synthetic plaintext prior to encrypted transport; no real credentials are used.
		if strings.HasSuffix(r.URL.Path, "/events/batch") || strings.HasSuffix(r.URL.Path, "/status") {
			return nil, errors.New("synthetic-secret-error")
		}
		return original.RoundTrip(r)
	})
	cmd := signedCommand(t, a, contracts.RemoteCommandTypeDisableProxy)
	f.mu.Lock()
	f.command = &cmd
	f.mu.Unlock()
	a.nextHeartbeat = time.Time{}
	a.AddEvent("SYNTHETIC", "Synthetic.")
	if err := a.Sync(ctx); err == nil {
		t.Fatal("events failure missing")
	}
	if a.Enabled() || len(a.pendingReceipts) != 1 {
		t.Fatal("receipt failure lost command execution/pending status")
	}
	a.nextHeartbeat = time.Time{}
	if err := a.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if f.count("heartbeat") != 3 {
		t.Fatal("independent failure blocked heartbeat")
	}
	a.Client.HTTP.Transport = original
	a.nextEvents = time.Time{}
	a.nextReceipts = time.Time{}
	if err := a.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if len(a.pendingReceipts) != 0 || len(a.events) != 0 {
		t.Fatal("retry did not recover pending state")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestControlFailureRetainsSafeCorrelation(t *testing.T) {
	f := newFakeControl(t)
	a := newControlApp(t, f)
	ctx := context.Background()
	if err := a.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.badPolicySignature = true
	f.mu.Unlock()
	a.nextPolicy = time.Time{}
	err := a.Sync(ctx)
	var detail *observability.Error
	if !errors.As(err, &detail) {
		t.Fatalf("missing typed evidence: %v", err)
	}
	if detail.Detail.Class != "SIGNATURE_INVALID" || detail.Detail.Stage != "policy_verify" || detail.Detail.ControlRequestID == "" || detail.Detail.ServerRequestID == "" {
		t.Fatal(detail.Detail)
	}
	if detail.Detail.ControlRequestID == detail.Detail.ServerRequestID {
		t.Fatal("control and business IDs conflated")
	}
	if len(a.controlFailures) != 1 || a.controlFailures["policy"].Count != 1 {
		t.Fatal("phase failure unavailable")
	}
	f.mu.Lock()
	f.badPolicySignature = false
	f.mu.Unlock()
	a.nextPolicy = time.Time{}
	if err := a.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if len(a.controlFailures) != 0 || a.lastControlError != nil {
		t.Fatal("recovery not observable")
	}
}

func TestTerminalReceiptConflictStopsRetryButRetainsReceipt(t *testing.T) {
	f := newFakeControl(t)
	a := newControlApp(t, f)
	ctx := context.Background()
	r := state.CommandReceipt{CommandID: uuid.NewString(), Status: contracts.RemoteCommandStatusSucceeded, ReceivedAtUTC: time.Now().UTC(), ResultCode: ptr("OK"), DeviceID: ptr(a.DeviceID())}
	if err := a.Store.SaveCommandReceipt(ctx, r); err != nil {
		t.Fatal(err)
	}
	f.receiptConflict = true
	a.pendingReceipts[r.CommandID] = r
	if err := a.reportCommand(ctx, r, "synthetic-token"); err != nil {
		t.Fatal(err)
	}
	if len(a.pendingReceipts) != 0 {
		t.Fatal("permanent conflict retried")
	}
	if got, err := a.Store.LoadCommandReceipt(ctx, r.CommandID); err != nil || got == nil || got.Status != r.Status {
		t.Fatal("receipt evidence lost", err)
	}
}
func TestCompiledAllowlistDistinguishesNilAndEmpty(t *testing.T) {
	a := newControlApp(t, newFakeControl(t))
	if a.Bypass("https://internal.example.invalid/ccr") {
		t.Fatal("empty allowlist treated as nil")
	}
	p := testPolicy(3)
	p.AllowlistedBaseURLs = nil
	if err := a.ApplyPolicy(context.Background(), p, "fixture"); err != nil {
		t.Fatal(err)
	}
	if !a.Bypass("https://internal.example.invalid/ccr/") {
		t.Fatal("nil fallback lost")
	}
	p = testPolicy(4)
	p.AllowlistedBaseURLs = []string{"https://fixture.example/v1"}
	if err := a.ApplyPolicy(context.Background(), p, "fixture"); err != nil {
		t.Fatal(err)
	}
	p.AllowlistedBaseURLs[0] = "https://changed.example"
	if !a.Bypass("https://fixture.example/v1") || a.Bypass("https://changed.example") {
		t.Fatal("policy snapshot was mutable")
	}
}

func TestInstallationGuardPausesControlAndOperationsUntilCommit(t *testing.T) {
	f := newFakeControl(t)
	a := newControlApp(t, f)
	ctx := context.Background()
	if err := installguard.Begin(a.Options.DataRoot, "fixture-install"); err != nil {
		t.Fatal(err)
	}
	if err := a.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if f.count("enroll") != 0 {
		t.Fatal("control ran during installation")
	}
	if _, _, err := a.operationOnce(ctx, contracts.RemoteCommandTypeDisableProxy); err == nil {
		t.Fatal("command executed before commit")
	}
	if err := a.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if err := installguard.Release(a.Options.DataRoot, "fixture-install"); err != nil {
		t.Fatal(err)
	}
	if err := a.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if f.count("enroll") != 1 {
		t.Fatal("control did not resume after commit")
	}
}
