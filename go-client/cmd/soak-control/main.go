// soak-control is an isolated encrypted test server. It is never shipped in MSI/PKG payloads.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"endpointai/client/internal/contracts"
	"endpointai/client/internal/protocol"
	"github.com/google/uuid"
)

const enrollmentToken = "isolated-soak-enrollment"

type controller struct {
	mu            sync.Mutex
	key           []byte
	policy        contracts.Policy
	token         string
	deviceIDs     map[string]bool
	agentTypes    map[string]bool
	counts        map[string]int
	failPolicy    bool
	maxAgents     int
	maxEndpoints  int
	maxActivity   int
	activeAssets  int
	trafficAssets int
}

func newController(key []byte) *controller {
	return &controller{key: key, token: uuid.NewString(), failPolicy: true,
		deviceIDs: map[string]bool{}, agentTypes: map[string]bool{}, counts: map[string]int{},
		policy: contracts.Policy{SchemaVersion: 1, ServerInstanceID: uuid.NewString(), PolicyVersion: 2,
			Enabled: true, RouteMode: "passthroughOriginal", PollIntervalSeconds: 15, HeartbeatIntervalSeconds: 15,
			IssuedAtUTC: time.Now().UTC(), AllowlistedBaseURLs: []string{}}}
}

func (c *controller) snapshot() map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	counts := make(map[string]int, len(c.counts))
	for name, value := range c.counts {
		counts[name] = value
	}
	return map[string]any{"counts": counts, "distinct_device_ids": len(c.deviceIDs),
		"distinct_agent_types": len(c.agentTypes), "max_agents": c.maxAgents, "max_endpoint_assets": c.maxEndpoints,
		"max_activity_assets": c.maxActivity, "attached_endpoint_assets": c.activeAssets, "traffic_activity_assets": c.trafficAssets,
		"transport": "aes-gcm-hkdf", "policy_signed": true, "policy_interval_seconds": 15}
}

func (c *controller) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" && r.URL.Path == "/stats" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(c.snapshot())
		return
	}
	if r.Method != "POST" || r.URL.Path != "/api/transport/v1" {
		http.NotFound(w, r)
		return
	}
	var envelope protocol.Envelope
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20))
	if decoder.Decode(&envelope) != nil {
		w.WriteHeader(400)
		return
	}
	plain, err := protocol.Open(c.key, "soak", envelope.RequestID, envelope, "request")
	if err != nil {
		w.WriteHeader(400)
		return
	}
	var request protocol.InnerRequest
	if json.Unmarshal(plain, &request) != nil {
		w.WriteHeader(400)
		return
	}
	body, err := base64.StdEncoding.DecodeString(request.Body)
	if err != nil {
		w.WriteHeader(400)
		return
	}
	c.mu.Lock()
	status, response, headers := c.handle(request, body)
	c.mu.Unlock()
	raw, err := json.Marshal(response)
	if err == nil && strings.HasSuffix(request.Path, "/policy") && status == 200 {
		headers["X-SF-Policy-Signature"], err = protocol.Sign(raw, c.key)
	}
	if err != nil {
		w.WriteHeader(500)
		return
	}
	inner, _ := json.Marshal(protocol.InnerResponse{Status: status, Headers: headers, Body: base64.StdEncoding.EncodeToString(raw)})
	outer, err := protocol.Seal(c.key, "soak", envelope.RequestID, inner, "response")
	if err != nil {
		w.WriteHeader(500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(outer)
}

// Called with mu held; only counts and aggregate metadata leave the helper.
func (c *controller) handle(in protocol.InnerRequest, body []byte) (int, any, map[string]string) {
	headers := map[string]string{}
	reject := func(status int) (int, any, map[string]string) {
		c.counts["rejected"]++
		return status, map[string]string{"error": "synthetic_request_rejected"}, headers
	}
	if in.Path == "/api/v2/enroll" && in.Method == "POST" {
		var request contracts.DeviceEnrollmentRequest
		if in.Token != enrollmentToken || json.Unmarshal(body, &request) != nil {
			return reject(400)
		}
		if id, err := uuid.Parse(request.DeviceID); err != nil || id == uuid.Nil {
			return reject(400)
		}
		c.counts["enroll"]++
		c.deviceIDs[request.DeviceID] = true
		return 200, contracts.DeviceEnrollmentResponse{DeviceID: request.DeviceID, DeviceToken: c.token, EnrolledAtUTC: time.Now().UTC()}, headers
	}
	if in.Token != c.token {
		return reject(401)
	}
	switch {
	case strings.HasSuffix(in.Path, "/policy") && in.Method == "GET":
		device := strings.TrimSuffix(strings.TrimPrefix(in.Path, "/api/v2/devices/"), "/policy")
		if !c.deviceIDs[device] {
			return reject(400)
		}
		c.counts["policy"]++
		if c.failPolicy {
			c.failPolicy = false
			c.counts["injected_policy_unavailable"]++
			return 503, map[string]string{"error": "synthetic_transient_failure"}, headers
		}
		return 200, c.policy, headers
	case in.Path == "/api/v2/heartbeat" && in.Method == "POST":
		var request contracts.HeartbeatV2Request
		if json.Unmarshal(body, &request) != nil || !c.deviceIDs[request.Device.DeviceID] {
			return reject(400)
		}
		c.counts["heartbeat"]++
		c.counts["assets"] += len(request.Endpoints)
		c.maxAgents = max(c.maxAgents, len(request.Agents))
		c.maxEndpoints = max(c.maxEndpoints, len(request.Endpoints))
		c.maxActivity = max(c.maxActivity, len(request.Activity))
		for _, agent := range request.Agents {
			c.agentTypes[fmt.Sprint(int(agent.AgentType))] = true
		}
		for _, endpoint := range request.Endpoints {
			if endpoint.RouteStatus == contracts.RouteStatusAttached {
				c.activeAssets++
			}
		}
		for _, activity := range request.Activity {
			if activity.RequestCountSinceBoot > 0 {
				c.trafficAssets++
			}
		}
		return 200, contracts.HeartbeatV2Response{ServerTimeUTC: time.Now().UTC(), AcceptedPolicyVersion: c.policy.PolicyVersion, NextHeartbeatSeconds: 15}, headers
	case in.Path == "/api/v2/events/batch" && in.Method == "POST":
		var request contracts.EventBatchRequest
		if json.Unmarshal(body, &request) != nil || !c.deviceIDs[request.DeviceID] {
			return reject(400)
		}
		c.counts["event_batches"]++
		c.counts["events"] += len(request.Events)
		return 200, contracts.EventBatchResponse{Accepted: len(request.Events), Errors: []contracts.ApiError{}}, headers
	default:
		return reject(404)
	}
}

func readKey(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() != 32 {
		return nil, errors.New("SOAK_KEY_FILE_INVALID")
	}
	key, err := os.ReadFile(path)
	if err != nil || len(key) != 32 {
		return nil, errors.New("SOAK_KEY_FILE_INVALID")
	}
	return key, nil
}

func run(ctx context.Context, keyFile, readyFile, gatewayOrigin string) error {
	gateway, err := url.Parse(gatewayOrigin)
	if err != nil || gateway.Scheme != "http" || gateway.Hostname() != "127.0.0.1" || gateway.Port() == "" || gateway.User != nil || gateway.Path != "" || gateway.RawQuery != "" || gateway.Fragment != "" {
		return errors.New("SOAK_GATEWAY_ORIGIN_INVALID")
	}
	key, err := readKey(keyFile)
	if err != nil {
		return err
	}
	defer clear(key)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return errors.New("SOAK_LISTENER_FAILED")
	}
	defer listener.Close()
	controller := newController(key)
	controller.policy.RouteMode = "fixedGateway"
	controller.policy.GatewayOrigin = &gatewayOrigin
	controller.policy.AllowInsecureGateway = true
	server := &http.Server{Handler: controller, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192, ErrorLog: log.New(io.Discard, "", 0)}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	ready, _ := json.Marshal(map[string]string{"origin": "http://" + listener.Addr().String()})
	if err = os.WriteFile(readyFile, ready, 0600); err != nil {
		_ = server.Close()
		return errors.New("SOAK_READY_FILE_FAILED")
	}
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err = server.Shutdown(shutdown); err != nil {
			_ = server.Close()
		}
		return nil
	case err = <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			return errors.New("SOAK_SERVER_FAILED")
		}
		return nil
	}
}

func main() {
	key := flag.String("key-file", "", "Private 32-byte random test key file")
	ready := flag.String("ready-file", "", "Private readiness metadata file")
	gateway := flag.String("gateway-origin", "", "Loopback synthetic upstream origin")
	flag.Parse()
	if *key == "" || *ready == "" || *gateway == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "SOAK_ARGUMENTS_INVALID")
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, *key, *ready, *gateway); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
