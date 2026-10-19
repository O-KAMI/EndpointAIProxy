package main

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"endpointai/client/internal/contracts"
	"endpointai/client/internal/control"
	"github.com/google/uuid"
)

func TestEncryptedControlRecoveryAndCounters(t *testing.T) {
	key := make([]byte, 32)
	controller := newController(key)
	server := httptest.NewServer(controller)
	defer server.Close()
	client, err := control.New(control.Options{Origin: server.URL, EnrollmentToken: enrollmentToken, PolicyKey: key, TransportKey: key, TransportKeyID: "soak"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	deviceID := uuid.NewString()
	credential, err := client.Enroll(ctx, contracts.DeviceEnrollmentRequest{SchemaVersion: 2, DeviceID: deviceID})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = client.Policy(ctx, deviceID, credential.DeviceToken); err == nil {
		t.Fatal("injected transient failure was not returned")
	}
	policy, _, err := client.Policy(ctx, deviceID, credential.DeviceToken)
	if err != nil || policy.PolicyVersion != 2 {
		t.Fatalf("signed policy after recovery: %+v %v", policy, err)
	}
	_, err = client.Heartbeat(ctx, contracts.HeartbeatV2Request{Device: contracts.DeviceIdentity{DeviceID: deviceID},
		Agents:    []contracts.AgentInventoryItem{{AgentType: contracts.AgentType(1)}},
		Endpoints: []contracts.AgentEndpointAsset{{RouteStatus: contracts.RouteStatusAttached}},
		Activity:  []contracts.ProxyActivityAsset{{RequestCountSinceBoot: 1}}}, credential.DeviceToken)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Events(ctx, contracts.EventBatchRequest{DeviceID: deviceID, Events: []contracts.EndpointEvent{{EventID: uuid.NewString(), OccurredAtUTC: time.Now().UTC()}}}, credential.DeviceToken)
	if err != nil {
		t.Fatal(err)
	}
	stats := controller.snapshot()
	counts := stats["counts"].(map[string]int)
	if counts["enroll"] != 1 || counts["policy"] != 2 || counts["heartbeat"] != 1 || counts["assets"] != 1 || counts["events"] != 1 || counts["injected_policy_unavailable"] != 1 || stats["distinct_device_ids"] != 1 || stats["attached_endpoint_assets"] != 1 || stats["traffic_activity_assets"] != 1 {
		t.Fatalf("unexpected aggregate stats: %v", stats)
	}
	if _, _, err = client.Policy(ctx, deviceID, "invalid-synthetic-token"); err == nil {
		t.Fatal("wrong token accepted")
	}
}

func TestKeyRequiresPrivateRegular32ByteFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, make([]byte, 32), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readKey(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readKey(path); err == nil {
		t.Fatal("publicly readable key accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := path + ".link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readKey(link); err == nil {
		t.Fatal("symlink key accepted")
	}
}
