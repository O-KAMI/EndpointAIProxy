package main

import (
	"context"
	"encoding/json"
	"endpointai/client/internal/contracts"
	"endpointai/client/internal/control"
	"flag"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/google/uuid"
)

// Synthetic loopback-only interop probe; no production credentials or state.
func main() {
	origin := flag.String("origin", "", "synthetic loopback HTTPS server")
	pin := flag.String("pin", "", "synthetic server pin")
	device := flag.String("device", "", "synthetic device ID")
	fixture := flag.String("fixture", "", "synthetic heartbeat fixture")
	v2 := flag.Bool("v2", false, "expect server-secret device binding")
	rotate := flag.Bool("rotate", false, "exercise synthetic server key overlap")
	flag.Parse()
	u, err := url.Parse(*origin)
	if err != nil || u.Scheme != "https" || u.Hostname() != "127.0.0.1" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		fmt.Fprintln(os.Stderr, "loopback HTTPS required")
		os.Exit(2)
	}
	raw, err := os.ReadFile(*fixture)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fixture unavailable")
		os.Exit(2)
	}
	var data struct {
		Heartbeat contracts.HeartbeatV2Request `json:"heartbeat"`
	}
	if json.Unmarshal(raw, &data) != nil {
		fmt.Fprintln(os.Stderr, "invalid fixture")
		os.Exit(2)
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	client, err := control.New(control.Options{Origin: *origin, EnrollmentToken: "test-enrollment-token", PolicyKey: key, TransportKey: key, TransportKeyID: "production-2026-01", CertificatePin: *pin})
	if err != nil {
		fmt.Fprintln(os.Stderr, "control setup failed")
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	enrolled, err := client.Enroll(ctx, contracts.DeviceEnrollmentRequest{SchemaVersion: 2, DeviceID: *device, Hostname: data.Heartbeat.Device.Hostname, ServiceVersion: "synthetic"})
	if err != nil {
		fmt.Fprintln(os.Stderr, "synthetic enrollment failed")
		os.Exit(1)
	}
	data.Heartbeat.Device.DeviceID = *device
	reply, err := client.Heartbeat(ctx, data.Heartbeat, enrolled.DeviceToken)
	if err != nil || (!*v2 && !reply.DeviceTransport) {
		fmt.Fprintln(os.Stderr, "synthetic negotiation failed")
		os.Exit(1)
	}
	if _, _, err = client.Policy(ctx, *device, enrolled.DeviceToken); err != nil {
		fmt.Fprintln(os.Stderr, "device-bound policy request failed")
		os.Exit(1)
	}
	if *rotate {
		data.Heartbeat.HeartbeatID = uuid.NewString()
		if _, err = client.Heartbeat(ctx, data.Heartbeat, enrolled.DeviceToken); err != nil {
			fmt.Fprintln(os.Stderr, "overlap heartbeat failed")
			os.Exit(1)
		}
		if _, _, err = client.Policy(ctx, *device, enrolled.DeviceToken); err != nil {
			fmt.Fprintln(os.Stderr, "rotated device-bound policy request failed")
			os.Exit(1)
		}
	}
	if !reply.CompactInventory {
		fmt.Fprintln(os.Stderr, "compact capability missing")
		os.Exit(1)
	}
	compact := data.Heartbeat
	compact.HeartbeatID = uuid.NewString()
	compact.ObservedAtUTC = time.Now().UTC()
	compact.InventoryUnchanged, compact.CompactInventory = true, true
	compact.Users = []contracts.EndpointUser{}
	compact.Agents = []contracts.AgentInventoryItem{}
	compact.Endpoints = []contracts.AgentEndpointAsset{}
	if _, err = client.Heartbeat(ctx, compact, enrolled.DeviceToken); err != nil {
		fmt.Fprintln(os.Stderr, "compact device-bound heartbeat failed")
		os.Exit(1)
	}
	fmt.Println("synthetic device-bound interop passed")
}
