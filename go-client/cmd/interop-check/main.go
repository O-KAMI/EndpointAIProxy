// interop-check exercises synthetic state only; invoked by scripts/interop-dotnet.py.
package main

import (
	"context"
	"endpointai/client/internal/contracts"
	"endpointai/client/internal/protect"
	"endpointai/client/internal/state"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

var fixtureTime = time.Date(2026, 9, 13, 1, 2, 3, 123456700, time.UTC)

const serverID = "40000000-0000-0000-0000-000000000004"
const commandID = "30000000-0000-0000-0000-000000000003"

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: interop-check verify-dotnet|write-go TEMP_DIRECTORY")
		os.Exit(2)
	}
	if e := run(os.Args[1], os.Args[2]); e != nil {
		fmt.Fprintln(os.Stderr, "synthetic state interoperability failed:", e)
		os.Exit(1)
	}
}
func check(ok bool, field string) error {
	if !ok {
		return errors.New("fixture mismatch: " + field)
	}
	return nil
}
func run(mode, dir string) error {
	p, e := protect.NewFileKey(filepath.Join(dir, "machine.key"))
	if e != nil {
		return e
	}
	ctx := context.Background()
	if mode == "verify-dotnet" {
		blob, e := os.ReadFile(filepath.Join(dir, "dotnet.blob"))
		if e != nil {
			return e
		}
		plain, e := p.Unprotect(blob)
		if e != nil {
			return e
		}
		if e = check(plain == "synthetic-dotnet-protected", ".NET AES blob"); e != nil {
			return e
		}
		s, e := state.OpenReadOnly(filepath.Join(dir, "dotnet.db"), p)
		if e != nil {
			return e
		}
		defer s.Close()
		return verify(ctx, s, dir, "dotnet", 41, "synthetic-dotnet-token")
	}
	if mode != "write-go" {
		return errors.New("unknown mode")
	}
	blob, e := p.Protect("synthetic-go-protected")
	if e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(dir, "go.blob"), blob, 0600); e != nil {
		return e
	}
	s, e := state.Open(filepath.Join(dir, "go.db"), p)
	if e != nil {
		return e
	}
	defer s.Close()
	id, e := s.GetOrCreateDeviceID(ctx)
	if e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(dir, "go-device-id"), []byte(id), 0600); e != nil {
		return e
	}
	origin, pin := "https://example.invalid/", "synthetic-pin"
	if e = s.SaveCredential(ctx, state.Credential{Token: "synthetic-go-token", EnrolledAtUTC: fixtureTime, ServerOrigin: &origin, ServerCertificateSPKISHA256: &pin}); e != nil {
		return e
	}
	policy := contracts.Policy{SchemaVersion: 1, ServerInstanceID: serverID, PolicyVersion: 42, Enabled: true, RouteMode: "passthroughOriginal", PollIntervalSeconds: 60, HeartbeatIntervalSeconds: 60, IssuedAtUTC: fixtureTime, AllowlistedBaseURLs: []string{}}
	if e = s.SavePolicy(ctx, policy, "synthetic-signature", fixtureTime); e != nil {
		return e
	}
	code, summary := "SYNTHETIC_CODE", "Synthetic summary"
	if e = s.SaveOperationState(ctx, state.OperationState{State: contracts.ClientOperationStateDisabled, UpdatedAtUTC: fixtureTime, LastErrorCode: &code, LastErrorSummary: &summary}); e != nil {
		return e
	}
	expires := fixtureTime.Add(time.Hour)
	if e = s.SaveCommandReceipt(ctx, state.CommandReceipt{CommandID: commandID, DeviceID: &id, Type: contracts.RemoteCommandTypeDisableProxy, Status: contracts.RemoteCommandStatusExecuting, ReceivedAtUTC: fixtureTime, IssuedAtUTC: &fixtureTime, ExpiresAtUTC: &expires, ResultCode: &code, ResultSummary: &summary}); e != nil {
		return e
	}
	r := contracts.Route{RouteID: "interop-route", UserSID: "synthetic-user", AgentType: 8, ProviderID: "direct", OriginalBaseURL: "https://example.invalid/v1", InjectedBaseURL: "http://127.0.0.1:18080/r/interop-route", Status: 3, CreatedAtUTC: fixtureTime, UpdatedAtUTC: fixtureTime}
	return s.UpsertRoute(ctx, r)
}
func verify(ctx context.Context, s *state.Store, dir, prefix string, version int64, token string) error {
	// Read-only identity validation is done by comparing receipt's ID to the writer's marker.
	id, e := os.ReadFile(filepath.Join(dir, prefix+"-device-id"))
	if e != nil {
		return e
	}
	c, e := s.LoadCredential(ctx)
	if e != nil {
		return e
	}
	if e = check(c != nil && c.Token == token && c.EnrolledAtUTC.Equal(fixtureTime) && c.ServerOrigin != nil && *c.ServerOrigin == "https://example.invalid/" && c.ServerCertificateSPKISHA256 != nil && *c.ServerCertificateSPKISHA256 == "synthetic-pin", "credential"); e != nil {
		return e
	}
	p, e := s.LoadPolicy(ctx)
	if e != nil {
		return e
	}
	if e = check(p != nil && p.Policy.PolicyVersion == version && p.Policy.ServerInstanceID == serverID && p.Policy.RouteMode == "passthroughOriginal" && p.Policy.GatewayOrigin == nil && p.Policy.AllowlistedBaseURLs != nil && len(p.Policy.AllowlistedBaseURLs) == 0 && p.Policy.IssuedAtUTC.Equal(fixtureTime) && p.ReceivedAtUTC.Equal(fixtureTime) && p.Signature == "synthetic-signature", "cached policy"); e != nil {
		return e
	}
	op, e := s.LoadOperationState(ctx)
	if e != nil {
		return e
	}
	if e = check(op.State == contracts.ClientOperationStateDisabled && op.UpdatedAtUTC.Equal(fixtureTime) && op.LastErrorCode != nil && *op.LastErrorCode == "SYNTHETIC_CODE", "operation state"); e != nil {
		return e
	}
	receipt, e := s.LoadCommandReceipt(ctx, commandID)
	if e != nil {
		return e
	}
	if e = check(receipt != nil && receipt.Type == contracts.RemoteCommandTypeDisableProxy && receipt.Status == contracts.RemoteCommandStatusExecuting && receipt.DeviceID != nil && *receipt.DeviceID == string(id) && receipt.ReceivedAtUTC.Equal(fixtureTime) && receipt.CompletedAtUTC == nil && receipt.IssuedAtUTC != nil && receipt.IssuedAtUTC.Equal(fixtureTime) && receipt.ExpiresAtUTC != nil && receipt.ExpiresAtUTC.Equal(fixtureTime.Add(time.Hour)), "command receipt"); e != nil {
		return e
	}
	routes, e := s.ListRoutes(ctx)
	if e != nil {
		return e
	}
	return check(len(routes) == 1 && routes[0].RouteID == "interop-route" && routes[0].UserSID == "synthetic-user" && routes[0].AgentType == 8 && routes[0].Status == 3 && routes[0].OriginalBaseURL == "https://example.invalid/v1" && routes[0].InjectedBaseURL == "http://127.0.0.1:18080/r/interop-route" && routes[0].CreatedAtUTC.Equal(fixtureTime) && routes[0].UpdatedAtUTC.Equal(fixtureTime), "route")
}
