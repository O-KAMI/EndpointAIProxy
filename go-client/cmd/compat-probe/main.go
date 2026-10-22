// compat-probe checks the live control contract using a labelled synthetic
// device. It never opens installed client state or DSH credential storage.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"os"
	"strings"
	"time"

	"endpointai/client/internal/contracts"
	"endpointai/client/internal/control"
	"endpointai/client/internal/observability"
	"endpointai/client/internal/proxy"
)

type credentials struct {
	Origin        string `json:"origin"`
	ClientToken   string `json:"clientToken"`
	PolicyHmacKey string `json:"policyHmacKey"`
	TransportKey  string `json:"transportKey"`
	KeyID         string `json:"keyId"`
}

type check struct {
	Name       string `json:"name"`
	Passed     bool   `json:"passed"`
	Code       string `json:"code,omitempty"`
	HTTPStatus int    `json:"httpStatus,omitempty"`
}
type report struct {
	Status                 string  `json:"status"`
	SyntheticDeviceID      string  `json:"syntheticDeviceId"`
	Checks                 []check `json:"checks"`
	NativeClientAcceptance bool    `json:"nativeClientAcceptance"`
	CredentialsExported    bool    `json:"credentialsExported"`
}

func run(path string, r *report) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var input credentials
	if err = json.Unmarshal(data, &input); err != nil {
		return err
	}
	policyKey, err := base64.StdEncoding.DecodeString(input.PolicyHmacKey)
	if err != nil {
		return err
	}
	transportKey, err := base64.StdEncoding.DecodeString(input.TransportKey)
	if err != nil {
		return err
	}
	client, err := control.New(control.Options{Origin: input.Origin, EnrollmentToken: input.ClientToken, PolicyKey: policyKey, TransportKey: transportKey, TransportKeyID: input.KeyID})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	id := proxy.UUID()
	r.SyntheticDeviceID = id
	observe := func(name string, err error) bool {
		item := check{Name: name, Passed: err == nil}
		if err != nil {
			detail := observability.Classify(err)
			item.Code, item.HTTPStatus = detail.Code, detail.HTTPStatus
		}
		r.Checks = append(r.Checks, item)
		return err == nil
	}
	enrolled, err := client.Enroll(ctx, contracts.DeviceEnrollmentRequest{SchemaVersion: 2, DeviceID: id, Hostname: "EndpointAI-Acceptance-20261022", ServiceVersion: "0.2.3"})
	if !observe("synthetic_enrollment", err) {
		return err
	}
	_, _, err = client.Policy(ctx, id, enrolled.DeviceToken)
	if !observe("signed_policy", err) {
		return err
	}
	now := time.Now().UTC()
	sid := "S-1-5-21-1-2-3-1001"
	heartbeat := contracts.HeartbeatV2Request{
		SchemaVersion: 2, HeartbeatID: proxy.UUID(), ObservedAtUTC: now,
		Device:  contracts.DeviceIdentity{DeviceID: id, Hostname: "EndpointAI-Acceptance-20261022", OSVersion: "Windows acceptance fixture", ServiceVersion: "0.2.3", BootID: proxy.UUID()},
		Runtime: contracts.DeviceRuntimeState{ServiceStartedAtUTC: now.Add(-time.Second), UptimeSeconds: 1, OperationState: contracts.ClientOperationStateEnabled},
		Users:   []contracts.EndpointUser{{SID: sid, AccountName: "acceptance-fixture"}}, Agents: []contracts.AgentInventoryItem{}, Endpoints: []contracts.AgentEndpointAsset{}, Activity: []contracts.ProxyActivityAsset{},
	}
	_, err = client.Heartbeat(ctx, heartbeat, enrolled.DeviceToken)
	if !observe("baseline_v2_heartbeat", err) {
		return err
	}
	heartbeat.HeartbeatID = proxy.UUID()
	heartbeat.Agents = []contracts.AgentInventoryItem{{InstanceID: proxy.UUID(), UserSID: sid, AgentType: contracts.AgentTypeClaudeCode, DisplayName: "Acceptance fixture", InstallMethod: contracts.InstallMethod(1), DiscoveryConfidence: 2, Installed: true, RouteStatus: contracts.RouteStatus(1), LastSeenAtUTC: now}}
	_, err = client.Heartbeat(ctx, heartbeat, enrolled.DeviceToken)
	if !observe("baseline_agent_inventory", err) {
		return err
	}
	heartbeat.HeartbeatID = proxy.UUID()
	heartbeat.Agents[0].AgentType = contracts.AgentTypeDeepSeekHarness
	heartbeat.Agents[0].InstanceID = proxy.UUID()
	_, err = client.Heartbeat(ctx, heartbeat, enrolled.DeviceToken)
	if !observe("dsh_agent_type_11", err) {
		return err
	}
	origin := "https://synthetic.example.invalid/anthropic"
	provider := "dsh:messages:account:" + strings.Repeat("b", 64)
	heartbeat.HeartbeatID = proxy.UUID()
	heartbeat.Endpoints = []contracts.AgentEndpointAsset{{AssetID: proxy.UUID(), UserSID: sid, AgentFamily: "deepseekHarness", ConfigurationSource: contracts.AgentConfigurationSource(1), ProviderID: &provider, IsCurrent: true, WireAPI: contracts.AgentWireApiAnthropicMessages, OriginalTargetBaseURL: &origin, EffectiveConfiguredBaseURL: &origin, RouteStatus: contracts.RouteStatus(1), ObservedAtUTC: now}}
	_, err = client.Heartbeat(ctx, heartbeat, enrolled.DeviceToken)
	if !observe("dsh_endpoint_wire_contract", err) {
		return err
	}
	return nil
}

func main() {
	path := flag.String("credentials", "", "external protected client credential file")
	output := flag.String("report", "", "protected report path")
	flag.Parse()
	if *path == "" || *output == "" {
		os.Exit(2)
	}
	file, openErr := os.OpenFile(*output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if openErr != nil {
		os.Exit(2)
	}
	defer file.Close()
	r := report{Status: "blocked", Checks: []check{}}
	err := run(*path, &r)
	if err == nil {
		r.Status = "passed"
	}
	data, _ := json.MarshalIndent(r, "", "  ")
	if _, err := file.Write(data); err != nil {
		os.Exit(2)
	}
	if file.Sync() != nil {
		os.Exit(2)
	}
	if err != nil {
		os.Exit(1)
	}
}
