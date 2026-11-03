package protocol

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"endpointai/client/internal/contracts"
)

// Generated independently by Python cryptography from the synthetic seed bytes 0..31.
func TestEd25519PythonInteropAndDomainSeparation(t *testing.T) {
	public, _ := base64.StdEncoding.DecodeString("A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=")
	policy := "ed25519-v1:xgsc0hsLjP_MvWXeRW-Hn7qwufu4KcBpSwsqibsFYkbu0WUzmD1D8cNEpPmFILXs5ckRJImW3tGJj1CdO9tADQ"
	command := "ed25519-v1:yWtUaVkwtBl8RC7qwtJo-ecmySH7jkOXVOXyt3jFYt6AaAmPpcsfwdGuL8GVjdGVxULSFlbZBQ906DM6RwEgBQ"
	for _, tc := range []struct {
		body, signature, purpose string
		ok                       bool
	}{
		{"synthetic policy", policy, "policy", true},
		{"synthetic policy", command, "command", true},
		{"synthetic policy", policy, "command", false},
		{"modified", policy, "policy", false},
		{"synthetic policy", "v1:legacy", "policy", false},
		{"synthetic policy", "ed25519-v1:bad", "policy", false},
	} {
		if got := VerifyEd25519([]byte(tc.body), tc.signature, public, tc.purpose); (got == nil) != tc.ok {
			t.Fatalf("purpose %q signature %q: %v", tc.purpose, tc.signature, got)
		}
	}
}

func TestEd25519PythonCommandVector(t *testing.T) {
	public, _ := base64.StdEncoding.DecodeString("A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=")
	b, err := os.ReadFile("testdata/dotnet-v0.1.19.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct{ CommandBody string }
	if err := json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	var payload contracts.RemoteCommandPayload
	if err := json.Unmarshal([]byte(fixture.CommandBody), &payload); err != nil {
		t.Fatal(err)
	}
	command := contracts.SignedRemoteCommand{Payload: payload, Signature: "ed25519-v1:h-r0af9-1bTE8XnVPRNWe4il2hwRKYgebuvamxuPmjk6D5T0798LW5iwdioeTLl2bzFM3rNSXNGbFNbOx6DZDQ"}
	if err := VerifyCommandEd25519(command, public); err != nil {
		t.Fatal(err)
	}
	command.Payload.DeviceID = "00000000-0000-0000-0000-000000000002"
	if err := VerifyCommandEd25519(command, public); err == nil {
		t.Fatal("accepted modified device")
	}
}
