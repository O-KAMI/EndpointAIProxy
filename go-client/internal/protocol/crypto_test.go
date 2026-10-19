package protocol

import (
	"bytes"
	"encoding/json"
	"endpointai/client/internal/contracts"
	"github.com/google/uuid"
	"os"
	"testing"
)

func TestDotNetCommandAndPolicyVectors(t *testing.T) {
	var f struct {
		PolicyBody, PolicySignature string
		CommandVectors              []struct{ Body, Signature string }
	}
	b, e := os.ReadFile("testdata/dotnet-v0.1.19.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &f); e != nil {
		t.Fatal(e)
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	if e = Verify([]byte(f.PolicyBody), f.PolicySignature, key); e != nil {
		t.Fatal(e)
	}
	for _, v := range f.CommandVectors {
		var p contracts.RemoteCommandPayload
		if e = json.Unmarshal([]byte(v.Body), &p); e != nil {
			t.Fatal(e)
		}
		actual, e := CommandBody(p)
		if e != nil {
			t.Fatal(e)
		}
		if string(actual) != v.Body {
			t.Fatalf("serialization mismatch\n%s\n%s", actual, v.Body)
		}
		if e = VerifyCommand(contracts.SignedRemoteCommand{Payload: p, Signature: v.Signature}, key); e != nil {
			t.Fatal(e)
		}
	}
}
func TestTransportAuthenticationAndBinding(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	id := uuid.NewString()
	e, err := Seal(key, "test", id, []byte("synthetic"), "response")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Open(key, "test", id, e, "response")
	if err != nil || string(b) != "synthetic" {
		t.Fatalf("%q %v", b, err)
	}
	cases := []Envelope{e, e, e, e}
	cases[0].RequestID = uuid.NewString()
	cases[1].Timestamp -= 301
	cases[2].KeyID = "other"
	cases[3].Tag = "AAAAAAAAAAAAAAAAAAAAAA=="
	for _, v := range cases {
		if _, err = Open(key, "test", id, v, "response"); err == nil {
			t.Fatal("accepted altered envelope")
		}
	}
	if _, err = Open(key, "test", id, e, "request"); err == nil {
		t.Fatal("accepted wrong direction")
	}
}
func TestSignatureRejectsChangedBody(t *testing.T) {
	key := make([]byte, 32)
	sig, e := Sign([]byte("original"), key)
	if e != nil {
		t.Fatal(e)
	}
	if Verify([]byte("tampered"), sig, key) == nil {
		t.Fatal("accepted altered policy")
	}
}

func TestDotNetAllowlistVectors(t *testing.T) {
	var f struct {
		AllowlistVectors []struct {
			Input, Normalized string
			Valid             bool
		}
	}
	b, e := os.ReadFile("testdata/dotnet-v0.1.19.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &f); e != nil {
		t.Fatal(e)
	}
	for _, v := range f.AllowlistVectors {
		n, e := NormalizeBaseURL(v.Input)
		if (e == nil) != v.Valid || (e == nil && n != v.Normalized) {
			t.Errorf("%q: got %q %v, want %q valid=%v", v.Input, n, e, v.Normalized, v.Valid)
		}
	}
	empty, e := NormalizeAllowlist([]string{})
	if e != nil || empty == nil {
		t.Fatal("empty allowlist became null")
	}
	none, e := NormalizeAllowlist(nil)
	if e != nil || none != nil {
		t.Fatal("null allowlist became empty")
	}
}
