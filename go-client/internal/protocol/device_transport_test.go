package protocol

import (
	"context"
	encodinghex "encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func TestDeviceTransportDerivationVectorAndValidation(t *testing.T) {
	id := "11111111-2222-4333-8444-555555555555"
	keyID, key, err := deviceTransportKey(id, "synthetic-device-token-1234567890")
	if err != nil || keyID != "dv1_11111111222243338444555555555555" || encodinghex.EncodeToString(key) != "4b70d6d084f7b137a74034ff407c481d0bbbd14a1fef24a6017d18b82d78b894" {
		t.Fatalf("device key derivation mismatch: %v", err)
	}
	for _, bad := range []string{"", "00000000-0000-0000-0000-000000000000", "11111111-2222-4333-8444-55555555555A"} {
		if _, _, err := deviceTransportKey(bad, "synthetic-device-token-1234567890"); err == nil {
			t.Fatal("invalid identity accepted")
		}
	}
	if _, _, err := deviceTransportKey(id, "short"); err == nil {
		t.Fatal("short token accepted")
	}
}

func TestDeviceV2KeyBindingAndGenerationValidation(t *testing.T) {
	device := "11111111-2222-4333-8444-555555555555"
	valid := "dv2_42_11111111222243338444555555555555"
	if generation, err := ValidateDeviceV2Key(device, valid, make([]byte, 32)); err != nil || generation != 42 {
		t.Fatalf("valid key rejected: %v", err)
	}
	for _, id := range []string{"dv2_042_11111111222243338444555555555555", "dv2_x_11111111222243338444555555555555", "dv2_42_aaaaaaaaaaaa4aaa8aaaaaaaaaaaaaaa", "dv2_0_11111111222243338444555555555555"} {
		if _, err := ValidateDeviceV2Key(device, id, make([]byte, 32)); err == nil {
			t.Fatalf("invalid key ID accepted: %s", id)
		}
	}
	if _, err := ValidateDeviceV2Key(device, valid, make([]byte, 31)); err == nil {
		t.Fatal("invalid key length accepted")
	}
}

func TestDeviceV2ContextFormattingRedactsKey(t *testing.T) {
	device := "11111111-2222-4333-8444-555555555555"
	id := "dv2_2_11111111222243338444555555555555"
	key := []byte("sensitive-test-device-key-123456")
	ctx, err := WithDeviceV2Key(context.Background(), device, id, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, rendered := range []string{fmt.Sprint(ctx), fmt.Sprintf("%#v", ctx)} {
		if strings.Contains(rendered, string(key)) || strings.Contains(rendered, "115 101 110 115 105 116 105 118 101") {
			t.Fatal("context formatting exposed device key")
		}
	}
}
