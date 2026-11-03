package protocol

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

const deviceTransportDomain = "sf-endpointai-device-transport-v1\n"

type deviceIdentityKey struct{}

// WithDeviceIdentity selects a device-bound envelope for this request only.
func WithDeviceIdentity(ctx context.Context, device string) context.Context {
	return context.WithValue(ctx, deviceIdentityKey{}, device)
}

func deviceTransportKey(device, token string) (string, []byte, error) {
	id, err := uuid.Parse(device)
	if err != nil || id == uuid.Nil || id.String() != device || len(token) < 16 || len(token) > 512 {
		return "", nil, errors.New("invalid device transport identity")
	}
	digest := sha256.Sum256([]byte(token))
	mac := hmac.New(sha256.New, digest[:])
	_, _ = mac.Write([]byte(deviceTransportDomain + device))
	return "dv1_" + id.String()[:8] + id.String()[9:13] + id.String()[14:18] + id.String()[19:23] + id.String()[24:], mac.Sum(nil), nil
}

// deviceEnvelopeKey is request-local; the key must never be logged or serialized.
type deviceEnvelopeKey struct {
	device, keyID string
	key           [32]byte
}

// String methods prevent accidental context formatting from exposing key bytes.
func (deviceEnvelopeKey) String() string   { return "[redacted device key]" }
func (deviceEnvelopeKey) GoString() string { return "[redacted device key]" }

type deviceEnvelopeKeyContext struct{}

// ValidateDeviceV2Key verifies identity binding and returns the monotonic generation.
func ValidateDeviceV2Key(device, keyID string, key []byte) (uint64, error) {
	id, err := uuid.Parse(device)
	if err != nil || id == uuid.Nil || id.String() != device || len(key) != 32 {
		return 0, errors.New("invalid device transport key")
	}
	parts := strings.Split(keyID, "_")
	if len(parts) != 3 || parts[0] != "dv2" || len(parts[1]) < 1 || len(parts[1]) > 10 || parts[1][0] == '0' || parts[2] != strings.ReplaceAll(device, "-", "") {
		return 0, errors.New("invalid device transport key")
	}
	for _, ch := range parts[1] {
		if ch < '0' || ch > '9' {
			return 0, errors.New("invalid device transport key")
		}
	}
	generation, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil || generation == 0 {
		return 0, errors.New("invalid device transport key")
	}
	return generation, nil
}

// WithDeviceV2Key attaches an already authenticated device key to one request.
func WithDeviceV2Key(ctx context.Context, device, keyID string, key []byte) (context.Context, error) {
	if _, err := ValidateDeviceV2Key(device, keyID, key); err != nil {
		return nil, errors.New("invalid device transport key")
	}
	value := deviceEnvelopeKey{device: device, keyID: keyID}
	copy(value.key[:], key)
	return context.WithValue(ctx, deviceEnvelopeKeyContext{}, value), nil
}
