package control

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"endpointai/client/internal/contracts"
	"endpointai/client/internal/observability"
	"endpointai/client/internal/protocol"
	"github.com/google/uuid"
)

type CredentialRotationStore interface {
	LoadPendingCredentialRotation(context.Context) (string, error)
	SavePendingCredentialRotation(context.Context, string, string) error
	CommitCredentialRotation(context.Context, contracts.CredentialRotationState) error
}

type pendingCredentialRotation struct {
	Device, Origin, Pin, RotationID, Token string
	PreviousHash                           []byte
	Binding                                *persistedDeviceTransport
}

func (pendingCredentialRotation) String() string   { return "[redacted credential rotation]" }
func (pendingCredentialRotation) GoString() string { return "[redacted credential rotation]" }

type credentialRotationResponse struct {
	DeviceID          string                       `json:"deviceId"`
	RotationID        string                       `json:"rotationId"`
	State             string                       `json:"state"`
	ServerTimeUTC     time.Time                    `json:"serverTimeUtc"`
	ExpiresAtUTC      *time.Time                   `json:"expiresAtUtc"`
	EnrolledAtUTC     *time.Time                   `json:"enrolledAtUtc"`
	DeviceTransportV2 *contracts.DeviceTransportV2 `json:"deviceTransportV2"`
}

func validRotationToken(token string) bool {
	value, err := base64.StdEncoding.Strict().DecodeString(token)
	defer clear(value)
	return err == nil && len(value) == 32 && base64.StdEncoding.EncodeToString(value) == token
}

func rotationNeedsPrepare(err error) bool {
	var status *HTTPError
	if errors.As(err, &status) && status.Status == http.StatusUnauthorized {
		return true
	}
	d := observability.Classify(err)
	return d.Stage == "transport_http" && (d.HTTPStatus == http.StatusBadRequest || d.HTTPStatus == http.StatusUnauthorized)
}

// RotateCredential resumes protected pending work even when the server no
// longer advertises new rotations. The caller serializes control operations and
// reloads the credential after changed=true. pending=true suppresses re-enrollment.
func (c *Client) RotateCredential(ctx context.Context, device, token string, enrolled time.Time, heartbeat *contracts.HeartbeatV2Response) (changed, pending bool, failure error) {
	defer func() {
		if failure != nil && observability.Classify(failure).Code == "" {
			failure = observability.Wrap("credential_rotation", "CONTROL_CREDENTIAL_ROTATION_FAILED", failure)
		}
	}()
	store, ok := c.deviceStore.(CredentialRotationStore)
	if !ok {
		return false, false, nil
	}
	value, err := store.LoadPendingCredentialRotation(ctx)
	if err != nil {
		return false, true, errors.New("CONTROL_ROTATION_STORE_READ_FAILED")
	}
	if value == "" && (heartbeat == nil || heartbeat.CredentialRotationV1 == nil) {
		return false, false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if c.deviceStoreErr != nil || !strings.HasPrefix(c.Options.Origin, "https://") || c.Options.CertificatePin == "" {
		return false, value != "", errors.New("CONTROL_ROTATION_IDENTITY_INVALID")
	}
	if _, ok = c.HTTP.Transport.(*protocol.Transport); !ok {
		return false, value != "", errors.New("CONTROL_ROTATION_IDENTITY_INVALID")
	}
	c.deviceMu.RLock()
	boundDevice, generation, oldHash := c.deviceTransportID, c.deviceTransportGeneration, c.deviceTokenHash
	c.deviceMu.RUnlock()
	actual := sha256.Sum256([]byte(token))
	if device != boundDevice || generation == 0 || subtle.ConstantTimeCompare(actual[:], oldHash[:]) != 1 {
		return false, value != "", errors.New("CONTROL_ROTATION_IDENTITY_INVALID")
	}
	var work pendingCredentialRotation
	if value == "" {
		age := heartbeat.CredentialRotationV1.MinAgeSeconds
		if age < 30*86400 || age > 365*86400 || heartbeat.ServerTimeUTC.IsZero() || enrolled.IsZero() {
			return false, false, errors.New("CONTROL_ROTATION_CAPABILITY_INVALID")
		}
		if heartbeat.ServerTimeUTC.Sub(enrolled) < time.Duration(age)*time.Second {
			return false, false, nil
		}
		var random [32]byte
		if _, err = rand.Read(random[:]); err != nil {
			return false, false, errors.New("CONTROL_ROTATION_RANDOM_FAILED")
		}
		work = pendingCredentialRotation{Device: device, Origin: c.Options.Origin, Pin: c.Options.CertificatePin, RotationID: uuid.NewString(), Token: base64.StdEncoding.EncodeToString(random[:]), PreviousHash: oldHash[:]}
		clear(random[:])
		data, err := json.Marshal(work)
		if err != nil {
			return false, false, errors.New("CONTROL_ROTATION_STATE_INVALID")
		}
		value = string(data)
		clear(data)
		if err = store.SavePendingCredentialRotation(ctx, "", value); err != nil {
			return false, true, errors.New("CONTROL_ROTATION_STORE_WRITE_FAILED")
		}
	} else {
		if len(value) > 16384 || json.Unmarshal([]byte(value), &work) != nil {
			return false, true, errors.New("CONTROL_ROTATION_STATE_INVALID")
		}
	}
	pending = true
	id, err := uuid.Parse(work.RotationID)
	if err != nil || id == uuid.Nil || id.String() != work.RotationID || work.Device != device || work.Origin != c.Options.Origin || work.Pin != c.Options.CertificatePin || !validRotationToken(work.Token) || subtle.ConstantTimeCompare(work.PreviousHash, oldHash[:]) != 1 {
		return false, true, errors.New("CONTROL_ROTATION_STATE_INVALID")
	}
	nextHash := sha256.Sum256([]byte(work.Token))
	if subtle.ConstantTimeCompare(nextHash[:], oldHash[:]) == 1 {
		return false, true, errors.New("CONTROL_ROTATION_STATE_INVALID")
	}
	validateBinding := func(b *persistedDeviceTransport) (uint64, error) {
		if b == nil || b.Device != device || b.Origin != work.Origin || b.Pin != work.Pin || subtle.ConstantTimeCompare(b.TokenHash, nextHash[:]) != 1 {
			return 0, errors.New("CONTROL_ROTATION_BINDING_INVALID")
		}
		g, err := protocol.ValidateDeviceV2Key(device, b.KeyID, b.Key)
		if err != nil {
			return 0, errors.New("CONTROL_ROTATION_BINDING_INVALID")
		}
		return g, nil
	}
	validateResponse := func(out *credentialRotationResponse, commit bool) (*persistedDeviceTransport, error) {
		if out.DeviceID != device || out.RotationID != work.RotationID || out.ServerTimeUTC.IsZero() || out.DeviceTransportV2 == nil || (out.State != "active" && (commit || out.State != "prepared")) {
			return nil, errors.New("CONTROL_ROTATION_RESPONSE_INVALID")
		}
		if out.State == "prepared" && (out.ExpiresAtUTC == nil || !out.ExpiresAtUTC.After(out.ServerTimeUTC) || out.ExpiresAtUTC.Sub(out.ServerTimeUTC) > 48*time.Hour) {
			return nil, errors.New("CONTROL_ROTATION_RESPONSE_INVALID")
		}
		if out.State == "active" && (out.EnrolledAtUTC == nil || out.EnrolledAtUTC.IsZero() || out.EnrolledAtUTC.After(out.ServerTimeUTC)) {
			return nil, errors.New("CONTROL_ROTATION_RESPONSE_INVALID")
		}
		binding := &persistedDeviceTransport{Origin: work.Origin, Pin: work.Pin, Device: device, KeyID: out.DeviceTransportV2.KeyID, Key: out.DeviceTransportV2.Key, TokenHash: nextHash[:]}
		g, err := validateBinding(binding)
		if err != nil || g < generation {
			return nil, errors.New("CONTROL_ROTATION_BINDING_INVALID")
		}
		return binding, nil
	}
	prepare := func() error {
		var out credentialRotationResponse
		_, _, err := c.call(ctx, "POST", "/api/v2/devices/"+device+"/credential/prepare", token, struct {
			RotationID string `json:"rotationId"`
			Token      string `json:"nextDeviceToken"`
		}{work.RotationID, work.Token}, &out)
		if err != nil {
			return err
		}
		binding, err := validateResponse(&out, false)
		if err != nil {
			return err
		}
		work.Binding = binding
		data, err := json.Marshal(work)
		if err != nil {
			return errors.New("CONTROL_ROTATION_STATE_INVALID")
		}
		next := string(data)
		clear(data)
		if err = store.SavePendingCredentialRotation(ctx, value, next); err != nil {
			return errors.New("CONTROL_ROTATION_STORE_WRITE_FAILED")
		}
		value = next
		return nil
	}
	if work.Binding != nil {
		g, err := validateBinding(work.Binding)
		if err != nil {
			return false, true, err
		}
		if g < generation {
			if err = prepare(); err != nil {
				return false, true, err
			}
		}
	} else if err = prepare(); err != nil {
		return false, true, err
	}
	commit := func() (credentialRotationResponse, error) {
		// Use the next binding on this request only; the live client retains its
		// old binding until the credential and binding commit together on disk.
		binding := work.Binding
		g, _ := validateBinding(binding)
		next := &Client{Options: c.Options, HTTP: c.HTTP, Observe: c.Observe, deviceTransportID: device, deviceTransportV2ID: binding.KeyID, deviceTransportGeneration: g, deviceTokenHash: nextHash}
		copy(next.deviceTransportV2Key[:], binding.Key)
		defer clear(next.deviceTransportV2Key[:])
		var out credentialRotationResponse
		_, _, err := next.call(ctx, "POST", "/api/v2/devices/"+device+"/credential/commit", work.Token, struct {
			RotationID string `json:"rotationId"`
		}{work.RotationID}, &out)
		return out, err
	}
	out, err := commit()
	if err != nil && rotationNeedsPrepare(err) {
		// A prepared token may have expired before commit. Re-prove the old
		// primary, without falling back to a shared key or registering again.
		if err = prepare(); err == nil {
			out, err = commit()
		}
	}
	if err != nil {
		return false, true, err
	}
	binding, err := validateResponse(&out, true)
	if err != nil {
		return false, true, err
	}
	data, err := json.Marshal(binding)
	if err != nil {
		return false, true, errors.New("CONTROL_ROTATION_STATE_INVALID")
	}
	defer clear(data)
	g, _ := validateBinding(binding)
	c.deviceMu.Lock()
	defer c.deviceMu.Unlock()
	if c.deviceTransportID != device || c.deviceTokenHash != oldHash || c.deviceTransportGeneration > g {
		return false, true, errors.New("CONTROL_ROTATION_IDENTITY_CHANGED")
	}
	err = store.CommitCredentialRotation(ctx, contracts.CredentialRotationState{PreviousToken: token, Pending: value, Token: work.Token, Transport: string(data), Origin: work.Origin, Pin: work.Pin, ActivatedAtUTC: *out.EnrolledAtUTC})
	if err != nil {
		return false, true, errors.New("CONTROL_ROTATION_STORE_COMMIT_FAILED")
	}
	c.deviceTransportV2ID, c.deviceTransportGeneration, c.deviceTokenHash = binding.KeyID, g, nextHash
	copy(c.deviceTransportV2Key[:], binding.Key)
	clear(binding.Key)
	return true, false, nil
}
