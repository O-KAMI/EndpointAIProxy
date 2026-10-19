package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"endpointai/client/internal/contracts"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"strconv"
	"strings"
	"time"
)

const transportLabel = "sf-endpointai-transport-v1"

type Envelope struct {
	Version    int    `json:"version"`
	KeyID      string `json:"keyId"`
	RequestID  string `json:"requestId"`
	Timestamp  int64  `json:"timestamp"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
	Tag        string `json:"tag"`
}

func digest(key, b []byte) []byte { h := hmac.New(sha256.New, key); h.Write(b); return h.Sum(nil) }
func transportKey(master []byte, direction string) []byte {
	prk := digest([]byte(transportLabel), master)
	defer clear(prk)
	return digest(prk, append([]byte(direction), 1))
}
func aad(e Envelope, direction string) []byte {
	return []byte(strings.Join([]string{transportLabel, direction, e.KeyID, e.RequestID, strconv.FormatInt(e.Timestamp, 10), e.Nonce}, "\n"))
}
func transportAEAD(master []byte, direction string) (cipher.AEAD, error) {
	if len(master) != 32 || (direction != "request" && direction != "response") {
		return nil, errors.New("invalid transport key or direction")
	}
	key := transportKey(master, direction)
	defer clear(key)
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}
func Seal(master []byte, keyID, requestID string, plain []byte, direction string) (Envelope, error) {
	e := Envelope{Version: 1, KeyID: keyID, RequestID: requestID, Timestamp: time.Now().Unix()}
	a, err := transportAEAD(master, direction)
	if err != nil {
		return e, err
	}
	nonce := make([]byte, 12)
	if _, err = rand.Read(nonce); err != nil {
		return e, err
	}
	e.Nonce = base64.StdEncoding.EncodeToString(nonce)
	sealed := a.Seal(nil, nonce, plain, aad(e, direction))
	e.Ciphertext = base64.StdEncoding.EncodeToString(sealed[:len(sealed)-16])
	e.Tag = base64.StdEncoding.EncodeToString(sealed[len(sealed)-16:])
	return e, nil
}
func Open(master []byte, keyID, requestID string, e Envelope, direction string) ([]byte, error) {
	id, err := uuid.Parse(e.RequestID)
	now := time.Now().Unix()
	if err != nil || id.String() != e.RequestID || e.Version != 1 || e.KeyID != keyID || e.RequestID != requestID || e.Timestamp < now-300 || e.Timestamp > now+300 {
		return nil, errors.New("invalid encrypted control response binding")
	}
	nonce, err := base64.StdEncoding.DecodeString(e.Nonce)
	if err != nil || len(nonce) != 12 || base64.StdEncoding.EncodeToString(nonce) != e.Nonce {
		return nil, errors.New("invalid nonce")
	}
	tag, err := base64.StdEncoding.DecodeString(e.Tag)
	if err != nil || len(tag) != 16 {
		return nil, errors.New("invalid tag")
	}
	if len(e.Ciphertext) > 54_666_668 {
		return nil, errors.New("ciphertext too large")
	}
	ct, err := base64.StdEncoding.DecodeString(e.Ciphertext)
	if err != nil || len(ct) > 41_000_000 {
		return nil, errors.New("invalid ciphertext")
	}
	a, err := transportAEAD(master, direction)
	if err != nil {
		return nil, err
	}
	return a.Open(nil, nonce, append(ct, tag...), aad(e, direction))
}
func Sign(body, key []byte) (string, error) {
	if len(key) < 32 {
		return "", errors.New("HMAC key must contain at least 32 bytes")
	}
	return "v1:" + base64.RawURLEncoding.EncodeToString(digest(key, body)), nil
}
func Verify(body []byte, signature string, key []byte) error {
	if len(key) < 32 {
		return errors.New("POLICY_HMAC_KEY_INVALID")
	}
	if !strings.HasPrefix(signature, "v1:") {
		return errors.New("POLICY_SIGNATURE_VERSION_UNSUPPORTED")
	}
	raw := strings.TrimPrefix(signature, "v1:")
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(raw, "="))
	if err != nil {
		return errors.New("POLICY_SIGNATURE_MALFORMED")
	}
	if !hmac.Equal(b, digest(key, body)) {
		return errors.New("POLICY_SIGNATURE_INVALID")
	}
	return nil
}

// DotNetTime matches System.Text.Json's DateTimeOffset representation, including UTC offset.
func DotNetTime(t time.Time) string { return t.Format("2006-01-02T15:04:05.9999999-07:00") }
func CommandBody(p contracts.RemoteCommandPayload) ([]byte, error) {
	// Field order is part of the existing command signature contract.
	return json.Marshal(struct {
		SchemaVersion int                         `json:"schemaVersion"`
		CommandID     string                      `json:"commandId"`
		DeviceID      string                      `json:"deviceId"`
		Type          contracts.RemoteCommandType `json:"type"`
		IssuedAtUTC   string                      `json:"issuedAtUtc"`
		ExpiresAtUTC  string                      `json:"expiresAtUtc"`
	}{p.SchemaVersion, p.CommandID, p.DeviceID, p.Type, DotNetTime(p.IssuedAtUTC), DotNetTime(p.ExpiresAtUTC)})
}
func VerifyCommand(c contracts.SignedRemoteCommand, key []byte) error {
	if len(key) < 32 {
		return errors.New("POLICY_HMAC_KEY_INVALID")
	}
	p := c.Payload
	id, e := uuid.Parse(p.CommandID)
	did, de := uuid.Parse(p.DeviceID)
	if p.SchemaVersion != 1 || e != nil || de != nil || id == uuid.Nil || did == uuid.Nil || p.Type < 0 || p.Type > 1 || !p.ExpiresAtUTC.After(p.IssuedAtUTC) {
		return errors.New("COMMAND_BODY_INVALID")
	}
	b, err := CommandBody(p)
	if err != nil {
		return err
	}
	derived := digest(key, []byte("sf-endpoint-ai-command-v1"))
	defer clear(derived)
	return Verify(b, c.Signature, derived)
}

type GatewayMetadata struct {
	DeviceID, UserID, UserSID, Agent, AgentSurface, ProviderID, OriginalBaseURL, OriginalAuthority, RequestID string
	TimestampUTC                                                                                              time.Time
	Method, PathAndQuery                                                                                      string
}

func SignGateway(m GatewayMetadata, key []byte) (string, error) {
	b := strings.Join([]string{"v1", m.RequestID, fmt.Sprint(m.TimestampUTC.Unix()), m.DeviceID, m.UserID, m.UserSID, m.Agent, m.AgentSurface, m.ProviderID, m.OriginalBaseURL, m.OriginalAuthority, strings.ToUpper(m.Method), m.PathAndQuery}, "\n")
	return Sign([]byte(b), key)
}
