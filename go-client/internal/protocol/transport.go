package protocol

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"endpointai/client/internal/observability"
	"errors"
	"github.com/google/uuid"
	"io"
	"net/http"
	"strings"
)

type InnerRequest struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Query  string `json:"query"`
	Token  string `json:"token"`
	Body   string `json:"body"`
}
type InnerResponse struct {
	Status  int               `json:"status"`
	Body    string            `json:"body"`
	Headers map[string]string `json:"headers"`
}

// Trace is per-call local metadata, never added to the encrypted wire contract.
type Trace struct{ ControlRequestID, ServerRequestID string }
type traceKey struct{}

func WithTrace(ctx context.Context, trace *Trace) context.Context {
	return context.WithValue(ctx, traceKey{}, trace)
}

// Transport performs encrypted control requests using the supplied base transport.
type Transport struct {
	Base                http.RoundTripper
	MasterKey           []byte
	KeyID, ServerOrigin string
}

func bounded(r io.Reader, limit int64) ([]byte, error) {
	b, e := io.ReadAll(io.LimitReader(r, limit+1))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) > limit {
		return nil, errors.New("control payload too large")
	}
	return b, nil
}
func (t *Transport) RoundTrip(r *http.Request) (response *http.Response, failure error) {
	trace, _ := r.Context().Value(traceKey{}).(*Trace)
	stage := "transport_encode"
	defer func() {
		if failure != nil {
			d := observability.Classify(failure)
			if d.Stage == "" {
				d.Stage = stage
			}
			if d.Code == "" {
				d.Code = "CONTROL_TRANSPORT_FAILED"
			}
			if d.Class == "" || d.Class == "OTHER" {
				if stage == "transport_authenticate" {
					d.Class = "AUTHENTICATION_FAILED"
				} else if stage != "transport_connect" {
					d.Class = "CONTRACT_INVALID"
				}
			}
			if trace != nil {
				d.ControlRequestID = trace.ControlRequestID
				d.ServerRequestID = trace.ServerRequestID
			}
			failure = &observability.Error{Detail: d, Cause: failure}
		}
	}()
	var body []byte
	var err error
	if r.Body != nil {
		body, err = bounded(r.Body, 30_000_000)
		r.Body.Close()
		if err != nil {
			return nil, err
		}
	}
	inner := InnerRequest{r.Method, r.URL.EscapedPath(), r.URL.RawQuery, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), base64.StdEncoding.EncodeToString(body)}
	b, err := json.Marshal(inner)
	if err != nil {
		return nil, err
	}
	id := uuid.NewString()
	if trace != nil {
		trace.ControlRequestID = id
	}
	env, err := Seal(t.MasterKey, t.KeyID, id, b, "request")
	if err != nil {
		return nil, err
	}
	b, err = json.Marshal(env)
	if err != nil {
		return nil, err
	}
	outer, err := http.NewRequestWithContext(r.Context(), http.MethodPost, strings.TrimRight(t.ServerOrigin, "/")+"/api/transport/v1", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	outer.Header.Set("Content-Type", "application/json")
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	stage = "transport_connect"
	res, err := base.RoundTrip(outer)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		d := observability.Detail{Stage: "transport_http", Class: "HTTP", Code: "CONTROL_TRANSPORT_REJECTED", HTTPStatus: res.StatusCode}
		return nil, &observability.Error{Detail: d}
	}
	stage = "transport_read"
	b, err = bounded(res.Body, 56_000_000)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(b, &env); err != nil {
		return nil, err
	}
	stage = "transport_authenticate"
	b, err = Open(t.MasterKey, t.KeyID, id, env, "response")
	if err != nil {
		return nil, err
	}
	stage = "transport_decode"
	var decoded InnerResponse
	if err = json.Unmarshal(b, &decoded); err != nil {
		return nil, err
	}
	if decoded.Status < 200 || decoded.Status > 599 {
		return nil, errors.New("invalid business status")
	}
	b, err = base64.StdEncoding.DecodeString(decoded.Body)
	if err != nil || len(b) > 30_000_000 {
		return nil, errors.New("invalid business response body")
	}
	h := make(http.Header)
	for k, v := range decoded.Headers {
		if strings.EqualFold(k, "Content-Type") || strings.EqualFold(k, "X-SF-Policy-Signature") || strings.EqualFold(k, "X-Request-ID") {
			h.Set(k, v)
		}
	}
	if trace != nil {
		trace.ServerRequestID = observability.SafeID(h.Get("X-Request-ID"))
	}
	return &http.Response{StatusCode: decoded.Status, Status: http.StatusText(decoded.Status), Header: h, Body: io.NopCloser(bytes.NewReader(b)), ContentLength: int64(len(b)), Request: r}, nil
}
