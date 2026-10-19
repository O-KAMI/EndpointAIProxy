// Package observability classifies failures without persisting free-form errors.
package observability

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"os"
	"syscall"

	"github.com/google/uuid"
)

type Detail struct {
	Stage            string `json:"stage,omitempty"`
	Class            string `json:"errorClass,omitempty"`
	Code             string `json:"errorCode,omitempty"`
	Timeout          bool   `json:"timeout"`
	OSCode           int    `json:"osErrorCode,omitempty"`
	HTTPStatus       int    `json:"httpStatusCode,omitempty"`
	ControlRequestID string `json:"controlRequestId,omitempty"`
	ServerRequestID  string `json:"serverRequestId,omitempty"`
}

// Error retains the cause in memory; Error returns only a fixed public code.
type Error struct {
	Detail Detail
	Cause  error
}

func (e *Error) Error() string {
	if e.Detail.Code != "" {
		return e.Detail.Code
	}
	return "OPERATION_FAILED"
}
func (e *Error) Unwrap() error { return e.Cause }

func Wrap(stage, code string, err error) *Error {
	d := Classify(err)
	if d.Stage == "" {
		d.Stage = stage
	}
	d.Code = code
	return &Error{Detail: d, Cause: err}
}

func SafeID(value string) string {
	id, err := uuid.Parse(value)
	if err != nil || id == uuid.Nil {
		return ""
	}
	return id.String()
}

func Classify(err error) Detail {
	if err == nil {
		return Detail{}
	}
	var retained *Error
	if errors.As(err, &retained) {
		return retained.Detail
	}
	d := Detail{Class: "OTHER"}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		d.OSCode = int(errno)
	}
	var dns *net.DNSError
	var hostname x509.HostnameError
	var authority x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var network net.Error
	switch {
	case errors.Is(err, context.Canceled):
		d.Class = "CANCELLED"
	case errors.Is(err, context.DeadlineExceeded):
		d.Class = "TIMEOUT"
		d.Timeout = true
	case errors.As(err, &dns):
		d.Class = "DNS_FAILED"
		d.Timeout = dns.Timeout()
		if dns.IsNotFound {
			d.Class = "DNS_NOT_FOUND"
		}
	case errors.As(err, &hostname):
		d.Class = "TLS_HOSTNAME"
	case errors.As(err, &authority):
		d.Class = "TLS_UNTRUSTED"
	case errors.As(err, &invalid):
		d.Class = "TLS_CERTIFICATE"
		if invalid.Reason == x509.Expired {
			d.Class = "TLS_EXPIRED"
		}
	case os.IsPermission(err):
		d.Class = "PERMISSION_DENIED"
	case os.IsNotExist(err):
		d.Class = "NOT_FOUND"
	case errors.Is(err, syscall.ENOSPC):
		d.Class = "DISK_FULL"
	case errors.Is(err, syscall.ECONNREFUSED):
		d.Class = "CONNECTION_REFUSED"
	case errors.Is(err, syscall.ECONNRESET):
		d.Class = "CONNECTION_RESET"
	case errors.Is(err, syscall.EPIPE):
		d.Class = "BROKEN_PIPE"
	case errors.Is(err, io.ErrUnexpectedEOF):
		d.Class = "UNEXPECTED_EOF"
	case errors.Is(err, io.EOF):
		d.Class = "EOF"
	case errors.Is(err, net.ErrClosed):
		d.Class = "CONNECTION_CLOSED"
	case errors.As(err, &network) && network.Timeout():
		d.Class = "TIMEOUT"
		d.Timeout = true
	default:
		// Walk wrappers, matching only exact authored codes. Never persist text.
		for cause, depth := err, 0; cause != nil && depth < 16; cause, depth = errors.Unwrap(cause), depth+1 {
			switch cause.Error() {
			case "CONTROL_TLS_PIN_MISMATCH":
				d.Class = "TLS_PIN_MISMATCH"
			case "CONTROL_TLS_HOST_MISMATCH", "CONTROL_TLS_HOSTNAME_INVALID":
				d.Class = "TLS_HOSTNAME"
			case "CONTROL_TLS_CERTIFICATE_EXPIRED":
				d.Class = "TLS_EXPIRED"
			case "POLICY_SIGNATURE_INVALID":
				d.Class = "SIGNATURE_INVALID"
			}
			if d.Class != "OTHER" {
				break
			}
		}
	}
	if d.Class == "OTHER" {
		if class := nativeClass(d.OSCode); class != "" {
			d.Class = class
			if class == "TIMEOUT" {
				d.Timeout = true
			}
		}
	}
	return d
}

func Fields(d Detail) map[string]any {
	m := map[string]any{"stage": d.Stage, "errorClass": d.Class, "timeout": d.Timeout}
	if d.Code != "" {
		m["errorCode"] = d.Code
	}
	if d.OSCode != 0 {
		m["osErrorCode"] = d.OSCode
	}
	if d.HTTPStatus != 0 {
		m["httpStatusCode"] = d.HTTPStatus
	}
	if id := SafeID(d.ControlRequestID); id != "" {
		m["controlRequestId"] = id
	}
	if id := SafeID(d.ServerRequestID); id != "" {
		m["serverRequestId"] = id
	}
	return m
}
