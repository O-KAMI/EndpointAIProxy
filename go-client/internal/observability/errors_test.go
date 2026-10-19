package observability

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
)

func TestClassifiedCausesDoNotExposeFreeText(t *testing.T) {
	for _, tc := range []struct {
		err   error
		class string
	}{
		{context.Canceled, "CANCELLED"}, {context.DeadlineExceeded, "TIMEOUT"},
		{&net.DNSError{Err: "private token", Name: "private.example", IsNotFound: true}, "DNS_NOT_FOUND"},
		{x509.HostnameError{Host: "private.example"}, "TLS_HOSTNAME"},
		{x509.UnknownAuthorityError{}, "TLS_UNTRUSTED"},
		{&os.PathError{Op: "write", Path: "/private/token", Err: syscall.ENOSPC}, "DISK_FULL"},
		{fmt.Errorf("secret: %w", syscall.ECONNREFUSED), "CONNECTION_REFUSED"},
		{io.ErrUnexpectedEOF, "UNEXPECTED_EOF"}, {errors.New("Bearer private-token"), "OTHER"},
	} {
		d := Classify(tc.err)
		if d.Class != tc.class {
			t.Fatalf("got %s want %s", d.Class, tc.class)
		}
		wrapped := Wrap("connect", "GATEWAY_CONNECTION_FAILED", tc.err)
		if wrapped.Error() != "GATEWAY_CONNECTION_FAILED" || !errors.Is(wrapped, tc.err) {
			t.Fatal("lost safe code or cause")
		}
	}
}

func TestCorrelationIDsAreValidated(t *testing.T) {
	fields := Fields(Detail{ControlRequestID: "token=private", ServerRequestID: "10000000-0000-0000-0000-000000000001"})
	if _, exists := fields["controlRequestId"]; exists {
		t.Fatal("unvalidated correlation ID")
	}
	if fields["serverRequestId"] == nil {
		t.Fatal("lost valid correlation ID")
	}
}
