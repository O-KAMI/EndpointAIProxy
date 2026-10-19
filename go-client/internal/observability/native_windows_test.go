//go:build windows

package observability

import (
	"golang.org/x/sys/windows"
	"testing"
)

func TestWindowsNativeFailureCodes(t *testing.T) {
	for _, tc := range []struct {
		err   windows.Errno
		class string
	}{{windows.ERROR_DISK_FULL, "DISK_FULL"}, {windows.WSAECONNREFUSED, "CONNECTION_REFUSED"}, {windows.WSAECONNRESET, "CONNECTION_RESET"}} {
		if got := Classify(tc.err); got.Class != tc.class || got.OSCode != int(tc.err) {
			t.Fatalf("lost native failure: %+v", got)
		}
	}
}
