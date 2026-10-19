//go:build windows

package observability

import "golang.org/x/sys/windows"

func nativeClass(code int) string {
	switch windows.Errno(code) {
	case windows.ERROR_DISK_FULL, windows.ERROR_HANDLE_DISK_FULL:
		return "DISK_FULL"
	case windows.WSAECONNREFUSED:
		return "CONNECTION_REFUSED"
	case windows.WSAECONNRESET:
		return "CONNECTION_RESET"
	case windows.WSAETIMEDOUT:
		return "TIMEOUT"
	case windows.ERROR_BROKEN_PIPE:
		return "BROKEN_PIPE"
	}
	return ""
}
