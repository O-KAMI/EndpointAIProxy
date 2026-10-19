//go:build windows

package configuration

import (
	"errors"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

func duplicateEffectiveToken() (windows.Token, error) {
	// Capture the caller's effective identity, including any existing
	// impersonation, before handing its private duplicate to a dedicated thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var source windows.Token
	err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, true, &source)
	if errors.Is(err, windows.ERROR_NO_TOKEN) {
		err = windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &source)
	}
	if err != nil {
		return 0, err
	}
	defer source.Close()
	var duplicate windows.Token
	err = windows.DuplicateTokenEx(source, windows.TOKEN_QUERY|windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_IMPERSONATE, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &duplicate)
	return duplicate, err
}

func hasEnabledPrivilege(token windows.Token, luid windows.LUID) (bool, error) {
	var size uint32
	err := windows.GetTokenInformation(token, windows.TokenPrivileges, nil, 0, &size)
	if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) || size < 4 || size > 1<<20 {
		return false, errors.New("cannot inspect token privileges")
	}
	buf := make([]byte, size)
	if err = windows.GetTokenInformation(token, windows.TokenPrivileges, &buf[0], size, &size); err != nil {
		return false, err
	}
	privileges := (*windows.Tokenprivileges)(unsafe.Pointer(&buf[0]))
	if uint64(privileges.PrivilegeCount)*12+4 > uint64(len(buf)) {
		return false, errors.New("invalid token privileges")
	}
	for _, privilege := range privileges.AllPrivileges() {
		if privilege.Luid == luid {
			return privilege.Attributes&windows.SE_PRIVILEGE_ENABLED != 0, nil
		}
	}
	return false, nil
}

// Enable only an already assigned privilege on a private token. The process
// token is never changed. The dedicated locked thread is retired on exit even
// if RevertToSelf fails, so its impersonation cannot leak to another goroutine.
func withRestorePrivilege(fn func() error) error {
	token, err := duplicateEffectiveToken()
	if err != nil {
		return err
	}
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		// Deliberately do not UnlockOSThread: Go destroys a locked OS thread
		// when its goroutine exits, providing a final containment boundary.
		defer token.Close()
		var outcome error
		impersonating := false
		defer func() {
			if impersonating {
				outcome = errors.Join(outcome, windows.RevertToSelf())
			}
			result <- outcome
		}()
		name, _ := windows.UTF16PtrFromString("SeRestorePrivilege")
		var luid windows.LUID
		if outcome = windows.LookupPrivilegeValue(nil, name, &luid); outcome != nil {
			return
		}
		state := windows.Tokenprivileges{PrivilegeCount: 1, Privileges: [1]windows.LUIDAndAttributes{{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}}}
		if outcome = windows.AdjustTokenPrivileges(token, false, &state, 0, nil, nil); outcome != nil {
			return
		}
		// AdjustTokenPrivileges can succeed with ERROR_NOT_ALL_ASSIGNED;
		// verify the resulting token instead of treating BOOL success as enough.
		var enabled bool
		enabled, outcome = hasEnabledPrivilege(token, luid)
		if outcome != nil {
			return
		}
		if !enabled {
			outcome = windows.ERROR_PRIVILEGE_NOT_HELD
			return
		}
		if outcome = windows.SetThreadToken(nil, token); outcome != nil {
			return
		}
		impersonating = true
		outcome = fn()
	}()
	return <-result
}
