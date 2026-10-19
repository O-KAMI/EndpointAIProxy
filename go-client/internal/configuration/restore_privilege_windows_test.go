package configuration

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func restoreLUID(t *testing.T) windows.LUID {
	t.Helper()
	name, _ := windows.UTF16PtrFromString("SeRestorePrivilege")
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, name, &luid); err != nil {
		t.Fatal(err)
	}
	return luid
}

func TestWindowsRestorePrivilegeDoesNotChangeProcessToken(t *testing.T) {
	luid := restoreLUID(t)
	before, err := hasEnabledPrivilege(windows.GetCurrentProcessToken(), luid)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	callbackError := errors.New("intentional callback failure")
	err = withRestorePrivilege(func() error {
		called = true
		enabled, e := hasEnabledPrivilege(windows.GetCurrentThreadToken(), luid)
		if e != nil || !enabled {
			t.Error("restore privilege not active only on thread", e)
		}
		processEnabled, e := hasEnabledPrivilege(windows.GetCurrentProcessToken(), luid)
		if e != nil || processEnabled != before {
			t.Error("process token was changed", e)
		}
		return callbackError
	})
	after, inspectErr := hasEnabledPrivilege(windows.GetCurrentProcessToken(), luid)
	if inspectErr != nil || after != before {
		t.Fatal("process privilege leaked", inspectErr)
	}
	if errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) && !called {
		t.Skip("SeRestorePrivilege not assigned; elevated/SYSTEM test required")
	}
	if !called || !errors.Is(err, callbackError) {
		t.Fatal("callback failure not preserved", err)
	}
}

func TestWindowsForeignOwnerPreserved(t *testing.T) {
	root := t.TempDir()
	source, target := filepath.Join(root, "source"), filepath.Join(root, "staging")
	for _, path := range []string{source, target} {
		if err := os.WriteFile(path, []byte("test"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	// A synthetic, valid user SID models a configuration belonging to a
	// different account without creating accounts or touching real user data.
	foreign, err := windows.StringToSid("S-1-5-21-123456789-987654321-112233445-1001")
	if err != nil {
		t.Fatal(err)
	}
	err = withRestorePrivilege(func() error {
		return windows.SetNamedSecurityInfo(source, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, foreign, nil, nil, nil)
	})
	if errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) {
		t.Skip("cross-owner fixture requires elevated/SYSTEM SeRestorePrivilege")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		user, e := windows.GetCurrentProcessToken().GetTokenUser()
		if e == nil {
			_ = withRestorePrivilege(func() error {
				return windows.SetNamedSecurityInfo(source, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, user.User.Sid, nil, nil, nil)
			})
		}
	}()
	info, err := os.Stat(source)
	if err != nil {
		t.Fatal(err)
	}
	if err = copyMetadata(source, target, info); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(target, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := sd.Owner()
	if err != nil || !owner.Equals(foreign) {
		t.Fatal("foreign owner was not retained", err)
	}
}
