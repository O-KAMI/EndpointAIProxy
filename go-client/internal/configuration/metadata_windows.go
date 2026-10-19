//go:build windows

package configuration

import (
	"errors"
	"golang.org/x/sys/windows"
	"os"
)

func copyMetadata(source, target string, info os.FileInfo) error {
	sd, e := windows.GetNamedSecurityInfo(source, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		return e
	}
	owner, _, e := sd.Owner()
	if e != nil {
		return e
	}
	group, _, e := sd.Group()
	if e != nil {
		return e
	}
	dacl, _, e := sd.DACL()
	if e != nil {
		return e
	}
	control, _, e := sd.Control()
	if e != nil {
		return e
	}
	flags := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION | windows.GROUP_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION)
	if control&windows.SE_DACL_PROTECTED != 0 {
		flags |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		flags |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	apply := func() error {
		return windows.SetNamedSecurityInfo(target, windows.SE_FILE_OBJECT, flags, owner, group, dacl, nil)
	}
	e = apply()
	if errors.Is(e, windows.ERROR_INVALID_OWNER) || errors.Is(e, windows.ERROR_ACCESS_DENIED) || errors.Is(e, windows.ERROR_PRIVILEGE_NOT_HELD) {
		// SYSTEM normally owns the staging file but not the user's original.
		// Arbitrary ownership restoration requires an enabled SeRestorePrivilege.
		return withRestorePrivilege(apply)
	}
	return e
}

func metadataVerification(source, target string, info os.FileInfo) (func(string) error, error) {
	return nil, nil
}

// Newly-created entries keep the DACL inherited from their parent. Assign only
// the registry-discovered profile SID as owner, without copying directory ACLs
// onto a file or changing existing inheritance protection.
func setProfileOwner(p Profile, path string) error {
	owner, e := windows.StringToSid(p.SID)
	if e != nil {
		return problem("CONFIG_PROFILE_IDENTITY_UNAVAILABLE")
	}
	apply := func() error {
		return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, owner, nil, nil, nil)
	}
	e = apply()
	if errors.Is(e, windows.ERROR_INVALID_OWNER) || errors.Is(e, windows.ERROR_ACCESS_DENIED) || errors.Is(e, windows.ERROR_PRIVILEGE_NOT_HELD) {
		return withRestorePrivilege(apply)
	}
	return e
}
