package configuration

import (
	"context"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsReplacementPreservesDACLProtectionAndRollback(t *testing.T) {
	for _, protected := range []bool{true, false} {
		t.Run(map[bool]string{true: "protected", false: "inheriting"}[protected], func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "settings.json")
			if err := os.WriteFile(path, []byte("before"), 0600); err != nil {
				t.Fatal(err)
			}
			sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
			if err != nil {
				t.Fatal(err)
			}
			dacl, _, err := sd.DACL()
			if err != nil {
				t.Fatal(err)
			}
			flag := windows.SECURITY_INFORMATION(windows.UNPROTECTED_DACL_SECURITY_INFORMATION)
			if protected {
				flag = windows.PROTECTED_DACL_SECURITY_INFORMATION
			}
			if err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|flag, nil, nil, dacl, nil); err != nil {
				t.Fatal(err)
			}
			sd, err = windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
			if err != nil {
				t.Fatal(err)
			}
			originalDACL := sd.String()
			update, err := ApplyFile(context.Background(), path, []byte("before"), []byte("after"), filepath.Join(root, "backups"))
			if err != nil {
				t.Fatal(err)
			}
			assertDACL := func() {
				t.Helper()
				current, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
				if err != nil {
					t.Fatal(err)
				}
				control, _, err := current.Control()
				if err != nil || (control&windows.SE_DACL_PROTECTED != 0) != protected {
					t.Fatalf("protection changed: %v %v", control, err)
				}
				if current.String() != originalDACL {
					t.Fatal("replacement changed DACL")
				}
			}
			assertDACL()
			if err = update.Rollback(context.Background(), filepath.Join(root, "backups")); err != nil {
				t.Fatal(err)
			}
			assertDACL()
			data, _ := os.ReadFile(path)
			if string(data) != "before" {
				t.Fatal("rollback did not restore original")
			}
		})
	}
}

func TestWindowsCreateDoesNotOverwriteConcurrentFile(t *testing.T) {
	root := t.TempDir()
	source, target := filepath.Join(root, "temp"), filepath.Join(root, "target")
	if err := os.WriteFile(source, []byte("ours"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("user"), 0600); err != nil {
		t.Fatal(err)
	}
	if replaceFile(source, target, false) == nil {
		t.Fatal("overwrote concurrent file")
	}
	data, _ := os.ReadFile(target)
	if string(data) != "user" {
		t.Fatal("user file changed")
	}
}

func fixtureProfileSID(t *testing.T) string {
	t.Helper()
	u, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		t.Fatal(e)
	}
	return u.User.Sid.String()
}

func TestWindowsNewProfileConfigKeepsInheritedDACL(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	if e := os.Mkdir(home, 0700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(home, ".codex", "config.toml")
	p := Profile{SID: fixtureProfileSID(t), Home: home}
	if _, e := applyProfileFile(context.Background(), p, path, nil, []byte("fixture"), filepath.Join(root, "backups")); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{filepath.Dir(path), path} {
		sd, e := windows.GetNamedSecurityInfo(name, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if e != nil {
			t.Fatal(e)
		}
		owner, _, e := sd.Owner()
		if e != nil || owner.String() != p.SID {
			t.Fatal("owner changed", e)
		}
		control, _, e := sd.Control()
		if e != nil || control&windows.SE_DACL_PROTECTED != 0 {
			t.Fatal("new DACL inheritance protected", e)
		}
		dacl, _, e := sd.DACL()
		if e != nil || dacl == nil {
			t.Fatal("new config lacks inherited ACL", e)
		}
	}
}
