//go:build !windows

package configuration

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

func fixtureProfileSID(t *testing.T) string { return "fixture-user" }

func TestNewProfileConfigurationOwnerAndDirectoryModes(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	if e := os.Mkdir(home, 0750); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(home, ".claude", "nested", "settings.json")
	p := Profile{SID: "fixture-user", Home: home}
	u, e := applyProfileFile(context.Background(), p, path, nil, []byte("fixture"), filepath.Join(root, "backups"))
	if e != nil {
		t.Fatal(e)
	}
	expected, _ := os.Stat(home)
	owner := expected.Sys().(*syscall.Stat_t)
	for _, name := range []string{filepath.Dir(filepath.Dir(path)), filepath.Dir(path), path} {
		info, e := os.Stat(name)
		if e != nil {
			t.Fatal(e)
		}
		stat := info.Sys().(*syscall.Stat_t)
		if stat.Uid != owner.Uid || stat.Gid != owner.Gid {
			t.Fatal("incorrect owner", name)
		}
		mode := os.FileMode(0600)
		if info.IsDir() {
			mode = 0700
		}
		if info.Mode().Perm() != mode {
			t.Fatal("incorrect mode", info.Mode())
		}
	}
	if e = u.Rollback(context.Background(), filepath.Join(root, "backups")); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("created config not removed")
	}
	// Existing home and directories are not chmod/chown targets.
	if got, _ := os.Stat(home); got.Mode().Perm() != 0750 {
		t.Fatal("existing home mode changed")
	}
}

func TestProfilePathSymlinkAndEscapeRejected(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	outside := filepath.Join(root, "outside")
	if e := os.Mkdir(home, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(outside, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(outside, filepath.Join(home, ".claude")); e != nil {
		t.Fatal(e)
	}
	p := Profile{Home: home}
	for _, path := range []string{filepath.Join(home, ".claude", "settings.json"), filepath.Join(outside, "settings.json")} {
		if _, e := applyProfileFile(context.Background(), p, path, nil, []byte("fixture"), filepath.Join(root, "backups")); e == nil {
			t.Fatal("unsafe profile path accepted")
		}
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatal("wrote outside profile")
	}
}

// Runs a real cross-UID probe when the suite is invoked by an administrator.
// Ordinary-user CI reports it skipped, not passed.
func TestRootCreatesUsableUserConfiguration(t *testing.T) {
	if path := os.Getenv("ENDPOINTAI_OWNER_FIXTURE"); path != "" {
		f, e := os.OpenFile(path, os.O_RDWR, 0)
		if e != nil {
			t.Fatal(e)
		}
		f.Close()
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root for actual cross-UID creation")
	}
	root, e := os.MkdirTemp("/private/tmp", "endpointai-owner-")
	if e != nil {
		root, e = os.MkdirTemp("/tmp", "endpointai-owner-")
	}
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(root)
	if e = os.Chmod(root, 0711); e != nil {
		t.Fatal(e)
	}
	home := filepath.Join(root, "home")
	if e = os.Mkdir(home, 0700); e != nil {
		t.Fatal(e)
	}
	const uid = 65534
	if e = os.Chown(home, uid, uid); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(home, ".codex", "config.toml")
	if _, e = applyProfileFile(context.Background(), Profile{Home: home}, path, nil, []byte("model='fixture'\n"), filepath.Join(root, "backups")); e != nil {
		t.Fatal(e)
	}
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	// The Go test executable may itself live under a private root-owned cache.
	helper := filepath.Join(root, "owner-test")
	data, e := os.ReadFile(exe)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(helper, data, 0755); e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(helper, "-test.run=^TestRootCreatesUsableUserConfiguration$")
	cmd.Env = append(os.Environ(), "ENDPOINTAI_OWNER_FIXTURE="+path)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid}}
	if b, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("target UID %s cannot read/write config: %v %s", strconv.Itoa(uid), e, b)
	}
}
