//go:build darwin

package configuration

import (
	"bytes"
	"context"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestDarwinReplacementAndRollbackPreserveACLAndXattrs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	backups := filepath.Join(dir, "backups")
	if err := os.WriteFile(path, []byte("before"), 0644); err != nil {
		t.Fatal(err)
	}
	if b, err := exec.Command("/bin/chmod", "+a", "user:nobody deny read", path).CombinedOutput(); err != nil {
		t.Fatalf("ACL setup: %v %s", err, b)
	}
	const attr = "com.sf.endpointai.fixture"
	if err := unix.Setxattr(path, attr, []byte("synthetic-metadata"), 0); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	original, err := openMetadataFile(path)
	if err != nil {
		t.Fatal(err)
	}
	expectedACL, err := darwinACL(original.Fd())
	original.Close()
	if err != nil || len(expectedACL) <= 44 {
		t.Fatal("fixture ACL missing", err)
	}
	check := func() {
		t.Helper()
		b, err := exec.Command("/bin/ls", "-le", path).Output()
		if err != nil || !strings.Contains(string(b), "deny read") {
			t.Fatalf("ACL lost: %v", err)
		}
		// Account-name rendering can vary with directory-service resolution. Check
		// the entire native ACL identity/permissions as well as the independent BSD
		// permission listing, rather than treating its display label as identity.
		file, e := openMetadataFile(path)
		if e != nil {
			t.Fatal(e)
		}
		actualACL, e := darwinACL(file.Fd())
		file.Close()
		if e != nil || !bytes.Equal(expectedACL, actualACL) {
			t.Fatal("native ACL identity or permissions changed", e)
		}
		attrBytes := make([]byte, 64)
		n, err := unix.Getxattr(path, attr, attrBytes)
		if err != nil || string(attrBytes[:n]) != "synthetic-metadata" {
			t.Fatal("xattr lost")
		}
		after, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		oldStat, newStat := before.Sys().(*syscall.Stat_t), after.Sys().(*syscall.Stat_t)
		if before.Mode().Perm() != after.Mode().Perm() || oldStat.Uid != newStat.Uid || oldStat.Gid != newStat.Gid {
			t.Fatal("owner/mode changed")
		}
	}
	u, err := ApplyFile(context.Background(), path, []byte("before"), []byte("after"), backups)
	if err != nil {
		t.Fatal(err)
	}
	check()
	if err = u.Rollback(context.Background(), backups); err != nil {
		t.Fatal(err)
	}
	check()
}

func TestDarwinMetadataReadFailureDoesNotReplaceConfiguration(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can bypass ACL read restriction")
	}
	owner, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	if err = os.WriteFile(path, []byte("before"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = unix.Setxattr(path, "com.sf.endpointai.fixture", []byte("synthetic"), 0); err != nil {
		t.Fatal(err)
	}
	if b, e := exec.Command("/bin/chmod", "+a", "user:"+owner.Username+" deny readextattr", path).CombinedOutput(); e != nil {
		t.Fatalf("ACL setup: %v %s", e, b)
	}
	u, err := ApplyFile(context.Background(), path, []byte("before"), []byte("after"), filepath.Join(dir, "backups"))
	if err == nil || u.Replaced {
		t.Fatal("unreadable metadata allowed replacement")
	}
	b, e := os.ReadFile(path)
	if e != nil || string(b) != "before" {
		t.Fatal("failed metadata copy changed configuration")
	}
}

func TestDarwinMetadataConcurrentChangeDetected(t *testing.T) {
	dir := t.TempDir()
	source, target := filepath.Join(dir, "source"), filepath.Join(dir, "target")
	for _, path := range []string{source, target} {
		if err := os.WriteFile(path, []byte("synthetic"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	info, err := os.Stat(source)
	if err != nil {
		t.Fatal(err)
	}
	if err = copyMetadata(source, target, info); err != nil {
		t.Fatal(err)
	}
	verify, err := metadataVerification(source, target, info)
	if err != nil {
		t.Fatal(err)
	}
	if err = unix.Setxattr(source, "com.sf.endpointai.fixture", []byte("user-change"), 0); err != nil {
		t.Fatal(err)
	}
	if err = verify(source); err == nil {
		t.Fatal("concurrent metadata change ignored")
	}
}

func TestDarwinReplacementDoesNotAddInheritedACL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, []byte("before"), 0600); err != nil {
		t.Fatal(err)
	}
	if b, err := exec.Command("/bin/chmod", "+a", "user:nobody deny read,file_inherit", dir).CombinedOutput(); err != nil {
		t.Fatalf("inherited ACL setup: %v %s", err, b)
	}
	if _, err := ApplyFile(context.Background(), path, []byte("before"), []byte("after"), filepath.Join(dir, "backups")); err != nil {
		t.Fatal(err)
	}
	f, err := openMetadataFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	acl, err := darwinACL(f.Fd())
	if err != nil || len(acl) != 0 {
		t.Fatalf("replacement added parent ACL: %v", err)
	}
}
