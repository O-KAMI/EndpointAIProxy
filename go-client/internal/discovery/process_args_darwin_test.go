//go:build darwin

package discovery

import (
	"context"
	"encoding/binary"
	"endpointai/client/internal/platform"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"reflect"
	"testing"
)

func TestDarwinProcessArgumentsPreserveBoundariesAndIgnoreEnvironment(t *testing.T) {
	want := []string{"node", "/tmp/目录 has spaces/bin.js", "", "--patch", "a b.yml"}
	raw := make([]byte, 4)
	binary.LittleEndian.PutUint32(raw, uint32(len(want)))
	raw = append(raw, []byte("/usr/local/bin/node\x00\x00\x00")...)
	for _, arg := range want {
		raw = append(raw, []byte(arg)...)
		raw = append(raw, 0)
	}
	raw = append(raw, []byte("SYNTHETIC_SECRET=never-returned\x00")...)
	got, err := parseDarwinProcessArgs(raw)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("argv boundaries lost: %v", err)
	}
	for _, truncated := range [][]byte{nil, raw[:4], raw[:12], raw[:len(raw)-len("SYNTHETIC_SECRET=never-returned\x00")-1]} {
		if _, err := parseDarwinProcessArgs(truncated); err == nil {
			t.Fatal("truncated argv accepted")
		}
	}
	if got, err = nativeProcessArgs(context.Background(), os.Getpid()); err != nil || len(got) == 0 {
		t.Fatalf("native current process argv unavailable: %v", err)
	}
}

func TestDarwinIncompleteNodeReadMarksOnlyItsUserUnknown(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node unavailable")
	}
	cmd := exec.Command(node, "-e", "setInterval(()=>{},1000)")
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	owner, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	profiles := []platform.Profile{{SID: "macos:" + owner.Username, Home: owner.HomeDir}, {SID: "unrelated-review-fixture", Home: "/nonexistent-unrelated-review-fixture"}}
	samples, err := processSamplesWithArgs(context.Background(), profiles, func(ctx context.Context, pid int) ([]string, error) {
		if pid == cmd.Process.Pid {
			return nil, errors.New("PROCESS_ARGUMENTS_INCOMPLETE")
		}
		return nativeProcessArgs(ctx, pid)
	})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range samples {
		if s.inspectionUnknown {
			if s.sid != profiles[0].SID {
				t.Fatal("unrelated user marked unknown")
			}
			found = true
		}
	}
	if !found {
		t.Fatal("incomplete Node read treated as absence")
	}
}

func TestDarwinLongAccountNameUsesTrustedNumericOwner(t *testing.T) {
	home := t.TempDir()
	sid := "macos:long-account-name-that-ps-would-truncate"
	owners, unknown := unixProfileOwners([]platform.Profile{{SID: sid, Home: home}})
	if owners[sid] == "" || unknown[sid] {
		t.Fatal("long account name lost trusted UID association")
	}
}
