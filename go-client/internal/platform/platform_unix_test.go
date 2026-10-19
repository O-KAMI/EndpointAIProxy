//go:build !windows

package platform

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestProfilesExcludeSystemAndHidden(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"Shared", "Guest", ".hidden", "alice", "bob"} {
		if e := os.Mkdir(filepath.Join(root, name), 0700); e != nil {
			t.Fatal(e)
		}
	}
	p, e := ProfilesAt(context.Background(), root)
	if e != nil || len(p) != 2 || p[0].SID != "macos:alice" || p[1].SID != "macos:bob" {
		t.Fatal(p, e)
	}
	if p[0].Home != filepath.Join(root, "alice") || len(p[0].SearchPaths) != 7 {
		t.Fatal(p[0])
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := ProfilesAt(ctx, root); e == nil {
		t.Fatal("cancellation ignored")
	}
}
