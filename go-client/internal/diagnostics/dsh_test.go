package diagnostics

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDSHMetadataExcludesConfigurationAndIdentity(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(home, ".dsh", "profiles", "private-profile", "cordis.patch.yml")
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("apiKey: synthetic-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	records := dshMetadata(home)
	raw, _ := json.Marshal(records)
	if len(records) != 1 || strings.Contains(string(raw), "synthetic-secret") || strings.Contains(string(raw), "private-profile") || strings.Contains(string(raw), home) {
		t.Fatal(string(raw))
	}
	if err := os.Symlink(filepath.Dir(p), filepath.Join(home, ".dsh", "profiles", "link")); err == nil && len(dshMetadata(home)) != 1 {
		t.Fatal("symlink profile followed")
	}
}
