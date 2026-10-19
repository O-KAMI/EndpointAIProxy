package discovery

import (
	"context"
	"endpointai/client/internal/platform"
	"os"
	"path/filepath"
	"testing"
)

func TestManifestIdentityAndUnknownEvidence(t *testing.T) {
	home := t.TempDir()
	npm := filepath.Join(home, "npm")
	path := filepath.Join(npm, "node_modules", "@openai", "codex", "package.json")
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path, []byte(`{"version":"1.2.3"}`), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.MkdirAll(filepath.Join(home, ".qoder"), 0700); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(home, ".qoder", "settings.json"), []byte("secret must never be read"), 0600)
	agents, e := discover(context.Background(), []platform.Profile{{SID: "fixture", Home: home, SearchPaths: []string{npm}, Roaming: home, Local: home}}, false)
	if e != nil {
		t.Fatal(e)
	}
	var codex, unknown bool
	for _, a := range agents {
		if a.AgentType == CodexCLI {
			codex = a.Confirmed && a.Version == "1.2.3"
		}
		if a.AgentType == UnknownCandidate {
			unknown = !a.Confirmed
		}
	}
	if !codex || !unknown {
		t.Fatalf("identity mismatch: %+v", agents)
	}
}
func TestSurfaceClassification(t *testing.T) {
	for _, tc := range []struct {
		path string
		want int
	}{{"/Applications/Codex.app/Contents/MacOS/Codex", CodexDesktop}, {`C:\Users\fixture\.vscode\extensions\anthropic.claude-code-1.0\claude.exe`, ClaudeIDE}, {"/usr/local/bin/codex", CodexCLI}} {
		kind, ok := processKind(tc.path)
		if !ok || kind != tc.want {
			t.Fatalf("%s got %d", tc.path, kind)
		}
	}
}
