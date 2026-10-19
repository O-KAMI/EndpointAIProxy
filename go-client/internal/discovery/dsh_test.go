package discovery

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"endpointai/client/internal/platform"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeDSHFixture(t *testing.T, path, body string) {
	t.Helper()
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path, []byte(body), 0600); e != nil {
		t.Fatal(e)
	}
}
func TestDSHManifestAndWeakCommand(t *testing.T) {
	home := t.TempDir()
	npm := filepath.Join(home, "npm")
	writeDSHFixture(t, filepath.Join(npm, "dsh"), "credentials must not be read")
	p := platform.Profile{SID: "fixture", Home: home, Roaming: home, Local: home, SearchPaths: []string{npm}}
	a, e := discover(context.Background(), []platform.Profile{p}, false)
	if e != nil {
		t.Fatal(e)
	}
	for _, v := range a {
		if v.AgentType == DeepSeekHarness {
			t.Fatal("same-name command must remain weak")
		}
	}
	writeDSHFixture(t, filepath.Join(npm, "node_modules/@deepseek-ai/dsh/package.json"), `{"name":"not-dsh","version":"fake"}`)
	a, _ = discover(context.Background(), []platform.Profile{p}, false)
	for _, v := range a {
		if v.AgentType == DeepSeekHarness {
			t.Fatal("wrong package identity")
		}
	}
	writeDSHFixture(t, filepath.Join(npm, "node_modules/@deepseek-ai/dsh/package.json"), `{"name":"@deepseek-ai/dsh","version":"0.9.0"}`)
	a, _ = discover(context.Background(), []platform.Profile{p}, false)
	found := false
	for _, v := range a {
		if v.AgentType == DeepSeekHarness && v.Confirmed && v.Version == "0.9.0" {
			found = true
		}
	}
	if !found {
		t.Fatal(a)
	}
}
func TestDSHProfileDoesNotInventRuntimeVersion(t *testing.T) {
	home := t.TempDir()
	writeDSHFixture(t, filepath.Join(home, ".dsh/profiles/cli/package.json"), `{"version":"0.2.1-alpha.5","dsh":{"profile":{"bundles":[]}}}`)
	samples := dshProfileSamples(platform.Profile{SID: "fixture", Home: home}, []string{filepath.Join(home, ".dsh")})
	if len(samples) != 1 || samples[0].strength != 1 || samples[0].version != "" {
		t.Fatal(samples)
	}
}
func TestDSHNodeEntryNeverScansArgumentValues(t *testing.T) {
	root := filepath.Join(t.TempDir(), "has spaces", "node_modules", "@deepseek-ai", "dsh")
	writeDSHFixture(t, filepath.Join(root, "package.json"), `{"name":"@deepseek-ai/dsh","version":"0.2.1-alpha.5","bin":{"dsh":"lib/bin.js"}}`)
	entry := filepath.Join(root, "lib/bin.js")
	writeDSHFixture(t, entry, "throw new Error('discovery must never execute this')")
	path, v, ok := dshNodeEntry([]string{"/usr/bin/node", entry, "--api-key", "SECRET"})
	if !ok || path != mustReal(t, entry) || v != DSHSupportedVersion {
		t.Fatal(path, v, ok)
	}
	for _, args := range [][]string{{"node", "-e", entry}, {"node", "other.js", entry}, {"node", filepath.Join(root, "lib/other.js")}, {"dsh", entry}} {
		if _, _, ok := dshNodeEntry(args); ok {
			t.Fatal(args)
		}
	}
	args := splitProcessArgs(`/usr/bin/node "` + entry + `" --api-key SECRET`)
	path, _, ok = dshNodeEntry(args)
	if !ok || strings.Contains(path, "SECRET") {
		t.Fatal(args, path)
	}
}
func TestDSHDesktopPackedIdentity(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "Applications/DeepSeek Harness.app/Contents/Resources")
	body := []byte(`{"name":"@deepseek-ai/dsh-desktop","version":"0.2.1-alpha.5"}`)
	header, _ := json.Marshal(map[string]any{"files": map[string]any{"package.json": map[string]any{"size": len(body), "offset": "0"}}})
	padding := (4 - (len(header) % 4)) % 4
	headerSize := 8 + len(header) + padding
	data := make([]byte, 8+headerSize)
	binary.LittleEndian.PutUint32(data[0:4], 4)
	binary.LittleEndian.PutUint32(data[4:8], uint32(headerSize))
	binary.LittleEndian.PutUint32(data[8:12], uint32(headerSize-4))
	binary.LittleEndian.PutUint32(data[12:16], uint32(len(header)))
	copy(data[16:], header)
	data = append(data, body...)
	path := filepath.Join(root, "app.asar")
	writeDSHFixture(t, path, string(data))
	os.MkdirAll(filepath.Join(root, "runtime/primary-runtime"), 0700)
	found := dshDesktopSamples(platform.Profile{Home: home, SID: "fixture"})
	if len(found) != 1 || found[0].version != DSHSupportedVersion {
		t.Fatal(found)
	}
	data[12] = 255
	os.WriteFile(path, data, 0600)
	if _, e := dshASARManifest(path); e == nil {
		t.Fatal("invalid bounds accepted")
	}
}
func TestNodeManifestResolverClosestDependency(t *testing.T) {
	root := t.TempDir()
	start := filepath.Join(root, "node_modules/@deepseek-ai/dsh")
	os.MkdirAll(start, 0700)
	near := filepath.Join(start, "node_modules/@earendil-works/pi-ai/package.json")
	writeDSHFixture(t, near, `{"name":"@earendil-works/pi-ai","version":"1.3.0"}`)
	writeDSHFixture(t, filepath.Join(root, "node_modules/@earendil-works/pi-ai/package.json"), `{"name":"@earendil-works/pi-ai","version":"1.1.0"}`)
	if got := resolveNodeManifest(start, "@earendil-works/pi-ai"); got != mustReal(t, near) {
		t.Fatal(got)
	}
}

func mustReal(t *testing.T, path string) string {
	t.Helper()
	r, e := filepath.EvalSymlinks(path)
	if e != nil {
		t.Fatal(e)
	}
	return r
}

func TestDSHMetadataVersionAndResolvedSDK(t *testing.T) {
	home := t.TempDir()
	npm := filepath.Join(home, "npm")
	p := platform.Profile{SID: "fixture", Home: home, Roaming: home, Local: home, SearchPaths: []string{npm}}
	writeDSHFixture(t, filepath.Join(npm, "node_modules/@deepseek-ai/dsh/package.json"), `{"name":"@deepseek-ai/dsh","version":"0.2.1-alpha.5"}`)
	writeDSHFixture(t, filepath.Join(npm, "node_modules/@deepseek-ai/dsh-llm-pi-ai/package.json"), `{"name":"@deepseek-ai/dsh-llm-pi-ai","version":"0.2.1-alpha.5"}`)
	writeDSHFixture(t, filepath.Join(npm, "node_modules/@earendil-works/pi-ai/package.json"), `{"name":"@earendil-works/pi-ai","version":"1.3.0"}`)
	got := DSHProfileMetadata(context.Background(), []platform.Profile{p}, nil)[p.SID]
	if got.Version != DSHSupportedVersion || got.DSHPiAIVersion != "1.3.0" {
		t.Fatal(got)
	}
	writeDSHFixture(t, filepath.Join(home, "npm2/node_modules/@deepseek-ai/dsh/package.json"), `{"name":"@deepseek-ai/dsh","version":"0.9.0"}`)
	p.SearchPaths = append(p.SearchPaths, filepath.Join(home, "npm2"))
	got = DSHProfileMetadata(context.Background(), []platform.Profile{p}, nil)[p.SID]
	if got.Version != "" {
		t.Fatal("ambiguous runtime version accepted", got)
	}
}

func TestDSHStandardLaunchAndOverlayUncertainty(t *testing.T) {
	root := filepath.Join(t.TempDir(), "node_modules/@deepseek-ai/dsh")
	writeDSHFixture(t, filepath.Join(root, "package.json"), `{"name":"@deepseek-ai/dsh","version":"0.2.1-alpha.5","bin":{"dsh":"lib/bin.js"}}`)
	entry := filepath.Join(root, "lib/bin.js")
	writeDSHFixture(t, entry, "do not execute")
	for _, tail := range [][]string{{"web"}, {"--profile", "tui"}, {"--profile=web"}} {
		profile, unknown := dshLaunchProfile(append([]string{"node", entry}, tail...))
		if profile == "" || unknown {
			t.Fatal(tail, profile, unknown)
		}
	}
	for _, tail := range [][]string{{"web", "--patch", "SECRET.yml"}, {"--profile", "web", "--patch=SECRET.yml"}, {"desktop"}, {"plugin"}, {"../escape"}, {"web", "--unknown", "SECRET"}, {}} {
		profile, unknown := dshLaunchProfile(append([]string{"node", entry}, tail...))
		if !unknown || profile != "" {
			t.Fatal(tail, profile, unknown)
		}
	}
}
