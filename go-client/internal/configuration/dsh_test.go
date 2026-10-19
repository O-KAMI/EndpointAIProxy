package configuration

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const dshFixtureManifest = `{"dsh":{"profile":{"bundles":["@deepseek-ai/dsh-base","@deepseek-ai/dsh-headless"]}}}`
const dshDeepSeekFixture = `# user comment
- id: llm-deepseek
  config:
    baseURL: https://synthetic.example.invalid/anthropic/v1
    apiKeyEnv: DEEPSEEK_API_KEY
    models:
      - id: fixture-model
- id: untouched
  config:
    arbitrary: retained
`

func writeDSHFixture(t *testing.T, p Profile, root, profile, content string) string {
	t.Helper()
	dir := filepath.Join(root, "profiles", profile)
	writeFixture(t, filepath.Join(dir, "package.json"), dshFixtureManifest)
	path := filepath.Join(dir, "cordis.patch.yml")
	writeFixture(t, path, content)
	return path
}
func trustedDSH(p Profile) Profile {
	p.DSHVersion = DSHSupportedVersion
	p.DSHPiAIVersion = "1.3.0"
	return p
}
func dshOnly(rs []Result) []Result {
	var out []Result
	for _, r := range rs {
		if r.AgentType == dshAgent {
			out = append(out, r)
		}
	}
	return out
}
func TestDSHAttachMultiProfileStableAndDetachWithFlagOff(t *testing.T) {
	m, p := fixtureManager(t)
	p = trustedDSH(p)
	m.EnableDSH = true
	ctx := context.Background()
	root := filepath.Join(p.Home, ".dsh")
	one := writeDSHFixture(t, p, root, "headless", dshDeepSeekFixture)
	writeDSHFixture(t, p, root, "web", dshDeepSeekFixture)
	rs, e := m.Reconcile(ctx, []Profile{p})
	if e != nil {
		t.Fatal(e)
	}
	rs = dshOnly(rs)
	if len(rs) != 2 || rs[0].Status != 3 || rs[0].RouteID == rs[1].RouteID {
		t.Fatal(rs)
	}
	routes, _ := m.Store.ListRoutes(ctx)
	if len(routes) != 2 {
		t.Fatal(routes)
	}
	for _, r := range routes {
		if !strings.HasPrefix(r.ProviderID, "dsh:messages:deepseek:") || r.OriginalBaseURL != "https://synthetic.example.invalid/anthropic/v1" {
			t.Fatal(r)
		}
	}
	again, e := m.Reconcile(ctx, []Profile{p})
	if e != nil {
		t.Fatal(e)
	}
	for _, r := range dshOnly(again) {
		if r.Changed {
			t.Fatal("not idempotent", r)
		}
	}
	b, _ := os.ReadFile(one)
	if !strings.Contains(string(b), "# user comment") || !strings.Contains(string(b), "arbitrary: retained") {
		t.Fatal("lost config/comment")
	}
	b = append(b, []byte("- id: user-added\n  config: {keep: true}\n")...)
	if e = os.WriteFile(one, b, 0600); e != nil {
		t.Fatal(e)
	}
	m.EnableDSH = false
	p.DSHVersion = ""
	p.DSHOverlaysUnknown = false
	if _, e = m.DetachAll(ctx, []Profile{p}); e != nil {
		t.Fatal(e)
	}
	b, _ = os.ReadFile(one)
	if strings.Contains(string(b), "127.0.0.1") || !strings.Contains(string(b), "user-added") {
		t.Fatal(string(b))
	}
	routes, _ = m.Store.ListRoutes(ctx)
	if len(routes) != 0 {
		t.Fatal("unretired", routes)
	}
}
func TestDSHDefaultDisabled(t *testing.T) {
	m, p := fixtureManager(t)
	p = trustedDSH(p)
	path := writeDSHFixture(t, p, filepath.Join(p.Home, ".dsh"), "web", dshDeepSeekFixture)
	if _, e := m.Reconcile(context.Background(), []Profile{p}); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(path)
	if string(b) != dshDeepSeekFixture {
		t.Fatal("DSH enabled by default")
	}
	assets, e := m.Inspect(context.Background(), []Profile{p})
	if e != nil || len(assets) != 1 || assets[0].Family != "deepseekHarness" {
		t.Fatal(assets, e)
	}
}
func TestDSHCustomThreeProtocolsAndSearch(t *testing.T) {
	m, p := fixtureManager(t)
	p = trustedDSH(p)
	m.EnableDSH = true
	config := `- id: llm-pi-ai
  config:
    providers:
      company-chat:
        baseURL: https://synthetic.example.invalid/v1
        api: openai-completions
        apiKeyEnv: COMPANY_KEY
        models: [{id: sample-chat, reasoningEfforts: false}]
        compat: {supportsStore: false, maxTokensField: max_tokens}
      company-responses:
        baseURL: https://synthetic.example.invalid/v1
        api: openai-responses
        apiKeyEnv: COMPANY_KEY
        models: [{id: sample-responses}]
      company-messages:
        baseURL: https://synthetic.example.invalid
        api: anthropic-messages
        apiKeyEnv: COMPANY_KEY
        models: [{id: sample-messages}]
- id: web-search-deepseek
  config:
    baseURL: https://synthetic.example.invalid
    apiKeyEnv: DEEPSEEK_API_KEY
`
	path := writeDSHFixture(t, p, filepath.Join(p.Home, ".dsh"), "web", config)
	rs, e := m.Reconcile(context.Background(), []Profile{p})
	if e != nil {
		t.Fatal(e)
	}
	rs = dshOnly(rs)
	if len(rs) != 4 {
		t.Fatal(rs)
	}
	for _, r := range rs {
		if r.Status != 3 {
			t.Fatal(r)
		}
	}
	var tree yaml.Node
	b, _ := os.ReadFile(path)
	if dshParse(b, &tree) != nil || !strings.Contains(string(b), "maxTokensField: max_tokens") || !strings.Contains(string(b), "apiKeyEnv: COMPANY_KEY") {
		t.Fatal(string(b))
	}
	if _, e = m.DetachAll(context.Background(), []Profile{p}); e != nil {
		t.Fatal(e)
	}
	b, _ = os.ReadFile(path)
	if strings.Contains(string(b), "127.0.0.1") || !strings.Contains(string(b), "company-responses") {
		t.Fatal(string(b))
	}
}
func TestDSHUnsupportedNeverChangesConfig(t *testing.T) {
	cases := []struct {
		name, patch, homePatch, version, sdk string
		overlay                              bool
	}{
		{name: "unknown version", patch: dshDeepSeekFixture, version: "0.3.0"},
		{name: "unknown overlays", patch: dshDeepSeekFixture, version: DSHSupportedVersion, overlay: true},
		{name: "home override", patch: dshDeepSeekFixture, version: DSHSupportedVersion, homePatch: "- id: llm-deepseek\n  config: {baseURL: https://override.example}\n"},
		{name: "dynamic expression", patch: "- id: llm-deepseek\n  config: {baseURL: !!js process.env.BASE_URL}\n", version: DSHSupportedVersion},
		{name: "missing url", patch: "- id: llm-deepseek\n  config: {apiKeyEnv: DEEPSEEK_API_KEY}\n", version: DSHSupportedVersion},
		{name: "account", patch: "- id: llm-deepseek-account\n  config: {inferenceOrigin: https://chat.deepseek.com}\n", version: DSHSupportedVersion},
		{name: "duplicate ids", patch: dshDeepSeekFixture + dshDeepSeekFixture, version: DSHSupportedVersion},
		{name: "duplicate yaml keys", patch: "- id: llm-deepseek\n  config: {baseURL: https://one.example, baseURL: https://two.example}\n", version: DSHSupportedVersion},
		{name: "alias", patch: "- id: llm-deepseek\n  config: &x {baseURL: https://one.example}\n- id: other\n  config: *x\n", version: DSHSupportedVersion},
		{name: "user info url", patch: "- id: llm-deepseek\n  config: {baseURL: 'https://secret:credential@example.com'}\n", version: DSHSupportedVersion},
		{name: "changed plugin", patch: "- id: llm-deepseek\n  name: '@untrusted/plugin'\n  config: {baseURL: https://example.com}\n", version: DSHSupportedVersion},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, p := fixtureManager(t)
			m.EnableDSH = true
			p.DSHVersion = c.version
			p.DSHOverlaysUnknown = c.overlay
			root := filepath.Join(p.Home, ".dsh")
			path := writeDSHFixture(t, p, root, "web", c.patch)
			if c.homePatch != "" {
				writeFixture(t, filepath.Join(root, "cordis.patch.yml"), c.homePatch)
			}
			rs, e := m.Reconcile(context.Background(), []Profile{p})
			if e != nil {
				t.Fatal(e)
			}
			rs = dshOnly(rs)
			if len(rs) == 0 || rs[0].Status != 5 {
				t.Fatal(rs)
			}
			b, _ := os.ReadFile(path)
			if string(b) != c.patch {
				t.Fatal("unsafe mutation")
			}
			routes, _ := m.Store.ListRoutes(context.Background())
			if len(routes) != 0 {
				t.Fatal(routes)
			}
		})
	}
}
func TestDSHRecoveryJournalFindsCustomRootAndDoesNotContainSecrets(t *testing.T) {
	m, p := fixtureManager(t)
	p = trustedDSH(p)
	m.EnableDSH = true
	custom := filepath.Join(p.Home, "custom-dsh")
	p.DSHHomes = []string{custom}
	path := writeDSHFixture(t, p, custom, "web", dshDeepSeekFixture)
	if _, e := m.Reconcile(context.Background(), []Profile{p}); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(m.dshJournalPath(p))
	if e != nil || strings.Contains(string(b), "DEEPSEEK_API_KEY") || strings.Contains(string(b), "baseURL") {
		t.Fatal(string(b), e)
	}
	p.DSHHomes = nil
	m.EnableDSH = false
	if _, e = m.DetachAll(context.Background(), []Profile{p}); e != nil {
		t.Fatal(e)
	}
	b, _ = os.ReadFile(path)
	if strings.Contains(string(b), "127.0.0.1") {
		t.Fatal(string(b))
	}
}
func TestDSHDetachUserChangedURLAndMissingFilePreserveRecovery(t *testing.T) {
	for _, remove := range []bool{false, true} {
		t.Run(map[bool]string{false: "changed", true: "missing"}[remove], func(t *testing.T) {
			m, p := fixtureManager(t)
			p = trustedDSH(p)
			m.EnableDSH = true
			path := writeDSHFixture(t, p, filepath.Join(p.Home, ".dsh"), "web", dshDeepSeekFixture)
			if _, e := m.Reconcile(context.Background(), []Profile{p}); e != nil {
				t.Fatal(e)
			}
			if remove {
				os.Remove(path)
			} else {
				writeFixture(t, path, strings.ReplaceAll(dshDeepSeekFixture, "synthetic.example.invalid", "user-edited.example"))
			}
			if _, e := m.DetachAll(context.Background(), []Profile{p}); e == nil {
				t.Fatal("missing recovery failure")
			}
			routes, _ := m.Store.ListRoutes(context.Background())
			if len(routes) != 1 {
				t.Fatal("lost original", routes)
			}
		})
	}
}
func TestDSHApplyDetectsConcurrentWrite(t *testing.T) {
	m, p := fixtureManager(t)
	p = trustedDSH(p)
	path := writeDSHFixture(t, p, filepath.Join(p.Home, ".dsh"), "web", dshDeepSeekFixture)
	docs, e := dshDocuments(p)
	if e != nil || len(docs) != 1 {
		t.Fatal(e)
	}
	doc := docs[0]
	c := doc.candidates[0]
	d, e := m.resolve(context.Background(), p, dshAgent, c.identity, c.current, false)
	if e != nil {
		t.Fatal(e)
	}
	c.urlNode.Value = d.target
	writeFixture(t, path, "# concurrently replaced\n"+dshDeepSeekFixture)
	err := m.dshApplyDocument(context.Background(), p, doc, []ccPlanned{{decision: d, result: Result{Changed: true}}}, []*yaml.Node{c.urlNode}, []string{c.current})
	if errorCode(err) != "CONFIG_CHANGED_CONCURRENTLY" {
		t.Fatal(err)
	}
	routes, _ := m.Store.ListRoutes(context.Background())
	if len(routes) != 0 {
		t.Fatal(routes)
	}
}
func TestDSHGenericCompatibilityRejectsURLSensitiveAndCatalog(t *testing.T) {
	for _, v := range []struct {
		provider, url string
		ok            bool
	}{{"company", "https://synthetic.example.invalid/v1", true}, {"openai", "https://synthetic.example.invalid/v1", false}, {"company", "https://api.deepseek.com/v1", false}, {"company", "https://api.openai.com/v1", false}, {"company", "https://example.invalid/path/openrouter.ai", false}} {
		if got := dshCustomURLCompatibility(v.provider, v.url); (got == "") != v.ok {
			t.Fatal(v, got)
		}
	}
}

func TestDSHDetachMissingUserProfileFails(t *testing.T) {
	m, p := fixtureManager(t)
	p = trustedDSH(p)
	m.EnableDSH = true
	writeDSHFixture(t, p, filepath.Join(p.Home, ".dsh"), "web", dshDeepSeekFixture)
	if _, e := m.Reconcile(context.Background(), []Profile{p}); e != nil {
		t.Fatal(e)
	}
	if _, e := m.DetachAll(context.Background(), nil); e == nil {
		t.Fatal("unresolved DSH route allowed uninstall")
	}
}
func TestDSHAllowlistRestoresOnlyDSHURL(t *testing.T) {
	m, p := fixtureManager(t)
	p = trustedDSH(p)
	m.EnableDSH = true
	path := writeDSHFixture(t, p, filepath.Join(p.Home, ".dsh"), "web", dshDeepSeekFixture)
	if _, e := m.Reconcile(context.Background(), []Profile{p}); e != nil {
		t.Fatal(e)
	}
	m.Allowlisted = func(s string) bool { return s == "https://synthetic.example.invalid/anthropic/v1" }
	if _, e := m.Reconcile(context.Background(), []Profile{p}); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(path)
	routes, _ := m.Store.ListRoutes(context.Background())
	if strings.Contains(string(b), "127.0.0.1") || len(routes) != 0 {
		t.Fatal(string(b), routes)
	}
}
func TestDSHOutsideRootNotReadAndSymlinkNotFollowed(t *testing.T) {
	m, p := fixtureManager(t)
	p = trustedDSH(p)
	m.EnableDSH = true
	outside := t.TempDir()
	path := writeDSHFixture(t, p, outside, "web", dshDeepSeekFixture)
	p.DSHHomes = []string{outside}
	rs, e := m.Reconcile(context.Background(), []Profile{p})
	if e != nil {
		t.Fatal(e)
	}
	rs = dshOnly(rs)
	if len(rs) != 1 || rs[0].ErrorCode != "DSH_ROOT_OUTSIDE_USER_OR_SYMLINK" {
		t.Fatal(rs)
	}
	b, _ := os.ReadFile(path)
	if string(b) != dshDeepSeekFixture {
		t.Fatal("outside root mutated")
	}
	if e = os.MkdirAll(p.Home, 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink(outside, filepath.Join(p.Home, ".dsh")); e != nil {
		t.Skip("symlink not available", e)
	}
	p.DSHHomes = nil
	rs, e = m.Reconcile(context.Background(), []Profile{p})
	if e != nil {
		t.Fatal(e)
	}
	if len(dshOnly(rs)) != 1 {
		t.Fatal(rs)
	}
}
func TestDSHCCFailureDoesNotBlockIndependentTakeover(t *testing.T) {
	m, p := fixtureManager(t)
	p = trustedDSH(p)
	m.EnableDSH = true
	writeDSHFixture(t, p, filepath.Join(p.Home, ".dsh"), "web", dshDeepSeekFixture)
	writeFixture(t, filepath.Join(p.Home, ".cc-switch", "cc-switch.db"), "not sqlite")
	rs, e := m.Reconcile(context.Background(), []Profile{p})
	if e == nil {
		t.Fatal("CC corrupt error missing")
	}
	rs = dshOnly(rs)
	if len(rs) != 1 || rs[0].Status != 3 {
		t.Fatal(rs)
	}
}

func TestDSHSearchUsesMessagesWireIdentity(t *testing.T) {
	m, p := fixtureManager(t)
	p = trustedDSH(p)
	m.EnableDSH = true
	writeDSHFixture(t, p, filepath.Join(p.Home, ".dsh"), "web", "- id: web-search-deepseek\n  config:\n    baseURL: https://synthetic.example.invalid/anthropic\n    apiKeyEnv: DEEPSEEK_API_KEY\n")
	rs, e := m.Reconcile(context.Background(), []Profile{p})
	if e != nil {
		t.Fatal(e)
	}
	rs = dshOnly(rs)
	if len(rs) != 1 || !strings.HasPrefix(rs[0].ProviderID, "dsh:messages:search:") {
		t.Fatal(rs)
	}
}

func TestDSHLocalGatewayRecursionGuard(t *testing.T) {
	cases := []struct {
		origin, upstream string
		agent            int
		allowed          bool
	}{
		{"http://127.0.0.1:18080", "http://localhost:8000/v1", 11, true},
		{"http://127.0.0.1:18080", "http://[::1]:8000/v1", 11, true},
		{"http://127.0.0.1:18080", "https://localhost/v1", 11, true},
		{"http://127.0.0.1:18080", "http://127.0.0.2:18080/v1", 11, false},
		{"http://127.0.0.1:18080", "https://localhost:18080/v1", 11, false},
		{"http://127.0.0.1:18080", "http://[::1]:18080/v1", 11, false},
		{"http://127.0.0.1:18080", "http://[::ffff:127.0.0.1]:18080/v1", 11, false},
		{"http://127.0.0.1:18080", "http://localhost.:18080/v1", 11, false},
		{"http://127.0.0.1:18080", "http://localhost:018080/v1", 11, false},
		{"http://127.0.0.1:18080", "http://localhost:65536/v1", 11, false},
		{"http://127.0.0.1", "http://localhost:80/v1", 11, false},
		{"http://127.0.0.1", "https://localhost/v1", 11, true},
		{"http://127.0.0.1:18080", "http://localhost:8000/v1", 0, false},
		{"http://127.0.0.1:18080", "http://localhost:8000/v1", 1, false},
	}
	for _, c := range cases {
		t.Run(c.origin+" "+c.upstream+string(rune(c.agent+'0')), func(t *testing.T) {
			m, p := fixtureManager(t)
			m.Origin = c.origin
			d, e := m.resolve(context.Background(), p, c.agent, "local", c.upstream, false)
			if (e == nil) != c.allowed {
				t.Fatal(c, e)
			}
			if c.allowed && d.route.OriginalBaseURL != c.upstream {
				t.Fatal(d)
			}
		})
	}
}
func TestDSHLocalGatewayAttachRecoverAndCancellation(t *testing.T) {
	m, p := fixtureManager(t)
	p = trustedDSH(p)
	m.EnableDSH = true
	content := strings.ReplaceAll(dshDeepSeekFixture, "https://synthetic.example.invalid/anthropic/v1", "http://localhost:8000/anthropic/v1")
	path := writeDSHFixture(t, p, filepath.Join(p.Home, ".dsh"), "web", content)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := m.Reconcile(ctx, []Profile{p}); e == nil {
		t.Fatal("canceled context ignored")
	}
	b, _ := os.ReadFile(path)
	if string(b) != content {
		t.Fatal("canceled operation wrote config")
	}
	if _, e := m.Reconcile(context.Background(), []Profile{p}); e != nil {
		t.Fatal(e)
	}
	if _, e := m.Reconcile(context.Background(), []Profile{p}); e != nil {
		t.Fatal("owned loopback route did not recover", e)
	}
	if _, e := m.DetachAll(context.Background(), []Profile{p}); e != nil {
		t.Fatal(e)
	}
	b, _ = os.ReadFile(path)
	if !strings.Contains(string(b), "http://localhost:8000/anthropic/v1") {
		t.Fatal(string(b))
	}
}

func TestDSHOriginRetirementPreservesCrossSurfaceReferences(t *testing.T) {
	m, p := fixtureManager(t)
	p = trustedDSH(p)
	m.EnableDSH = true
	path := writeDSHFixture(t, p, filepath.Join(p.Home, ".dsh"), "web", dshDeepSeekFixture)
	if _, e := m.Reconcile(context.Background(), []Profile{p}); e != nil {
		t.Fatal(e)
	}
	routes, _ := m.Store.ListRoutes(context.Background())
	route := routes[0]
	writeFixture(t, configPath(p, "claude"), `{"env":{"ANTHROPIC_BASE_URL":"`+route.InjectedBaseURL+`"}}`)
	if _, e := m.dshProfile(context.Background(), p, true); e == nil {
		t.Fatal("unowned cross-surface reference was retired")
	}
	b, _ := os.ReadFile(path)
	if strings.Contains(string(b), "127.0.0.1") {
		t.Fatal("DSH failed to restore")
	}
	routes, _ = m.Store.ListRoutes(context.Background())
	if len(routes) != 1 {
		t.Fatal("lost origin still referenced by Claude", routes)
	}
}

func TestDSHRebindingRetiresOldRouteAndDetachCompletes(t *testing.T) {
	for _, change := range []string{"profile-rename", "profile-move", "provider-key"} {
		t.Run(change, func(t *testing.T) {
			m, p := fixtureManager(t)
			p = trustedDSH(p)
			m.EnableDSH = true
			ctx := context.Background()
			root := filepath.Join(p.Home, ".dsh")
			content := dshDeepSeekFixture
			if change == "provider-key" {
				content = "- id: llm-pi-ai\n  config:\n    providers:\n      original-company:\n        baseURL: https://synthetic.example.invalid/v1\n        api: openai-responses\n        apiKeyEnv: COMPANY_API_KEY\n        models: [{id: fixture}]\n"
			}
			path := writeDSHFixture(t, p, root, "before", content)
			if _, e := m.Reconcile(ctx, []Profile{p}); e != nil {
				t.Fatal(e)
			}
			switch change {
			case "profile-rename":
				if e := os.Rename(filepath.Dir(path), filepath.Join(root, "profiles", "after")); e != nil {
					t.Fatal(e)
				}
			case "profile-move":
				newRoot := filepath.Join(p.Home, "new-dsh-root")
				if e := os.MkdirAll(filepath.Join(newRoot, "profiles"), 0700); e != nil {
					t.Fatal(e)
				}
				if e := os.Rename(filepath.Dir(path), filepath.Join(newRoot, "profiles", "after")); e != nil {
					t.Fatal(e)
				}
				p.DSHHomes = []string{newRoot}
			case "provider-key":
				b, _ := os.ReadFile(path)
				writeFixture(t, path, strings.ReplaceAll(string(b), "original-company:", "renamed-company:"))
			}
			if _, e := m.Reconcile(ctx, []Profile{p}); e != nil {
				t.Fatal(e)
			}
			routes, _ := m.Store.ListRoutes(ctx)
			if len(routes) != 1 {
				t.Fatal("stale route after rebind", routes)
			}
			p.DSHHomes = nil
			m.EnableDSH = false
			if _, e := m.DetachAll(ctx, []Profile{p}); e != nil {
				t.Fatal(e)
			}
			if _, e := m.DetachAll(ctx, []Profile{p}); e != nil {
				t.Fatal("detach not idempotent", e)
			}
			routes, _ = m.Store.ListRoutes(ctx)
			if len(routes) != 0 {
				t.Fatal(routes)
			}
		})
	}
}
func TestDSHRebindingCandidateSurvivesSharedReferenceUntilLaterDetach(t *testing.T) {
	m, p := fixtureManager(t)
	p = trustedDSH(p)
	m.EnableDSH = true
	ctx := context.Background()
	root := filepath.Join(p.Home, ".dsh")
	path := writeDSHFixture(t, p, root, "before", dshDeepSeekFixture)
	if _, e := m.Reconcile(ctx, []Profile{p}); e != nil {
		t.Fatal(e)
	}
	routes, _ := m.Store.ListRoutes(ctx)
	old := routes[0]
	writeFixture(t, configPath(p, "claude"), `{"env":{"ANTHROPIC_BASE_URL":"`+old.InjectedBaseURL+`"}}`)
	if e := os.Rename(filepath.Dir(path), filepath.Join(root, "profiles", "after")); e != nil {
		t.Fatal(e)
	}
	// Reconcile only DSH: Claude must retain the old route while still referencing it.
	if _, e := m.dshProfile(ctx, p, false); e != nil {
		t.Fatal(e)
	}
	routes, _ = m.Store.ListRoutes(ctx)
	if len(routes) != 2 {
		t.Fatal("shared origin was retired", routes)
	}
	// Simulate a later independent configuration restoration and a new Manager.
	writeFixture(t, configPath(p, "claude"), `{"env":{"ANTHROPIC_BASE_URL":"https://synthetic.example.invalid/anthropic/v1"}}`)
	later := &Manager{Store: m.Store, Origin: m.Origin, BackupRoot: m.BackupRoot}
	if _, e := later.DetachAll(ctx, []Profile{p}); e != nil {
		t.Fatal("persistent candidate was lost", e)
	}
	routes, _ = m.Store.ListRoutes(ctx)
	if len(routes) != 0 {
		t.Fatal(routes)
	}
}

func TestDSHDeletedProfileAndProviderRetireWhenAllSurfacesProveUnreferenced(t *testing.T) {
	for _, removeProfile := range []bool{false, true} {
		t.Run(map[bool]string{false: "provider", true: "profile"}[removeProfile], func(t *testing.T) {
			m, p := fixtureManager(t)
			p = trustedDSH(p)
			m.EnableDSH = true
			root := filepath.Join(p.Home, ".dsh")
			path := writeDSHFixture(t, p, root, "web", dshDeepSeekFixture)
			ctx := context.Background()
			if _, e := m.Reconcile(ctx, []Profile{p}); e != nil {
				t.Fatal(e)
			}
			if removeProfile {
				if e := os.RemoveAll(filepath.Dir(path)); e != nil {
					t.Fatal(e)
				}
			} else {
				writeFixture(t, path, "[]\n")
			}
			if _, e := m.Reconcile(ctx, []Profile{p}); e != nil {
				t.Fatal(e)
			}
			routes, _ := m.Store.ListRoutes(ctx)
			if len(routes) != 0 {
				t.Fatal("deleted scope left stale origin", routes)
			}
			if _, e := m.DetachAll(ctx, []Profile{p}); e != nil {
				t.Fatal(e)
			}
		})
	}
}
func TestDSHDeletedProfileWithUnknownHomeOverlayPreservesRecovery(t *testing.T) {
	for _, overlay := range []string{"literal", "dynamic", "include", "alias"} {
		t.Run(overlay, func(t *testing.T) {
			m, p := fixtureManager(t)
			p = trustedDSH(p)
			m.EnableDSH = true
			root := filepath.Join(p.Home, ".dsh")
			path := writeDSHFixture(t, p, root, "web", dshDeepSeekFixture)
			ctx := context.Background()
			if _, e := m.Reconcile(ctx, []Profile{p}); e != nil {
				t.Fatal(e)
			}
			routes, _ := m.Store.ListRoutes(ctx)
			old := routes[0]
			if e := os.RemoveAll(filepath.Join(root, "profiles")); e != nil {
				t.Fatal(e)
			}
			patch := "- id: llm-deepseek\n  config: {baseURL: '" + old.InjectedBaseURL + "'}\n"
			switch overlay {
			case "dynamic":
				patch = "- id: llm-deepseek\n  config: {baseURL: !!js process.env.BASE_URL}\n"
			case "include":
				patch = "- id: external\n  include: ./unknown.yml\n"
			case "alias":
				patch = "- id: llm-deepseek\n  config: &config {baseURL: '" + old.InjectedBaseURL + "'}\n- id: clone\n  config: *config\n"
			}
			writeFixture(t, filepath.Join(root, "cordis.patch.yml"), patch)
			if _, e := m.DetachAll(ctx, []Profile{p}); e == nil {
				t.Fatal("unknown overlay allowed route retirement", path)
			}
			routes, _ = m.Store.ListRoutes(ctx)
			if len(routes) != 1 {
				t.Fatal("lost recovery", routes)
			}
		})
	}
}
func TestDSHUnknownProfileLayerPreservesDeletedProviderRecovery(t *testing.T) {
	m, p := fixtureManager(t)
	p = trustedDSH(p)
	m.EnableDSH = true
	root := filepath.Join(p.Home, ".dsh")
	path := writeDSHFixture(t, p, root, "web", dshDeepSeekFixture)
	ctx := context.Background()
	if _, e := m.Reconcile(ctx, []Profile{p}); e != nil {
		t.Fatal(e)
	}
	writeFixture(t, path, "- id: external\n  include: ./unknown.yml\n")
	if _, e := m.DetachAll(ctx, []Profile{p}); e == nil {
		t.Fatal("include treated as complete scan")
	}
	routes, _ := m.Store.ListRoutes(ctx)
	if len(routes) != 1 {
		t.Fatal(routes)
	}
}

func TestDSHDeletedProfileUnknownCommandOverlayPreservesRecovery(t *testing.T) {
	m, p := fixtureManager(t)
	p = trustedDSH(p)
	m.EnableDSH = true
	root := filepath.Join(p.Home, ".dsh")
	writeDSHFixture(t, p, root, "web", dshDeepSeekFixture)
	ctx := context.Background()
	if _, e := m.Reconcile(ctx, []Profile{p}); e != nil {
		t.Fatal(e)
	}
	os.RemoveAll(filepath.Join(root, "profiles"))
	p.DSHOverlaysUnknown = true
	if _, e := m.DetachAll(ctx, []Profile{p}); e == nil {
		t.Fatal("unknown command overlay treated as no reference")
	}
	routes, _ := m.Store.ListRoutes(ctx)
	if len(routes) != 1 {
		t.Fatal(routes)
	}
}

func TestDSHRecoveryProfilesRestoresRootsWithoutMutatingCaller(t *testing.T) {
	m, p := fixtureManager(t)
	p = trustedDSH(p)
	m.EnableDSH = true
	custom := filepath.Join(p.Home, "custom-dsh")
	p.DSHHomes = []string{custom}
	writeDSHFixture(t, p, custom, "web", dshDeepSeekFixture)
	ctx := context.Background()
	if _, e := m.Reconcile(ctx, []Profile{p}); e != nil {
		t.Fatal(e)
	}
	p.DSHHomes = nil
	restored, e := m.DSHRecoveryProfiles(ctx, []Profile{p})
	if e != nil || len(restored) != 1 || len(restored[0].DSHHomes) != 1 || restored[0].DSHHomes[0] != custom || p.DSHHomes != nil {
		t.Fatal(restored, e)
	}
	p.DSHHomes = []string{custom}
	restored, e = m.DSHRecoveryProfiles(ctx, []Profile{p})
	if e != nil || len(restored[0].DSHHomes) != 1 {
		t.Fatal(restored, e)
	}
	bad := dshRootJournal{SID: p.SID, Home: p.Home, Roots: []string{t.TempDir()}}
	b, _ := json.Marshal(bad)
	writeFixture(t, m.dshJournalPath(p), string(b))
	if _, e = m.DSHRecoveryProfiles(ctx, []Profile{p}); e == nil {
		t.Fatal("unsafe recovery roots accepted")
	}
}
func TestDSHRecoveryProfilesCancellation(t *testing.T) {
	m, p := fixtureManager(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := m.DSHRecoveryProfiles(ctx, []Profile{p}); e == nil {
		t.Fatal("cancel ignored")
	}
}
