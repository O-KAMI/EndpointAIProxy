package discovery

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"endpointai/client/internal/platform"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	ClaudeCode = iota
	CodexCLI
	QoderCLI
	QoderIDE
	CCSwitch
	UnknownCandidate
	CodexIDE
	CodexDesktop
	ClaudeCLI
	ClaudeIDE
	ClaudeDesktop
	DeepSeekHarness // 11: append only; existing persisted values remain unchanged.
)

type Evidence struct {
	Collector     string    `json:"collector"`
	Artifact      string    `json:"artifact"`
	Strength      int       `json:"strength"`
	ObservedAtUTC time.Time `json:"observedAtUtc"`
}
type Agent struct {
	UserSID       string     `json:"userSid"`
	AgentType     int        `json:"agentType"`
	Confirmed     bool       `json:"confirmed"`
	Confidence    int        `json:"confidence"`
	Version       string     `json:"version,omitempty"`
	InstallMethod int        `json:"installMethod"`
	Evidence      []Evidence `json:"evidence"`
}
type sample struct {
	sid                      string
	kind                     int
	collector, path, version string
	strength, method         int
	launchProfile            string
	launchOverridesUnknown   bool
	inspectionUnknown        bool // local completeness signal, never inventory evidence
}

func exists(path string) bool { _, err := os.Stat(path); return err == nil }

// Only package manifests are read; Agent settings, credentials and conversation
// content are never opened by discovery.
func manifest(path string) (map[string]string, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	var raw map[string]json.RawMessage
	if e = json.NewDecoder(io.LimitReader(f, 1<<20)).Decode(&raw); e != nil {
		return nil, e
	}
	out := map[string]string{}
	for _, key := range []string{"name", "publisher", "version"} {
		var s string
		if json.Unmarshal(raw[key], &s) == nil {
			out[key] = s
		}
	}
	return out, nil
}
func Discover(ctx context.Context, profiles []platform.Profile) ([]Agent, error) {
	return discover(ctx, profiles, true)
}
func discover(ctx context.Context, profiles []platform.Profile, running bool) ([]Agent, error) {
	all := []sample{}
	for _, p := range profiles {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		add := func(kind int, collector, path, version string, strength, method int) {
			if exists(path) {
				all = append(all, sample{sid: p.SID, kind: kind, collector: collector, path: path, version: version, strength: strength, method: method})
			}
		}
		roots := append(append([]string{}, p.SearchPaths...), filepath.Join(p.Roaming, "npm"), filepath.Join(p.Local, "npm"), filepath.Join(p.Home, ".local", "bin"))
		for _, root := range roots {
			for _, sig := range []struct {
				name string
				kind int
			}{{"claude", ClaudeCLI}, {"codex", CodexCLI}, {"qoder", QoderCLI}, {"qodercli", QoderCLI}, {"dsh", DeepSeekHarness}} {
				for _, ext := range []string{"", ".exe", ".cmd", ".ps1"} {
					method := 1
					if ext == ".cmd" || ext == ".ps1" {
						method = 3
					}
					add(sig.kind, "cli-command", filepath.Join(root, sig.name+ext), "", 1, method)
				}
			}
		}
		npm := append(append([]string{}, roots...), filepath.Join(p.Home, ".npm-global", "lib"), "/opt/homebrew/lib", "/usr/local/lib")
		for _, root := range npm {
			for _, sig := range []struct {
				name string
				kind int
			}{{"@anthropic-ai/claude-code", ClaudeCLI}, {"@openai/codex", CodexCLI}, {"@qoder-ai/qodercli", QoderCLI}, {"@deepseek-ai/dsh", DeepSeekHarness}} {
				path := filepath.Join(root, "node_modules", filepath.FromSlash(sig.name), "package.json")
				if m, e := manifest(path); e == nil && (sig.kind != DeepSeekHarness || m["name"] == "@deepseek-ai/dsh") {
					add(sig.kind, "package-manifest", path, m["version"], 2, 3)
				}
			}
		}
		all = append(all, dshDesktopSamples(p)...)
		all = append(all, dshProfileSamples(p, []string{filepath.Join(p.Home, ".dsh")})...)
		add(QoderCLI, "config-artifact", filepath.Join(p.Home, ".qoder", "settings.json"), "", 1, 0)
		add(CCSwitch, "config-artifact", filepath.Join(p.Home, ".cc-switch", "cc-switch.db"), "", 1, 0)
		for _, root := range []string{".vscode/extensions", ".vscode-insiders/extensions", ".cursor/extensions"} {
			for _, sig := range []struct {
				prefix, publisher, name string
				kind                    int
			}{{"anthropic.claude-code-", "anthropic", "claude-code", ClaudeIDE}, {"openai.chatgpt-", "openai", "chatgpt", CodexIDE}} {
				matches, _ := filepath.Glob(filepath.Join(p.Home, filepath.FromSlash(root), sig.prefix+"*", "package.json"))
				var chosen, version string
				for _, path := range matches {
					m, e := manifest(path)
					if e == nil && strings.EqualFold(m["publisher"], sig.publisher) && strings.EqualFold(m["name"], sig.name) && (chosen == "" || versionLess(version, m["version"])) {
						chosen = path
						version = m["version"]
					}
				}
				if chosen != "" {
					add(sig.kind, "surface-artifact", chosen, version, 2, 10)
				}
			}
		}
		for _, root := range []string{filepath.Join(p.Roaming, "JetBrains"), filepath.Join(p.Home, "Library", "Application Support", "JetBrains")} {
			matches, _ := filepath.Glob(filepath.Join(root, "*", "plugins", "*claude*", "META-INF", "plugin.xml"))
			for _, path := range matches {
				f, e := os.Open(path)
				if e != nil {
					continue
				}
				var plugin struct {
					ID      string `xml:"id"`
					Name    string `xml:"name"`
					Vendor  string `xml:"vendor"`
					Version string `xml:"version"`
				}
				e = xml.NewDecoder(io.LimitReader(f, 1<<20)).Decode(&plugin)
				f.Close()
				if e == nil && strings.Contains(strings.ToLower(plugin.Vendor), "anthropic") && strings.Contains(strings.ToLower(plugin.ID+plugin.Name), "claude") {
					add(ClaudeIDE, "surface-artifact", path, plugin.Version, 2, 12)
				}
			}
		}
		for _, sig := range []struct {
			pattern string
			kind    int
		}{{"AnthropicClaude/Claude.exe", ClaudeDesktop}, {"AnthropicClaude/app-*/Claude.exe", ClaudeDesktop}, {"Programs/Claude/Claude.exe", ClaudeDesktop}, {"Packages/Anthropic.Claude_*", ClaudeDesktop}, {"Packages/OpenAI.Codex_*", CodexDesktop}, {"Packages/OpenAI.ChatGPT-Desktop_*", CodexDesktop}, {"Programs/CC Switch/CC Switch.exe", CCSwitch}, {"CC Switch/CC Switch.exe", CCSwitch}, {"qodercli/qodercli.exe", QoderCLI}} {
			matches, _ := filepath.Glob(filepath.Join(p.Local, filepath.FromSlash(sig.pattern)))
			for _, path := range matches {
				add(sig.kind, "surface-artifact", path, "", 2, 1)
			}
		}
		for _, root := range []string{"/Applications", filepath.Join(p.Home, "Applications")} {
			for _, sig := range []struct {
				name string
				kind int
			}{{"Claude.app", ClaudeDesktop}, {"ChatClaude.app", ClaudeDesktop}, {"ChatGPT.app", CodexDesktop}, {"Codex.app", CodexDesktop}, {"Qoder.app", QoderIDE}, {"CC Switch.app", CCSwitch}, {"CCSwitch.app", CCSwitch}} {
				add(sig.kind, "installed-application", filepath.Join(root, sig.name), "", 2, 1)
			}
		}
	}
	if running {
		installed, e := installedSamples(ctx, profiles)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if e == nil {
			all = append(all, installed...)
		}
		samples, e := processSamples(ctx, profiles)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if e == nil {
			all = append(all, samples...)
		}
	}
	grouped := map[string]*Agent{}
	seen := map[string]bool{}
	medium := map[string]map[string]bool{}
	for _, s := range all {
		if s.inspectionUnknown {
			continue
		}
		key := fmt.Sprintf("%s:%d", s.sid, s.kind)
		dedup := key + ":" + s.collector + ":" + strings.ToLower(s.path)
		if seen[dedup] {
			continue
		}
		seen[dedup] = true
		a := grouped[key]
		if a == nil {
			a = &Agent{UserSID: s.sid, AgentType: s.kind}
			grouped[key] = a
			medium[key] = map[string]bool{}
		}
		a.Evidence = append(a.Evidence, Evidence{s.collector, s.path, s.strength, time.Now().UTC()})
		if s.strength == 2 {
			a.Confirmed = true
			a.Confidence += 60
		} else if s.strength == 1 {
			medium[key][s.collector] = true
			a.Confidence += 30
		} else {
			a.Confidence += 10
		}
		if a.Version == "" {
			a.Version = s.version
		}
		if a.InstallMethod == 0 {
			a.InstallMethod = s.method
		}
	}
	out := []Agent{}
	for key, a := range grouped {
		a.Confirmed = a.Confirmed || len(medium[key]) >= 2
		if a.Confidence > 100 {
			a.Confidence = 100
		}
		if !a.Confirmed {
			a.AgentType = UnknownCandidate
			if a.Confidence > 59 {
				a.Confidence = 59
			}
		}
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].UserSID == out[j].UserSID {
			return out[i].AgentType < out[j].AgentType
		}
		return out[i].UserSID < out[j].UserSID
	})
	return out, nil
}
func versionLess(a, b string) bool {
	var av, bv [4]int
	for i, v := range strings.Split(a, ".") {
		if i == 4 {
			break
		}
		fmt.Sscanf(v, "%d", &av[i])
	}
	for i, v := range strings.Split(b, ".") {
		if i == 4 {
			break
		}
		fmt.Sscanf(v, "%d", &bv[i])
	}
	for i := range av {
		if av[i] != bv[i] {
			return av[i] < bv[i]
		}
	}
	return a < b
}
func processKind(path string) (int, bool) {
	p := strings.ToLower(strings.ReplaceAll(path, `\`, "/"))
	name := strings.TrimSuffix(filepath.Base(p), ".exe")
	var kind int
	switch name {
	case "deepseek harness":
		if !dshDesktopProcess(path) {
			return 0, false
		}
		kind = DeepSeekHarness
	case "dsh":
		kind = DeepSeekHarness
	case "claude":
		kind = ClaudeCLI
		if strings.Contains(p, "anthropic.claude-code-") || strings.Contains(p, "/plugins/claude-code") {
			kind = ClaudeIDE
		} else if strings.Contains(p, "anthropicclaude/") || strings.Contains(p, "anthropic.claude_") || strings.Contains(p, "claude.app/") {
			kind = ClaudeDesktop
		}
	case "codex":
		kind = CodexCLI
		if strings.Contains(p, "openai.chatgpt-") {
			kind = CodexIDE
		} else if strings.Contains(p, "openai.codex_") || strings.Contains(p, "openai.chatgpt-desktop_") || strings.Contains(p, "codex.app/") {
			kind = CodexDesktop
		}
	case "chatgpt":
		kind = CodexDesktop
	case "qoder", "qodercli":
		kind = QoderCLI
		if strings.Contains(p, "qoder.app/") {
			kind = QoderIDE
		}
	case "cc-switch", "cc switch", "ccswitch":
		kind = CCSwitch
	default:
		return 0, false
	}
	return kind, true
}
