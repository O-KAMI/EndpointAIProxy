package discovery

import (
	"context"
	"encoding/json"
	"endpointai/client/internal/platform"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const DSHSupportedVersion = "0.2.1-alpha.5"

type DSHMetadata struct {
	DSHPiAIVersion  string
	Version         string
	OverlaysUnknown bool
}

// DSHProfileMetadata reads manifests only. roots must come from trusted deployment
// configuration; no environment or shell startup file is read by discovery.
func DSHProfileMetadata(ctx context.Context, profiles []platform.Profile, roots map[string][]string) map[string]DSHMetadata {
	out := make(map[string]DSHMetadata)
	running, scanErr := processSamples(ctx, profiles)

	for _, p := range profiles {
		if ctx.Err() != nil {
			break
		}
		versions := map[string]bool{}
		piVersions := map[string]bool{}
		for _, s := range dshDesktopSamples(p) {
			if s.version != "" {
				versions[s.version] = true
			}
		}
		for _, root := range dshNPMRoots(p) {
			m, e := manifest(filepath.Join(root, "node_modules", "@deepseek-ai", "dsh", "package.json"))
			if e == nil && m["name"] == "@deepseek-ai/dsh" && m["version"] != "" {
				versions[m["version"]] = true
				pluginPath := resolveNodeManifest(filepath.Join(root, "node_modules", "@deepseek-ai", "dsh"), "@deepseek-ai/dsh-llm-pi-ai")
				pi, e := manifest(resolveNodeManifest(filepath.Dir(pluginPath), "@earendil-works/pi-ai"))
				if e == nil && pi["name"] == "@earendil-works/pi-ai" {
					piVersions[pi["version"]] = true
				}
			}
		}

		profileRoots := append([]string{filepath.Join(p.Home, ".dsh")}, roots[p.SID]...)
		for _, profile := range dshProfileSamples(p, profileRoots) {
			plugin := resolveNodeManifest(filepath.Dir(profile.path), "@deepseek-ai/dsh-llm-pi-ai")
			if plugin != "" {
				if pi, e := manifest(resolveNodeManifest(filepath.Dir(plugin), "@earendil-works/pi-ai")); e == nil && pi["name"] == "@earendil-works/pi-ai" && pi["version"] != "" {
					piVersions[pi["version"]] = true
				}
			}
		}
		for _, s := range running {
			if s.sid != p.SID || s.kind != DeepSeekHarness || s.version == "" {
				continue
			}
			versions[s.version] = true
		}
		// Profile manifest version describes the profile package, not the CLI. Never
		// use it to assert a compatible DSH runtime.
		md := DSHMetadata{OverlaysUnknown: scanErr != nil}
		for _, s := range running {
			if s.sid == p.SID && s.inspectionUnknown {
				md.OverlaysUnknown = true
			}
			if s.sid != p.SID || s.kind != DeepSeekHarness {
				continue
			}
			known := false
			if !s.launchOverridesUnknown && s.launchProfile != "" {
				for _, profile := range dshProfileSamples(p, profileRoots) {
					if filepath.Base(filepath.Dir(profile.path)) == s.launchProfile {
						known = true
						break
					}
				}
			}
			if !known {
				md.OverlaysUnknown = true
			}
		}
		if len(piVersions) == 1 {
			for v := range piVersions {
				md.DSHPiAIVersion = v
			}
		}
		if len(versions) == 1 {
			for v := range versions {
				md.Version = v
			}
		}
		out[p.SID] = md
	}
	return out
}

func dshNPMRoots(p platform.Profile) []string {
	roots := append([]string{}, p.SearchPaths...)
	roots = append(roots, filepath.Join(p.Roaming, "npm"), filepath.Join(p.Local, "npm"), filepath.Join(p.Home, ".local", "bin"), filepath.Join(p.Home, ".npm-global", "lib"), "/opt/homebrew/lib", "/usr/local/lib")
	return roots
}

func dshProfileSamples(p platform.Profile, roots []string) []sample {
	out := []sample{}
	for _, root := range roots {
		paths, _ := filepath.Glob(filepath.Join(root, "profiles", "*", "package.json"))
		if len(paths) > 256 {
			paths = paths[:256]
		}
		for _, path := range paths {
			f, e := os.Open(path)
			if e != nil {
				continue
			}
			var v struct {
				DSH struct {
					Profile json.RawMessage `json:"profile"`
				} `json:"dsh"`
			}
			e = json.NewDecoder(io.LimitReader(f, 1<<20)).Decode(&v)
			f.Close()
			var profile map[string]json.RawMessage
			if e == nil && json.Unmarshal(v.DSH.Profile, &profile) == nil && profile != nil {
				out = append(out, sample{sid: p.SID, kind: DeepSeekHarness, collector: "dsh-profile-manifest", path: path, strength: 1, method: 3})
			}
		}
	}
	return out
}

// dshNodeEntry accepts only the first Node script and validates the official
// package's declared bin target. Application flags/values are never evidence.
func dshNodeEntry(args []string) (path, version string, ok bool) {
	if len(args) < 2 || !isNodeExecutable(args[0]) {
		return
	}
	i := 1
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		switch args[i] {
		case "--":
			i++
			goto script
		case "--enable-source-maps", "--no-warnings", "--trace-warnings":
			i++
		default:
			return "", "", false
		}
	}
script:
	if i >= len(args) || !filepath.IsAbs(args[i]) {
		return "", "", false
	}
	scriptPath, e := filepath.EvalSymlinks(args[i])
	if e != nil {
		return "", "", false
	}
	dir := filepath.Dir(scriptPath)
	for depth := 0; depth < 8; depth++ {
		f, e := os.Open(filepath.Join(dir, "package.json"))
		if e == nil {
			var pkg struct {
				Name    string          `json:"name"`
				Version string          `json:"version"`
				Bin     json.RawMessage `json:"bin"`
			}
			e = json.NewDecoder(io.LimitReader(f, 1<<20)).Decode(&pkg)
			f.Close()
			if e == nil && pkg.Name == "@deepseek-ai/dsh" {
				var bins map[string]string
				if json.Unmarshal(pkg.Bin, &bins) != nil {
					return "", "", false
				}
				target := bins["dsh"]
				if target == "" || filepath.IsAbs(target) {
					return "", "", false
				}
				rel, e := filepath.Rel(dir, filepath.Join(dir, target))
				if e != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
					return "", "", false
				}
				declared, e := filepath.EvalSymlinks(filepath.Join(dir, target))
				resolvedRel, relErr := filepath.Rel(dir, declared)
				if e != nil || declared != scriptPath || relErr != nil || resolvedRel == ".." || strings.HasPrefix(resolvedRel, ".."+string(filepath.Separator)) {
					return "", "", false
				}
				return scriptPath, pkg.Version, true
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", "", false
}

func isNodeExecutable(path string) bool {
	name := strings.ToLower(filepath.Base(strings.ReplaceAll(path, `\`, "/")))
	return name == "node" || name == "node.exe" || name == "nodejs"
}

// A different, fully delimited ordinary Node script is outside the DSH CLI
// scope. Unsupported Node launch options or a malformed declared DSH entry
// cannot prove absence and must inhibit automatic configuration mutation.
func nodeArgumentsUncertain(args []string) bool {
	if len(args) < 2 {
		return true
	}
	i := 1
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		switch args[i] {
		case "--":
			i++
			goto script
		case "--enable-source-maps", "--no-warnings", "--trace-warnings":
			i++
		default:
			return true
		}
	}
script:
	if i >= len(args) || !filepath.IsAbs(args[i]) {
		return true
	}
	path := strings.ReplaceAll(args[i], `\`, "/")
	return strings.Contains(path, "/node_modules/@deepseek-ai/dsh/")
}

// splitProcessArgs is a conservative tokenizer, never a shell evaluator. Raw
// command lines remain local variables and are never returned as evidence.
func splitProcessArgs(line string) []string {
	if len(line) > 65536 {
		return nil
	}
	var out []string
	var b strings.Builder
	var quote rune
	escape := false
	active := false
	for _, r := range line {
		if escape {
			b.WriteRune(r)
			escape = false
			active = true
			continue
		}
		if r == '\\' && quote != '\'' {
			escape = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			} else {
				b.WriteRune(r)
			}
			active = true
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			active = true
			continue
		}
		if r == ' ' || r == '\t' || r == '\n' {
			if active {
				out = append(out, b.String())
				b.Reset()
				active = false
			}
			continue
		}
		b.WriteRune(r)
		active = true
	}
	if quote != 0 || escape {
		return nil
	}
	if active {
		out = append(out, b.String())
	}
	return out
}

// Resolve package manifests with Node's ancestor node_modules search, including
// pnpm symlinks, without executing JS or using a runtime module loader.
func resolveNodeManifest(from, name string) string {
	dir, e := filepath.EvalSymlinks(from)
	if e != nil {
		return ""
	}
	for depth := 0; depth < 32; depth++ {
		candidate := filepath.Join(dir, "node_modules", filepath.FromSlash(name), "package.json")
		if exists(candidate) {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

// Return only a safe profile identifier and uncertainty. Exact standard boot
// forms can be matched to trusted roots; extra application/launcher arguments
// and Desktop remain conservative. No argument values are exported as evidence.
func dshLaunchProfile(args []string) (string, bool) {
	if _, _, ok := dshNodeEntry(args); !ok {
		return "", true
	}
	i := 1
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		if args[i] == "--" {
			i++
			break
		}
		i++
	}
	if i >= len(args) {
		return "", true
	}
	tail := args[i+1:]
	var profile string
	if len(tail) == 1 && !strings.HasPrefix(tail[0], "-") {
		profile = tail[0]
	} else if len(tail) == 2 && tail[0] == "--profile" {
		profile = tail[1]
	} else if len(tail) == 1 && strings.HasPrefix(tail[0], "--profile=") {
		profile = strings.TrimPrefix(tail[0], "--profile=")
	} else {
		return "", true
	}
	if profile == "" || len(profile) > 128 || profile == "desktop" || profile == "plugin" {
		return "", true
	}
	for _, r := range profile {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return "", true
		}
	}
	return profile, false
}
