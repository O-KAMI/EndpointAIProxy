package configuration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"endpointai/client/internal/contracts"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const DSHSupportedVersion = "0.2.1-alpha.5"
const dshAgent = 11
const dshFileLimit = 2 << 20

// DSH configuration is a Cordis patch list, not a key/value settings file.
// Parsing never loads plugins, resolves expressions, reads credentials or runs DSH.
type dshDocument struct {
	referencesUnknown   bool
	path, root, profile string
	bytes               []byte
	tree                yaml.Node
	candidates          []dshCandidate
	issue               string
}
type dshCandidate struct {
	identity, protocol, role, model, current, issue string
	urlNode                                         *yaml.Node
}

func dshRead(path string) ([]byte, error) {
	info, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() {
		return nil, problem("DSH_CONFIG_NOT_REGULAR")
	}
	if info.Size() > dshFileLimit {
		return nil, problem("DSH_CONFIG_TOO_LARGE")
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, dshFileLimit+1))
	if len(b) > dshFileLimit {
		return nil, problem("DSH_CONFIG_TOO_LARGE")
	}
	return b, e
}
func dshWithin(home, path string) bool {
	rel, e := filepath.Rel(home, path)
	return e == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}
func dshSafePath(home, path string) bool {
	homeAbs, e := filepath.Abs(home)
	if e != nil {
		return false
	}
	pathAbs, e := filepath.Abs(path)
	if e != nil || !dshWithin(homeAbs, pathAbs) {
		return false
	}
	// Reject every link component, including ancestors, before reading or modifying.
	cur := pathAbs
	for {
		i, e := os.Lstat(cur)
		if e != nil && !os.IsNotExist(e) {
			return false
		}
		if e == nil && i.Mode()&os.ModeSymlink != 0 {
			return false
		}
		if cur == homeAbs {
			return true
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return false
		}
		cur = parent
	}
}
func dshIdentity(p Profile, root, profile, entry, provider, protocol, role string) string {
	b, _ := json.Marshal([]string{p.SID, filepath.Clean(root), profile, entry, provider})
	h := sha256.Sum256(b)
	return "dsh:" + protocol + ":" + role + ":" + hex.EncodeToString(h[:])
}
func yamlField(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}
func yamlString(n *yaml.Node) string {
	if n != nil && n.Kind == yaml.ScalarNode && n.Tag == "!!str" {
		return n.Value
	}
	return ""
}
func dshStatic(n *yaml.Node, depth int) bool {
	if n == nil || depth > 32 || n.Kind == yaml.AliasNode || n.Anchor != "" {
		return false
	}
	if n.Tag != "" && n.Tag != "!!map" && n.Tag != "!!seq" && n.Tag != "!!str" && n.Tag != "!!bool" && n.Tag != "!!int" && n.Tag != "!!float" && n.Tag != "!!null" {
		return false
	}
	if n.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode || k.Tag != "!!str" || seen[k.Value] {
				return false
			}
			seen[k.Value] = true
		}
	}
	for _, c := range n.Content {
		if !dshStatic(c, depth+1) {
			return false
		}
	}
	return true
}
func dshParse(b []byte, tree *yaml.Node) error {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	if e := dec.Decode(tree); e != nil {
		return problem("DSH_YAML_INVALID")
	}
	var extra yaml.Node
	if e := dec.Decode(&extra); e != io.EOF {
		return problem("DSH_YAML_MULTIPLE_DOCUMENTS")
	}
	if len(tree.Content) != 1 || tree.Content[0].Kind != yaml.SequenceNode || !dshStatic(tree, 0) {
		return problem("DSH_DYNAMIC_OR_UNSUPPORTED_YAML")
	}
	return nil
}
func dshValidURL(s string) bool {
	u, e := url.Parse(s)
	return e == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && !strings.Contains(s, "${") && !strings.Contains(s, "{{")
}

func dshManifest(path string) bool {
	b, e := dshRead(path)
	if e != nil {
		return false
	}
	var m struct {
		DSH struct {
			Profile struct {
				Bundles []string `json:"bundles"`
			} `json:"profile"`
		} `json:"dsh"`
	}
	if json.Unmarshal(b, &m) != nil || len(m.DSH.Profile.Bundles) == 0 {
		return false
	}
	for _, s := range m.DSH.Profile.Bundles {
		switch s {
		case "@deepseek-ai/dsh-base", "@deepseek-ai/dsh-web-app", "@deepseek-ai/dsh-headless", "@deepseek-ai/dsh-sdk-app", "@deepseek-ai/dsh-sdk-minimal", "@deepseek-ai/dsh-acp-app":
		default:
			return false
		}
	}
	return true
}
func dshRoots(p Profile) []string {
	out := []string{filepath.Join(p.Home, ".dsh")}
	for _, root := range p.DSHHomes {
		if filepath.IsAbs(root) {
			out = append(out, filepath.Clean(root))
		}
	}
	seen := map[string]bool{}
	var unique []string
	for _, root := range out {
		if !seen[root] {
			seen[root] = true
			unique = append(unique, root)
		}
	}
	return unique
}
func dshDocuments(p Profile) ([]*dshDocument, error) {
	if len(p.DSHHomes) > 256 || len(dshRoots(p)) > 129 {
		return nil, problem("DSH_ROOT_LIMIT")
	}
	var out []*dshDocument
	var errs []error
	for _, root := range dshRoots(p) {
		// Outside-home roots are discovered by the platform layer, never read as root.
		if !dshSafePath(p.Home, root) {
			out = append(out, &dshDocument{root: root, path: root, issue: "DSH_ROOT_OUTSIDE_USER_OR_SYMLINK"})
			continue
		}
		dir := filepath.Join(root, "profiles")
		if !dshSafePath(p.Home, dir) {
			out = append(out, &dshDocument{root: root, path: dir, issue: "DSH_CONFIG_SYMLINK"})
			continue
		}
		homeIssue := ""
		homePatch := filepath.Join(root, "cordis.patch.yml")
		if !dshSafePath(p.Home, homePatch) {
			homeIssue = "DSH_HOME_PATCH_UNSUPPORTED"
		} else if b, e := dshRead(homePatch); e == nil {
			var n yaml.Node
			if dshParse(b, &n) != nil || len(n.Content[0].Content) > 0 {
				homeIssue = "DSH_HOME_PATCH_OVERRIDE"
			}
		} else if !os.IsNotExist(e) {
			homeIssue = "DSH_HOME_PATCH_UNREADABLE"
		}
		if homeIssue != "" {
			out = append(out, &dshDocument{root: root, path: homePatch, issue: homeIssue})
		}
		entries, e := os.ReadDir(dir)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			errs = append(errs, e)
			continue
		}
		if len(entries) > 128 {
			return out, problem("DSH_PROFILE_LIMIT")
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				if entry.Type()&os.ModeSymlink != 0 {
					out = append(out, &dshDocument{root: root, path: filepath.Join(dir, entry.Name()), issue: "DSH_CONFIG_SYMLINK"})
				}
				continue
			}
			path := filepath.Join(dir, entry.Name(), "cordis.patch.yml")
			doc := &dshDocument{root: root, profile: entry.Name(), path: path}
			out = append(out, doc)
			if !dshSafePath(p.Home, path) {
				doc.issue = "DSH_CONFIG_SYMLINK"
				continue
			}
			b, e := dshRead(path)
			if os.IsNotExist(e) {
				doc.issue = "DSH_PROFILE_PATCH_MISSING"
				continue
			}
			if e != nil {
				doc.issue = errorCode(e)
				errs = append(errs, e)
				continue
			}
			doc.bytes = b
			if e = dshParse(b, &doc.tree); e != nil {
				doc.issue = errorCode(e)
				continue
			}
			doc.candidates = dshFindCandidates(p, doc)
			manifestKnown := dshSafePath(p.Home, filepath.Join(dir, entry.Name(), "package.json")) && dshManifest(filepath.Join(dir, entry.Name(), "package.json"))
			if !manifestKnown {
				doc.referencesUnknown = true
			}
			switch {
			case p.DSHOverlaysUnknown:
				doc.issue = "DSH_COMMAND_OVERLAY_UNKNOWN"
			case homeIssue != "":
				doc.issue = homeIssue
			case p.DSHVersion != DSHSupportedVersion:
				doc.issue = "DSH_VERSION_UNVERIFIED"
			case !manifestKnown:
				doc.issue = "DSH_PROFILE_MANIFEST_UNSUPPORTED"
			}
		}
	}
	return out, errors.Join(errs...)
}
func dshFindCandidates(p Profile, doc *dshDocument) []dshCandidate {
	var out []dshCandidate
	ids := map[string]bool{}
	duplicate := false
	var walk func(*yaml.Node)
	walk = func(list *yaml.Node) {
		if list == nil || list.Kind != yaml.SequenceNode {
			return
		}
		for _, row := range list.Content {
			if row.Kind != yaml.MappingNode {
				duplicate = true
				continue
			}
			id := yamlString(yamlField(row, "id"))
			name := yamlString(yamlField(row, "name"))
			if id != "" {
				if ids[id] {
					duplicate = true
				}
				ids[id] = true
			}
			config := yamlField(row, "config")
			if config != nil && config.Kind == yaml.SequenceNode {
				walk(config)
				continue
			}
			if yamlField(row, "include") != nil {
				duplicate = true
				continue
			}
			role, protocol := "", ""
			expected := ""
			switch id {
			case "llm-deepseek":
				role = "deepseek"
				protocol = "messages"
				expected = "@deepseek-ai/dsh-llm-deepseek-api-key"
			case "web-search-deepseek":
				role = "search"
				protocol = "messages"
				expected = "@deepseek-ai/dsh-web-search-deepseek"
			case "llm-pi-ai":
				role = "custom"
				expected = "@deepseek-ai/dsh-llm-pi-ai"
			case "llm-deepseek-account":
				role = "account"
			}
			if role == "" {
				continue
			}
			issue := ""
			if name != "" && name != expected {
				issue = "DSH_PLUGIN_UNVERIFIED"
			}
			if disabled := yamlField(row, "disabled"); disabled != nil && !(disabled.Tag == "!!bool" && disabled.Value == "false") {
				issue = "DSH_ENTRY_DISABLED"
			}
			add := func(provider, proto, role string, n *yaml.Node, extraIssue string) {
				v := yamlField(n, "baseURL")
				current := yamlString(v)
				problemCode := issue
				if extraIssue != "" {
					problemCode = extraIssue
				}
				if current == "" {
					problemCode = "DSH_EXPLICIT_BASE_URL_REQUIRED"
				} else if !dshValidURL(current) {
					problemCode = "DSH_BASE_URL_UNSUPPORTED"
				}
				out = append(out, dshCandidate{identity: dshIdentity(p, doc.root, doc.profile, id, provider, proto, role), protocol: proto, role: role, current: current, urlNode: v, issue: problemCode})
			}
			if role == "account" {
				out = append(out, dshCandidate{identity: dshIdentity(p, doc.root, doc.profile, id, "", "messages", "account"), role: role, protocol: "messages", issue: "DSH_ACCOUNT_UNSUPPORTED"})
				continue
			}
			if role != "custom" {
				add("", protocol, role, config, "")
				continue
			}
			providers := yamlField(config, "providers")
			if providers == nil || providers.Kind != yaml.MappingNode {
				continue
			}
			for i := 0; i+1 < len(providers.Content); i += 2 {
				provider := providers.Content[i].Value
				cfg := providers.Content[i+1]
				api := yamlString(yamlField(cfg, "api"))
				proto := ""
				switch api {
				case "openai-completions":
					proto = "chat"
				case "openai-responses":
					proto = "responses"
				case "anthropic-messages":
					proto = "messages"
				}
				extra := ""
				if proto == "" {
					proto = "unknown"
					extra = "DSH_PROTOCOL_UNSUPPORTED"
				} else {
					extra = dshCustomCompatible(provider, cfg)
					if p.DSHPiAIVersion != "1.3.0" {
						extra = "DSH_PI_AI_VERSION_UNVERIFIED"
					}
				}
				add(provider, proto, "custom", cfg, extra)
			}
		}
	}
	walk(doc.tree.Content[0])
	if duplicate {
		doc.referencesUnknown = true
		for i := range out {
			out[i].issue = "DSH_AMBIGUOUS_PATCH_TARGET"
		}
		if len(out) == 0 {
			doc.issue = "DSH_AMBIGUOUS_PATCH_TARGET"
		}
	}
	return out
}

// Only literal custom API-key providers with proven endpoint-independent wire
// compatibility are admitted. Native catalog/OAuth providers remain discovery-only.
func dshCustomCompatible(provider string, cfg *yaml.Node) string {
	if yamlString(yamlField(cfg, "apiKeyEnv")) == "" {
		return "DSH_CUSTOM_CREDENTIAL_MODE_UNVERIFIED"
	}
	models := yamlField(cfg, "models")
	if models == nil || models.Kind != yaml.SequenceNode || len(models.Content) == 0 {
		return "DSH_CUSTOM_MODELS_REQUIRED"
	}
	for _, m := range models.Content {
		if yamlField(m, "baseURL") != nil || yamlField(m, "api") != nil {
			return "DSH_MODEL_ENDPOINT_OVERRIDE_UNSUPPORTED"
		}
	}
	// Completed against the fixed pi-ai dependency by the compatibility tests.
	return dshCustomURLCompatibility(provider, yamlString(yamlField(cfg, "baseURL")))
}

func (m *Manager) dshProfile(ctx context.Context, p Profile, detach bool) ([]Result, error) {
	if roots, e := m.dshSavedRoots(p); e == nil {
		p.DSHHomes = append(p.DSHHomes, roots...)
	} else {
		return nil, e
	}
	docs, e := dshDocuments(p)
	scanIncomplete := e != nil
	var errs []error
	if e != nil {
		errs = append(errs, e)
	}
	var results []Result
	blocked := map[string]bool{}
	knownRoutes, routeReadErr := m.Store.ListRoutes(ctx)
	if routeReadErr != nil {
		return nil, routeReadErr
	}
	retired, retireErr := m.dshRetireCandidates(p)
	if retireErr != nil {
		return nil, retireErr
	}
	for _, doc := range docs {
		if len(doc.candidates) == 0 {
			if doc.issue != "" {
				results = append(results, Result{SID: p.SID, Path: doc.path, AgentType: dshAgent, Mode: "unsupported", Ownership: "direct", Status: 5, ErrorCode: doc.issue})
			}
			continue
		}
		var planned []ccPlanned
		var nodes []*yaml.Node
		var previous []string
		for _, c := range doc.candidates {
			r := Result{SID: p.SID, Path: doc.path, ProviderID: c.identity, AgentType: dshAgent, Mode: "ordinary", Ownership: "direct", Status: 2}
			issue := c.issue
			if doc.issue != "" {
				issue = doc.issue
			}
			if !detach && issue != "" {
				r.Mode = "unsupported"
				r.Status = 5
				r.ErrorCode = issue
				results = append(results, r)
				continue
			}
			if c.urlNode == nil || c.current == "" || !dshValidURL(c.current) {
				for _, old := range knownRoutes {
					if old.UserSID == p.SID && old.AgentType == dshAgent && old.ProviderID == c.identity {
						blocked[old.RouteID] = true
					}
				}
				r.Mode = "unsupported"
				r.Status = 5
				r.ErrorCode = "DSH_BASE_URL_UNSUPPORTED"
				results = append(results, r)
				continue
			}
			d, err := m.resolve(ctx, p, dshAgent, c.identity, c.current, detach)
			if err != nil {
				for _, old := range knownRoutes {
					if old.UserSID == p.SID && old.AgentType == dshAgent && old.ProviderID == c.identity {
						blocked[old.RouteID] = true
					}
				}
				r.Status = 6
				r.ErrorCode = errorCode(err)
				results = append(results, r)
				errs = append(errs, err)
				continue
			}
			if detach && d.before == nil {
				results = append(results, r)
				continue
			}
			r = makeResult(p, doc.path, c.identity, dshAgent, d)
			r.Changed = !sameURL(c.current, d.target)
			planned = append(planned, ccPlanned{decision: d, result: r})
			nodes = append(nodes, c.urlNode)
			previous = append(previous, c.current)
			c.urlNode.Value = d.target
		}
		if len(planned) == 0 {
			continue
		}
		err := m.dshApplyDocument(ctx, p, doc, planned, nodes, previous)
		if err != nil {
			scanIncomplete = true
		}
		for _, plan := range planned {
			r := plan.result
			if err != nil {
				r.Status = 6
				r.ErrorCode = errorCode(err)
			} else if plan.decision.route != nil {
				r.Status = 3
			}
			results = append(results, r)
		}
		if err != nil {
			errs = append(errs, err)
		} else {
			for _, plan := range planned {
				if plan.decision.before != nil && plan.decision.bypass {
					retired[plan.decision.before.RouteID] = true
				}
			}
		}
	}
	routes, err := m.Store.ListRoutes(ctx)
	if err != nil {
		return results, errors.Join(append(errs, err)...)
	}
	if saved, e := m.dshRetireCandidates(p); e != nil {
		return results, errors.Join(append(errs, e)...)
	} else {
		for id := range saved {
			retired[id] = true
		}
	}
	refs := map[string]bool{}
	unknown := scanIncomplete || p.DSHOverlaysUnknown
	otherRefs, refError := m.referencesBase(ctx, p)
	if refError != nil {
		unknown = true
	}
	for _, ref := range otherRefs {
		refs[ref] = true
	}
	for _, doc := range docs {
		if len(doc.tree.Content) == 0 || doc.referencesUnknown || dshReferenceScanUnknown(doc.issue) {
			unknown = true
		}
		dshCollectURLReferences(&doc.tree, refs)
		for _, c := range doc.candidates {
			if c.urlNode != nil {
				refs[c.urlNode.Value] = true
			}
		}
	}
	for _, route := range routes {
		if route.UserSID != p.SID || route.AgentType != dshAgent {
			continue
		}
		if refs[route.InjectedBaseURL] || unknown || blocked[route.RouteID] {
			if detach {
				errs = append(errs, problem("DSH_DETACH_RECOVERY_REQUIRED"))
			}
			continue
		}
		if detach || retired[route.RouteID] || !refs[route.InjectedBaseURL] {
			if err = m.Store.DeleteRoute(ctx, route.RouteID); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if e := m.dshPruneRetirementCandidates(ctx, p); e != nil {
		errs = append(errs, e)
	}
	return results, errors.Join(errs...)
}
func (m *Manager) dshApplyDocument(ctx context.Context, p Profile, doc *dshDocument, planned []ccPlanned, nodes []*yaml.Node, previous []string) error {
	changed := false
	for _, plan := range planned {
		changed = changed || plan.result.Changed
	}
	var b bytes.Buffer
	if changed {
		enc := yaml.NewEncoder(&b)
		enc.SetIndent(2)
		if e := enc.Encode(&doc.tree); e != nil {
			return e
		}
		if e := enc.Close(); e != nil {
			return e
		}
	}
	saved := 0
	undo := func() error {
		var errs []error
		for i := saved - 1; i >= 0; i-- {
			errs = append(errs, m.undoRoute(context.Background(), planned[i].decision))
		}
		for i, n := range nodes {
			n.Value = previous[i]
		}
		return errors.Join(errs...)
	}
	if e := m.dshRememberRoot(p, doc.root); e != nil {
		return errors.Join(e, undo())
	}
	if e := m.dshRememberRetireCandidates(p, planned); e != nil {
		return errors.Join(e, undo())
	}
	for _, plan := range planned {
		if e := m.save(ctx, plan.decision); e != nil {
			return errors.Join(e, undo())
		}
		saved++
	}
	var update FileUpdate
	var e error
	if changed {
		update, e = applyProfileFile(ctx, p, doc.path, doc.bytes, b.Bytes(), m.BackupRoot)
		if e != nil {
			if update.Replaced {
				if rollback := update.Rollback(context.Background(), m.BackupRoot); rollback != nil {
					return errors.Join(e, rollback)
				}
			}
			return errors.Join(e, undo())
		}
	}
	for _, plan := range planned {
		if e = m.finish(ctx, plan.decision); e != nil {
			if changed {
				if rollback := update.Rollback(context.Background(), m.BackupRoot); rollback != nil {
					return errors.Join(e, rollback)
				}
			}
			return errors.Join(e, undo())
		}
	}
	return nil
}
func (m *Manager) InspectDSH(ctx context.Context, profiles []Profile) ([]Endpoint, error) {
	routes, e := m.Store.ListRoutes(ctx)
	if e != nil {
		return nil, e
	}
	return m.inspectDSHWithRoutes(ctx, profiles, routes)
}
func (m *Manager) inspectDSHWithRoutes(ctx context.Context, profiles []Profile, routes []contracts.Route) ([]Endpoint, error) {
	var out []Endpoint
	var errs []error
	for _, p := range profiles {
		if e := ctx.Err(); e != nil {
			return out, e
		}
		roots, e := m.dshSavedRoots(p)
		if e != nil {
			errs = append(errs, e)
		}
		p.DSHHomes = append(p.DSHHomes, roots...)
		docs, e := dshDocuments(p)
		if e != nil {
			errs = append(errs, e)
		}
		for _, doc := range docs {
			if len(doc.candidates) == 0 && doc.issue != "" {
				out = append(out, Endpoint{SID: p.SID, Family: "deepseekHarness", ProviderID: dshIdentity(p, doc.root, doc.profile, "unsupported", "", "unknown", "custom"), Mode: "unsupported", Source: 1, RouteStatus: 5})
				continue
			}
			for _, c := range doc.candidates {
				mode := "ordinary"
				if c.issue != "" || doc.issue != "" {
					mode = "unsupported"
				}
				asset := m.inspectEndpoint(p, "deepseekHarness", c.identity, c.current, mode, 1, true, dshAgent, routes)
				asset.Model = c.model
				out = append(out, asset)
			}
		}
	}
	return out, errors.Join(errs...)
}

type dshRootJournal struct {
	SID   string   `json:"sid"`
	Home  string   `json:"home"`
	Roots []string `json:"roots"`
}

func (m *Manager) dshJournalPath(p Profile) string {
	h := sha256.Sum256([]byte(p.SID + "\x00" + filepath.Clean(p.Home)))
	return filepath.Join(m.BackupRoot, "dsh-roots-"+hex.EncodeToString(h[:])+".json")
}
func (m *Manager) dshSavedRoots(p Profile) ([]string, error) {
	if m.BackupRoot == "" {
		return nil, nil
	}
	path := m.dshJournalPath(p)
	b, e := dshRead(path)
	if os.IsNotExist(e) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	var j dshRootJournal
	if json.Unmarshal(b, &j) != nil || j.SID != p.SID || filepath.Clean(j.Home) != filepath.Clean(p.Home) || len(j.Roots) > 128 {
		return nil, problem("DSH_RECOVERY_JOURNAL_INVALID")
	}
	for _, root := range j.Roots {
		if !filepath.IsAbs(root) || !dshSafePath(p.Home, root) {
			return nil, problem("DSH_RECOVERY_JOURNAL_INVALID")
		}
	}
	return j.Roots, nil
}
func (m *Manager) dshRememberRoot(p Profile, root string) error {
	if !dshSafePath(p.Home, root) {
		return problem("DSH_ROOT_OUTSIDE_USER_OR_SYMLINK")
	}
	roots, e := m.dshSavedRoots(p)
	if e != nil {
		return e
	}
	for _, s := range roots {
		if s == root {
			return nil
		}
	}
	if len(roots) >= 128 {
		return problem("DSH_ROOT_LIMIT")
	}
	roots = append(roots, root)
	b, e := json.Marshal(dshRootJournal{SID: p.SID, Home: p.Home, Roots: roots})
	if e != nil {
		return e
	}
	if e = os.MkdirAll(m.BackupRoot, 0700); e != nil {
		return e
	}
	path := m.dshJournalPath(p)
	before, e := readOptional(path)
	if e != nil {
		return e
	}
	_, e = ApplyFile(context.Background(), path, before, b, m.BackupRoot)
	return e
}

// A local model server is allowed for DSH, but every recognized loopback alias
// at the proxy's own port is rejected. Scheme does not bypass the recursion
// guard; URL default ports are expanded before comparison.
func dshIsLoopback(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "localhost" {
		return true
	}
	if i := strings.LastIndex(host, "%"); i >= 0 {
		host = host[:i]
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
func urlEffectivePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		value, e := strconv.ParseUint(port, 10, 16)
		if e != nil || value == 0 {
			return ""
		}
		return strconv.FormatUint(value, 10)
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}
func (m *Manager) dshLocalUpstreamAllowed(upstream *url.URL) bool {
	if validateTarget(m.Origin, false) != nil || !dshIsLoopback(upstream.Hostname()) {
		return false
	}
	origin, e := url.Parse(m.Origin)
	return e == nil && urlEffectivePort(upstream) != "" && urlEffectivePort(origin) != "" && urlEffectivePort(upstream) != urlEffectivePort(origin)
}

// A rebinding can leave the previous route referenced by another configuration.
// Persist its retirement eligibility, so a later detach can retire it after the
// final reference disappears without treating arbitrary missing files as safe.
func (m *Manager) dshRetirementPath(p Profile) string {
	return strings.TrimSuffix(m.dshJournalPath(p), ".json") + "-retirement.json"
}
func (m *Manager) dshRetireCandidates(p Profile) (map[string]bool, error) {
	out := map[string]bool{}
	if m.BackupRoot == "" {
		return out, nil
	}
	b, e := dshRead(m.dshRetirementPath(p))
	if os.IsNotExist(e) {
		return out, nil
	}
	if e != nil {
		return nil, e
	}
	var ids []string
	if json.Unmarshal(b, &ids) != nil || len(ids) > 4096 {
		return nil, problem("DSH_RETIREMENT_JOURNAL_INVALID")
	}
	for _, id := range ids {
		raw, e := base64.RawURLEncoding.DecodeString(id)
		if e != nil || len(raw) != 16 {
			return nil, problem("DSH_RETIREMENT_JOURNAL_INVALID")
		}
		out[id] = true
	}
	return out, nil
}
func (m *Manager) dshRememberRetireCandidates(p Profile, planned []ccPlanned) error {
	ids, e := m.dshRetireCandidates(p)
	if e != nil {
		return e
	}
	changed := false
	for _, plan := range planned {
		d := plan.decision
		if d.referenced != nil && d.referenced.AgentType == dshAgent && (d.route == nil || d.referenced.RouteID != d.route.RouteID) {
			if !ids[d.referenced.RouteID] {
				ids[d.referenced.RouteID] = true
				changed = true
			}
		}
	}
	if !changed {
		return nil
	}
	if len(ids) > 4096 {
		return problem("DSH_RETIREMENT_JOURNAL_LIMIT")
	}
	list := make([]string, 0, len(ids))
	for id := range ids {
		list = append(list, id)
	}
	sort.Strings(list)
	b, e := json.Marshal(list)
	if e != nil {
		return e
	}
	path := m.dshRetirementPath(p)
	before, e := readOptional(path)
	if e != nil {
		return e
	}
	_, e = ApplyFile(context.Background(), path, before, b, m.BackupRoot)
	return e
}

func dshReferenceScanUnknown(issue string) bool {
	switch issue {
	case "", "DSH_VERSION_UNVERIFIED":
		return false
	default:
		return true
	}
}
func dshCollectURLReferences(node *yaml.Node, refs map[string]bool) {
	if node == nil {
		return
	}
	if node.Kind == yaml.ScalarNode && node.Tag == "!!str" {
		refs[node.Value] = true
	}
	for _, child := range node.Content {
		dshCollectURLReferences(child, refs)
	}
}

func (m *Manager) dshPruneRetirementCandidates(ctx context.Context, p Profile) error {
	ids, e := m.dshRetireCandidates(p)
	if e != nil || len(ids) == 0 {
		return e
	}
	routes, e := m.Store.ListRoutes(ctx)
	if e != nil {
		return e
	}
	var kept []string
	for _, r := range routes {
		if r.UserSID == p.SID && r.AgentType == dshAgent && ids[r.RouteID] {
			kept = append(kept, r.RouteID)
		}
	}
	if len(kept) == len(ids) {
		return nil
	}
	sort.Strings(kept)
	if kept == nil {
		kept = []string{}
	}
	b, e := json.Marshal(kept)
	if e != nil {
		return e
	}
	path := m.dshRetirementPath(p)
	before, e := readOptional(path)
	if e != nil {
		return e
	}
	_, e = ApplyFile(ctx, path, before, b, m.BackupRoot)
	return e
}

// DSHRecoveryProfiles validates and restores journaled roots before the caller
// discovers running DSH processes and overlay metadata. Callers must propagate
// errors; treating an invalid recovery journal as an empty root list is unsafe.
func (m *Manager) DSHRecoveryProfiles(ctx context.Context, profiles []Profile) ([]Profile, error) {
	out := make([]Profile, 0, len(profiles))
	for _, p := range profiles {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		roots, e := m.dshSavedRoots(p)
		if e != nil {
			return nil, e
		}
		// Clone slices: metadata preparation must not mutate the caller's profiles.
		merged := append(append([]string(nil), p.DSHHomes...), roots...)
		seen := map[string]bool{}
		p.DSHHomes = nil
		for _, root := range merged {
			clean := filepath.Clean(root)
			if !seen[clean] {
				seen[clean] = true
				p.DSHHomes = append(p.DSHHomes, clean)
			}
		}
		out = append(out, p)
	}
	return out, nil
}
