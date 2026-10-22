package configuration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"endpointai/client/internal/contracts"
	"endpointai/client/internal/proxy"
	"gopkg.in/yaml.v3"
)

const DSHDesktopSupportedVersion = "0.2.1-rc.2"

var accountRowNames = map[string]string{
	"deepseek-account":     "@deepseek-ai/dsh-deepseek-account-platform",
	"llm-deepseek-account": "@deepseek-ai/dsh-llm-deepseek-account",
}

// Configuration ownership is journaled before publication; grants stay in DSH.
type accountJournal struct {
	SID, Path, Identity string
	Route               contracts.Route
	Before, Managed     map[string]*yaml.Node
}

func validAccountJournal(record *accountJournal) bool {
	origin, suffix, err := accountOriginal(record.Before)
	if err != nil || origin != record.Route.OriginalBaseURL || len(record.Managed) != 2 {
		return false
	}
	u, err := url.Parse(record.Route.InjectedBaseURL)
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	for id, name := range accountRowNames {
		row := record.Managed[id]
		if yamlString(yamlField(row, "id")) != id || yamlString(yamlField(row, "name")) != "" && yamlString(yamlField(row, "name")) != name {
			return false
		}
	}
	return yamlString(yamlField(yamlField(record.Managed["deepseek-account"], "config"), "inferenceOrigin")) == record.Route.InjectedBaseURL && yamlString(yamlField(yamlField(record.Managed["llm-deepseek-account"], "config"), "baseURL")) == record.Route.InjectedBaseURL+suffix
}

func cloneYAML(n *yaml.Node) *yaml.Node {
	if n == nil {
		return nil
	}
	copy := *n
	copy.Content = nil
	for _, child := range n.Content {
		copy.Content = append(copy.Content, cloneYAML(child))
	}
	return &copy
}

func accountRows(doc *dshDocument) (map[string]*yaml.Node, error) {
	rows := map[string]*yaml.Node{}
	for _, row := range doc.tree.Content[0].Content {
		id := yamlString(yamlField(row, "id"))
		if _, wanted := accountRowNames[id]; !wanted {
			continue
		}
		if rows[id] != nil {
			return nil, problem("DSH_ACCOUNT_PATCH_AMBIGUOUS")
		}
		if name := yamlString(yamlField(row, "name")); name != "" && name != accountRowNames[id] {
			return nil, problem("DSH_ACCOUNT_PLUGIN_UNVERIFIED")
		}
		if disabled := yamlField(row, "disabled"); disabled != nil && (disabled.Tag != "!!bool" || disabled.Value != "false") {
			return nil, problem("DSH_ACCOUNT_ENTRY_DISABLED")
		}
		if cfg := yamlField(row, "config"); cfg != nil && cfg.Kind != yaml.MappingNode {
			return nil, problem("DSH_ACCOUNT_CONFIG_UNSUPPORTED")
		}
		rows[id] = cloneYAML(row)
	}
	return rows, nil
}

func sameAccountRows(left, right map[string]*yaml.Node) bool {
	for id := range accountRowNames {
		a, leftErr := yaml.Marshal(left[id])
		b, rightErr := yaml.Marshal(right[id])
		if leftErr != nil || rightErr != nil || !bytes.Equal(a, b) {
			return false
		}
	}
	return true
}

func setAccountRows(doc *dshDocument, rows map[string]*yaml.Node) {
	var content []*yaml.Node
	seen := map[string]bool{}
	for _, row := range doc.tree.Content[0].Content {
		id := yamlString(yamlField(row, "id"))
		if _, owned := accountRowNames[id]; !owned {
			content = append(content, row)
			continue
		}
		seen[id] = true
		if rows[id] != nil {
			content = append(content, cloneYAML(rows[id]))
		}
	}
	for _, id := range []string{"deepseek-account", "llm-deepseek-account"} {
		if !seen[id] && rows[id] != nil {
			content = append(content, cloneYAML(rows[id]))
		}
	}
	doc.tree.Content[0].Content = content
}

func yamlSet(n *yaml.Node, key, value string) {
	if old := yamlField(n, key); old != nil {
		old.Kind, old.Tag, old.Value = yaml.ScalarNode, "!!str", value
		old.Content = nil
		return
	}
	n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value})
}

func accountConfig(rows map[string]*yaml.Node, id string) *yaml.Node {
	row := rows[id]
	if row == nil {
		row = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		yamlSet(row, "id", id)
		yamlSet(row, "name", accountRowNames[id])
		rows[id] = row
	}
	cfg := yamlField(row, "config")
	if cfg == nil {
		cfg = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		row.Content = append(row.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "config"}, cfg)
	}
	return cfg
}

func accountOriginal(rows map[string]*yaml.Node) (string, string, error) {
	origin, base := "https://api.deepseek.com", "https://api.deepseek.com/anthropic"
	if row := rows["deepseek-account"]; row != nil {
		if n := yamlField(yamlField(row, "config"), "inferenceOrigin"); n != nil {
			origin = yamlString(n)
		}
	}
	if row := rows["llm-deepseek-account"]; row != nil {
		if n := yamlField(yamlField(row, "config"), "baseURL"); n != nil {
			base = yamlString(n)
		}
	}
	u, err := url.Parse(origin)
	b, baseErr := url.Parse(base)
	if err != nil || baseErr != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || b.Scheme != u.Scheme || b.Host != u.Host || b.User != nil || b.RawQuery != "" || b.Fragment != "" {
		return "", "", problem("DSH_ACCOUNT_ORIGIN_UNSUPPORTED")
	}
	path := strings.TrimRight(b.Path, "/")
	if path != "/anthropic" && path != "/anthropic/v1" {
		return "", "", problem("DSH_ACCOUNT_PATH_UNSUPPORTED")
	}
	return strings.TrimRight(origin, "/"), path, nil
}

func (m *Manager) accountJournalPath(identity string) string {
	digest := sha256.Sum256([]byte(identity))
	return filepath.Join(m.BackupRoot, "dsh-account."+hex.EncodeToString(digest[:])+".json")
}

func (m *Manager) hasAccountJournal(p Profile, doc *dshDocument) bool {
	identity := dshIdentity(p, doc.root, doc.profile, "llm-deepseek-account", "", "messages", "account")
	_, err := os.Lstat(m.accountJournalPath(identity))
	return err == nil || !os.IsNotExist(err)
}

func writeAccountJournal(path string, record *accountJournal) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return problem("DSH_ACCOUNT_JOURNAL_UNSAFE")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".account-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return errors.Join(err, closeErr)
	}
	return os.Rename(file.Name(), path)
}

func (m *Manager) dshAccountProfile(ctx context.Context, p Profile, doc *dshDocument, detach bool) ([]Result, error) {
	identity := dshIdentity(p, doc.root, doc.profile, "llm-deepseek-account", "", "messages", "account")
	result := Result{SID: p.SID, Path: doc.path, ProviderID: identity, AgentType: dshAgent, Mode: "ordinary", Ownership: "direct", Status: 2}
	fail := func(code string) ([]Result, error) {
		result.Status, result.ErrorCode = 6, code
		return []Result{result}, problem(code)
	}
	if len(doc.tree.Content) == 0 {
		return fail("DSH_ACCOUNT_PATCH_UNREADABLE")
	}
	current, err := accountRows(doc)
	if err != nil {
		return fail(errorCode(err))
	}
	journalPath := m.accountJournalPath(identity)
	var record *accountJournal
	if raw, err := dshRead(journalPath); err == nil {
		record = &accountJournal{}
		if json.Unmarshal(raw, record) != nil || record.Identity != identity || record.SID != p.SID || record.Path != doc.path || !proxy.ValidRouteID(record.Route.RouteID) || record.Route.UserSID != p.SID || record.Route.ProviderID != identity || record.Route.AgentType != dshAgent || !validAccountJournal(record) {
			return fail("DSH_ACCOUNT_JOURNAL_INVALID")
		}
	} else if !os.IsNotExist(err) {
		return fail("DSH_ACCOUNT_JOURNAL_UNREADABLE")
	}
	if detach {
		if record == nil {
			return []Result{result}, nil
		}
		return m.detachAccount(ctx, p, doc, current, record, journalPath, result)
	}
	if !p.DSHDesktopAccountVerified || p.DSHVersion != DSHDesktopSupportedVersion {
		return fail("DSH_DESKTOP_ACCOUNT_UNVERIFIED")
	}
	if doc.referencesUnknown {
		return fail("DSH_ACCOUNT_PATCH_AMBIGUOUS")
	}
	if doc.issue != "" && doc.issue != "DSH_VERSION_UNVERIFIED" {
		return fail(doc.issue)
	}
	basePath := filepath.Join(filepath.Dir(doc.path), "cordis.yml")
	base, err := dshRead(basePath)
	var baseTree yaml.Node
	if err != nil || !dshSafePath(p.Home, basePath) || dshParse(base, &baseTree) != nil || len(baseTree.Content[0].Content) != 0 {
		return fail("DSH_DESKTOP_BASE_CONFIG_UNVERIFIED")
	}
	originalRows := current
	if record != nil {
		if !sameAccountRows(current, record.Before) && !sameAccountRows(current, record.Managed) {
			return fail("DSH_ACCOUNT_CONFIG_CHANGED")
		}
		originalRows = record.Before
	}
	origin, suffix, err := accountOriginal(originalRows)
	if err != nil {
		return fail(errorCode(err))
	}
	if m.Allowlisted != nil && (m.Allowlisted(origin) || m.Allowlisted(origin+suffix)) {
		if record != nil {
			return m.detachAccount(ctx, p, doc, current, record, journalPath, result)
		}
		result.Status = 7
		return []Result{result}, nil
	}
	resolveFrom := origin
	if record != nil && sameAccountRows(current, record.Managed) {
		resolveFrom = record.Route.InjectedBaseURL
	}
	d, err := m.resolve(ctx, p, dshAgent, identity, resolveFrom, false)
	if err != nil {
		return fail(errorCode(err))
	}
	if record != nil {
		if d.before != nil && d.before.RouteID != record.Route.RouteID {
			return fail("DSH_ACCOUNT_ROUTE_ID_CHANGED")
		}
		d.route.RouteID = record.Route.RouteID
		d.route.CreatedAtUTC = record.Route.CreatedAtUTC
	}
	if m.AccountOrigin == nil {
		return fail("DSH_ACCOUNT_LISTENER_UNAVAILABLE")
	}
	previousOrigin := ""
	if record != nil {
		previousOrigin = record.Route.InjectedBaseURL
	}
	local, err := m.AccountOrigin(d.route.RouteID, previousOrigin)
	if err != nil {
		return fail("DSH_ACCOUNT_LISTENER_UNAVAILABLE")
	}
	d.route.OriginalBaseURL, d.route.InjectedBaseURL, d.target = origin, local, local
	if record == nil {
		managed := map[string]*yaml.Node{}
		for id, row := range current {
			managed[id] = cloneYAML(row)
		}
		cfg := accountConfig(managed, "deepseek-account")
		yamlSet(cfg, "inferenceOrigin", local)
		if yamlField(cfg, "desktopPlatform") == nil {
			yamlSet(cfg, "desktopPlatform", "win32")
		}
		yamlSet(accountConfig(managed, "llm-deepseek-account"), "baseURL", local+suffix)
		record = &accountJournal{SID: p.SID, Path: doc.path, Identity: identity, Route: *d.route, Before: current, Managed: managed}
		if err := m.dshRememberRoot(p, doc.root); err != nil {
			return fail(errorCode(err))
		}
		if err := writeAccountJournal(journalPath, record); err != nil {
			return fail("DSH_ACCOUNT_JOURNAL_WRITE_FAILED")
		}
	}
	if err = m.save(ctx, d); err != nil {
		return fail("DSH_ACCOUNT_ROUTE_WRITE_FAILED")
	}
	changed := !sameAccountRows(current, record.Managed)
	var update FileUpdate
	if changed {
		setAccountRows(doc, record.Managed)
		data, encodeErr := yaml.Marshal(&doc.tree)
		if encodeErr == nil {
			update, err = applyProfileFile(ctx, p, doc.path, doc.bytes, data, m.BackupRoot)
		} else {
			err = encodeErr
		}
	}
	if err == nil {
		err = m.finish(ctx, d)
	}
	if err != nil {
		if update.Replaced {
			if rollback := update.Rollback(context.Background(), m.BackupRoot); rollback != nil {
				return fail("DSH_ACCOUNT_RECOVERY_REQUIRED")
			}
		}
		setAccountRows(doc, current)
		if m.undoRoute(context.Background(), d) != nil {
			return fail("DSH_ACCOUNT_RECOVERY_REQUIRED")
		}
		return fail("DSH_ACCOUNT_CONFIG_WRITE_FAILED")
	}
	result.Status, result.RouteID, result.Changed = 3, d.route.RouteID, changed
	return []Result{result}, nil
}

func (m *Manager) detachAccount(ctx context.Context, p Profile, doc *dshDocument, current map[string]*yaml.Node, record *accountJournal, journalPath string, result Result) ([]Result, error) {
	fail := func(code string) ([]Result, error) {
		result.Status, result.ErrorCode = 6, code
		return []Result{result}, problem(code)
	}
	if !sameAccountRows(current, record.Managed) && !sameAccountRows(current, record.Before) {
		return fail("DSH_ACCOUNT_CONFIG_CHANGED")
	}
	var update FileUpdate
	changed := !sameAccountRows(current, record.Before)
	if changed {
		setAccountRows(doc, record.Before)
		data, err := yaml.Marshal(&doc.tree)
		if err != nil {
			return fail("DSH_ACCOUNT_CONFIG_WRITE_FAILED")
		}
		update, err = applyProfileFile(ctx, p, doc.path, doc.bytes, data, m.BackupRoot)
		if err != nil {
			if update.Replaced && update.Rollback(context.Background(), m.BackupRoot) != nil {
				return fail("DSH_ACCOUNT_RECOVERY_REQUIRED")
			}
			setAccountRows(doc, current)
			return fail("DSH_ACCOUNT_CONFIG_WRITE_FAILED")
		}
	}
	if err := m.Store.DeleteRoute(ctx, record.Route.RouteID); err != nil {
		if update.Replaced && update.Rollback(context.Background(), m.BackupRoot) != nil {
			return fail("DSH_ACCOUNT_RECOVERY_REQUIRED")
		}
		setAccountRows(doc, current)
		return fail("DSH_ACCOUNT_ROUTE_DELETE_FAILED")
	}
	if err := os.Remove(journalPath); err != nil {
		return fail("DSH_ACCOUNT_JOURNAL_CLEANUP_FAILED")
	}
	result.Status, result.RouteID, result.Changed = 2, record.Route.RouteID, changed
	return []Result{result}, nil
}
