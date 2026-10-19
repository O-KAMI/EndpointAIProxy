package diagnostics

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	_ "modernc.org/sqlite"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var hashedIdentifierPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var uuidPattern = regexp.MustCompile(`(?i)^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
var tokenEnumPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]*$`)
var codePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,100}$`)

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
func hashIdentifier(v string) string { return fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(v))) }
func safeFile(path string) bool {
	for p := filepath.Clean(path); ; {
		st, e := os.Lstat(p)
		if e != nil || st.Mode()&os.ModeSymlink != 0 {
			return false
		}
		next := filepath.Dir(p)
		if next == p {
			break
		}
		p = next
	}
	st, e := os.Stat(path)
	return e == nil && st.Mode().IsRegular()
}

type limitedReadCloser struct {
	io.Reader
	closers []io.Closer
}

func (r *limitedReadCloser) Close() error {
	for _, c := range r.closers {
		c.Close()
	}
	return nil
}
func openEvidence(path string) (io.ReadCloser, error) {
	if !safeFile(path) {
		return nil, errors.New("unsafe evidence file")
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	var r io.Reader = f
	closers := []io.Closer{f}
	if strings.HasSuffix(strings.ToLower(path), ".gz") {
		gz, e := gzip.NewReader(f)
		if e != nil {
			f.Close()
			return nil, e
		}
		r = gz
		closers = append([]io.Closer{gz}, closers...)
	}
	return &limitedReadCloser{Reader: io.LimitReader(r, 8<<20), closers: closers}, nil
}
func lowerObject(raw map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range raw {
		out[strings.ToLower(k)] = v
	}
	return out
}
func str(v any) string { s, _ := v.(string); return s }

func sanitizeURI(value string) string {
	u, e := url.Parse(value)
	if e != nil {
		return "[invalid-url]"
	}
	u.User = nil
	u.Fragment = ""
	if u.RawQuery != "" {
		u.RawQuery = "redacted"
	}
	parts := strings.Split(u.Path, "/")
	for i, part := range parts {
		if regexp.MustCompile(`(?i)^(sk|key|token)-[A-Za-z0-9_-]{16,}$`).MatchString(part) || len(part) > 64 {
			parts[i] = hashIdentifier(part)
		}
	}
	u.Path = strings.Join(parts, "/")
	u.RawPath = ""
	return strings.TrimRight(u.String(), "/")
}

// Only typed diagnostic fields survive. Free text messages and error summaries
// are excluded because they can embed credentials or request contents.
func sanitizeRow(raw map[string]any) map[string]any { return sanitizeRowDepth(raw, 0) }
func sanitizeRowDepth(raw map[string]any, depth int) map[string]any {
	out := map[string]any{}
	for key, value := range raw {
		lk := strings.ToLower(key)
		switch lk {
		case "auditdiagnostics", "lastauditfailure", "controlfailure":
			if nested, ok := value.(map[string]any); ok {
				if depth < 2 {
					out[key] = sanitizeRowDepth(nested, depth+1)
				}
			}
		case "requestid", "routeid", "commandid", "deviceid", "collectionid", "controlrequestid", "serverrequestid", "operationid", "runid", "userhash", "pathhash", "providerhash":
			if s := str(value); uuidPattern.MatchString(s) || hashedIdentifierPattern.MatchString(s) {
				out[key] = s
			} else if s != "" {
				out[key] = hashIdentifier(s)
			}
		case "originalbaseurl", "inboundpathandquery", "outboundpathandquery":
			if s := str(value); s != "" {
				out[key] = sanitizeURI(s)
			}
		case "userid", "usersid", "providerid", "artifact", "path", "markdownpath":
			if s := str(value); s != "" {
				out[key] = hashIdentifier(s)
			}
		case "startedatutc", "completedatutc", "timeutc", "timestamp", "timestamputc", "updatedatutc", "receivedatutc", "agentrequestreceivedatutc", "gatewayrequeststartedatutc", "gatewayresponseheadersreceivedatutc", "agentresponsestartedatutc", "lastcontrolsyncatutc", "lastcontrolsuccessatutc", "firstatutc", "lastatutc", "firstfailureatutc", "lastfailureatutc":
			if s := str(value); s != "" {
				if _, e := time.Parse(time.RFC3339Nano, s); e == nil {
					out[key] = s
				}
			}
		case "statuscode", "durationmilliseconds", "gatewayroundtripmilliseconds", "requestbytes", "responsebytes", "commandtype", "type", "failurecount", "confidence", "agenttype", "installmethod", "policyversion", "length", "uptimeseconds", "activeroutes", "routecount", "items", "droppedcount", "logdroppedcount", "logwritefailurecount", "logsuppressedcount", "logqueuedepth", "auditfailurecount", "oscode", "oserrorcode", "httpstatuscode", "capturefinalizemilliseconds", "queuewaitmilliseconds", "successfulrequestcount", "suppressedcount", "count", "durationsummilliseconds", "durationmaxmilliseconds", "capturefinalizesummilliseconds", "capturefinalizemaxmilliseconds":
			switch value.(type) {
			case float64, int, int64:
				out[key] = value
			}
		case "failed", "changed":
			switch value.(type) {
			case bool, int, int64, float64:
				out[key] = value
			}
		case "capturetruncated", "capturedegraded", "confirmed", "enabled", "timeout", "restored", "concurrentchange", "partial":
			if b, ok := value.(bool); ok {
				out[key] = b
			}
		case "errorcode", "eventcode", "eventname", "code", "errorclass", "lastcontrolerrorcode", "lasterrorcode", "resultcode":
			if s := str(value); codePattern.MatchString(s) {
				out[key] = s
			}
		case "version", "clientversion":
			if x := str(value); len(x) <= 32 && regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9]+)*$`).MatchString(x) {
				out[key] = x
			}
		case "operationstate":
			if n, ok := value.(float64); ok {
				out[key] = n
			} else if x := str(value); len(x) <= 64 && tokenEnumPattern.MatchString(x) {
				out[key] = x
			}
		case "outcome", "level", "severity", "agent", "agentsurface", "stage", "component", "operation", "family", "mode", "source", "ownership", "implementation", "status", "proxystate", "auditstate":
			if n, ok := value.(float64); ok && (lk == "level" || lk == "status") {
				out[key] = n
				continue
			}
			if s := str(value); len(s) <= 64 && tokenEnumPattern.MatchString(s) {
				out[key] = s
			}
		}
	}
	return out
}
func rowTime(raw map[string]any) (time.Time, bool) {
	for _, key := range []string{"timestamputc", "completedatutc", "startedatutc", "timeutc", "timestamp", "receivedatutc"} {
		if s := str(raw[key]); s != "" {
			t, e := time.Parse(time.RFC3339Nano, s)
			if e == nil {
				return t, true
			}
		}
	}
	return time.Time{}, false
}
func collectEvidence(ctx context.Context, o Options, since time.Time) (map[string][]byte, []string, bool) {
	out := map[string][]byte{}
	errorsFound := []string{}
	truncated := false
	summary, failures, logs, capturePaths, coverage, scanErrors, partial := readEvidenceWindow(ctx, o, since)
	errorsFound = append(errorsFound, scanErrors...)
	truncated = partial
	out["evidence/search-coverage.json"], _ = json.Marshal(coverage)
	jsonl := func(rows []map[string]any) []byte {
		var b strings.Builder
		for _, r := range rows {
			raw, _ := json.Marshal(r)
			b.Write(raw)
			b.WriteByte('\n')
		}
		return []byte(b.String())
	}
	out["requests/recent-summary.jsonl"] = jsonl(summary)
	out["requests/failures.jsonl"] = jsonl(failures)
	out["service/operational-log.jsonl"] = jsonl(logs)
	captureRoot, _ := filepath.Abs(filepath.Join(o.DataRoot, "captures"))
	for id, p := range capturePaths {
		if p == "" {
			continue
		}
		abs, e := filepath.Abs(p)
		if e != nil || !strings.HasPrefix(abs, captureRoot+string(filepath.Separator)) {
			continue
		}
		if !safeFile(abs) && safeFile(abs+".gz") {
			abs += ".gz"
		}
		r, e := openEvidence(abs)
		if e != nil {
			errorsFound = append(errorsFound, "capture:unavailable")
			continue
		}
		raw, e := io.ReadAll(io.LimitReader(r, 2<<20))
		r.Close()
		if e != nil {
			errorsFound = append(errorsFound, "capture:read_failed")
			continue
		}
		if len(raw) == 2<<20 {
			truncated = true
		}
		out["requests/sanitized-captures/"+strings.ReplaceAll(id, "-", "")+".md"] = []byte(sanitizeMarkdown(string(raw)))
	}
	backupRoot := filepath.Join(o.DataRoot, "config-backups")
	metadata := []map[string]any{}
	walked := 0
	_ = filepath.WalkDir(backupRoot, func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		walked++
		if walked > 500 {
			truncated = true
			return filepath.SkipAll
		}
		if !safeFile(path) {
			return nil
		}
		st, e := d.Info()
		if e == nil {
			metadata = append(metadata, map[string]any{"RelativePathHash": hashIdentifier(strings.TrimPrefix(path, backupRoot)), "Length": st.Size(), "LastWriteTimeUtc": st.ModTime().UTC()})
		}
		return nil
	})
	out["configuration/backups-metadata.json"], _ = json.Marshal(metadata)
	config := []map[string]any{}
	for _, profile := range o.Profiles {
		record := map[string]any{"UserSidHash": hashIdentifier(profile.SID), "HomeHash": hashIdentifier(profile.Home)}
		files := []map[string]any{}
		for _, relative := range []string{".claude/settings.json", ".codex/config.toml", ".cc-switch/cc-switch.db"} {
			p := filepath.Join(profile.Home, filepath.FromSlash(relative))
			item := map[string]any{"Kind": relative, "Exists": safeFile(p)}
			if safeFile(p) {
				if st, e := os.Stat(p); e == nil {
					item["Length"] = st.Size()
					item["LastWriteTimeUtc"] = st.ModTime().UTC()
				}
			}
			files = append(files, item)
		}
		files = append(files, dshMetadata(profile.Home)...)
		record["ConfigurationMetadata"] = files
		config = append(config, record)
	}
	out["configuration/profiles.json"], _ = json.Marshal(config)
	agents := []map[string]any{}
	for _, a := range o.Agents {
		artifacts := []map[string]any{}
		for _, e := range a.Evidence {
			artifacts = append(artifacts, map[string]any{"Collector": e.Collector, "ArtifactHash": hashIdentifier(e.Artifact), "Strength": e.Strength, "ObservedAtUtc": e.ObservedAtUTC})
		}
		agents = append(agents, map[string]any{"UserSidHash": hashIdentifier(a.UserSID), "AgentType": a.AgentType, "Confirmed": a.Confirmed, "Confidence": a.Confidence, "InstallMethod": a.InstallMethod, "Evidence": artifacts})
	}
	out["agents/inventory.json"], _ = json.Marshal(agents)
	stateMetadata(ctx, o.DataRoot, out, &errorsFound)
	if o.Routes != nil {
		routes := []map[string]any{}
		for _, r := range o.Routes {
			routes = append(routes, map[string]any{"RouteId": r.RouteID, "UserSidHash": hashIdentifier(r.UserSID), "AgentType": r.AgentType, "ProviderHash": hashIdentifier(r.ProviderID), "OriginalBaseUrl": sanitizeURI(r.OriginalBaseURL), "InjectedBaseUrl": sanitizeURI(r.InjectedBaseURL), "Status": r.Status, "CreatedAtUtc": r.CreatedAtUTC, "UpdatedAtUtc": r.UpdatedAtUTC})
		}
		out["routes/registry-sanitized.json"], _ = json.Marshal(routes)
	}
	if o.Endpoints != nil {
		endpoints := []map[string]any{}
		for _, ep := range o.Endpoints {
			endpoints = append(endpoints, map[string]any{"UserSidHash": hashIdentifier(ep.SID), "Family": ep.Family, "ProviderHash": hashIdentifier(ep.ProviderID), "Source": ep.Source, "Current": ep.Current, "Model": ep.Model, "Mode": ep.Mode, "OriginalBaseUrl": sanitizeURI(ep.OriginalBaseURL), "EffectiveBaseUrl": sanitizeURI(ep.EffectiveBaseURL), "LocalRouteUrl": sanitizeURI(ep.LocalRouteURL), "Bypassed": ep.Bypassed, "RouteStatus": ep.RouteStatus})
		}
		out["configuration/endpoints.json"], _ = json.Marshal(endpoints)
	}
	return out, errorsFound, truncated
}
func sanitizeMarkdown(raw string) string {
	var out strings.Builder
	out.WriteString("# Sanitized capture\n\n## Metadata\n\n")
	section := "metadata"
	for _, line := range strings.Split(raw, "\n") {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "## ") {
			section = strings.ToLower(strings.TrimPrefix(trim, "## "))
			if section == "latency" || section == "completion" {
				out.WriteString("\n" + trim + "\n\n")
			}
			continue
		}
		if section != "metadata" && section != "latency" && section != "completion" {
			continue
		}
		if !strings.HasPrefix(trim, "- ") {
			continue
		}
		key, value, ok := strings.Cut(strings.TrimPrefix(trim, "- "), ":")
		if !ok {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), "`")
		lk := strings.ToLower(key)
		valid := false
		switch lk {
		case "request id", "route":
			valid = uuidPattern.MatchString(value)
		case "user id", "user sid", "provider":
			value = hashIdentifier(value)
			valid = true
		case "started utc", "completed utc", "agent request received utc", "gateway request started utc", "gateway response headers received utc", "agent response started utc":
			_, e := time.Parse(time.RFC3339Nano, value)
			valid = e == nil
		case "request bytes", "response bytes", "gateway round trip milliseconds":
			_, e := strconv.ParseInt(value, 10, 64)
			valid = e == nil
		case "request sha-256", "response sha-256":
			valid = regexp.MustCompile(`^[a-fA-F0-9]{64}$`).MatchString(value)
		case "capture truncated", "capture degraded":
			valid = value == "True" || value == "False" || value == "true" || value == "false"
		case "error code":
			valid = codePattern.MatchString(value)
		case "outcome":
			valid = regexp.MustCompile(`^(Succeeded|Failed|Success|Error|Cancelled|succeeded|failed|success|error|cancelled)$`).MatchString(value)
		case "agent", "agent surface":
			valid = regexp.MustCompile(`^(ClaudeCode|ClaudeCli|ClaudeIde|ClaudeDesktop|CodexCli|CodexIde|CodexDesktop|QoderCli|QoderIde|CcSwitch|DeepSeekHarness|deepseekHarness|cli|desktop|ide|unknown|claudeCli|claudeIde|claudeDesktop|codexCli|codexIde|codexDesktop)$`).MatchString(value)
		}
		if valid {
			fmt.Fprintf(&out, "- %s: `%s`\n", key, value)
		}
	}
	out.WriteString("\n## Request body\n\n[OMITTED]\n\n## Response body\n\n[OMITTED]\n")
	return out.String()
}
func stateMetadata(ctx context.Context, root string, out map[string][]byte, errorsFound *[]string) {
	path := filepath.Join(root, "state", "client.db")
	if !safeFile(path) {
		out["state/client-runtime.json"] = []byte(`{"DatabaseExists":false}`)
		out["routes/registry-sanitized.json"] = []byte("[]")
		return
	}
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	q := u.Query()
	q.Set("mode", "ro")
	q.Set("_pragma", "busy_timeout(1000)")
	u.RawQuery = q.Encode()
	db, e := sql.Open("sqlite", u.String())
	if e != nil {
		*errorsFound = append(*errorsFound, "state:unavailable")
		return
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	queries := []struct{ name, query string }{{"state/identity.json", "SELECT device_id,created_at_utc FROM client_identity LIMIT 1"}, {"state/client-runtime.json", "SELECT operation_state,updated_at_utc,last_error_code FROM client_operation_state LIMIT 1"}, {"state/policy-metadata.json", "SELECT policy_version,server_instance_id,received_at_utc FROM cached_policy LIMIT 1"}, {"state/command-receipts.json", "SELECT command_id,command_type,status,received_at_utc,completed_at_utc,result_code FROM remote_command_receipts ORDER BY received_at_utc DESC LIMIT 50"}, {"routes/registry-sanitized.json", "SELECT route_id,user_sid,agent_type,provider_id,status,created_at_utc,updated_at_utc FROM routes LIMIT 500"}}
	for _, query := range queries {
		rows, e := db.QueryContext(ctx, query.query)
		if e != nil {
			*errorsFound = append(*errorsFound, query.name+":unavailable")
			continue
		}
		columns, _ := rows.Columns()
		records := []map[string]any{}
		for rows.Next() {
			values := make([]any, len(columns))
			ptr := make([]any, len(columns))
			for i := range values {
				ptr[i] = &values[i]
			}
			if rows.Scan(ptr...) != nil {
				continue
			}
			record := map[string]any{}
			for i, key := range columns {
				v := values[i]
				if bytes, ok := v.([]byte); ok {
					v = string(bytes)
				}
				if s, ok := v.(string); ok {
					switch key {
					case "device_id", "command_id", "route_id":
						if !uuidPattern.MatchString(s) {
							v = hashIdentifier(s)
						}
					case "user_sid", "provider_id", "server_instance_id":
						v = hashIdentifier(s)
					case "last_error_code", "result_code":
						if !codePattern.MatchString(s) {
							v = "OMITTED"
						}
					default:
						if _, e := time.Parse(time.RFC3339Nano, s); e != nil {
							v = "OMITTED"
						}
					}
				}
				record[key] = v
			}
			records = append(records, record)
		}
		if rows.Err() != nil {
			*errorsFound = append(*errorsFound, query.name+":read_failed")
		}
		rows.Close()
		out[query.name], _ = json.Marshal(records)
	}
}
