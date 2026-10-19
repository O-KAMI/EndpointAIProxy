package diagnostics

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"endpointai/client/internal/configuration"
	"endpointai/client/internal/contracts"
	"endpointai/client/internal/discovery"
	"endpointai/client/internal/platform"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

type Options struct {
	DataRoot, OutputPath, HealthURL string
	ClientVersion                   string
	Since                           time.Duration
	RequestID                       string
	Profiles                        []platform.Profile
	Agents                          []discovery.Agent
	Routes                          []contracts.Route
	Endpoints                       []configuration.Endpoint
}
type command struct {
	name, exe string
	args      []string
}
type result struct {
	Collected bool   `json:"collected"`
	Error     string `json:"error,omitempty"`
	Output    string `json:"output,omitempty"`
}

// Collect includes allowlisted metadata, bounded sanitized logs and local
// health. It never copies raw settings, databases, bodies or process arguments.
func Collect(ctx context.Context, o Options) (path string, err error) {
	started := time.Now().UTC()
	if o.ClientVersion == "" {
		o.ClientVersion = "0.2.0"
	}
	if o.Since == 0 {
		o.Since = 72 * time.Hour
	}
	if o.Since < time.Hour || o.Since > 168*time.Hour {
		return "", errors.New("diagnostic time range must be 1 to 168 hours")
	}
	if o.RequestID != "" && !uuidPattern.MatchString(o.RequestID) {
		return "", errors.New("invalid diagnostic request ID")
	}
	if o.OutputPath == "" {
		o.OutputPath = filepath.Join(o.DataRoot, "diagnostics", "diagnostics-"+time.Now().UTC().Format("20060102T150405.000000000")+".zip")
	}
	if e := os.MkdirAll(filepath.Dir(o.OutputPath), 0700); e != nil {
		return "", e
	}
	f, e := os.OpenFile(o.OutputPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return "", e
	}
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(o.OutputPath)
		}
	}()
	z := zip.NewWriter(f)
	checksums := map[string]string{}
	writeBytes := func(name string, b []byte) error {
		w, e := z.Create(name)
		if e != nil {
			return e
		}
		if _, e = w.Write(b); e != nil {
			return e
		}
		checksums[name] = fmt.Sprintf("%x", sha256.Sum256(b))
		return nil
	}
	write := func(name string, v any) error {
		b, e := json.MarshalIndent(v, "", "  ")
		if e != nil {
			return e
		}
		return writeBytes(name, append(b, '\n'))
	}
	if e = write("system.json", map[string]any{"os": runtime.GOOS, "architecture": runtime.GOARCH, "goVersion": runtime.Version(), "collectedAtUtc": time.Now().UTC()}); e != nil {
		return "", e
	}
	if o.HealthURL == "" {
		o.HealthURL = "http://127.0.0.1:18080/healthz"
	}
	health := collectHealth(ctx, o.HealthURL)
	errorsFound := []string{}
	sections := []map[string]any{}
	sections = append(sections, map[string]any{"Name": "system", "Status": "Collected", "Evidence": "system.json"}, map[string]any{"Name": "health", "Status": "Collected", "Evidence": "health.json"})
	if h, ok := health.(result); ok && h.Error != "" {
		errorsFound = append(errorsFound, "health:"+h.Error)
	}
	if e = write("health.json", health); e != nil {
		return "", e
	}
	for _, cmd := range commandsForOS(runtime.GOOS, o.Since) {
		if e := ctx.Err(); e != nil {
			return "", e
		}
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		var output boundedCommandOutput
		process := exec.CommandContext(cctx, cmd.exe, cmd.args...)
		process.Stdout = &output
		ce := process.Run()
		cancel()
		data := output.data
		r := result{Collected: ce == nil}
		if ce != nil {
			r.Error = "collector_failed"
			errorsFound = append(errorsFound, cmd.name+":collector_failed")
		} else {
			r.Output = sanitizeCommand(cmd.name, runtime.GOOS, string(data))
			if output.truncated {
				r.Error = "collector_truncated"
				errorsFound = append(errorsFound, cmd.name+":collector_truncated")
			}
			if cmd.name == "service" && runtime.GOOS == "darwin" {
				var safe []string
				for _, line := range strings.Split(r.Output, "\n") {
					line = strings.TrimSpace(line)
					if strings.HasSuffix(line, "\tcom.sf.endpointai.proxy") || strings.HasSuffix(line, " com.sf.endpointai.proxy") {
						safe = append(safe, line)
					}
				}
				r.Output = strings.Join(safe, "\n")
			}
		}
		if e = write(cmd.name+".json", r); e != nil {
			return "", e
		}
		status := "Collected"
		if !r.Collected {
			status = "Partial"
		}
		sections = append(sections, map[string]any{"Name": cmd.name, "Status": status, "Evidence": cmd.name + ".json"})
	}
	evidence, collectionErrors, truncated := collectEvidence(ctx, o, started.Add(-o.Since))
	errorsFound = append(errorsFound, collectionErrors...)
	staged := 0
	for name, data := range evidence {
		if staged+len(data) > 90<<20 {
			truncated = true
			continue
		}
		staged += len(data)
		if e = writeBytes(name, data); e != nil {
			return "", e
		}
		sections = append(sections, map[string]any{"Name": name, "Status": "Collected", "Evidence": name})
	}
	partial := len(errorsFound) > 0 || truncated
	checks := []map[string]any{{"Code": "DIAGNOSTICS_PARTIAL_COLLECTION", "Status": "Pass", "Summary": "Diagnostic sections collected.", "Evidence": "manifest.json"}}
	if partial {
		checks[0]["Status"] = "Warning"
		checks[0]["Summary"] = "Some sections are unavailable or truncated."
	}
	if e = write("assessment.json", checks); e != nil {
		return "", e
	}
	sort.Slice(sections, func(i, j int) bool { return sections[i]["Name"].(string) < sections[j]["Name"].(string) })
	if e = writeBytes("summary.md", []byte(fmt.Sprintf("# EndpointAIProxy diagnostic summary\n\nCollected UTC: %s\n\nPartial: %t; truncated: %t.\n\nRaw bodies, databases, credentials and configuration contents are omitted. See manifest.json for collection errors and sections.\n", started.Format(time.RFC3339), partial, truncated))); e != nil {
		return "", e
	}
	if e = write("manifest.json", map[string]any{"DiagnosticsSchemaVersion": 2, "StartedAtUtc": started, "CompletedAtUtc": time.Now().UTC(), "SinceUtc": started.Add(-o.Since), "RequestId": o.RequestID, "ClientVersion": o.ClientVersion, "Partial": partial, "Truncated": truncated, "Errors": errorsFound, "Sections": sections, "Security": map[string]bool{"RawRequestBodiesIncluded": false, "RawResponseBodiesIncluded": false, "RawConfigFilesIncluded": false, "RawDatabasesIncluded": false, "CredentialsRedacted": true}}); e != nil {
		return "", e
	}
	var sums strings.Builder
	for _, name := range sortedKeys(checksums) {
		fmt.Fprintf(&sums, "%s  %s\n", checksums[name], name)
	}
	if e = writeBytes("checksums.sha256", []byte(sums.String())); e != nil {
		return "", e
	}
	if e = z.Close(); e != nil {
		return "", e
	}
	if e = f.Sync(); e != nil {
		return "", e
	}
	if e = f.Close(); e != nil {
		return "", e
	}
	checksumFile, e := os.Open(o.OutputPath)
	if e != nil {
		return "", e
	}
	h := sha256.New()
	_, e = io.Copy(h, checksumFile)
	checksumFile.Close()
	if e != nil {
		return "", e
	}
	sumPath := o.OutputPath + ".sha256"
	sf, e := os.OpenFile(sumPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return "", e
	}
	_, e = fmt.Fprintf(sf, "%x  %s\n", h.Sum(nil), filepath.Base(o.OutputPath))
	ce := sf.Close()
	if e != nil {
		return "", e
	}
	if ce != nil {
		return "", ce
	}
	return o.OutputPath, nil
}
func collectHealth(ctx context.Context, raw string) any {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "http" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost" && u.Hostname() != "::1") || u.User != nil {
		return result{Error: "invalid_local_health_url"}
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, e := http.NewRequestWithContext(cctx, http.MethodGet, raw, nil)
	if e != nil {
		return result{Error: "invalid_health_request"}
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect forbidden") }, Transport: &http.Transport{Proxy: nil}}
	defer client.CloseIdleConnections()
	resp, e := client.Do(req)
	if e != nil {
		return result{Error: "health_unavailable"}
	}
	defer resp.Body.Close()
	var source map[string]json.RawMessage
	if e = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&source); e != nil {
		return map[string]any{"statusCode": resp.StatusCode, "error": "invalid_health_response"}
	}
	healthFields := map[string]any{}
	for key, v := range source {
		var val any
		if json.Unmarshal(v, &val) == nil {
			healthFields[key] = val
		}
	}
	out := sanitizeRow(healthFields)
	out["statusCode"] = resp.StatusCode
	return out
}
func commands() []command {
	return commandsForOS(runtime.GOOS, 72*time.Hour)
}
func commandsForOS(goos string, since time.Duration) []command {
	switch goos {
	case "windows":
		query := fmt.Sprintf("*[System[Provider[@Name='Service Control Manager'] and TimeCreated[timediff(@SystemTime) <= %d]]] and *[EventData[Data='SfEndpointAIProxy' or Data='顺丰终端 AI 请求代理']]", since.Milliseconds())
		return []command{{"service", "sc.exe", []string{"queryex", "SfEndpointAIProxy"}}, {"service-config", "sc.exe", []string{"qc", "SfEndpointAIProxy"}}, {"service-recovery", "sc.exe", []string{"qfailure", "SfEndpointAIProxy"}}, {"service-events", "wevtutil.exe", []string{"qe", "System", "/q:" + query, "/c:100", "/rd:true", "/f:xml", "/e:Events"}}, {"platform", "cmd.exe", []string{"/c", "ver"}}}
	case "darwin":
		return []command{{"service", "/bin/launchctl", []string{"list"}}, {"platform", "/usr/bin/sw_vers", nil}}
	default:
		return []command{{"platform", "uname", []string{"-srm"}}}
	}
}
