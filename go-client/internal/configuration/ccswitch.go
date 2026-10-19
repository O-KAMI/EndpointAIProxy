package configuration

import (
	"context"
	"database/sql"
	"fmt"
	"modernc.org/sqlite"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type CCProvider struct {
	ID, App, Name, Settings string
	Current                 bool
}
type CCEndpoint struct {
	ID                   int64
	ProviderID, App, URL string
}
type CCProxy struct {
	Enabled, ProxyEnabled, LiveTakeover, LiveBackup bool
	Address                                         string
	Port                                            int
}
type CCInspection struct {
	Providers []CCProvider
	Endpoints []CCEndpoint
	Proxies   map[string]CCProxy
}
type CCMutation struct {
	App, ProviderID, Expected, Updated string
	EndpointID                         *int64
}

func ccOpen(path string) (*sql.DB, error) {
	info, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() {
		return nil, problem("CCSWITCH_DATABASE_NOT_REGULAR")
	}
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	db, e := sql.Open("sqlite", u.String()+"?mode=rw&_pragma=busy_timeout(5000)")
	if e == nil {
		db.SetMaxOpenConns(1)
	}
	return db, e
}
func ccColumns(ctx context.Context, db *sql.DB, table string, required ...string) (bool, error) {
	rows, e := db.QueryContext(ctx, "PRAGMA table_info("+table+")")
	if e != nil {
		return false, e
	}
	defer rows.Close()
	cols := map[string]bool{}
	for rows.Next() {
		var cid, notnull, pk int
		var name, kind string
		var def any
		if e = rows.Scan(&cid, &name, &kind, &notnull, &def, &pk); e != nil {
			return false, e
		}
		cols[name] = true
	}
	if e = rows.Err(); e != nil {
		return false, e
	}
	if len(cols) == 0 {
		return false, nil
	}
	for _, name := range required {
		if !cols[name] {
			return true, problem("CCSWITCH_SCHEMA_UNSUPPORTED")
		}
	}
	return true, nil
}
func InspectCC(ctx context.Context, path string) (CCInspection, error) {
	out := CCInspection{Proxies: map[string]CCProxy{}}
	db, e := ccOpen(path)
	if e != nil {
		return out, e
	}
	defer db.Close()
	exists, e := ccColumns(ctx, db, "providers", "id", "app_type", "name", "settings_config", "is_current")
	if e != nil {
		return out, e
	}
	if !exists {
		return out, problem("CCSWITCH_SCHEMA_UNSUPPORTED")
	}
	rows, e := db.QueryContext(ctx, "SELECT id,app_type,name,settings_config,is_current FROM providers WHERE app_type IN ('claude','codex')")
	if e != nil {
		return out, e
	}
	for rows.Next() {
		var p CCProvider
		var current int
		if e = rows.Scan(&p.ID, &p.App, &p.Name, &p.Settings, &current); e != nil {
			rows.Close()
			return out, e
		}
		p.Current = current != 0
		out.Providers = append(out.Providers, p)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return out, e
	}
	exists, e = ccColumns(ctx, db, "provider_endpoints", "id", "provider_id", "app_type", "url")
	if e != nil {
		return out, e
	}
	if exists {
		rows, e = db.QueryContext(ctx, "SELECT id,provider_id,app_type,url FROM provider_endpoints WHERE app_type IN ('claude','codex')")
		if e != nil {
			return out, e
		}
		for rows.Next() {
			var p CCEndpoint
			if e = rows.Scan(&p.ID, &p.ProviderID, &p.App, &p.URL); e != nil {
				rows.Close()
				return out, e
			}
			out.Endpoints = append(out.Endpoints, p)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return out, e
		}
	}
	exists, e = ccColumns(ctx, db, "proxy_config", "app_type", "proxy_enabled", "enabled", "listen_address", "listen_port", "live_takeover_active")
	if e != nil {
		return out, e
	}
	if exists {
		rows, e = db.QueryContext(ctx, "SELECT app_type,proxy_enabled,enabled,listen_address,listen_port,live_takeover_active FROM proxy_config WHERE app_type IN ('claude','codex')")
		if e != nil {
			return out, e
		}
		for rows.Next() {
			var app string
			var p CCProxy
			var proxy, enabled, live int
			if e = rows.Scan(&app, &proxy, &enabled, &p.Address, &p.Port, &live); e != nil {
				rows.Close()
				return out, e
			}
			p.Enabled = enabled != 0
			p.ProxyEnabled = proxy != 0
			p.LiveTakeover = live != 0
			out.Proxies[app] = p
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return out, e
		}
	}
	columns, e := db.QueryContext(ctx, "PRAGMA table_info(proxy_live_backup)")
	if e != nil {
		return out, e
	}
	hasApp := false
	for columns.Next() {
		var cid, nn, pk int
		var name, kind string
		var def any
		if e = columns.Scan(&cid, &name, &kind, &nn, &def, &pk); e != nil {
			columns.Close()
			return out, e
		}
		if name == "app_type" {
			hasApp = true
		}
	}
	e = columns.Err()
	columns.Close()
	if e != nil {
		return out, e
	}
	if hasApp {
		backupRows, e := db.QueryContext(ctx, "SELECT app_type FROM proxy_live_backup WHERE app_type IN ('claude','codex')")
		if e != nil {
			return out, e
		}
		for backupRows.Next() {
			var app string
			if e = backupRows.Scan(&app); e != nil {
				backupRows.Close()
				return out, e
			}
			p, ok := out.Proxies[app]
			if ok {
				p.LiveBackup = true
				out.Proxies[app] = p
			}
		}
		e = backupRows.Err()
		backupRows.Close()
		if e != nil {
			return out, e
		}
	}
	return out, nil
}

// DetectCCMode uses app-level enabled + the actual live config, matching 0.1.22.
func DetectCCMode(app string, p CCProxy, present bool, live string) (mode, listener string) {
	if !present {
		return "ordinary", ""
	}
	if p.Port < 1 || p.Port > 65535 || p.Address == "" {
		return "unsupported", ""
	}
	host := p.Address
	if host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	if host == "::" {
		host = "::1"
	}
	listener = "http://" + net.JoinHostPort(host, strconv.Itoa(p.Port))
	u, e := url.Parse(live)
	l, _ := url.Parse(listener)
	matches := e == nil && u.Scheme == "http" && strings.EqualFold(u.Hostname(), l.Hostname()) && u.Port() == l.Port() && u.RawQuery == "" && u.Fragment == ""
	if matches {
		path := strings.TrimRight(u.Path, "/")
		matches = path == "" || app == "codex" && path == "/v1"
	}
	if p.Enabled && matches {
		return "local-proxy", listener
	}
	if !p.Enabled && !matches {
		return "ordinary", listener
	}
	return "inconsistent", listener
}
func BackupCC(ctx context.Context, db *sql.DB, path string) error {
	conn, e := db.Conn(ctx)
	if e != nil {
		return e
	}
	defer conn.Close()
	e = conn.Raw(func(driver any) error {
		c, ok := driver.(interface {
			NewBackup(string) (*sqlite.Backup, error)
		})
		if !ok {
			return problem("CCSWITCH_BACKUP_UNSUPPORTED")
		}
		b, e := c.NewBackup(path)
		if e != nil {
			return e
		}
		for {
			if e = ctx.Err(); e != nil {
				_ = b.Finish()
				return e
			}
			more, stepErr := b.Step(256)
			if stepErr != nil {
				_ = b.Finish()
				return stepErr
			}
			if !more {
				return b.Finish()
			}
		}
	})
	if e != nil {
		_ = os.Remove(path)
		return e
	}
	return os.Chmod(path, 0600)
}

// ApplyCC backs up through sqlite3_backup and applies every inspected value in
// one transaction. A single stale row rolls back the entire batch.
func ApplyCC(ctx context.Context, path, backupRoot string, mutations []CCMutation) (string, error) {
	if len(mutations) == 0 {
		return "", nil
	}
	db, e := ccOpen(path)
	if e != nil {
		return "", e
	}
	defer db.Close()
	if e = os.MkdirAll(backupRoot, 0700); e != nil {
		return "", e
	}
	backup := filepath.Join(backupRoot, "cc-switch."+time.Now().UTC().Format("20060102T150405")+"."+randomID()+".db")
	if e = BackupCC(ctx, db, backup); e != nil {
		return "", e
	}
	tx, e := db.BeginTx(ctx, nil)
	if e != nil {
		return backup, e
	}
	defer tx.Rollback()
	for _, m := range mutations {
		var result sql.Result
		if m.EndpointID == nil {
			result, e = tx.ExecContext(ctx, "UPDATE providers SET settings_config=? WHERE id=? AND app_type=? AND settings_config=?", m.Updated, m.ProviderID, m.App, m.Expected)
		} else {
			result, e = tx.ExecContext(ctx, "UPDATE provider_endpoints SET url=? WHERE id=? AND provider_id=? AND app_type=? AND url=?", m.Updated, *m.EndpointID, m.ProviderID, m.App, m.Expected)
		}
		if e != nil {
			return backup, e
		}
		n, e := result.RowsAffected()
		if e != nil {
			return backup, e
		}
		if n != 1 {
			return backup, problem("CCSWITCH_DB_CHANGED_CONCURRENTLY")
		}
	}
	return backup, tx.Commit()
}
func reverseCC(ms []CCMutation) []CCMutation {
	out := make([]CCMutation, len(ms))
	for i, m := range ms {
		m.Expected, m.Updated = m.Updated, m.Expected
		out[i] = m
	}
	return out
}
func ccIdentity(p CCProvider) string { return p.App + ":" + p.ID }
func endpointIdentity(p CCEndpoint) string {
	return fmt.Sprintf("%s:%s:endpoint:%d", p.App, p.ProviderID, p.ID)
}
