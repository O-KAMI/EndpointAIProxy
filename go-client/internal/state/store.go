package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"endpointai/client/internal/contracts"
	"errors"
	"github.com/google/uuid"
	"modernc.org/sqlite"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

type Protector interface {
	Protect(string) ([]byte, error)
	Unprotect([]byte) (string, error)
}
type Store struct {
	db      *sql.DB
	p       Protector
	routeMu sync.Mutex
	routes  atomic.Pointer[routeSnapshot]
	closed  atomic.Bool
}
type CachedPolicy struct {
	Policy        contracts.Policy
	Signature     string
	ReceivedAtUTC time.Time
}
type Credential struct {
	Token                                     string
	EnrolledAtUTC                             time.Time
	ServerOrigin, ServerCertificateSPKISHA256 *string
}
type OperationState struct {
	State                           contracts.ClientOperationState
	UpdatedAtUTC                    time.Time
	LastErrorCode, LastErrorSummary *string
}
type CommandReceipt struct {
	CommandID                           string
	Type                                contracts.RemoteCommandType
	Status                              contracts.RemoteCommandStatus
	ReceivedAtUTC                       time.Time
	CompletedAtUTC                      *time.Time
	ResultCode, ResultSummary, DeviceID *string
	IssuedAtUTC, ExpiresAtUTC           *time.Time
}

// OpenReadOnly never initializes schema, creates files, or changes permissions.
func OpenReadOnly(path string, p Protector) (*Store, error) {
	if p == nil {
		return nil, errors.New("state protector required")
	}
	absolute, e := filepath.Abs(path)
	if e != nil {
		return nil, e
	}
	for _, candidate := range []string{filepath.Dir(absolute), absolute, absolute + "-wal", absolute + "-shm"} {
		info, e := os.Lstat(candidate)
		if e != nil {
			if os.IsNotExist(e) && candidate != absolute {
				continue
			}
			return nil, e
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("state path must not be a symbolic link")
		}
	}
	uri := url.URL{Scheme: "file", Path: filepath.ToSlash(absolute)}
	q := uri.Query()
	q.Set("mode", "ro")
	q.Set("_pragma", "busy_timeout(5000)")
	uri.RawQuery = q.Encode()
	db, e := sql.Open("sqlite", uri.String())
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	if e = db.Ping(); e != nil {
		db.Close()
		return nil, e
	}
	return &Store{db: db, p: p}, nil
}

const schema = `
CREATE TABLE IF NOT EXISTS routes(route_id TEXT PRIMARY KEY,user_sid TEXT NOT NULL,agent_type INTEGER NOT NULL,provider_id TEXT NOT NULL,protected_original_base_uri BLOB NOT NULL,injected_base_uri TEXT NOT NULL,status INTEGER NOT NULL,created_at_utc TEXT NOT NULL,updated_at_utc TEXT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS ux_routes_identity ON routes(user_sid,agent_type,provider_id);
CREATE TABLE IF NOT EXISTS client_identity(singleton_id INTEGER PRIMARY KEY CHECK(singleton_id=1),device_id TEXT NOT NULL,created_at_utc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS cached_policy(singleton_id INTEGER PRIMARY KEY CHECK(singleton_id=1),policy_json TEXT NOT NULL,signature TEXT NOT NULL,policy_version INTEGER NOT NULL,server_instance_id TEXT NOT NULL,received_at_utc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS device_credential(singleton_id INTEGER PRIMARY KEY CHECK(singleton_id=1),protected_token BLOB NOT NULL,enrolled_at_utc TEXT NOT NULL,server_origin TEXT NULL,server_certificate_spki_sha256 TEXT NULL);
CREATE TABLE IF NOT EXISTS client_operation_state(singleton_id INTEGER PRIMARY KEY CHECK(singleton_id=1),operation_state INTEGER NOT NULL,updated_at_utc TEXT NOT NULL,last_error_code TEXT NULL,last_error_summary TEXT NULL);
CREATE TABLE IF NOT EXISTS remote_command_receipts(command_id TEXT PRIMARY KEY,command_type INTEGER NOT NULL,status INTEGER NOT NULL,received_at_utc TEXT NOT NULL,completed_at_utc TEXT NULL,result_code TEXT NULL,result_summary TEXT NULL,device_id TEXT NULL,issued_at_utc TEXT NULL,expires_at_utc TEXT NULL);`

func Open(path string, p Protector) (*Store, error) {
	if p == nil {
		return nil, errors.New("state protector required")
	}
	if path == "" {
		return nil, errors.New("empty state path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	for _, candidate := range []string{filepath.Dir(path), path, path + "-wal", path + "-shm"} {
		info, err := os.Lstat(candidate)
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("state path must not be a symbolic link")
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return nil, err
	}
	if err = f.Close(); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, p: p}
	if _, err = db.Exec(`PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;` + schema); err != nil {
		db.Close()
		return nil, err
	}
	for _, item := range [][2]string{{"device_credential", "server_origin"}, {"device_credential", "server_certificate_spki_sha256"}, {"remote_command_receipts", "device_id"}, {"remote_command_receipts", "issued_at_utc"}, {"remote_command_receipts", "expires_at_utc"}} {
		if err = s.ensureColumn(item[0], item[1]); err != nil {
			db.Close()
			return nil, err
		}
	}
	if err = s.initializeRoutes(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}
func (s *Store) ensureColumn(table, col string) error {
	rows, err := s.db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return err
	}
	found := false
	for rows.Next() {
		var cid, nn, pk int
		var n, t string
		var def any
		if err = rows.Scan(&cid, &n, &t, &nn, &def, &pk); err != nil {
			rows.Close()
			return err
		}
		if n == col {
			found = true
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if found {
		return nil
	}
	_, err = s.db.Exec("ALTER TABLE " + table + " ADD COLUMN " + col + " TEXT NULL")
	return err
}
func (s *Store) Close() error {
	s.routeMu.Lock()
	defer s.routeMu.Unlock()
	s.closed.Store(true)
	s.routes.Store(nil)
	return s.db.Close()
}

// Backup includes uncheckpointed WAL pages using SQLite's online backup API.
func (s *Store) Backup(ctx context.Context, destination string) error {
	f, e := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		os.Remove(destination)
		return e
	}
	conn, e := s.db.Conn(ctx)
	if e != nil {
		os.Remove(destination)
		return e
	}
	defer conn.Close()
	e = conn.Raw(func(raw any) error {
		source, ok := raw.(interface {
			NewBackup(string) (*sqlite.Backup, error)
		})
		if !ok {
			return errors.New("SQLite driver does not support online backup")
		}
		b, e := source.NewBackup(destination)
		if e != nil {
			return e
		}
		for {
			if e = ctx.Err(); e != nil {
				b.Finish()
				return e
			}
			more, e := b.Step(128)
			if e != nil {
				b.Finish()
				return e
			}
			if !more {
				return b.Finish()
			}
		}
	})
	if e != nil {
		os.Remove(destination)
	}
	return e
}
func format(t time.Time) string         { return t.Format("2006-01-02T15:04:05.0000000-07:00") }
func parse(v string) (time.Time, error) { return time.Parse(time.RFC3339Nano, v) }
func optionalTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return format(*t)
}
func parseOptional(v sql.NullString) (*time.Time, error) {
	if !v.Valid {
		return nil, nil
	}
	t, e := parse(v.String)
	return &t, e
}
func str(v sql.NullString) *string {
	if !v.Valid {
		return nil
	}
	return &v.String
}

type scanner interface{ Scan(...any) error }

const routeColumns = "route_id,user_sid,agent_type,provider_id,protected_original_base_uri,injected_base_uri,status,created_at_utc,updated_at_utc"

func (s *Store) readRoute(row scanner) (*contracts.Route, error) {
	var r contracts.Route
	var b []byte
	var c, u string
	if err := row.Scan(&r.RouteID, &r.UserSID, &r.AgentType, &r.ProviderID, &b, &r.InjectedBaseURL, &r.Status, &c, &u); err != nil {
		return nil, err
	}
	if s.p == nil {
		return nil, errors.New("route protector required")
	}
	var err error
	if r.OriginalBaseURL, err = s.p.Unprotect(b); err != nil {
		return nil, err
	}
	if r.CreatedAtUTC, err = parse(c); err != nil {
		return nil, err
	}
	r.UpdatedAtUTC, err = parse(u)
	return &r, err
}
func (s *Store) FindRoute(ctx context.Context, id string) (*contracts.Route, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if s.closed.Load() {
		return nil, sql.ErrConnDone
	}
	if snapshot := s.routes.Load(); snapshot != nil {
		if r, found := snapshot.values[id]; found {
			return &r, nil
		}
		return nil, nil
	}
	r, e := s.readRoute(s.db.QueryRowContext(ctx, "SELECT "+routeColumns+" FROM routes WHERE route_id=?", id))
	if errors.Is(e, sql.ErrNoRows) {
		return nil, nil
	}
	return r, e
}
func (s *Store) FindRouteByIdentity(ctx context.Context, sid string, agent int, provider string) (*contracts.Route, error) {
	r, e := s.readRoute(s.db.QueryRowContext(ctx, "SELECT "+routeColumns+" FROM routes WHERE user_sid=? AND agent_type=? AND provider_id=?", sid, agent, provider))
	if errors.Is(e, sql.ErrNoRows) {
		return nil, nil
	}
	return r, e
}
func (s *Store) ListRoutes(ctx context.Context) ([]contracts.Route, error) {
	rows, e := s.db.QueryContext(ctx, "SELECT "+routeColumns+" FROM routes ORDER BY created_at_utc")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []contracts.Route{}
	for rows.Next() {
		r, e := s.readRoute(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}
func (s *Store) UpsertRoute(ctx context.Context, r contracts.Route) error {
	if s.p == nil {
		return errors.New("route protector required")
	}
	b, e := s.p.Protect(r.OriginalBaseURL)
	if e != nil {
		return e
	}
	s.routeMu.Lock()
	defer s.routeMu.Unlock()
	_, e = s.db.ExecContext(ctx, `INSERT INTO routes (`+routeColumns+`) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(route_id) DO UPDATE SET user_sid=excluded.user_sid,agent_type=excluded.agent_type,provider_id=excluded.provider_id,protected_original_base_uri=excluded.protected_original_base_uri,injected_base_uri=excluded.injected_base_uri,status=excluded.status,updated_at_utc=excluded.updated_at_utc`, r.RouteID, r.UserSID, r.AgentType, r.ProviderID, b, r.InjectedBaseURL, r.Status, format(r.CreatedAtUTC), format(r.UpdatedAtUTC))
	if e == nil {
		s.publishRoute(r)
	}
	return e
}
func (s *Store) DeleteRoute(ctx context.Context, id string) error {
	s.routeMu.Lock()
	defer s.routeMu.Unlock()
	_, e := s.db.ExecContext(ctx, "DELETE FROM routes WHERE route_id=?", id)
	if e == nil {
		s.publishDeletion(id)
	}
	return e
}
func (s *Store) GetOrCreateDeviceID(ctx context.Context) (string, error) {
	_, e := s.db.ExecContext(ctx, "INSERT OR IGNORE INTO client_identity(singleton_id,device_id,created_at_utc) VALUES(1,?,?)", uuid.NewString(), format(time.Now().UTC()))
	if e != nil {
		return "", e
	}
	var id string
	e = s.db.QueryRowContext(ctx, "SELECT device_id FROM client_identity WHERE singleton_id=1").Scan(&id)
	if e == nil {
		_, e = uuid.Parse(id)
	}
	return id, e
}
func (s *Store) LoadPolicy(ctx context.Context) (*CachedPolicy, error) {
	var b, received string
	v := &CachedPolicy{}
	e := s.db.QueryRowContext(ctx, "SELECT policy_json,signature,received_at_utc FROM cached_policy WHERE singleton_id=1").Scan(&b, &v.Signature, &received)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	if e = json.Unmarshal([]byte(b), &v.Policy); e != nil {
		return nil, e
	}
	v.ReceivedAtUTC, e = parse(received)
	return v, e
}
func (s *Store) SavePolicy(ctx context.Context, p contracts.Policy, signature string, received time.Time) error {
	b, e := json.Marshal(p)
	if e != nil {
		return e
	}
	_, e = s.db.ExecContext(ctx, `INSERT INTO cached_policy VALUES(1,?,?,?,?,?) ON CONFLICT(singleton_id) DO UPDATE SET policy_json=excluded.policy_json,signature=excluded.signature,policy_version=excluded.policy_version,server_instance_id=excluded.server_instance_id,received_at_utc=excluded.received_at_utc`, string(b), signature, p.PolicyVersion, p.ServerInstanceID, format(received))
	return e
}
func (s *Store) LoadCredential(ctx context.Context) (*Credential, error) {
	if s.p == nil {
		return nil, nil
	}
	var b []byte
	var enrolled string
	var origin, pin sql.NullString
	v := &Credential{}
	e := s.db.QueryRowContext(ctx, "SELECT protected_token,enrolled_at_utc,server_origin,server_certificate_spki_sha256 FROM device_credential WHERE singleton_id=1").Scan(&b, &enrolled, &origin, &pin)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	if v.Token, e = s.p.Unprotect(b); e != nil {
		return nil, e
	}
	v.EnrolledAtUTC, e = parse(enrolled)
	v.ServerOrigin = str(origin)
	v.ServerCertificateSPKISHA256 = str(pin)
	return v, e
}
func (s *Store) SaveCredential(ctx context.Context, v Credential) error {
	if s.p == nil {
		return errors.New("credential protector required")
	}
	b, e := s.p.Protect(v.Token)
	if e != nil {
		return e
	}
	defer clear(b)
	_, e = s.db.ExecContext(ctx, `INSERT INTO device_credential VALUES(1,?,?,?,?) ON CONFLICT(singleton_id) DO UPDATE SET protected_token=excluded.protected_token,enrolled_at_utc=excluded.enrolled_at_utc,server_origin=excluded.server_origin,server_certificate_spki_sha256=excluded.server_certificate_spki_sha256`, b, format(v.EnrolledAtUTC), v.ServerOrigin, v.ServerCertificateSPKISHA256)
	return e
}
func (s *Store) LoadOperationState(ctx context.Context) (OperationState, error) {
	v := OperationState{State: contracts.ClientOperationStateEnabled, UpdatedAtUTC: time.Now().UTC()}
	var updated string
	var code, summary sql.NullString
	e := s.db.QueryRowContext(ctx, "SELECT operation_state,updated_at_utc,last_error_code,last_error_summary FROM client_operation_state WHERE singleton_id=1").Scan(&v.State, &updated, &code, &summary)
	if errors.Is(e, sql.ErrNoRows) {
		return v, nil
	}
	if e != nil {
		return v, e
	}
	v.UpdatedAtUTC, e = parse(updated)
	v.LastErrorCode = str(code)
	v.LastErrorSummary = str(summary)
	return v, e
}
func (s *Store) SaveOperationState(ctx context.Context, v OperationState) error {
	_, e := s.db.ExecContext(ctx, `INSERT INTO client_operation_state VALUES(1,?,?,?,?) ON CONFLICT(singleton_id) DO UPDATE SET operation_state=excluded.operation_state,updated_at_utc=excluded.updated_at_utc,last_error_code=excluded.last_error_code,last_error_summary=excluded.last_error_summary`, int(v.State), format(v.UpdatedAtUTC), v.LastErrorCode, v.LastErrorSummary)
	return e
}

const receiptColumns = "command_id,command_type,status,received_at_utc,completed_at_utc,result_code,result_summary,device_id,issued_at_utc,expires_at_utc"

func readReceipt(row scanner) (*CommandReceipt, error) {
	v := &CommandReceipt{}
	var received string
	var completed, code, summary, device, issued, expires sql.NullString
	e := row.Scan(&v.CommandID, &v.Type, &v.Status, &received, &completed, &code, &summary, &device, &issued, &expires)
	if e != nil {
		return nil, e
	}
	v.ReceivedAtUTC, e = parse(received)
	if e != nil {
		return nil, e
	}
	v.CompletedAtUTC, e = parseOptional(completed)
	if e != nil {
		return nil, e
	}
	v.IssuedAtUTC, e = parseOptional(issued)
	if e != nil {
		return nil, e
	}
	v.ExpiresAtUTC, e = parseOptional(expires)
	v.ResultCode = str(code)
	v.ResultSummary = str(summary)
	v.DeviceID = str(device)
	return v, e
}
func (s *Store) LoadCommandReceipt(ctx context.Context, id string) (*CommandReceipt, error) {
	v, e := readReceipt(s.db.QueryRowContext(ctx, "SELECT "+receiptColumns+" FROM remote_command_receipts WHERE command_id=?", id))
	if errors.Is(e, sql.ErrNoRows) {
		return nil, nil
	}
	return v, e
}
func (s *Store) ListExecutingReceipts(ctx context.Context, deviceID string) ([]CommandReceipt, error) {
	rows, e := s.db.QueryContext(ctx, "SELECT "+receiptColumns+" FROM remote_command_receipts WHERE status=2 AND device_id=? ORDER BY received_at_utc", deviceID)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []CommandReceipt{}
	for rows.Next() {
		v, e := readReceipt(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, *v)
	}
	return out, rows.Err()
}
func (s *Store) SaveCommandReceipt(ctx context.Context, v CommandReceipt) error {
	_, e := s.db.ExecContext(ctx, `INSERT INTO remote_command_receipts (`+receiptColumns+`) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(command_id) DO UPDATE SET status=excluded.status,completed_at_utc=excluded.completed_at_utc,result_code=excluded.result_code,result_summary=excluded.result_summary,device_id=COALESCE(excluded.device_id,remote_command_receipts.device_id),issued_at_utc=COALESCE(excluded.issued_at_utc,remote_command_receipts.issued_at_utc),expires_at_utc=COALESCE(excluded.expires_at_utc,remote_command_receipts.expires_at_utc)`, v.CommandID, int(v.Type), int(v.Status), format(v.ReceivedAtUTC), optionalTime(v.CompletedAtUTC), v.ResultCode, v.ResultSummary, v.DeviceID, optionalTime(v.IssuedAtUTC), optionalTime(v.ExpiresAtUTC))
	return e
}
