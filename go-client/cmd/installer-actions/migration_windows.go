//go:build windows

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"endpointai/client/internal/protect"
	"endpointai/client/internal/state"
)

type migrationBaseline struct {
	Present     bool              `json:"present"`
	DeviceID    string            `json:"deviceId,omitempty"`
	Fingerprint map[string]string `json:"fingerprint,omitempty"`
	RouteIDs    []string          `json:"routeIds,omitempty"`
}

// All paths are under the administrator-protected installation transaction.
// The database, keys and recovery journal are copied only after service stop.
func copyMigrationTree(source, target string) error {
	if err := rejectReparse(source); err != nil {
		return err
	}
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if info.IsDir() {
		if err = secureDirectory(target); err != nil {
			return err
		}
		items, e := os.ReadDir(source)
		if e != nil {
			return e
		}
		for _, item := range items {
			if e = copyMigrationTree(filepath.Join(source, item.Name()), filepath.Join(target, item.Name())); e != nil {
				return e
			}
		}
		return nil
	}
	if !info.Mode().IsRegular() {
		return errors.New("migration source not regular")
	}
	if err = rejectReparse(target); err != nil {
		return err
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if err == nil {
		err = out.Sync()
	}
	closed := out.Close()
	if err != nil {
		return err
	}
	return closed
}
func (a *action) migrationBaseline() string {
	return filepath.Join(a.transactionRoot, "migration-baseline.json")
}
func (a *action) snapshotState() error {
	listener, err := net.Listen("tcp4", "127.0.0.1:18080")
	if err != nil {
		return errors.New("migration listener not released")
	}
	defer listener.Close()
	b := migrationBaseline{}
	dbPath := filepath.Join(a.dataRoot, "state", "client.db")
	if _, err = os.Stat(dbPath); err == nil {
		p, e := protect.NewDPAPI()
		if e != nil {
			return e
		}
		store, e := state.OpenReadOnly(dbPath, p)
		if e != nil {
			return e
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		b.Fingerprint, e = store.StateFingerprint(ctx)
		if e == nil {
			b.DeviceID, e = store.ReadDeviceID(ctx)
		}
		if e == nil {
			routes, re := store.ListRoutes(ctx)
			e = re
			for _, route := range routes {
				b.RouteIDs = append(b.RouteIDs, route.RouteID)
			}
		}
		cancel()
		store.Close()
		if e != nil {
			return e
		}
		b.Present = true
	} else if !os.IsNotExist(err) {
		return err
	}
	for _, name := range []string{"state", "config-backups"} {
		source := filepath.Join(a.dataRoot, name)
		if _, err = os.Lstat(source); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return err
		}
		if err = copyMigrationTree(source, filepath.Join(a.transactionRoot, name)); err != nil {
			return err
		}
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(a.migrationBaseline(), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = file.Write(raw)
	if err == nil {
		err = file.Sync()
	}
	closed := file.Close()
	if err != nil {
		return err
	}
	return closed
}
func (a *action) readMigrationBaseline() (*migrationBaseline, error) {
	if err := rejectReparse(a.migrationBaseline()); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(a.migrationBaseline())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var b migrationBaseline
	if err = json.Unmarshal(raw, &b); err != nil {
		return nil, err
	}
	return &b, nil
}
func (a *action) verifyPreservedState(running bool) error {
	b, err := a.readMigrationBaseline()
	if err != nil || b == nil || !b.Present {
		return err
	}
	p, err := protect.NewDPAPI()
	if err != nil {
		return err
	}
	store, err := state.OpenReadOnly(filepath.Join(a.dataRoot, "state", "client.db"), p)
	if err != nil {
		return err
	}
	defer store.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	got, err := store.StateFingerprint(ctx)
	if err != nil {
		return err
	}
	if !running {
		if !reflect.DeepEqual(got, b.Fingerprint) {
			return errors.New("migration state changed before service start")
		}
		return nil
	}
	if got["identity"] != b.Fingerprint["identity"] {
		return errors.New("migration identity changed")
	}
	routes, err := store.ListRoutes(ctx)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, route := range routes {
		seen[route.RouteID] = true
	}
	for _, id := range b.RouteIDs {
		if !seen[id] {
			return errors.New("migration route missing")
		}
	}
	return nil
}
func (a *action) restoreState() error {
	b, err := a.readMigrationBaseline()
	if err != nil || b == nil {
		return err
	}
	if !b.Present {
		return nil
	} // First-install failure retains its diagnostic evidence.
	for _, name := range []string{"state", "config-backups"} {
		saved := filepath.Join(a.transactionRoot, name)
		if _, err = os.Stat(saved); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return err
		}
		target := filepath.Join(a.dataRoot, name)
		if err = rejectReparse(target); err != nil {
			return err
		}
		// Preserve failed candidate state for administrator recovery, never erase it.
		if _, err = os.Stat(target); err == nil {
			failed := filepath.Join(a.transactionRoot, "failed-"+name+"-"+time.Now().UTC().Format("20060102T150405.000000000"))
			if _, e := os.Stat(failed); !os.IsNotExist(e) {
				return errors.New("failed migration state already retained")
			}
			if err = os.Rename(target, failed); err != nil {
				return err
			}
		} else if !os.IsNotExist(err) {
			return err
		}
		if err = copyMigrationTree(saved, target); err != nil {
			return err
		}
	}
	return a.verifyPreservedState(false)
}

func executableDigest(path string) (string, error) {
	if err := rejectReparse(path); err != nil {
		return "", err
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func (a *action) verifyRestoredService(previous snapshot) error {
	if previous.OldExecutable == nil {
		return errors.New("restored service path missing")
	}
	digest, err := executableDigest(*previous.OldExecutable)
	if err != nil {
		return err
	}
	if previous.OldExecutableSHA256 != "" && previous.OldExecutableSHA256 != digest {
		return errors.New("restored executable hash mismatch")
	}
	b, err := a.readMigrationBaseline()
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("health redirect forbidden") }}
	defer client.CloseIdleConnections()
	return withService(func(service *mgr.Service) error {
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			status, e := service.Query()
			if e == nil && status.State == svc.Running && status.ProcessId != 0 {
				image, e := processImage(status.ProcessId)
				if e == nil && strings.EqualFold(image, *previous.OldExecutable) && verifyListenerPID(status.ProcessId, 18080) == nil {
					response, e := client.Get("http://127.0.0.1:18080/healthz")
					if e == nil {
						var health struct {
							Status   string `json:"status"`
							DeviceID string `json:"deviceId"`
						}
						decode := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&health)
						response.Body.Close()
						if decode == nil && response.StatusCode == 200 && health.Status == "ok" && (b == nil || !b.Present || health.DeviceID == b.DeviceID) {
							return nil
						}
					}
				}
			}
			time.Sleep(250 * time.Millisecond)
		}
		return errors.New("restored service health or identity mismatch")
	})
}
