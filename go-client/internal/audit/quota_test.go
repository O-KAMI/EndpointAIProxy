package audit

import (
	"bytes"
	"endpointai/client/internal/proxy"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func captureBytes(t *testing.T, root string) int64 {
	t.Helper()
	var total int64
	err := filepath.WalkDir(filepath.Join(root, "captures"), func(path string, d os.DirEntry, err error) error {
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			info, err := d.Info()
			if err != nil {
				return err
			}
			total += info.Size()
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return total
}
func TestConcurrentCaptureCapacityIncludesBufferedDataAndSummaries(t *testing.T) {
	store := New(t.TempDir())
	store.captureLimit = 64 << 10
	t.Cleanup(store.CloseLogs)
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := fixtureRecord()
			rec.RequestID = proxy.UUID()
			c := store.Start(rec)
			if c == nil {
				return
			}
			c.Request(bytes.Repeat([]byte("x"), 8<<10))
			c.Complete("SUCCESS", 200, "", time.Millisecond)
		}()
	}
	wg.Wait()
	used := captureBytes(t, store.Root)
	if used > store.captureLimit {
		t.Fatalf("capture files exceed budget: %d > %d", used, store.captureLimit)
	}
	if !store.Degraded() || !store.quotaPressure.Load() {
		t.Fatal("capacity exhaustion must signal degraded capture")
	}
	store.quotaMu.Lock()
	reserved := store.quotaUsed
	store.quotaMu.Unlock()
	if reserved < used || reserved > store.captureLimit {
		t.Fatalf("invalid accounting: files=%d reserved=%d", used, reserved)
	}
}
func TestExistingFilesAndRetentionReleaseCapacity(t *testing.T) {
	store := New(t.TempDir())
	store.captureLimit = 100 << 10
	dir := filepath.Join(store.Root, "captures", "fixture")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(dir, "old.md")
	if err := os.WriteFile(old, bytes.Repeat([]byte("x"), 98<<10), 0600); err != nil {
		t.Fatal(err)
	}
	at := time.Now().Add(-time.Hour)
	if err := os.Chtimes(old, at, at); err != nil {
		t.Fatal(err)
	}
	if err := store.reserveCapture(4 << 10); !errors.Is(err, errCaptureCapacity) {
		t.Fatalf("expected capacity refusal: %v", err)
	}
	store.Maintain(time.Now().UTC())
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatalf("old capture was not reclaimed: %v", err)
	}
	if err := store.reserveCapture(4 << 10); err != nil {
		t.Fatalf("released capacity was not reusable: %v", err)
	}
	store.releaseCapture(4 << 10)
}
func TestCompressionCountsTemporaryOutputAndPreservesSourceWhenFull(t *testing.T) {
	store := New(t.TempDir())
	store.captureLimit = 100 << 10
	dir := filepath.Join(store.Root, "captures", "fixture")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(dir, "capture.md")
	data := make([]byte, 98<<10)
	for i := range data {
		data[i] = byte((i*71 + i/251) % 256)
	}
	if err := os.WriteFile(source, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := store.reserveCapture(2 << 10); err != nil {
		t.Fatal(err)
	}
	if err := store.compress(source); !errors.Is(err, errCaptureCapacity) {
		t.Fatalf("expected compression capacity error: %v", err)
	}
	store.releaseCapture(2 << 10)
	got, err := os.ReadFile(source)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("source evidence was not preserved", err)
	}
	if _, err = os.Stat(source + ".gz.tmp"); !os.IsNotExist(err) {
		t.Fatal("temporary compression file retained", err)
	}
	if captureBytes(t, store.Root) > store.captureLimit {
		t.Fatal("compression exceeded capture budget")
	}
}

func TestCaptureRejectsLinkedDirectory(t *testing.T) {
	store := New(t.TempDir())
	outside := t.TempDir()
	root := filepath.Join(store.Root, "captures")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "fixture-user")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if c := store.Start(fixtureRecord()); c != nil || !store.Degraded() {
		t.Fatal("linked capture directory accepted")
	}
	entries, err := os.ReadDir(outside)
	if err != nil || len(entries) != 0 {
		t.Fatalf("outside directory was modified: %v", err)
	}
}
