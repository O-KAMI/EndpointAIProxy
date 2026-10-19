package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// Completing requests rename .partial files while retention enumerates them.
// Missing entries are normal concurrent transitions, not an audit failure.
func TestMaintenanceDuringCapturePublication(t *testing.T) {
	s := New(t.TempDir())
	t.Cleanup(s.CloseLogs)
	dir := filepath.Join(s.Root, "captures", "fixture")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 500; i++ {
			partial := filepath.Join(dir, fmt.Sprintf("capture-%04d.partial", i))
			if err := os.WriteFile(partial, []byte("synthetic completed evidence"), 0600); err != nil {
				done <- err
				return
			}
			runtime.Gosched()
			if err := os.Rename(partial, partial+".md"); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	for {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
			if s.Degraded() {
				t.Fatal("normal capture publication marked retention/audit degraded")
			}
			return
		default:
			s.Maintain(time.Now().UTC())
		}
	}
}
