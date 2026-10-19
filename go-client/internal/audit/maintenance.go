package audit

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	compressionDelay            = 2 * time.Second
	compressionBusyDelay        = time.Minute
	compressionBatchFiles       = 4
	compressionBatchBytes int64 = 8 << 20
	compressionBatchTime        = 100 * time.Millisecond
)

// Compression is recoverable housekeeping, never part of capture completion.
// Pending work is bounded; the periodic disk scan recovers dropped hints and
// work left by a restart. Under sustained traffic one old file can still make
// progress per tick, while short bursts avoid competing disk syncs entirely.
func (s *Store) runMaintenance(ctx context.Context) {
	s.Maintain(time.Now().UTC())
	tick := time.NewTicker(time.Second)
	sweep := time.NewTicker(time.Minute)
	defer tick.Stop()
	defer sweep.Stop()
	pending := make(map[string]bool, cap(s.queue))
	for {
		select {
		case <-ctx.Done():
			return
		case path := <-s.queue:
			if len(pending) < cap(s.queue) {
				pending[path] = true
			}
		case now := <-tick.C:
			s.compressBatch(ctx, now, pending)
		case now := <-sweep.C:
			s.Maintain(now)
		}
	}
}

func (s *Store) compressBatch(ctx context.Context, now time.Time, pending map[string]bool) {
	type candidate struct {
		path string
		info os.FileInfo
	}
	files := make([]candidate, 0, len(pending))
	for path := range pending {
		info, e := os.Lstat(path)
		if e != nil || !info.Mode().IsRegular() {
			delete(pending, path)
			if e != nil && !os.IsNotExist(e) {
				s.compressionFailure(path, e)
			}
			continue
		}
		files = append(files, candidate{path, info})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].info.ModTime().Before(files[j].info.ModTime()) })
	began, count, bytes := time.Now(), 0, int64(0)
	for _, file := range files {
		if ctx.Err() != nil || count >= compressionBatchFiles || bytes >= compressionBatchBytes || time.Since(began) >= compressionBatchTime {
			return
		}
		age := now.Sub(file.info.ModTime())
		busy := s.capturesInFlight.Load() > 0
		if age < compressionDelay || (busy && age < compressionBusyDelay) {
			continue
		}
		delete(pending, file.path)
		if e := s.compress(file.path); e != nil {
			s.compressionFailure(file.path, e)
		}
		count++
		bytes += file.info.Size()
		if busy {
			return
		}
	}
}

func (s *Store) compressionFailure(path string, e error) {
	if strings.Contains(path, string(filepath.Separator)+"captures"+string(filepath.Separator)) {
		s.captureFailure("capture_compress", e)
	} else {
		s.writeFailures.Add(1)
	}
}
