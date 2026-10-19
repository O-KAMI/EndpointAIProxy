package audit

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maximumSummaryWriters = 2

type summaryWriter struct {
	file *os.File
	used uint64
}

// PerformanceSample is an opt-in test/profiling measurement. Configure the
// channel before starting workers. The production default is nil; reporting
// never blocks and does not write logs or capture bodies.
type PerformanceSample struct {
	Stage    string
	Duration time.Duration
}

func (s *Store) performanceStart() time.Time {
	if s.PerformanceSamples == nil {
		return time.Time{}
	}
	return time.Now()
}
func (s *Store) performance(stage string, start time.Time) {
	if start.IsZero() {
		return
	}
	select {
	case s.PerformanceSamples <- PerformanceSample{Stage: stage, Duration: time.Since(start)}:
	default:
	}
}

func (s *Store) releaseDay(day string) {
	s.daysMu.Lock()
	if s.activeDays[day] <= 1 {
		delete(s.activeDays, day)
	} else {
		s.activeDays[day]--
	}
	s.daysMu.Unlock()
	s.capturesInFlight.Add(-1)
}

func (s *Store) isSummary(path string) bool {
	return filepath.Clean(filepath.Dir(path)) == filepath.Join(s.Root, "captures", "summary") &&
		(strings.HasSuffix(path, ".jsonl") || strings.HasSuffix(path, ".jsonl.gz"))
}

// summaryMu protects the complete lifetime of each summary file, not only its
// Write. An opened descriptor must never survive compression or unlink.
func (s *Store) summaryActiveLocked(path string, now time.Time) bool {
	day := strings.TrimSuffix(strings.TrimSuffix(filepath.Base(path), ".gz"), ".jsonl")
	s.daysMu.Lock()
	defer s.daysMu.Unlock()
	return day == now.UTC().Format("2006-01-02") || s.activeDays[day] > 0
}

func (s *Store) closeSummaryLocked(path string) error {
	if writer := s.summaryWriters[path]; writer != nil {
		delete(s.summaryWriters, path)
		return writer.file.Close()
	}
	return nil
}

func (s *Store) closeSummaries() {
	s.summaryMu.Lock()
	var failures []error
	for path := range s.summaryWriters {
		if e := s.closeSummaryLocked(path); e != nil {
			failures = append(failures, e)
		}
	}
	s.summaryMu.Unlock()
	for _, e := range failures {
		s.captureFailure("summary_close", e)
	}
}

func (s *Store) append(path string, value any) error {
	encodedAt := s.performanceStart()
	line, e := json.Marshal(value)
	if e != nil {
		return e
	}
	line = append(line, '\n')
	s.performance("summary_encode", encodedAt)
	waitAt := s.performanceStart()
	s.summaryMu.Lock()
	defer s.summaryMu.Unlock()
	s.performance("summary_lock_wait", waitAt)
	writer := s.summaryWriters[path]
	if writer == nil {
		if len(s.summaryWriters) >= maximumSummaryWriters {
			oldest, sequence := "", ^uint64(0)
			for candidate, existing := range s.summaryWriters {
				if existing.used < sequence {
					oldest, sequence = candidate, existing.used
				}
			}
			if e = s.closeSummaryLocked(oldest); e != nil {
				return e
			}
		}
		if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
			return e
		}
		// Preserve the legacy per-record WriteThrough contract. Keeping the
		// descriptor avoids open/close overhead without buffering acknowledgments.
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY|os.O_SYNC, 0600)
		if err != nil {
			return err
		}
		writer = &summaryWriter{file: f}
		s.summaryWriters[path] = writer
	}
	s.summarySequence++
	writer.used = s.summarySequence
	writeAt := s.performanceStart()
	n, e := writer.file.Write(line)
	s.performance("summary_write", writeAt)
	if e == nil && n != len(line) {
		e = io.ErrShortWrite
	}
	if e != nil {
		_ = s.closeSummaryLocked(path)
	}
	return e
}

func (s *Store) removeManaged(path string, now time.Time) (bool, error) {
	if s.isSummary(path) {
		s.summaryMu.Lock()
		defer s.summaryMu.Unlock()
		if s.summaryActiveLocked(path, now) {
			return false, nil
		}
		if e := s.closeSummaryLocked(strings.TrimSuffix(path, ".gz")); e != nil {
			return false, e
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active[path] {
		return false, nil
	}
	e := os.Remove(path)
	return e == nil || os.IsNotExist(e), e
}
