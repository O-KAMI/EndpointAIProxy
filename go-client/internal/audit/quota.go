package audit

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const captureCapacity int64 = 512 << 20

var errCaptureCapacity = errors.New("CAPTURE_CAPACITY_EXCEEDED")

// The service has one owning process per data root. The budget includes all
// regular files, temporary compression output, and buffered capture writes.
// Files written by unrelated processes are outside this accounting contract.
func (s *Store) initializeQuotaLocked() error {
	if s.quotaInitialized {
		return nil
	}
	var total int64
	root := filepath.Join(s.Root, "captures")
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			if path == root {
				return errors.New("capture root is a symlink")
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			total += info.Size()
		}
		return nil
	})
	if err != nil {
		return err
	}
	s.quotaUsed = total
	s.quotaInitialized = true
	return nil
}

func (s *Store) reserveCapture(n int64) error {
	s.quotaMu.Lock()
	defer s.quotaMu.Unlock()
	if err := s.initializeQuotaLocked(); err != nil {
		return err
	}
	if n < 0 || s.quotaUsed > s.captureLimit || n > s.captureLimit-s.quotaUsed {
		s.quotaPressure.Store(true)
		return errCaptureCapacity
	}
	s.quotaUsed += n
	return nil
}

func (s *Store) releaseCapture(n int64) {
	s.quotaMu.Lock()
	defer s.quotaMu.Unlock()
	s.quotaUsed -= n
	if s.quotaUsed < 0 {
		s.quotaUsed = 0
	}
}

// removeCapture holds the accounting lock across stat and unlink so a new
// reservation cannot observe space released before the file is removed.
func (s *Store) removeCapture(path string) (bool, error) {
	s.quotaMu.Lock()
	defer s.quotaMu.Unlock()
	if err := s.initializeQuotaLocked(); err != nil {
		return false, err
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, errors.New("capture is not a regular file")
	}
	if err = os.Remove(path); err != nil {
		return false, err
	}
	s.quotaUsed -= info.Size()
	if s.quotaUsed < 0 {
		s.quotaUsed = 0
	}
	return true, nil
}

type captureQuotaWriter struct {
	store  *Store
	target io.Writer
}

func (w captureQuotaWriter) Write(p []byte) (int, error) {
	if err := w.store.reserveCapture(int64(len(p))); err != nil {
		return 0, err
	}
	n, err := w.target.Write(p)
	w.store.releaseCapture(int64(len(p) - n))
	return n, err
}

// Capture paths must remain within the quota-managed tree. The data root must
// additionally be protected from untrusted concurrent filesystem changes.
func (s *Store) ensureCaptureDirectory(dir string) error {
	root := filepath.Join(s.Root, "captures")
	rel, err := filepath.Rel(root, dir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("capture directory outside root")
	}
	if err := os.MkdirAll(s.Root, 0700); err != nil {
		return err
	}
	current := root
	paths := []string{root}
	if rel != "." {
		for _, part := range strings.Split(rel, string(filepath.Separator)) {
			current = filepath.Join(current, part)
			paths = append(paths, current)
		}
	}
	for _, path := range paths {
		if err := os.Mkdir(path, 0700); err != nil && !os.IsExist(err) {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("capture directory is not a real directory")
		}
	}
	return nil
}
