//go:build windows

package instance

import (
	"fmt"
	"golang.org/x/sys/windows"
	"os"
)

type Lock struct {
	file       *os.File
	overlapped windows.Overlapped
}

func Acquire(path string) (*Lock, error) {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	l := &Lock{file: f}
	if e = windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &l.overlapped); e != nil {
		f.Close()
		return nil, fmt.Errorf("CLIENT_ALREADY_RUNNING")
	}
	return l, nil
}
func (l *Lock) Close() error {
	_ = windows.UnlockFileEx(windows.Handle(l.file.Fd()), 0, 1, 0, &l.overlapped)
	return l.file.Close()
}
