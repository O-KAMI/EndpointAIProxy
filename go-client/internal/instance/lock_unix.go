//go:build !windows

package instance

import (
	"fmt"
	"os"
	"syscall"
)

type Lock struct{ file *os.File }

func Acquire(path string) (*Lock, error) {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		return nil, fmt.Errorf("CLIENT_ALREADY_RUNNING")
	}
	return &Lock{f}, nil
}
func (l *Lock) Close() error {
	_ = syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	return l.file.Close()
}
