// Package installguard suspends configuration and control mutations until the
// native installer commits. The marker lives in the protected client data root.
package installguard

import (
	"errors"
	"os"
	"path/filepath"
)

const Filename = ".installation-pending"

func Pending(root string) bool {
	_, err := os.Lstat(filepath.Join(root, Filename))
	return !os.IsNotExist(err)
}
func Begin(root, transaction string) error {
	if transaction == "" {
		return errors.New("installation transaction missing")
	}
	path := filepath.Join(root, Filename)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		info, e := os.Lstat(path)
		if e != nil || !info.Mode().IsRegular() {
			return errors.New("installation marker unsafe")
		}
		saved, e := os.ReadFile(path)
		if e == nil && string(saved) == transaction {
			return nil
		}
		return errors.New("another installation transaction pending")
	}
	_, err = f.WriteString(transaction)
	if err == nil {
		err = f.Sync()
	}
	closed := f.Close()
	if err != nil {
		return err
	}
	return closed
}
func Release(root, transaction string) error {
	path := filepath.Join(root, Filename)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("installation marker unsafe")
	}
	saved, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if string(saved) != transaction {
		return errors.New("installation transaction mismatch")
	}
	return os.Remove(path)
}
