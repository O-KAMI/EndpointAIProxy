//go:build windows

package configuration

import (
	"bytes"
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"unsafe"
)

var replaceFileW = windows.NewLazySystemDLL("kernel32.dll").NewProc("ReplaceFileW")

type uncertainReplacementError struct{ cause error }

func (e *uncertainReplacementError) Error() string {
	return "native replacement may have changed configuration: " + e.cause.Error()
}
func (e *uncertainReplacementError) Unwrap() error { return e.cause }
func replacementMayHaveChanged(err error) bool {
	var uncertain *uncertainReplacementError
	return errors.As(err, &uncertain)
}

func nativeReplace(target, source, backup *uint16) error {
	ok, _, callErr := replaceFileW.Call(uintptr(unsafe.Pointer(target)), uintptr(unsafe.Pointer(source)), uintptr(unsafe.Pointer(backup)), 0, 0, 0)
	if ok == 0 {
		return callErr
	}
	return nil
}

// ReplaceFileW preserves the replaced file's Windows metadata. Never fall back
// to delete-then-rename: failure must leave a recoverable original and backup.
func replaceFile(temp, path string, exists bool) error {
	source, err := windows.UTF16PtrFromString(temp)
	if err != nil {
		return err
	}
	target, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	if !exists {
		// No REPLACE_EXISTING flag: a file created since the CAS check wins.
		return windows.MoveFileEx(source, target, windows.MOVEFILE_WRITE_THROUGH)
	}
	return replaceExistingFile(temp, path, source, target, nativeReplace)
}

func replaceExistingFile(temp, path string, source, target *uint16, call func(*uint16, *uint16, *uint16) error) error {
	originalInfo, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !originalInfo.Mode().IsRegular() {
		return problem("CONFIG_NOT_REGULAR")
	}
	original, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	// Same-volume backup keeps the original Windows security descriptor and
	// ensures documented 1176/1177 errors leave a recoverable original name.
	backupPath := temp + ".original"
	if _, err = os.Lstat(backupPath); !os.IsNotExist(err) {
		return problem("CONFIG_CHANGED_CONCURRENTLY")
	}
	backup, err := windows.UTF16PtrFromString(backupPath)
	if err != nil {
		return err
	}
	if err = call(target, source, backup); err == nil {
		_ = os.Remove(backupPath) // the separate durable transaction backup remains
		return nil
	}
	// Never overwrite a file another writer installed while replacement failed.
	if _, statErr := os.Lstat(path); os.IsNotExist(statErr) {
		if backupInfo, backupErr := os.Lstat(backupPath); backupErr == nil && backupInfo.Mode().IsRegular() && os.SameFile(originalInfo, backupInfo) {
			if restoreErr := windows.MoveFileEx(backup, target, windows.MOVEFILE_WRITE_THROUGH); restoreErr != nil {
				return &uncertainReplacementError{errors.Join(err, restoreErr)}
			}
		}
	}
	currentInfo, statErr := os.Lstat(path)
	current, readErr := os.ReadFile(path)
	if statErr == nil && readErr == nil && currentInfo.Mode().IsRegular() && os.SameFile(originalInfo, currentInfo) && bytes.Equal(original, current) {
		return err
	}
	// ApplyFile marks Replaced and Manager attempts only a byte-CAS rollback;
	// if that is impossible it retains pending route metadata for recovery.
	return &uncertainReplacementError{err}
}
