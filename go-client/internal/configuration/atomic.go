package configuration

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
)

type FileUpdate struct {
	Path, Backup  string
	Before, After []byte
	Created       bool
	Replaced      bool // set immediately after rename, before fallible verification
}

func randomID() string {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b[:])
}

// ApplyFile compares the inspected bytes twice, preserves metadata, writes a
// durable backup, and replaces from the same filesystem. Symlinks are rejected.
func ApplyFile(ctx context.Context, path string, expected, updated []byte, backupRoot string) (FileUpdate, error) {
	return applyFile(ctx, path, expected, updated, backupRoot, nil)
}

// applyProfileFile uses the trusted profile home identity for newly-created
// live configuration. Existing files keep their own metadata.
func applyProfileFile(ctx context.Context, p Profile, path string, expected, updated []byte, backupRoot string) (FileUpdate, error) {
	return applyFile(ctx, path, expected, updated, backupRoot, &p)
}
func applyFile(ctx context.Context, path string, expected, updated []byte, backupRoot string, profile *Profile) (FileUpdate, error) {
	result := FileUpdate{Path: path, Before: expected, After: updated}
	if e := ctx.Err(); e != nil {
		return result, e
	}
	info, e := os.Lstat(path)
	exists := e == nil
	if e != nil && !os.IsNotExist(e) {
		return result, e
	}
	if exists && !info.Mode().IsRegular() {
		return result, problem("CONFIG_NOT_REGULAR")
	}
	result.Created = !exists
	current, e := readOptional(path)
	if e != nil {
		return result, e
	}
	if !bytes.Equal(current, expected) {
		return result, problem("CONFIG_CHANGED_CONCURRENTLY")
	}
	if profile != nil {
		if e = prepareProfileDirectory(*profile, path); e != nil {
			return result, e
		}
	} else if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return result, e
	}
	if e = os.MkdirAll(backupRoot, 0700); e != nil {
		return result, e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".endpointai-*.tmp")
	if e != nil {
		return result, e
	}
	temp := f.Name()
	defer os.Remove(temp)
	defer f.Close()
	if _, e = f.Write(updated); e != nil {
		return result, e
	}
	if exists {
		if e = copyMetadata(path, temp, info); e != nil {
			return result, e
		}
	} else if profile != nil {
		if e = setProfileOwner(*profile, temp); e != nil {
			return result, e
		}
	}
	var verifyMetadata func(string) error
	if exists {
		verifyMetadata, e = metadataVerification(path, temp, info)
		if e != nil {
			return result, e
		}
	}
	if e = f.Sync(); e != nil {
		return result, e
	}
	if e = f.Close(); e != nil {
		return result, e
	}
	verify, e := readOptional(path)
	if e != nil {
		return result, e
	}
	if !bytes.Equal(verify, expected) {
		return result, problem("CONFIG_CHANGED_CONCURRENTLY")
	}
	verifyInfo, statErr := os.Lstat(path)
	if exists {
		if statErr != nil || !verifyInfo.Mode().IsRegular() || !os.SameFile(info, verifyInfo) {
			return result, problem("CONFIG_CHANGED_CONCURRENTLY")
		}
	} else if !os.IsNotExist(statErr) {
		return result, problem("CONFIG_CHANGED_CONCURRENTLY")
	}
	if verifyMetadata != nil {
		if e = verifyMetadata(path); e != nil {
			return result, e
		}
	}
	if e = ctx.Err(); e != nil {
		return result, e
	}
	if exists {
		result.Backup = filepath.Join(backupRoot, filepath.Base(path)+"."+randomID()+".bak")
		if e = writeExclusive(result.Backup, current); e != nil {
			return result, e
		}
	}
	if e = replaceFile(temp, path, exists); e != nil {
		// A native Windows replacement can fail after moving the original.
		// Retain the route when recovery cannot prove that the file is unchanged.
		result.Replaced = replacementMayHaveChanged(e)
		return result, e
	}
	result.Replaced = true
	persisted, e := os.ReadFile(path)
	if e != nil {
		return result, e
	}
	if !bytes.Equal(persisted, updated) {
		return result, problem("CONFIG_VERIFY_FAILED")
	}
	if verifyMetadata != nil {
		if e = verifyMetadata(path); e != nil {
			return result, e
		}
	}
	syncDirectory(filepath.Dir(path))
	return result, nil
}
func writeExclusive(path string, b []byte) error {
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	if _, e = f.Write(b); e != nil {
		return e
	}
	return f.Sync()
}
func readOptional(path string) ([]byte, error) {
	b, e := os.ReadFile(path)
	if os.IsNotExist(e) {
		return nil, nil
	}
	return b, e
}

// Rollback changes only bytes this update wrote; later user changes are retained.
func (u FileUpdate) Rollback(ctx context.Context, backupRoot string) error {
	b, e := os.ReadFile(u.Path)
	if e != nil {
		return e
	}
	if !bytes.Equal(b, u.After) {
		return problem("CONFIG_CHANGED_CONCURRENTLY")
	}
	if u.Created {
		return os.Remove(u.Path)
	}
	_, e = ApplyFile(ctx, u.Path, u.After, u.Before, backupRoot)
	return e
}
func syncDirectory(path string) {
	if f, e := os.Open(path); e == nil {
		_ = f.Sync()
		_ = f.Close()
	}
}

// Reject symlink ancestry and paths outside the discovered home. Never chown
// existing directories: only components created by this operation are changed.
func prepareProfileDirectory(p Profile, path string) error {
	home, e := filepath.Abs(p.Home)
	if e != nil {
		return e
	}
	parent, e := filepath.Abs(filepath.Dir(path))
	if e != nil {
		return e
	}
	rel, e := filepath.Rel(home, parent)
	if e != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return problem("CONFIG_PROFILE_PATH_INVALID")
	}
	info, err := os.Lstat(home)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return problem("CONFIG_PROFILE_HOME_UNSAFE")
	}
	current := home
	if rel == "." {
		return nil
	}
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return problem("CONFIG_PROFILE_PATH_UNSAFE")
			}
			continue
		}
		if !os.IsNotExist(err) {
			return err
		}
		if err = os.Mkdir(current, 0700); err != nil {
			return err
		}
		if err = setProfileOwner(p, current); err != nil {
			return err
		}
	}
	return nil
}
