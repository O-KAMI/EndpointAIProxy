//go:build !windows && !darwin

package configuration

import (
	"os"
	"syscall"
)

func copyMetadata(source, target string, info os.FileInfo) error {
	if s, ok := info.Sys().(*syscall.Stat_t); ok {
		if e := os.Chown(target, int(s.Uid), int(s.Gid)); e != nil {
			return e
		}
	}
	return os.Chmod(target, info.Mode().Perm())
}
func metadataVerification(source, target string, info os.FileInfo) (func(string) error, error) {
	return nil, nil
}
