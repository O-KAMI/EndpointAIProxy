//go:build !windows

package configuration

import (
	"os"
	"syscall"
)

// Home metadata comes from the discovered profile, never an agent configuration.
func setProfileOwner(p Profile, path string) error {
	info, e := os.Lstat(p.Home)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return problem("CONFIG_PROFILE_HOME_UNSAFE")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return problem("CONFIG_PROFILE_IDENTITY_UNAVAILABLE")
	}
	if e = os.Chown(path, int(owner.Uid), int(owner.Gid)); e != nil {
		return e
	}
	return nil
}
