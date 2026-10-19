//go:build !windows

package configuration

import "os"

func replaceFile(temp, path string, exists bool) error { return os.Rename(temp, path) }

func replacementMayHaveChanged(err error) bool { return false }
