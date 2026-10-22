//go:build !windows

package main

import "os"

func privateKeyFile(_ string, info os.FileInfo) bool { return info.Mode().Perm()&0077 == 0 }
