//go:build !windows

package main

import "testing"

func setTestKeyPermissions(*testing.T, string, bool) {}
