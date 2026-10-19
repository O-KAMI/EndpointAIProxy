//go:build !windows

package observability

func nativeClass(int) string { return "" }
