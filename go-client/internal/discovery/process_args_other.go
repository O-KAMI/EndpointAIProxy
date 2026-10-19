//go:build !windows && !darwin

package discovery

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// Other Unix test hosts use procfs' NUL-delimited argv, never shell text.
func nativeProcessArgs(ctx context.Context, pid int) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	defer clear(raw)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw) > 2<<20 || raw[len(raw)-1] != 0 {
		return nil, errors.New("PROCESS_ARGUMENTS_INCOMPLETE")
	}
	return strings.Split(string(raw[:len(raw)-1]), "\x00"), nil
}
func processGone(err error) bool {
	return errors.Is(err, syscall.ESRCH) || errors.Is(err, syscall.ENOENT)
}
