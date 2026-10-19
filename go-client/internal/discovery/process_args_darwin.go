//go:build darwin

package discovery

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"golang.org/x/sys/unix"
	"syscall"
)

func nativeProcessArgs(ctx context.Context, pid int) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// KERN_PROCARGS2 preserves argument boundaries. Its trailing environment is
	// deliberately ignored and the kernel buffer is cleared after parsing.
	raw, err := unix.SysctlRaw("kern.procargs2", pid)
	defer clear(raw)
	if err != nil {
		return nil, err
	}
	return parseDarwinProcessArgs(raw)
}

func parseDarwinProcessArgs(raw []byte) ([]string, error) {
	invalid := errors.New("PROCESS_ARGUMENTS_INCOMPLETE")
	if len(raw) < 6 || len(raw) > 2<<20 {
		return nil, invalid
	}
	argc := int(binary.LittleEndian.Uint32(raw[:4]))
	if argc < 1 || argc > 8192 {
		return nil, invalid
	}
	pos := bytes.IndexByte(raw[4:], 0)
	if pos < 0 {
		return nil, invalid
	}
	pos += 5 // executable path and its terminating NUL
	for pos < len(raw) && raw[pos] == 0 {
		pos++
	}
	args := make([]string, 0, argc)
	for len(args) < argc {
		if pos >= len(raw) {
			return nil, invalid
		}
		n := bytes.IndexByte(raw[pos:], 0)
		if n < 0 {
			return nil, invalid
		}
		args = append(args, string(raw[pos:pos+n]))
		pos += n + 1
	}
	return args, nil
}

func processGone(err error) bool {
	return errors.Is(err, syscall.ESRCH) || errors.Is(err, syscall.ENOENT)
}
