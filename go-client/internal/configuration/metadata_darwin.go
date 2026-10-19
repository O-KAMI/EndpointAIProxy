//go:build darwin

package configuration

import (
	"bytes"
	"encoding/binary"
	"errors"
	"golang.org/x/sys/unix"
	"maps"
	"os"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

const darwinMetadataLimit = 4 << 20

type darwinMetadata struct {
	uid, gid uint32
	mode     uint32
	acl      []byte
	xattrs   map[string][]byte
}

func openMetadataFile(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		if err != nil {
			return nil, err
		}
		return nil, problem("CONFIG_NOT_REGULAR")
	}
	return f, nil
}

// Darwin exposes ACLs as ATTR_CMN_EXTENDED_SECURITY, not listxattr. These
// kernel calls preserve the native filesec bytes without cgo or subprocesses.
func darwinACL(fd uintptr) ([]byte, error) {
	attrs := unix.Attrlist{Bitmapcount: 5, Commonattr: unix.ATTR_CMN_EXTENDED_SECURITY}
	for size := 4096; size <= darwinMetadataLimit; size *= 2 {
		buf := make([]byte, size)
		_, _, errno := syscall.Syscall6(unix.SYS_FGETATTRLIST, fd, uintptr(unsafe.Pointer(&attrs)), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), unix.FSOPT_REPORT_FULLSIZE, 0)
		runtime.KeepAlive(&attrs)
		runtime.KeepAlive(buf)
		if errno != 0 {
			return nil, errno
		}
		full := int64(binary.LittleEndian.Uint32(buf[:4]))
		if full > int64(len(buf)) {
			continue
		}
		if full < 12 {
			return nil, problem("CONFIG_METADATA_INVALID")
		}
		start := 4 + int64(int32(binary.LittleEndian.Uint32(buf[4:8])))
		length := int64(binary.LittleEndian.Uint32(buf[8:12]))
		if start < 12 || length < 0 || start+length > full {
			return nil, problem("CONFIG_METADATA_INVALID")
		}
		return append([]byte(nil), buf[start:start+length]...), nil
	}
	return nil, problem("CONFIG_METADATA_TOO_LARGE")
}

func setDarwinACL(fd uintptr, acl []byte) error {
	if len(acl) == 0 {
		// kauth_filesec with KAUTH_FILESEC_NOACL removes any inherited ACL on
		// the staging inode when the original has no extended ACL.
		acl = make([]byte, 44)
		binary.LittleEndian.PutUint32(acl[:4], 0x012cc16d)
		binary.LittleEndian.PutUint32(acl[36:40], 0xffffffff)
	}
	attrs := unix.Attrlist{Bitmapcount: 5, Commonattr: unix.ATTR_CMN_EXTENDED_SECURITY}
	buf := make([]byte, 8+len(acl))
	binary.LittleEndian.PutUint32(buf[:4], 8)
	binary.LittleEndian.PutUint32(buf[4:8], uint32(len(acl)))
	copy(buf[8:], acl)
	_, _, errno := syscall.Syscall6(unix.SYS_FSETATTRLIST, fd, uintptr(unsafe.Pointer(&attrs)), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0, 0)
	runtime.KeepAlive(&attrs)
	runtime.KeepAlive(buf)
	if errno != 0 {
		return errno
	}
	return nil
}

func darwinXattrs(fd int) (map[string][]byte, error) {
	n, err := unix.Flistxattr(fd, nil)
	if err != nil {
		return nil, err
	}
	if n < 0 || n > darwinMetadataLimit {
		return nil, problem("CONFIG_METADATA_TOO_LARGE")
	}
	list := make([]byte, n)
	if n > 0 {
		actual, e := unix.Flistxattr(fd, list)
		if e != nil {
			return nil, e
		}
		if actual != n {
			return nil, problem("CONFIG_METADATA_CHANGED")
		}
	}
	attrs := map[string][]byte{}
	total := len(list)
	for _, name := range strings.Split(string(list), "\x00") {
		if name == "" {
			continue
		}
		size, e := unix.Fgetxattr(fd, name, nil)
		if e != nil {
			return nil, e
		}
		if size < 0 || size > darwinMetadataLimit-total {
			return nil, problem("CONFIG_METADATA_TOO_LARGE")
		}
		value := make([]byte, size)
		actual, e := unix.Fgetxattr(fd, name, value)
		if e != nil {
			return nil, e
		}
		if actual != size {
			return nil, problem("CONFIG_METADATA_CHANGED")
		}
		attrs[name] = value
		total += size
	}
	return attrs, nil
}

func readDarwinMetadata(f *os.File) (darwinMetadata, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &stat); err != nil {
		return darwinMetadata{}, err
	}
	acl, err := darwinACL(f.Fd())
	if err != nil {
		return darwinMetadata{}, err
	}
	attrs, err := darwinXattrs(int(f.Fd()))
	if err != nil {
		return darwinMetadata{}, err
	}
	return darwinMetadata{uid: stat.Uid, gid: stat.Gid, mode: uint32(stat.Mode) & 07777, acl: acl, xattrs: attrs}, nil
}

func sameDarwinMetadata(a, b darwinMetadata) bool {
	return a.uid == b.uid && a.gid == b.gid && a.mode == b.mode && bytes.Equal(a.acl, b.acl) && maps.EqualFunc(a.xattrs, b.xattrs, bytes.Equal)
}

func copyMetadata(source, target string, info os.FileInfo) error {
	src, err := openMetadataFile(source)
	if err != nil {
		return err
	}
	defer src.Close()
	actual, err := src.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(info, actual) {
		return problem("CONFIG_CHANGED_CONCURRENTLY")
	}
	expected, err := readDarwinMetadata(src)
	if err != nil {
		return errors.Join(problem("CONFIG_METADATA_READ_FAILED"), err)
	}
	dst, err := openMetadataFile(target)
	if err != nil {
		return err
	}
	defer dst.Close()
	if err = dst.Chown(int(expected.uid), int(expected.gid)); err != nil {
		return err
	}
	if err = unix.Fchmod(int(dst.Fd()), expected.mode); err != nil {
		return err
	}
	if err = setDarwinACL(dst.Fd(), nil); err != nil {
		return errors.Join(problem("CONFIG_METADATA_COPY_FAILED"), err)
	}
	current, err := darwinXattrs(int(dst.Fd()))
	if err != nil {
		return err
	}
	for name := range current {
		if _, ok := expected.xattrs[name]; !ok {
			if err = unix.Fremovexattr(int(dst.Fd()), name); err != nil {
				return errors.Join(problem("CONFIG_METADATA_COPY_FAILED"), err)
			}
		}
	}
	for name, value := range expected.xattrs {
		if err = unix.Fsetxattr(int(dst.Fd()), name, value, 0); err != nil {
			return errors.Join(problem("CONFIG_METADATA_COPY_FAILED"), err)
		}
	}
	if err = setDarwinACL(dst.Fd(), expected.acl); err != nil {
		return errors.Join(problem("CONFIG_METADATA_COPY_FAILED"), err)
	}
	copied, err := readDarwinMetadata(dst)
	if err != nil {
		return err
	}
	if !sameDarwinMetadata(expected, copied) {
		return problem("CONFIG_METADATA_VERIFY_FAILED")
	}
	return nil
}

// Capture the actual metadata once, then compare both the source immediately
// before replacement and the published inode afterward. A metadata CAS failure
// is handled by the same recovery path as a content CAS failure.
func metadataVerification(source, target string, info os.FileInfo) (func(string) error, error) {
	src, err := openMetadataFile(source)
	if err != nil {
		return nil, err
	}
	defer src.Close()
	actual, err := src.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(info, actual) {
		return nil, problem("CONFIG_CHANGED_CONCURRENTLY")
	}
	expected, err := readDarwinMetadata(src)
	if err != nil {
		return nil, err
	}
	check := func(path string) error {
		f, err := openMetadataFile(path)
		if err != nil {
			return err
		}
		defer f.Close()
		actual, err := readDarwinMetadata(f)
		if err != nil {
			return err
		}
		if !sameDarwinMetadata(expected, actual) {
			return problem("CONFIG_METADATA_CHANGED")
		}
		return nil
	}
	if err = check(target); err != nil {
		return nil, err
	}
	return check, nil
}
