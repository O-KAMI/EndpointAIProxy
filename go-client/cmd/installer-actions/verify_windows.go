package main

import (
	"encoding/binary"
	"errors"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"net/http"
	"path/filepath"
	"strings"
	"time"
	"unsafe"
)

func processImage(pid uint32) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, 32768)
	n := uint32(len(buf))
	if err = windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:n]), nil
}

// TCP_TABLE_OWNER_PID_LISTENER gives authoritative ownership, rather than
// trusting a health response from an unrelated process occupying port 18080.
func verifyListenerPID(pid uint32, expectedPort uint16) error {
	proc := windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")
	var size uint32
	rc, _, _ := proc.Call(0, uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET, 3, 0)
	if rc != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) || size < 4 || size > 16<<20 {
		return errors.New("cannot inspect listener ownership")
	}
	for attempt := 0; attempt < 3; attempt++ {
		buf := make([]byte, size)
		rc, _, _ = proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET, 3, 0)
		if rc == uintptr(windows.ERROR_INSUFFICIENT_BUFFER) && size <= 16<<20 {
			continue
		}
		if rc != 0 || size < 4 || int(size) > len(buf) {
			return errors.New("cannot inspect listener ownership")
		}
		count := binary.LittleEndian.Uint32(buf[:4])
		if uint64(count)*24+4 > uint64(size) {
			return errors.New("invalid listener table")
		}
		found := false
		for i := uint32(0); i < count; i++ {
			row := buf[4+i*24 : 4+(i+1)*24]
			port := binary.BigEndian.Uint16(row[8:10])
			// Wildcard or IPv4 loopback can serve the health endpoint.
			addr := binary.LittleEndian.Uint32(row[4:8])
			if port == expectedPort && (addr == 0 || row[4] == 127) {
				if binary.LittleEndian.Uint32(row[20:24]) != pid {
					return errors.New("health listener belongs to another process")
				}
				found = true
			}
		}
		if found {
			return nil
		}
		return errors.New("service health listener unavailable")
	}
	return errors.New("listener table changed repeatedly")
}

func (a *action) verify() error {
	if err := a.verifyPreservedState(true); err != nil {
		return err
	}
	baseline, err := a.readMigrationBaseline()
	if err != nil {
		return err
	}
	expectedID := ""
	if baseline != nil && baseline.Present {
		expectedID = baseline.DeviceID
	}
	a.stage = "verify_service_ready"
	return withService(func(s *mgr.Service) error {
		if err := waitService(s, svc.Running, 30*time.Second); err != nil {
			return err
		}
		transport := &http.Transport{Proxy: nil}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("health redirect forbidden") }}
		deadline := time.Now().Add(30 * time.Second)
		var last error
		var readySince time.Time
		var readyPID uint32
		for {
			status, err := s.Query()
			if err == nil && status.State == svc.Running && status.ProcessId != 0 {
				image, imageErr := processImage(status.ProcessId)
				if imageErr != nil {
					return imageErr
				}
				if !strings.EqualFold(filepath.Clean(image), filepath.Join(a.installRoot, serviceExe)) {
					return errors.New("running service image mismatch")
				}
				err = verifyListenerPID(status.ProcessId, 18080)
				if err == nil {
					var resp *http.Response
					resp, err = client.Get("http://127.0.0.1:18080/healthz")
					if err == nil {
						if resp.StatusCode != http.StatusOK {
							err = errors.New("health status not ready")
						} else {
							err = validateHealth(resp.Body, version, expectedID)
						}
						resp.Body.Close()
					}
				}
				if err == nil {
					err = verifyListenerPID(status.ProcessId, 18080)
				}
				if err == nil {
					if readyPID != status.ProcessId {
						readySince = time.Now()
						readyPID = status.ProcessId
					}
					if time.Since(readySince) >= 3*time.Second {
						return a.verifyPreservedState(true)
					}
				} else {
					readySince = time.Time{}
					readyPID = 0
				}
			} else if err == nil {
				err = errors.New("service not running")
			}
			if err != nil {
				readySince = time.Time{}
				readyPID = 0
			}
			last = err
			if time.Now().After(deadline) {
				if last == nil {
					return errors.New("service stability timeout")
				}
				return last
			}
			time.Sleep(250 * time.Millisecond)
		}
	})
}
