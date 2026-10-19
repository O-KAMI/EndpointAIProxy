package discovery

import (
	"context"
	"endpointai/client/internal/platform"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"strings"
	"unsafe"
)

func processSamples(ctx context.Context, profiles []platform.Profile) ([]sample, error) {
	snap, e := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if e != nil {
		return nil, e
	}
	defer windows.CloseHandle(snap)
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	e = windows.Process32First(snap, &entry)
	out := []sample{}
	for e == nil {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		if _, ok := processKind(windows.UTF16ToString(entry.ExeFile[:])); ok || isNodeExecutable(windows.UTF16ToString(entry.ExeFile[:])) {
			nodeProcess := isNodeExecutable(windows.UTF16ToString(entry.ExeFile[:]))
			h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, entry.ProcessID)
			if err == nil {
				buf := make([]uint16, 32768)
				n := uint32(len(buf))
				if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) == nil {
					path := windows.UTF16ToString(buf[:n])
					sid := ""
					var token windows.Token
					if windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token) == nil {
						if user, err := token.GetTokenUser(); err == nil {
							sid = user.User.Sid.String()
						}
						token.Close()
					}
					kind, valid := processKind(path)
					version := ""
					launchProfile := ""
					launchUnknown := true
					strength := 2
					if isNodeExecutable(path) {
						if args := windowsProcessArgs(h); args != nil {
							if script, v, ok := dshNodeEntry(args); ok {
								launchProfile, launchUnknown = dshLaunchProfile(args)
								path = script
								version = v
								kind = DeepSeekHarness
								valid = true
							} else if nodeArgumentsUncertain(args) {
								out = append(out, uncertainProcessSamples(profiles, sid, path)...)
							}
						} else {
							out = append(out, uncertainProcessSamples(profiles, sid, path)...)
						}
						if sid == "" {
							out = append(out, uncertainProcessSamples(profiles, "", path)...)
						}
					}
					if kind == DeepSeekHarness && version == "" && !dshDesktopProcess(path) {
						strength = 1
					}
					if !valid {
						windows.CloseHandle(h)
						e = windows.Process32Next(snap, &entry)
						continue
					}
					for _, p := range profiles {
						if p.SID == sid || strings.HasPrefix(strings.ToLower(path), strings.ToLower(p.Home+`\`)) {
							out = append(out, sample{sid: p.SID, kind: kind, collector: "running-process", path: fmt.Sprintf("%s (PID %d)", path, entry.ProcessID), strength: strength, version: version, launchProfile: launchProfile, launchOverridesUnknown: launchUnknown})
							break
						}
					}
				} else if nodeProcess {
					out = append(out, uncertainProcessSamples(profiles, "", "")...)
				}
				windows.CloseHandle(h)
			} else if nodeProcess {
				out = append(out, uncertainProcessSamples(profiles, "", "")...)
			}
		}
		e = windows.Process32Next(snap, &entry)
	}
	if !errors.Is(e, windows.ERROR_NO_MORE_FILES) {
		return out, e
	}
	return out, nil
}

func windowsProcessArgs(h windows.Handle) []string {
	var size uint32
	windows.NtQueryInformationProcess(h, windows.ProcessCommandLineInformation, nil, 0, &size)
	if size < 16 || size > 65536 {
		return nil
	}
	buf := make([]byte, size)
	if windows.NtQueryInformationProcess(h, windows.ProcessCommandLineInformation, unsafe.Pointer(&buf[0]), size, &size) != nil {
		return nil
	}
	us := (*windows.NTUnicodeString)(unsafe.Pointer(&buf[0]))
	start := uintptr(unsafe.Pointer(us.Buffer))
	base := uintptr(unsafe.Pointer(&buf[0]))
	if us.Length == 0 || us.Length%2 != 0 || start < base || start+uintptr(us.Length) > base+uintptr(len(buf)) {
		return nil
	}
	line := windows.UTF16ToString(unsafe.Slice(us.Buffer, int(us.Length)/2))
	args, e := windows.DecomposeCommandLine(line)
	if e != nil || len(args) == 0 {
		return nil
	}
	return args
}
