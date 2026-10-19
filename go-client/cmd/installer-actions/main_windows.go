package main

import (
	"encoding/json"
	"endpointai/client/internal/installguard"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unsafe"
)

const serviceName = "SfEndpointAIProxy"
const serviceExe = "Sf.EndpointAI.Client.Service.exe"
const trayExe = "Sf.EndpointAI.Client.Tray.exe"
const configKey = `Software\SF\EndpointAIProxy`
const serviceKey = `SYSTEM\CurrentControlSet\Services\SfEndpointAIProxy`
const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`
const runName = "SF Endpoint AI Proxy Tray"

type valueState struct {
	Exists bool
	Value  *string
}
type snapshot struct {
	Values              map[string]valueState
	Dacl                *string
	EnvironmentExists   bool
	Environment         []string
	Run                 map[string]valueState
	WasRunning          bool
	OldExecutable       *string
	OldExecutableSHA256 string
}
type action struct{ mode, installRoot, dataRoot, transactionRoot, logPath, stage string }

func execute(args []string) (err error) {
	a := &action{stage: "arguments"}
	defer func() {
		if err != nil {
			a.log("failed", fmt.Sprintf("%T", err))
		}
	}()
	if len(args) != 8 {
		return errors.New("invalid arguments")
	}
	options := map[string]string{}
	for i := 0; i < len(args); i += 2 {
		if _, ok := options[args[i]]; ok {
			return errors.New("duplicate argument")
		}
		options[args[i]] = args[i+1]
	}
	for _, key := range []string{"--mode", "--install-dir", "--data-dir", "--transaction"} {
		if _, ok := options[key]; !ok {
			return errors.New("missing argument")
		}
	}
	a.mode = options["--mode"]
	if !strings.Contains("|preflight|snapshot|quiesce|apply|verify|rollback|commit|restore-state|verify-state|", "|"+a.mode+"|") {
		return errors.New("invalid mode")
	}
	a.installRoot, err = filepath.Abs(options["--install-dir"])
	if err != nil {
		return err
	}
	a.dataRoot, err = filepath.Abs(options["--data-dir"])
	if err != nil {
		return err
	}
	if !strings.EqualFold(a.dataRoot, filepath.Join(os.Getenv("ProgramData"), "SF", "EndpointAIProxy")) {
		return errors.New("unexpected data directory")
	}
	transaction := strings.Trim(options["--transaction"], "{}")
	if !regexp.MustCompile(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$`).MatchString(transaction) {
		return errors.New("invalid transaction")
	}
	sid, e := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if e != nil {
		return e
	}
	admin, e := windows.Token(0).IsMember(sid)
	if e != nil || !admin {
		return errors.New("administrator required")
	}
	a.stage = "initialize_logs"
	logs := filepath.Join(a.dataRoot, "InstallerLogs")
	a.transactionRoot = filepath.Join(a.dataRoot, "InstallerState", strings.ToLower(strings.ReplaceAll(transaction, "-", "")))
	for _, p := range []string{a.dataRoot, logs, filepath.Dir(a.transactionRoot), a.transactionRoot} {
		if e = secureDirectory(p); e != nil {
			return e
		}
	}
	marker := filepath.Join(a.transactionRoot, "run-id.txt")
	if e = rejectReparse(marker); e != nil {
		return e
	}
	if a.mode == "preflight" {
		if _, pending := os.Lstat(a.backup()); !errors.Is(pending, os.ErrNotExist) {
			return errors.New("pending snapshot")
		}
		id := time.Now().UTC().Format("20060102T150405.000000000")
		id = strings.ReplaceAll(id, ".", "")
		if e = os.WriteFile(marker, []byte(id), 0600); e != nil {
			return e
		}
	}
	id, e := os.ReadFile(marker)
	if e != nil {
		return e
	}
	if !regexp.MustCompile(`^[A-Za-z0-9-]+$`).Match(id) {
		return errors.New("invalid run marker")
	}
	a.logPath = filepath.Join(logs, "install-"+string(id)+".jsonl")
	if e = rejectReparse(a.logPath); e != nil {
		return e
	}
	a.log("begin", "")
	switch a.mode {
	case "preflight":
		a.stage = "check_pending_transaction"
		if _, e = os.Stat(a.backup()); e == nil {
			return errors.New("pending snapshot")
		}
		if key, e := openKey(serviceKey, registry.QUERY_VALUE); e == nil {
			environment, _, readError := key.GetStringsValue("Environment")
			key.Close()
			if readError != nil && !errors.Is(readError, registry.ErrNotExist) {
				return readError
			}
			for _, line := range environment {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 && strings.EqualFold(parts[0], "SF_PROXY_DATA_ROOT") && !strings.EqualFold(filepath.Clean(parts[1]), filepath.Clean(a.dataRoot)) {
					return errors.New("alternate legacy data root requires explicit migration")
				}
			}
		} else if !errors.Is(e, registry.ErrNotExist) {
			return e
		}
		a.stage = "close_legacy_tray"
		err = a.closeTray()
	case "snapshot":
		err = a.capture()
	case "quiesce":
		err = a.quiesce()
	case "apply":
		err = a.apply()
	case "verify":
		err = a.verify()
	case "rollback":
		err = a.rollback()
	case "restore-state":
		if exe, e := serviceExecutable(); e != nil {
			return e
		} else if exe != nil {
			if e = stopService(); e != nil {
				return e
			}
		}
		err = a.restoreState()
	case "verify-state":
		err = a.verifyPreservedState(true)
	case "commit":
		a.stage = "commit_cleanup"
		if err = installguard.Release(a.dataRoot, a.transactionRoot); err == nil {
			// Business activity can resume after release. Cleanup cannot trigger
			// rollback to an older state after new commands may have completed.
			if cleanupError := a.cleanup(); cleanupError != nil {
				a.log("cleanup_pending", "filesystem")
			}
		}
	}
	if err == nil {
		a.log("success", "")
	}
	return err
}
func (a *action) backup() string { return filepath.Join(a.transactionRoot, "rollback.json") }
func (a *action) log(outcome, errorType string) {
	if a.logPath == "" {
		return
	}
	f, e := os.OpenFile(a.logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if e != nil {
		return
	}
	defer f.Close()
	_ = json.NewEncoder(f).Encode(map[string]any{"timeUtc": time.Now().UTC(), "version": version, "mode": a.mode, "stage": a.stage, "outcome": outcome, "errorType": errorType})
}
func rejectReparse(path string) error {
	for current := filepath.Clean(path); ; {
		ptr, e := windows.UTF16PtrFromString(current)
		if e != nil {
			return e
		}
		attrs, e := windows.GetFileAttributes(ptr)
		if e == nil && attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errors.New("reparse point forbidden")
		}
		if e != nil && !errors.Is(e, windows.ERROR_FILE_NOT_FOUND) && !errors.Is(e, windows.ERROR_PATH_NOT_FOUND) {
			return e
		}
		next := filepath.Dir(current)
		if next == current {
			return nil
		}
		current = next
	}
}
func setACL(handle windows.Handle, kind windows.SE_OBJECT_TYPE, sddl string) error {
	sd, e := windows.SecurityDescriptorFromString(sddl)
	if e != nil {
		return e
	}
	dacl, _, e := sd.DACL()
	if e != nil {
		return e
	}
	control, _, e := sd.Control()
	if e != nil {
		return e
	}
	flags := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION)
	if control&windows.SE_DACL_PROTECTED != 0 {
		flags |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		flags |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	return windows.SetSecurityInfo(handle, kind, flags, nil, nil, dacl, nil)
}
func secureDirectory(path string) error {
	if e := rejectReparse(path); e != nil {
		return e
	}
	if e := os.MkdirAll(path, 0700); e != nil {
		return e
	}
	sd, e := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if e != nil {
		return e
	}
	dacl, _, e := sd.DACL()
	if e != nil {
		return e
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}
func openKey(path string, access uint32) (registry.Key, error) {
	return registry.OpenKey(registry.LOCAL_MACHINE, path, access|registry.WOW64_64KEY)
}
func readValue(k registry.Key, name string) (valueState, error) {
	if k == 0 {
		return valueState{}, nil
	}
	v, _, e := k.GetStringValue(name)
	if errors.Is(e, registry.ErrNotExist) {
		return valueState{}, nil
	}
	if e != nil {
		return valueState{}, e
	}
	return valueState{true, &v}, nil
}
func restoreValue(k registry.Key, name string, v valueState) error {
	if v.Exists {
		if v.Value == nil {
			return errors.New("invalid snapshot value")
		}
		return k.SetStringValue(name, *v.Value)
	}
	e := k.DeleteValue(name)
	if errors.Is(e, registry.ErrNotExist) {
		return nil
	}
	return e
}
func serviceExecutable() (*string, error) {
	k, e := openKey(serviceKey, registry.QUERY_VALUE)
	if errors.Is(e, registry.ErrNotExist) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	defer k.Close()
	raw, _, e := k.GetStringValue("ImagePath")
	if e != nil {
		return nil, e
	}
	raw, e = registry.ExpandString(raw)
	if e != nil {
		return nil, e
	}
	raw = strings.TrimSpace(raw)
	var path string
	if strings.HasPrefix(raw, `"`) {
		end := strings.Index(raw[1:], `"`)
		if end < 0 {
			return nil, errors.New("invalid image path")
		}
		path = raw[1 : 1+end]
	} else {
		end := strings.Index(strings.ToLower(raw), ".exe")
		if end < 0 {
			return nil, errors.New("invalid image path")
		}
		path = raw[:end+4]
	}
	path, e = filepath.Abs(path)
	if e != nil {
		return nil, e
	}
	if !strings.EqualFold(filepath.Base(path), serviceExe) {
		return nil, errors.New("unexpected service executable")
	}
	return &path, nil
}
func withService(fn func(*mgr.Service) error) error {
	m, e := mgr.Connect()
	if e != nil {
		return e
	}
	defer m.Disconnect()
	s, e := m.OpenService(serviceName)
	if e != nil {
		return e
	}
	defer s.Close()
	return fn(s)
}
func waitService(s *mgr.Service, state svc.State, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		status, e := s.Query()
		if e != nil {
			return e
		}
		if status.State == state {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("service timeout")
		}
		time.Sleep(250 * time.Millisecond)
	}
}
func stopService() error {
	return withService(func(s *mgr.Service) error {
		status, e := s.Query()
		if e != nil {
			return e
		}
		if status.State == svc.Stopped {
			return nil
		}
		if status.State != svc.StopPending {
			if _, e = s.Control(svc.Stop); e != nil {
				return e
			}
		}
		return waitService(s, svc.Stopped, 45*time.Second)
	})
}
func (a *action) capture() error {
	a.stage = "snapshot_previous_configuration"
	if e := rejectReparse(a.backup()); e != nil {
		return e
	}
	if _, e := os.Stat(a.backup()); e == nil {
		return errors.New("snapshot exists")
	}
	s := snapshot{Values: map[string]valueState{}, Run: map[string]valueState{}, Environment: []string{}}
	k, e := openKey(configKey, registry.QUERY_VALUE|windows.READ_CONTROL)
	if e != nil && !errors.Is(e, registry.ErrNotExist) {
		return e
	}
	if k != 0 {
		defer k.Close()
		sd, e := windows.GetSecurityInfo(windows.Handle(k), windows.SE_REGISTRY_KEY, windows.DACL_SECURITY_INFORMATION)
		if e != nil {
			return e
		}
		dacl := sd.String()
		s.Dacl = &dacl
	}
	for _, n := range controlNames {
		v, e := readValue(k, n)
		if e != nil {
			return e
		}
		s.Values[n] = v
	}
	service, e := openKey(serviceKey, registry.QUERY_VALUE)
	if e != nil && !errors.Is(e, registry.ErrNotExist) {
		return e
	}
	if service != 0 {
		defer service.Close()
		env, _, e := service.GetStringsValue("Environment")
		if e == nil {
			s.EnvironmentExists = true
			s.Environment = env
		} else if !errors.Is(e, registry.ErrNotExist) {
			return e
		}
		if e = withService(func(svc *mgr.Service) error {
			status, e := svc.Query()
			s.WasRunning = status.State == svcRunning
			return e
		}); e != nil {
			return e
		}
	}
	for _, view := range []struct {
		name string
		flag uint32
	}{{"Registry64", registry.WOW64_64KEY}, {"Registry32", registry.WOW64_32KEY}} {
		r, e := registry.OpenKey(registry.LOCAL_MACHINE, runKey, registry.QUERY_VALUE|view.flag)
		if e != nil && !errors.Is(e, registry.ErrNotExist) {
			return e
		}
		v, e := readValue(r, runName)
		if r != 0 {
			r.Close()
		}
		if e != nil {
			return e
		}
		s.Run[view.name] = v
	}
	s.OldExecutable, e = serviceExecutable()
	if e != nil {
		return e
	}
	if s.OldExecutable != nil {
		s.OldExecutableSHA256, e = executableDigest(*s.OldExecutable)
		if e != nil {
			return e
		}
	}
	raw, e := json.Marshal(s)
	if e != nil {
		return e
	}
	tmp := a.backup() + ".tmp"
	if e = rejectReparse(tmp); e != nil {
		return e
	}
	f, e := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(raw)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	return os.Rename(tmp, a.backup())
}

const svcRunning = svc.Running

func (a *action) readSnapshot() (snapshot, error) {
	var s snapshot
	if e := rejectReparse(a.backup()); e != nil {
		return s, e
	}
	raw, e := os.ReadFile(a.backup())
	if e != nil {
		return s, e
	}
	if e = json.Unmarshal(raw, &s); e != nil {
		return s, e
	}
	if s.Values == nil || s.Run == nil {
		return s, errors.New("invalid snapshot")
	}
	return s, nil
}
func (a *action) removeAutostart() error {
	for _, view := range []uint32{registry.WOW64_64KEY, registry.WOW64_32KEY} {
		k, e := registry.OpenKey(registry.LOCAL_MACHINE, runKey, registry.SET_VALUE|view)
		if errors.Is(e, registry.ErrNotExist) {
			continue
		}
		if e != nil {
			return e
		}
		e = k.DeleteValue(runName)
		k.Close()
		if e != nil && !errors.Is(e, registry.ErrNotExist) {
			return e
		}
	}
	return nil
}
func (a *action) quiesce() error {
	if _, e := a.readSnapshot(); e != nil {
		return e
	}
	a.stage = "remove_legacy_autostart"
	if e := a.removeAutostart(); e != nil {
		return e
	}
	a.stage = "close_legacy_tray"
	if e := a.closeTray(); e != nil {
		return e
	}
	a.stage = "stop_previous_service"
	exe, e := serviceExecutable()
	if e != nil {
		return e
	}
	if exe != nil {
		if e = stopService(); e != nil {
			return e
		}
	}
	a.stage = "snapshot_stopped_state"
	return a.snapshotState()
}
func (a *action) apply() error {
	a.stage = "validate_credentials"
	if _, e := a.readSnapshot(); e != nil {
		return e
	}
	path := filepath.Join(a.dataRoot, "client-credentials.json")
	if e := rejectReparse(path); e != nil {
		return e
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	values, e := credentials(raw)
	clear(raw)
	if e != nil {
		return e
	}
	a.stage = "verify_service_path"
	exe, e := serviceExecutable()
	if e != nil {
		return e
	}
	if exe == nil || !strings.EqualFold(*exe, filepath.Join(a.installRoot, serviceExe)) {
		return errors.New("service path mismatch")
	}
	service, e := openKey(serviceKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if e != nil {
		return e
	}
	defer service.Close()
	a.stage = "protect_registry"
	k, _, e := registry.CreateKey(registry.LOCAL_MACHINE, configKey, registry.ALL_ACCESS|registry.WOW64_64KEY)
	if e != nil {
		return e
	}
	defer k.Close()
	if e = setACL(windows.Handle(k), windows.SE_REGISTRY_KEY, "D:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)"); e != nil {
		return e
	}
	a.stage = "write_control_configuration"
	for name, value := range values {
		if e = k.SetStringValue(name, value); e != nil {
			return e
		}
	}
	for name, value := range values {
		actual, _, e := k.GetStringValue(name)
		if e != nil || actual != value {
			return errors.New("registry verification failed")
		}
	}
	a.stage = "remove_stale_service_overrides"
	env, _, e := service.GetStringsValue("Environment")
	if e != nil && !errors.Is(e, registry.ErrNotExist) {
		return e
	}
	retained := []string{}
	for _, line := range env {
		if !controlOverride(line) {
			retained = append(retained, line)
		}
	}
	if len(retained) > 0 {
		e = service.SetStringsValue("Environment", retained)
	} else {
		e = service.DeleteValue("Environment")
		if errors.Is(e, registry.ErrNotExist) {
			e = nil
		}
	}
	if e != nil {
		return e
	}
	if e = installguard.Begin(a.dataRoot, a.transactionRoot); e != nil {
		return e
	}
	a.stage = "verify_preserved_state_before_start"
	if e = a.verifyPreservedState(false); e != nil {
		return e
	}
	a.stage = "remove_legacy_autostart"
	if e = a.removeAutostart(); e != nil {
		return e
	}
	a.stage = "confirm_legacy_tray_closed"
	return a.closeTray()
}
func (a *action) rollback() error {
	a.stage = "rollback_configuration"
	if _, e := os.Stat(a.backup()); errors.Is(e, os.ErrNotExist) {
		a.log("no_snapshot", "")
		return nil
	}
	s, e := a.readSnapshot()
	if e != nil {
		return e
	}
	exe, e := serviceExecutable()
	if e != nil {
		return e
	}
	if exe != nil {
		old := s.OldExecutable != nil && strings.EqualFold(*exe, *s.OldExecutable)
		if !old && !strings.EqualFold(*exe, filepath.Join(a.installRoot, serviceExe)) {
			return errors.New("unexpected rollback service")
		}
		if e = stopService(); e != nil {
			return e
		}
	}
	k, _, e := registry.CreateKey(registry.LOCAL_MACHINE, configKey, registry.ALL_ACCESS|registry.WOW64_64KEY)
	if e != nil {
		return e
	}
	defer k.Close()
	for name, v := range s.Values {
		if e = restoreValue(k, name, v); e != nil {
			return e
		}
	}
	if s.Dacl != nil {
		if e = setACL(windows.Handle(k), windows.SE_REGISTRY_KEY, *s.Dacl); e != nil {
			return e
		}
	}
	if exe != nil {
		service, e := openKey(serviceKey, registry.SET_VALUE)
		if e != nil {
			return e
		}
		if s.EnvironmentExists {
			e = service.SetStringsValue("Environment", s.Environment)
		} else {
			e = service.DeleteValue("Environment")
			if errors.Is(e, registry.ErrNotExist) {
				e = nil
			}
		}
		service.Close()
		if e != nil {
			return e
		}
	}
	for _, view := range []struct {
		name string
		flag uint32
	}{{"Registry64", registry.WOW64_64KEY}, {"Registry32", registry.WOW64_32KEY}} {
		v, ok := s.Run[view.name]
		if !ok {
			return errors.New("missing run snapshot")
		}
		run, _, e := registry.CreateKey(registry.LOCAL_MACHINE, runKey, registry.SET_VALUE|view.flag)
		if e != nil {
			return e
		}
		e = restoreValue(run, runName, v)
		run.Close()
		if e != nil {
			return e
		}
	}
	if e = a.restoreState(); e != nil {
		return e
	}
	if e = installguard.Release(a.dataRoot, a.transactionRoot); e != nil {
		return e
	}
	if s.WasRunning && exe != nil {
		a.stage = "restart_restored_service"
		if e = withService(func(s *mgr.Service) error {
			if e := s.Start(); e != nil {
				return e
			}
			return waitService(s, svc.Running, 30*time.Second)
		}); e != nil {
			return e
		}
		if e = a.verifyRestoredService(s); e != nil {
			return e
		}
	}
	// Retain recovery evidence without blocking a later attempt of the same MSI.
	recovered := filepath.Join(filepath.Dir(a.transactionRoot), "Recovered")
	if e = secureDirectory(recovered); e != nil {
		return e
	}
	if e = rejectReparse(a.transactionRoot); e != nil {
		return e
	}
	destination := filepath.Join(recovered, filepath.Base(a.transactionRoot)+"-"+time.Now().UTC().Format("20060102T150405.000000000"))
	return os.Rename(a.transactionRoot, destination)
}
func (a *action) cleanup() error {
	if e := rejectReparse(a.transactionRoot); e != nil {
		return e
	}
	return os.RemoveAll(a.transactionRoot)
}

func (a *action) closeTray() error {
	allowed := map[string]bool{strings.ToLower(filepath.Join(a.installRoot, trayExe)): true}
	old, e := serviceExecutable()
	if e != nil {
		return e
	}
	if old != nil {
		allowed[strings.ToLower(filepath.Join(filepath.Dir(*old), trayExe))] = true
	}
	snap, e := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if e != nil {
		return e
	}
	defer windows.CloseHandle(snap)
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	e = windows.Process32First(snap, &entry)
	for e == nil {
		if strings.EqualFold(windows.UTF16ToString(entry.ExeFile[:]), trayExe) {
			h, he := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, entry.ProcessID)
			if he != nil {
				return he
			}
			buf := make([]uint16, 32768)
			n := uint32(len(buf))
			he = windows.QueryFullProcessImageName(h, 0, &buf[0], &n)
			if he != nil {
				windows.CloseHandle(h)
				return he
			}
			if allowed[strings.ToLower(windows.UTF16ToString(buf[:n]))] {
				user32 := windows.NewLazySystemDLL("user32.dll")
				enum := user32.NewProc("EnumWindows")
				getpid := user32.NewProc("GetWindowThreadProcessId")
				post := user32.NewProc("PostMessageW")
				callback := windows.NewCallback(func(hwnd, extra uintptr) uintptr {
					var pid uint32
					getpid.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
					if pid == entry.ProcessID {
						post.Call(hwnd, 0x0010, 0, 0)
					}
					return 1
				})
				enum.Call(callback, 0)
				wait, we := windows.WaitForSingleObject(h, 5000)
				if we != nil {
					windows.CloseHandle(h)
					return we
				}
				if wait == uint32(windows.WAIT_TIMEOUT) {
					if he = windows.TerminateProcess(h, 1); he != nil {
						windows.CloseHandle(h)
						return he
					}
					wait, we = windows.WaitForSingleObject(h, 10000)
					if we != nil || wait != windows.WAIT_OBJECT_0 {
						windows.CloseHandle(h)
						return errors.New("tray shutdown timeout")
					}
				}
			}
			windows.CloseHandle(h)
		}
		e = windows.Process32Next(snap, &entry)
	}
	if !errors.Is(e, windows.ERROR_NO_MORE_FILES) {
		return e
	}
	return nil
}
