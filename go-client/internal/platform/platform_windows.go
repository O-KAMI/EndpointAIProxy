package platform

import (
	"context"
	"encoding/json"
	"endpointai/client/internal/observability"
	"errors"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
)

func DefaultDataRoot() string {
	return filepath.Join(os.Getenv("ProgramData"), "SF", "EndpointAIProxy")
}
func IsElevated() (bool, error) {
	var t windows.Token
	if e := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &t); e != nil {
		return false, e
	}
	defer t.Close()
	return t.IsElevated(), nil
}
func ResolveUserID(sid string) string {
	return cachedUserIDs.resolve(sid)
}

// RefreshUserIDs schedules bounded native lookups outside the request path.
// Cancellation stops scheduling and discards late results; Windows' synchronous
// LookupAccount API cannot itself be interrupted, so shutdown never waits for it.
func RefreshUserIDs(ctx context.Context, sids []string) {
	cachedUserIDs.refresh(ctx, sids, lookupUserID)
}

var cachedUserIDs = newUserIDCache(4096, 4)

func lookupUserID(sid string) (string, error) {
	s, e := windows.StringToSid(sid)
	if e != nil {
		return "", e
	}
	account, domain, _, e := s.LookupAccount("")
	if e != nil || strings.TrimSpace(account) == "" {
		if e == nil {
			e = errors.New("ACCOUNT_NAME_UNAVAILABLE")
		}
		return "", e
	}
	if strings.EqualFold(domain, "SF") || domain == "" {
		return account, nil
	}
	return domain + `\` + account, nil
}
func ReadMachineSetting(name string) (string, error) {
	k, e := registry.OpenKey(registry.LOCAL_MACHINE, `Software\SF\EndpointAIProxy`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if errors.Is(e, registry.ErrNotExist) {
		return "", nil
	}
	if e != nil {
		return "", e
	}
	defer k.Close()
	s, _, e := k.GetStringValue(name)
	if errors.Is(e, registry.ErrNotExist) {
		return "", nil
	}
	return s, e
}
func expand(v string, p Profile) string {
	for _, pair := range [][2]string{{"%USERPROFILE%", p.Home}, {"%APPDATA%", p.Roaming}, {"%LOCALAPPDATA%", p.Local}, {"%SystemRoot%", os.Getenv("SystemRoot")}, {"%SystemDrive%", os.Getenv("SystemDrive")}, {"%ProgramFiles%", os.Getenv("ProgramFiles")}} {
		for {
			i := strings.Index(strings.ToLower(v), strings.ToLower(pair[0]))
			if i < 0 {
				break
			}
			v = v[:i] + pair[1] + v[i+len(pair[0]):]
		}
	}
	return v
}
func Profiles(ctx context.Context) ([]Profile, error) {
	k, e := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`, registry.READ|registry.WOW64_64KEY)
	if e != nil {
		return nil, e
	}
	defer k.Close()
	names, e := k.ReadSubKeyNames(-1)
	if e != nil {
		return nil, e
	}
	out := []Profile{}
	for _, sid := range names {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		if !strings.HasPrefix(sid, "S-1-5-21-") || strings.HasSuffix(strings.ToLower(sid), ".bak") {
			continue
		}
		s, e := registry.OpenKey(k, sid, registry.QUERY_VALUE)
		if e != nil {
			continue
		}
		home, _, e := s.GetStringValue("ProfileImagePath")
		s.Close()
		home = expand(home, Profile{})
		if e != nil || !filepath.IsAbs(home) {
			continue
		}
		st, e := os.Stat(home)
		if e != nil || !st.IsDir() {
			continue
		}
		p := Profile{SID: sid, Home: home, Roaming: filepath.Join(home, "AppData", "Roaming"), Local: filepath.Join(home, "AppData", "Local")}
		for _, folder := range []struct {
			name   string
			target *string
		}{{"AppData", &p.Roaming}, {"Local AppData", &p.Local}} {
			for _, base := range []string{`Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`, `Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`} {
				h, e := registry.OpenKey(registry.USERS, sid+`\`+base, registry.QUERY_VALUE)
				if e != nil {
					continue
				}
				v, _, e := h.GetStringValue(folder.name)
				h.Close()
				v = expand(v, p)
				if e == nil && filepath.IsAbs(v) {
					*folder.target = v
					break
				}
			}
		}
		p.SearchPaths = []string{filepath.Join(p.Roaming, "npm"), filepath.Join(p.Local, "npm")}
		for _, loc := range []struct {
			h    registry.Key
			path string
		}{{registry.USERS, sid + `\Environment`}, {registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`}} {
			h, e := registry.OpenKey(loc.h, loc.path, registry.QUERY_VALUE)
			if e != nil {
				continue
			}
			v, _, e := h.GetStringValue("Path")
			h.Close()
			if e != nil {
				continue
			}
			for _, path := range strings.Split(v, ";") {
				path = strings.Trim(expand(strings.TrimSpace(path), p), `"`)
				if filepath.IsAbs(path) {
					p.SearchPaths = append(p.SearchPaths, path)
				}
			}
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SID < out[j].SID })
	return out, nil
}

type handler struct {
	run func(context.Context) error
	err error
}

func (h *handler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	status <- svc.Status{State: svc.StartPending}
	done := make(chan error, 1)
	go func() { done <- h.run(ctx) }()
	current := svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	status <- current
	for {
		select {
		case e := <-done:
			h.err = e
			if e != nil {
				if output, logErr := eventlog.Open("SfEndpointAIProxy"); logErr == nil {
					fields := observability.Fields(observability.Classify(e))
					if fields["errorCode"] == nil {
						fields["errorCode"] = "CLIENT_START_FAILED"
					}
					data, _ := json.Marshal(fields)
					_ = output.Error(1001, string(data))
					_ = output.Close()
				}
				return true, StartupCode(e)
			}
			return false, 0
		case r := <-requests:
			switch r.Cmd {
			case svc.Interrogate:
				status <- current
			case svc.Stop, svc.Shutdown:
				current = svc.Status{State: svc.StopPending}
				status <- current
				cancel()
			}
		}
	}
}
func RunService(name string, run func(context.Context) error) error {
	service, e := svc.IsWindowsService()
	if e != nil {
		return e
	}
	if !service {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		return run(ctx)
	}
	h := &handler{run: run}
	if e := svc.Run(name, h); e != nil {
		return e
	}
	return h.err
}
