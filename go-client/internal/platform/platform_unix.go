//go:build !windows

package platform

import (
	"context"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

func DefaultDataRoot() string                           { return "/Library/Application Support/SF/EndpointAIProxy" }
func ReadMachineSetting(name string) (string, error)    { return "", nil }
func IsElevated() (bool, error)                         { return os.Geteuid() == 0, nil }
func ResolveUserID(sid string) string                   { return strings.TrimPrefix(sid, "macos:") }
func RefreshUserIDs(ctx context.Context, sids []string) {}
func Profiles(ctx context.Context) ([]Profile, error)   { return ProfilesAt(ctx, "/Users") }

// ProfilesAt allows fixture testing without inspecting real users' private data.
func ProfilesAt(ctx context.Context, root string) ([]Profile, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	profiles := []Profile{}
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") || e.Name() == "Guest" || e.Name() == "Shared" {
			continue
		}
		home := filepath.Join(root, e.Name())
		profiles = append(profiles, Profile{SID: "macos:" + e.Name(), Home: home, Roaming: filepath.Join(home, "Library", "Application Support"), Local: filepath.Join(home, "Library", "Caches"), SearchPaths: []string{filepath.Join(home, ".local", "bin"), filepath.Join(home, ".npm-global", "bin"), filepath.Join(home, ".volta", "bin"), filepath.Join(home, ".nvm", "current", "bin"), "/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"}})
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].SID < profiles[j].SID })
	return profiles, nil
}
func RunService(name string, run func(context.Context) error) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return run(ctx)
}
