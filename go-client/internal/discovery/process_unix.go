//go:build !windows

package discovery

import (
	"context"
	"endpointai/client/internal/platform"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func processSamples(ctx context.Context, profiles []platform.Profile) ([]sample, error) {
	return processSamplesWithArgs(ctx, profiles, nativeProcessArgs)
}

func processSamplesWithArgs(ctx context.Context, profiles []platform.Profile, readArgs func(context.Context, int) ([]string, error)) ([]sample, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	// Numeric UID avoids ps' display-width truncation of long account names.
	// Only real Mac profiles use home ownership; isolated fake-SID fixtures
	// continue to associate processes by their verified script path.
	owners, ownerUnknown := unixProfileOwners(profiles)
	uncertain := func(uid, path string) []sample {
		var out []sample
		for _, p := range profiles {
			owner, known := owners[p.SID]
			if known && owner == uid || ownerUnknown[p.SID] || strings.HasPrefix(path, p.Home+"/") {
				out = append(out, sample{sid: p.SID, inspectionUnknown: true})
			}
		}
		return out
	}
	b, e := exec.CommandContext(ctx, "/bin/ps", "-axo", "pid=,uid=,comm=").Output()
	if e != nil {
		return nil, e
	}
	out := []sample{}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		path := strings.Join(fields[2:], " ")
		kind, ok := processKind(path)
		version := ""
		launchProfile := ""
		launchUnknown := true
		strength := 2
		if isNodeExecutable(path) {
			pid, parseErr := strconv.Atoi(fields[0])
			var args []string
			var argsErr error
			if parseErr == nil {
				args, argsErr = readArgs(ctx, pid)
			} else {
				argsErr = parseErr
			}
			if argsErr == nil && len(args) > 0 {
				if entry, v, valid := dshNodeEntry(args); valid {
					launchProfile, launchUnknown = dshLaunchProfile(args)
					path = entry
					version = v
					kind = DeepSeekHarness
					ok = true
				} else if nodeArgumentsUncertain(args) {
					out = append(out, uncertain(fields[1], path)...)
				}
			} else if !processGone(argsErr) {
				out = append(out, uncertain(fields[1], path)...)
			}
		}
		if kind == DeepSeekHarness && version == "" && !dshDesktopProcess(path) {
			strength = 1
		}
		if !ok {
			continue
		}
		for _, p := range profiles {
			owner, known := owners[p.SID]
			if known && owner == fields[1] || strings.HasPrefix(path, p.Home+"/") {
				out = append(out, sample{sid: p.SID, kind: kind, collector: "running-process", path: path + " (PID " + fields[0] + ")", strength: strength, version: version, launchProfile: launchProfile, launchOverridesUnknown: launchUnknown})
				break
			}
		}
	}
	return out, ctx.Err()
}

func unixProfileOwners(profiles []platform.Profile) (map[string]string, map[string]bool) {
	owners, unknown := map[string]string{}, map[string]bool{}
	for _, p := range profiles {
		if !strings.HasPrefix(p.SID, "macos:") {
			continue
		}
		info, err := os.Lstat(p.Home)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			unknown[p.SID] = true
			continue
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			unknown[p.SID] = true
			continue
		}
		owners[p.SID] = strconv.FormatUint(uint64(owner.Uid), 10)
	}
	return owners, unknown
}
