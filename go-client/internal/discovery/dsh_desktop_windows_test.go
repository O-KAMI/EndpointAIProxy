package discovery

import (
	"path/filepath"
	"testing"
)

func TestDesktopHostRequiresPackagedLaunchShape(t *testing.T) {
	executable := filepath.Join(t.TempDir(), "应用", "DeepSeek Harness.exe")
	home := filepath.Join(t.TempDir(), "用户")
	resources := filepath.Join(filepath.Dir(executable), "resources")
	args := []string{executable, "--expose-internals",
		filepath.Join(resources, "app.asar", "dsh", "node_modules", "@deepseek-ai", "dsh-desktop-host", "lib", "index.js"),
		filepath.Join(resources, "app.asar", "dsh"), filepath.Join(home, ".dsh", "profiles", "desktop"),
		filepath.Join(resources, "runtime", "primary-runtime"),
		filepath.Join(resources, "runtime", "primary-runtime", "dependencies", "pnpm", "bin", "pnpm.mjs"),
		filepath.Join(resources, "runtime", "bin")}
	if !dshDesktopHostArgs(executable, home, args) {
		t.Fatal("packaged Desktop host rejected")
	}
	for index := range args {
		changed := append([]string{}, args...)
		changed[index] += "-override"
		if dshDesktopHostArgs(executable, home, changed) {
			t.Fatalf("unknown argument %d accepted", index)
		}
	}
	if dshDesktopHostArgs(executable, home, append(args, "--patch-file=unknown.yml")) {
		t.Fatal("extra overlay accepted")
	}
}
