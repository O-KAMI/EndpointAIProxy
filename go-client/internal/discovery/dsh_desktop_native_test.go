package discovery

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"endpointai/client/internal/platform"
)

// Explicitly opt in to read-only verification of an already installed Desktop.
func TestInstalledWindowsDesktopAccountRuntime(t *testing.T) {
	executable := os.Getenv("SF_PROXY_DSH_NATIVE_TEST_EXECUTABLE")
	if executable == "" || runtime.GOOS != "windows" {
		t.Skip("native Desktop fixture not requested")
	}
	version, verified := dshDesktopAccountRuntime(executable)
	if !verified || version != "0.2.1-rc.2" {
		t.Fatal("installed Desktop account runtime not verified", version)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	profiles, err := platform.Profiles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, profile := range profiles {
		if filepath.Clean(profile.Home) == filepath.Clean(os.Getenv("USERPROFILE")) {
			metadata := DSHProfileMetadata(ctx, []platform.Profile{profile}, nil)[profile.SID]
			if !metadata.DesktopAccountVerified {
				t.Fatalf("Desktop launch provenance not verified: %+v", metadata)
			}
			return
		}
	}
	t.Fatal("current Windows profile was not enumerated")
}
