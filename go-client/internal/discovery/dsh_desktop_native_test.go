package discovery

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"endpointai/client/internal/contracts"
	"endpointai/client/internal/platform"
)

func TestWindowsDesktopPackageIdentity(t *testing.T) {
	executable := os.Getenv("SF_PROXY_DSH_PACKAGE_TEST_EXECUTABLE")
	if executable == "" || runtime.GOOS != "windows" {
		t.Skip("read-only packaged Desktop fixture not requested")
	}
	version, verified := dshDesktopAccountRuntime(executable)
	if !verified || version != os.Getenv("SF_PROXY_DSH_PACKAGE_TEST_VERSION") {
		t.Fatal("packaged Desktop identity not verified", version)
	}
}

// Explicitly opt in to read-only verification of an already installed Desktop.
func TestInstalledWindowsDesktopAccountRuntime(t *testing.T) {
	executable := os.Getenv("SF_PROXY_DSH_NATIVE_TEST_EXECUTABLE")
	if executable == "" || runtime.GOOS != "windows" {
		t.Skip("native Desktop fixture not requested")
	}
	version, verified := dshDesktopAccountRuntime(executable)
	if !verified || !contracts.DSHDesktopAccountVersionSupported(version) {
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
				samples, scanErr := processSamples(ctx, []platform.Profile{profile})
				t.Logf("process inspection failed=%t", scanErr != nil)
				for _, s := range samples {
					t.Logf("kind=%d desktopProfile=%t overlayUnknown=%t inspectionUnknown=%t desktopRuntime=%t desktopHost=%t", s.kind, s.launchProfile == "desktop", s.launchOverridesUnknown, s.inspectionUnknown, s.desktopAccount, s.desktopHost)
				}
				t.Fatalf("Desktop launch provenance not verified: %+v", metadata)
			}
			return
		}
	}
	t.Fatal("current Windows profile was not enumerated")
}
