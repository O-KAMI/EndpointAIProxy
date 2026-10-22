//go:build !windows

package discovery

import "endpointai/client/internal/platform"

func dshInstalledResources(platform.Profile) []string { return nil }
