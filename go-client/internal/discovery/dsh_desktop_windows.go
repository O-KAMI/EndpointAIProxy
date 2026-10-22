package discovery

import (
	"endpointai/client/internal/platform"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"path/filepath"
	"strings"
)

func dshInstalledResources(p platform.Profile) []string {
	if _, err := windows.StringToSid(p.SID); err != nil {
		return nil
	}
	const uninstall = `Software\Microsoft\Windows\CurrentVersion\Uninstall`
	var roots []string
	for _, view := range []uint32{registry.WOW64_64KEY, registry.WOW64_32KEY} {
		for _, hive := range []struct {
			key  registry.Key
			path string
		}{{registry.LOCAL_MACHINE, uninstall}, {registry.USERS, p.SID + `\` + uninstall}} {
			root, err := registry.OpenKey(hive.key, hive.path, registry.READ|view)
			if err != nil {
				continue
			}
			names, _ := root.ReadSubKeyNames(-1)
			for _, name := range names {
				product, err := registry.OpenKey(root, name, registry.QUERY_VALUE)
				if err != nil {
					continue
				}
				display, _, _ := product.GetStringValue("DisplayName")
				location, _, _ := product.GetStringValue("InstallLocation")
				product.Close()
				if strings.HasPrefix(display, "DeepSeek Harness") && filepath.IsAbs(location) {
					roots = append(roots, filepath.Join(location, "resources"))
				}
			}
			root.Close()
		}
	}
	return roots
}
