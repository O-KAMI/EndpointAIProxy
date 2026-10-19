package discovery

import (
	"context"
	"endpointai/client/internal/platform"
	"golang.org/x/sys/windows/registry"
	"strings"
)

func installedSamples(ctx context.Context, profiles []platform.Profile) ([]sample, error) {
	out := []sample{}
	const uninstall = `Software\Microsoft\Windows\CurrentVersion\Uninstall`
	for _, p := range profiles {
		for _, view := range []uint32{registry.WOW64_64KEY, registry.WOW64_32KEY} {
			for _, loc := range []struct {
				hive registry.Key
				path string
			}{{registry.LOCAL_MACHINE, uninstall}, {registry.USERS, p.SID + `\` + uninstall}} {
				if e := ctx.Err(); e != nil {
					return nil, e
				}
				root, e := registry.OpenKey(loc.hive, loc.path, registry.READ|view)
				if e != nil {
					continue
				}
				names, e := root.ReadSubKeyNames(-1)
				if e != nil {
					root.Close()
					continue
				}
				for _, name := range names {
					product, e := registry.OpenKey(root, name, registry.QUERY_VALUE)
					if e != nil {
						continue
					}
					display, _, _ := product.GetStringValue("DisplayName")
					publisher, _, _ := product.GetStringValue("Publisher")
					kind := -1
					d, pub := strings.ToLower(display), strings.ToLower(publisher)
					switch {
					case strings.Contains(d, "cc switch"):
						kind = CCSwitch
					case strings.Contains(d, "claude") && strings.Contains(pub, "anthropic"):
						kind = ClaudeDesktop
					case (strings.Contains(d, "codex") || strings.Contains(d, "chatgpt")) && strings.Contains(pub, "openai"):
						kind = CodexDesktop
					}
					if kind >= 0 {
						path, _, _ := product.GetStringValue("DisplayIcon")
						if path == "" {
							path, _, _ = product.GetStringValue("InstallLocation")
						}
						if path == "" {
							path = "registry::" + loc.path + `\` + name
						}
						version, _, _ := product.GetStringValue("DisplayVersion")
						out = append(out, sample{sid: p.SID, kind: kind, collector: "installed-application", path: path, version: version, strength: 2, method: 1})
					}
					product.Close()
				}
				root.Close()
			}
		}
	}
	return out, nil
}
