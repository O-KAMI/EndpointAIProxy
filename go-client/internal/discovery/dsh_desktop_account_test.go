package discovery

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestDesktopAccountRequiresMatchingPackagedPlugins(t *testing.T) {
	for _, test := range []struct {
		version, changedPlugin string
		want                   bool
	}{
		// Manifest-only fixtures carry no reviewed implementation contract.
		{"0.2.1-rc.2", "", false},
		{"0.2.1-rc.3", "", false},
		{"0.2.1-rc.4", "", false},
		{"0.2.1-rc.3", "dsh-desktop-host", false},
		{"0.2.1-rc.3", "dsh-app-boot", false},
		{"0.2.1-rc.3", "dsh-deepseek-account-platform", false},
		{"0.2.1-rc.3", "dsh-llm-deepseek-account", false},
	} {
		t.Run(test.version+test.changedPlugin, func(t *testing.T) {
			root := t.TempDir()
			files := map[string]any{}
			var body []byte
			add := func(path, name, version string) {
				content, _ := json.Marshal(map[string]string{"name": name, "version": version})
				parts := strings.Split(path, "/")
				node := files
				for _, part := range parts[:len(parts)-1] {
					if node[part] == nil {
						node[part] = map[string]any{"files": map[string]any{}}
					}
					node = node[part].(map[string]any)["files"].(map[string]any)
				}
				node[parts[len(parts)-1]] = map[string]any{"size": len(content), "offset": strconv.Itoa(len(body))}
				body = append(body, content...)
			}
			add("package.json", "@deepseek-ai/dsh-desktop", test.version)
			for _, name := range []string{"dsh-desktop-host", "dsh-app-boot", "dsh-deepseek-account-platform", "dsh-llm-deepseek-account"} {
				version := test.version
				if name == test.changedPlugin {
					version = "0.2.1-rc.2"
				}
				add("dsh/node_modules/@deepseek-ai/"+name+"/package.json", "@deepseek-ai/"+name, version)
			}
			header, _ := json.Marshal(map[string]any{"files": files})
			headerSize := 8 + len(header) + (4-len(header)%4)%4
			archive := make([]byte, 8+headerSize)
			binary.LittleEndian.PutUint32(archive[0:4], 4)
			binary.LittleEndian.PutUint32(archive[4:8], uint32(headerSize))
			binary.LittleEndian.PutUint32(archive[8:12], uint32(headerSize-4))
			binary.LittleEndian.PutUint32(archive[12:16], uint32(len(header)))
			copy(archive[16:], header)
			archive = append(archive, body...)
			writeDSHFixture(t, filepath.Join(root, "resources", "app.asar"), string(archive))
			if err := os.MkdirAll(filepath.Join(root, "resources", "runtime", "primary-runtime"), 0700); err != nil {
				t.Fatal(err)
			}
			version, verified := dshDesktopAccountRuntime(filepath.Join(root, "Desktop.exe"))
			if verified != test.want || verified && version != test.version {
				t.Fatal("packaged account gate", version, verified)
			}
		})
	}
}
