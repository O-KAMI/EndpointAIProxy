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

func TestReviewedDesktopContractIsIndependentOfProductVersion(t *testing.T) {
	executable := os.Getenv("SF_PROXY_DSH_PACKAGE_TEST_EXECUTABLE")
	if executable == "" {
		t.Skip("official package fixture not supplied")
	}
	original := filepath.Join(filepath.Dir(executable), "resources", "app.asar")
	for _, version := range []string{"0.2.1-rc.3", "0.2.1-rc.4", "9.0.0"} {
		t.Run(version, func(t *testing.T) {
			files := map[string]any{}
			var body []byte
			add := func(path string, content []byte) {
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
			add("package.json", []byte(`{"name":"@deepseek-ai/dsh-desktop","version":"`+version+`"}`))
			for _, name := range []string{"dsh-llm-deepseek-account", "dsh-deepseek-account-platform", "dsh-desktop-host", "dsh-app-boot"} {
				base := "dsh/node_modules/@deepseek-ai/" + name + "/"
				add(base+"package.json", []byte(`{"name":"@deepseek-ai/`+name+`","version":"independent-plugin-release"}`))
				module, err := dshASARFile(original, base+"lib/index.js")
				if err != nil {
					t.Fatal(err)
				}
				add(base+"lib/index.js", module)
			}
			header, _ := json.Marshal(map[string]any{"files": files})
			size := 8 + len(header) + (4-len(header)%4)%4
			archive := make([]byte, 8+size)
			binary.LittleEndian.PutUint32(archive, 4)
			binary.LittleEndian.PutUint32(archive[4:], uint32(size))
			binary.LittleEndian.PutUint32(archive[8:], uint32(size-4))
			binary.LittleEndian.PutUint32(archive[12:], uint32(len(header)))
			copy(archive[16:], header)
			archive = append(archive, body...)
			root := t.TempDir()
			writeDSHFixture(t, filepath.Join(root, "resources", "app.asar"), string(archive))
			if err := os.MkdirAll(filepath.Join(root, "resources", "runtime", "primary-runtime"), 0700); err != nil {
				t.Fatal(err)
			}
			got, verified := dshDesktopAccountRuntime(filepath.Join(root, "Desktop.exe"))
			if !verified || got != version {
				t.Fatal("release label overrode a reviewed contract", got, verified)
			}
		})
	}
	if reviewedDesktopModule("dsh-llm-deepseek-account", []byte("unknown implementation")) {
		t.Fatal("unreviewed implementation accepted")
	}
}
