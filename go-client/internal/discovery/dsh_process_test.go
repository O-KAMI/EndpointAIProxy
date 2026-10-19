package discovery

import (
	"context"
	"endpointai/client/internal/platform"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestRealDSHNodeLaunchWithSpacesAndChinese(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node unavailable")
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(base, "中文 has spaces")
	pkg := filepath.Join(home, ".local/bin/node_modules/@deepseek-ai/dsh")
	writeDSHFixture(t, filepath.Join(pkg, "package.json"), `{"name":"@deepseek-ai/dsh","version":"0.2.1-alpha.5","bin":{"dsh":"lib/bin.js"}}`)
	entry := filepath.Join(pkg, "lib/bin.js")
	writeDSHFixture(t, entry, "setInterval(()=>{},1000)")
	writeDSHFixture(t, filepath.Join(home, ".dsh/profiles/web/package.json"), `{"dsh":{"profile":{"bundles":["@deepseek-ai/dsh-base"]}}}`)
	p := platform.Profile{SID: "fixture", Home: home}
	for _, tc := range []struct {
		name    string
		tail    []string
		unknown bool
	}{{"standard", []string{"web"}, false}, {"overlay", []string{"web", "--patch", "overlay 有 空格.yml"}, true}} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(node, append([]string{entry}, tc.tail...)...)
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { cmd.Process.Kill(); cmd.Wait() }()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			for {
				samples, e := processSamples(ctx, []platform.Profile{p})
				if e != nil {
					t.Fatal(e)
				}
				seen := false
				for _, s := range samples {
					if s.sid == p.SID && s.kind == DeepSeekHarness && s.collector == "running-process" {
						seen = true
					}
				}
				if seen {
					md := DSHProfileMetadata(ctx, []platform.Profile{p}, nil)[p.SID]
					if md.Version != DSHSupportedVersion || md.OverlaysUnknown != tc.unknown {
						t.Fatalf("incorrect metadata: %+v", md)
					}
					return
				}
				select {
				case <-ctx.Done():
					t.Fatal("Node-hosted DSH not discovered")
				case <-time.After(25 * time.Millisecond):
				}
			}
		})
	}
}

func TestIncompleteProcessOwnershipIsConservative(t *testing.T) {
	profiles := []platform.Profile{{SID: "one", Home: filepath.FromSlash("/users/one")}, {SID: "two", Home: filepath.FromSlash("/users/two")}}
	if got := uncertainProcessSamples(profiles, "one", ""); len(got) != 1 || got[0].sid != "one" || !got[0].inspectionUnknown {
		t.Fatal("known owner uncertainty not scoped")
	}
	if got := uncertainProcessSamples(profiles, "", ""); len(got) != 2 {
		t.Fatal("unknown owner treated as complete")
	}
}

func TestUnknownNodeInvocationIsNotTreatedAsAbsence(t *testing.T) {
	for _, args := range [][]string{{"node"}, {"node", "--inspect", filepath.Join(t.TempDir(), "script.js")}, {"node", "relative-script.js"}, {"node", filepath.Join(t.TempDir(), "node_modules/@deepseek-ai/dsh/lib/bin.js")}} {
		if !nodeArgumentsUncertain(args) {
			t.Fatal("unsupported Node invocation considered complete")
		}
	}
	if nodeArgumentsUncertain([]string{"node", filepath.Join(t.TempDir(), "ordinary-script.js")}) {
		t.Fatal("ordinary absolute Node script marked as DSH")
	}
}
