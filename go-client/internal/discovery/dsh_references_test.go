package discovery

import "testing"

func TestDesktopReferenceScopeExcludesOtherDSHLaunches(t *testing.T) {
	const sid = "fixture-sid"
	host := sample{sid: sid, kind: DeepSeekHarness, desktopHost: true, desktopAccount: true}
	for _, tt := range []struct {
		name  string
		other sample
		want  bool
	}{
		{"unidentified-node", sample{sid: sid, kind: UnknownCandidate, inspectionUnknown: true}, true},
		{"other-dsh-profile", sample{sid: sid, kind: DeepSeekHarness, launchProfile: "web"}, false},
		{"uninspected-dsh", sample{sid: sid, kind: DeepSeekHarness, inspectionUnknown: true}, false},
		{"other-user", sample{sid: "other-sid", kind: DeepSeekHarness, launchOverridesUnknown: true}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := desktopReferenceScopeKnown([]sample{host, tt.other}, sid); got != tt.want {
				t.Fatal(got)
			}
		})
	}
}
