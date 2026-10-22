package discovery

import "testing"

func TestDesktopAccountProvenanceIsScopedToVerifiedHost(t *testing.T) {
	host := sample{sid: "user", kind: DeepSeekHarness, launchProfile: "desktop", desktopAccount: true, desktopHost: true}
	main := sample{sid: "user", kind: DeepSeekHarness, launchProfile: "desktop", desktopAccount: true}
	for _, test := range []struct {
		name    string
		samples []sample
		want    bool
	}{
		{"host", []sample{main, host}, true},
		{"main alone", []sample{main}, false},
		{"unidentified node", []sample{host, {sid: "user", inspectionUnknown: true}}, true},
		{"unknown host arguments", []sample{main, {sid: "user", kind: DeepSeekHarness, launchOverridesUnknown: true}}, false},
		{"confirmed desktop overlay", []sample{host, {sid: "user", kind: DeepSeekHarness, launchProfile: "desktop", launchOverridesUnknown: true}}, false},
		{"known other profile", []sample{host, {sid: "user", kind: DeepSeekHarness, launchProfile: "other"}}, true},
		{"other user", []sample{{sid: "other", kind: DeepSeekHarness, desktopAccount: true, desktopHost: true}}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := desktopAccountProvenance(test.samples, "user"); got != test.want {
				t.Fatalf("got %t, want %t", got, test.want)
			}
		})
	}
}
