package platform

import "testing"

func TestShortAccountNamesKeepSIDSeparate(t *testing.T) {
	for input, want := range map[string]string{`SF\01443343`: "01443343", "SF/01443343": "01443343", `HOST\local-admin`: "local-admin", "local-admin": "local-admin", "macos:alice": "alice", "S-1-5-21-123": "", "": ""} {
		if got := ShortAccountName(input); got != want {
			t.Fatalf("account normalization: %q -> %q", input, got)
		}
	}
}
