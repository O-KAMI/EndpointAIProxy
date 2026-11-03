package contracts

import (
	"encoding/json"
	"testing"
)

func TestDSHDesktopAccountVersionPins(t *testing.T) {
	for _, version := range []string{"0.2.1-rc.2", "0.2.1-rc.3"} {
		if !DSHDesktopAccountVersionSupported(version) {
			t.Fatal("reviewed Desktop rejected", version)
		}
	}
	for _, version := range []string{"", "0.2.1-alpha.5", "0.2.1-rc.4", "0.2.1", "0.2.1-rc.3-nightly", "0.2.1-rc.3 ", "v0.2.1-rc.3"} {
		if DSHDesktopAccountVersionSupported(version) {
			t.Fatal("unreviewed Desktop accepted", version)
		}
	}
}

func TestAgentTypeDSHAppendOnly(t *testing.T) {
	legacy := []string{"claudeCode", "codexCli", "qoderCli", "qoderIde", "ccSwitch", "unknownCandidate", "codexIde", "codexDesktop", "claudeCli", "claudeIde", "claudeDesktop"}
	for i, name := range legacy {
		b, err := json.Marshal(AgentType(i))
		if err != nil || string(b) != `"`+name+`"` {
			t.Fatalf("legacy %d changed: %s %v", i, b, err)
		}
	}
	for _, input := range []string{`11`, `"deepseekHarness"`} {
		var got AgentType
		if err := json.Unmarshal([]byte(input), &got); err != nil || got != AgentTypeDeepSeekHarness {
			t.Fatalf("%s: %d %v", input, got, err)
		}
	}
}
