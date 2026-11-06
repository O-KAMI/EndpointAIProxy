package contracts

import (
	"encoding/json"
	"testing"
)

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
