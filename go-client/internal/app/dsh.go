package app

import (
	"endpointai/client/internal/contracts"
	"strings"
)

// DSH provider identities include the protocol; never infer a DSH wire API from
// another agent family or from the destination host.
func endpointWireAPI(family, provider string) contracts.AgentWireApi {
	switch family {
	case "claude":
		return contracts.AgentWireApiAnthropicMessages
	case "codex":
		return contracts.AgentWireApiOpenAiResponses
	case "deepseekHarness":
		parts := strings.Split(provider, ":")
		if len(parts) != 4 || parts[0] != "dsh" {
			return contracts.AgentWireApiUnknown
		}
		switch parts[1] {
		case "messages":
			return contracts.AgentWireApiAnthropicMessages
		case "responses":
			return contracts.AgentWireApiOpenAiResponses
		case "chat":
			return contracts.AgentWireApiChatCompletions
		}
	}
	return contracts.AgentWireApiUnknown
}
