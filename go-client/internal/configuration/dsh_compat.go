package configuration

import "strings"

// This conservative gate follows pi-ai 1.3.0's three HTTP wire implementations
// (api/openai-completions, api/openai-responses and api/anthropic-messages).
// Rewriting a generic endpoint to loopback leaves each URL detection branch
// false, while existing explicit compat/model options remain unchanged. Catalog
// providers and URLs triggering vendor-specific behavior require a separate
// compatibility proof and are deliberately not rewritten.
func dshCustomURLCompatibility(provider, baseURL string) string {
	catalog := "amazon-bedrock ant-ling anthropic azure baseten cerebras cloudflare-ai-gateway cloudflare-workers-ai deepseek fireworks github-copilot google google-vertex groq huggingface kimi-coding meta minimax minimax-cn mistral moonshotai moonshotai-cn nvidia openai openai-codex opencode opencode-go openrouter qwen-token-plan qwen-token-plan-cn qwen-token-plan-individual radius together typesafe vercel-ai-gateway xai xiaomi xiaomi-token-plan-ams xiaomi-token-plan-cn xiaomi-token-plan-sgp zai zai-coding-cn"
	for _, id := range strings.Fields(catalog) {
		if provider == id {
			return "DSH_CATALOG_PROVIDER_UNSUPPORTED"
		}
	}
	lower := strings.ToLower(baseURL)
	for _, marker := range []string{"api.openai.com", "api.z.ai", "open.bigmodel.cn", "api.together.ai", "api.together.xyz", "api.moonshot.", "openrouter.ai", "api.cloudflare.com", "gateway.ai.cloudflare.com", "integrate.api.nvidia.com", "api.ant-ling.com", "cerebras.ai", "deepseek.com", "api.x.ai", "chutes.ai", "opencode.ai"} {
		if strings.Contains(lower, marker) {
			return "DSH_CUSTOM_URL_COMPAT_UNVERIFIED"
		}
	}
	return ""
}
