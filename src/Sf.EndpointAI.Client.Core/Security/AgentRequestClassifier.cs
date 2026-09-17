using Sf.EndpointAI.Client.Core.Routing;
using Sf.EndpointAI.Contracts;

namespace Sf.EndpointAI.Client.Core.Security;

public static class AgentRequestClassifier
{
    public static string GetFamily(RouteRecord route)
    {
        ArgumentNullException.ThrowIfNull(route);
        if (route.AgentType == AgentType.CcSwitch)
        {
            if (route.ProviderId.StartsWith("claude:", StringComparison.OrdinalIgnoreCase))
            {
                return "ClaudeCode";
            }

            if (route.ProviderId.StartsWith("codex:", StringComparison.OrdinalIgnoreCase))
            {
                return "Codex";
            }
        }

        return route.AgentType switch
        {
            AgentType.ClaudeCode or AgentType.ClaudeCli or AgentType.ClaudeIde or AgentType.ClaudeDesktop => "ClaudeCode",
            AgentType.CodexCli or AgentType.CodexIde or AgentType.CodexDesktop => "Codex",
            _ => route.AgentType.ToString(),
        };
    }

    public static string GetSurface(RouteRecord route, IEnumerable<string> userAgentValues)
    {
        ArgumentNullException.ThrowIfNull(route);
        ArgumentNullException.ThrowIfNull(userAgentValues);
        var userAgent = string.Join(' ', userAgentValues);
        if (userAgent.Contains("vscode", StringComparison.OrdinalIgnoreCase)
            || userAgent.Contains("jetbrains", StringComparison.OrdinalIgnoreCase)
            || userAgent.Contains("cursor", StringComparison.OrdinalIgnoreCase))
        {
            return "ide";
        }

        if (userAgent.Contains("desktop", StringComparison.OrdinalIgnoreCase)
            || userAgent.Contains("electron", StringComparison.OrdinalIgnoreCase))
        {
            return "desktop";
        }

        if (userAgent.Contains("codex_cli", StringComparison.OrdinalIgnoreCase)
            || userAgent.Contains("claude-code-cli", StringComparison.OrdinalIgnoreCase))
        {
            return "cli";
        }

        return route.AgentType switch
        {
            AgentType.ClaudeCli or AgentType.CodexCli when !string.Equals(route.ProviderId, "direct", StringComparison.Ordinal) => "unknown",
            AgentType.ClaudeIde or AgentType.CodexIde => "ide",
            AgentType.ClaudeDesktop or AgentType.CodexDesktop => "desktop",
            _ => "unknown",
        };
    }
}
