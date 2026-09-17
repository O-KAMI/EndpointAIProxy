namespace Sf.EndpointAI.Contracts;

public enum RouteMode
{
    PassthroughOriginal,
    FixedGateway,
}

public enum AgentType
{
    // Legacy/shared Claude Code route identity. New inventory records use the
    // surface-specific values appended below so persisted numeric values remain stable.
    ClaudeCode,
    CodexCli,
    QoderCli,
    QoderIde,
    CcSwitch,
    UnknownCandidate,
    CodexIde,
    CodexDesktop,
    ClaudeCli,
    ClaudeIde,
    ClaudeDesktop,
}

public enum InstallMethod
{
    Unknown,
    Native,
    Portable,
    Npm,
    Pnpm,
    Yarn,
    Pip,
    Pipx,
    Winget,
    Chocolatey,
    VsCodeExtension,
    MicrosoftStore,
    JetBrainsPlugin,
}

public enum EvidenceStrength
{
    Weak,
    Medium,
    Strong,
}

public enum RouteStatus
{
    Discovered,
    Pending,
    RestartRequired,
    Attached,
    NonCompliant,
    Unsupported,
    Error,
    Bypassed,
}

public enum PolicyApplyStatus
{
    Unknown,
    Pending,
    Applied,
    Failed,
    Disabled,
}

public enum ProxyState
{
    Unknown,
    Stopped,
    Starting,
    Listening,
    Degraded,
}

public enum AuditState
{
    Healthy,
    Degraded,
    Disabled,
}

public enum EventSeverity
{
    Info,
    Warning,
    Error,
    Critical,
}

public enum ClientOperationState
{
    Unknown,
    Enabled,
    Disabled,
    DisableFailed,
    EnableFailed,
}

public enum AgentConfigurationSource
{
    Unknown,
    Direct,
    CcSwitchProvider,
    CcSwitchEndpoint,
}

public enum AgentWireApi
{
    Unknown,
    AnthropicMessages,
    OpenAiResponses,
    ChatCompletions,
}

public enum ProxyTrafficState
{
    NeverObserved,
    Succeeded,
    GatewayReachedWithError,
    ConnectionFailed,
    RouteFailed,
    AllowlistBypassed,
}

public enum DeviceOnlineState
{
    Online,
    Stale,
    Offline,
    LegacyClient,
}

public enum RemoteCommandType
{
    DisableProxy,
    EnableProxy,
}

public enum RemoteCommandStatus
{
    Pending,
    Delivered,
    Executing,
    Succeeded,
    Failed,
    Expired,
    Cancelled,
}
