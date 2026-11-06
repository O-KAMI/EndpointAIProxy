"""0.1.19 wire contracts, ported directly from Sf.EndpointAI.Contracts."""
from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import Any, Annotated, Literal
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field, model_validator

Int32 = Annotated[int, Field(ge=-(2**31), le=2**31-1)]
Int64 = Annotated[int, Field(ge=-(2**63), le=2**63-1)]

class WireEnum(str, Enum):
    @classmethod
    def _missing_(cls, value):
        members = list(cls)
        if isinstance(value, int) and not isinstance(value, bool) and 0 <= value < len(members):
            return members[value]
        if isinstance(value, str):
            return next((m for m in members if m.value.lower() == value.lower()), None)
        return None

class Contract(BaseModel):
    model_config = ConfigDict(extra="ignore", allow_inf_nan=False)
    @model_validator(mode="before")
    @classmethod
    def insensitive_fields(cls, data):
        if not isinstance(data, dict):
            return data
        names = {k.lower(): k for k in cls.model_fields}
        return {names.get(k.lower(), k): v for k, v in data.items()}

class RouteMode(WireEnum):
    PassthroughOriginal = "passthroughOriginal"
    FixedGateway = "fixedGateway"

class AgentType(WireEnum):
    ClaudeCode = "claudeCode"
    CodexCli = "codexCli"
    QoderCli = "qoderCli"
    QoderIde = "qoderIde"
    CcSwitch = "ccSwitch"
    UnknownCandidate = "unknownCandidate"
    CodexIde = "codexIde"
    CodexDesktop = "codexDesktop"
    ClaudeCli = "claudeCli"
    ClaudeIde = "claudeIde"
    ClaudeDesktop = "claudeDesktop"
    DeepSeekHarness = "deepseekHarness"

class InstallMethod(WireEnum):
    Unknown = "unknown"
    Native = "native"
    Portable = "portable"
    Npm = "npm"
    Pnpm = "pnpm"
    Yarn = "yarn"
    Pip = "pip"
    Pipx = "pipx"
    Winget = "winget"
    Chocolatey = "chocolatey"
    VsCodeExtension = "vsCodeExtension"
    MicrosoftStore = "microsoftStore"
    JetBrainsPlugin = "jetBrainsPlugin"

class EvidenceStrength(WireEnum):
    Weak = "weak"
    Medium = "medium"
    Strong = "strong"

class RouteStatus(WireEnum):
    Discovered = "discovered"
    Pending = "pending"
    RestartRequired = "restartRequired"
    Attached = "attached"
    NonCompliant = "nonCompliant"
    Unsupported = "unsupported"
    Error = "error"
    Bypassed = "bypassed"

class PolicyApplyStatus(WireEnum):
    Unknown = "unknown"
    Pending = "pending"
    Applied = "applied"
    Failed = "failed"
    Disabled = "disabled"

class ProxyState(WireEnum):
    Unknown = "unknown"
    Stopped = "stopped"
    Starting = "starting"
    Listening = "listening"
    Degraded = "degraded"

class AuditState(WireEnum):
    Healthy = "healthy"
    Degraded = "degraded"
    Disabled = "disabled"

class EventSeverity(WireEnum):
    Info = "info"
    Warning = "warning"
    Error = "error"
    Critical = "critical"

class ClientOperationState(WireEnum):
    Unknown = "unknown"
    Enabled = "enabled"
    Disabled = "disabled"
    DisableFailed = "disableFailed"
    EnableFailed = "enableFailed"

class AgentConfigurationSource(WireEnum):
    Unknown = "unknown"
    Direct = "direct"
    CcSwitchProvider = "ccSwitchProvider"
    CcSwitchEndpoint = "ccSwitchEndpoint"

class AgentWireApi(WireEnum):
    Unknown = "unknown"
    AnthropicMessages = "anthropicMessages"
    OpenAiResponses = "openAiResponses"
    ChatCompletions = "chatCompletions"

class ProxyTrafficState(WireEnum):
    NeverObserved = "neverObserved"
    Succeeded = "succeeded"
    GatewayReachedWithError = "gatewayReachedWithError"
    ConnectionFailed = "connectionFailed"
    RouteFailed = "routeFailed"
    AllowlistBypassed = "allowlistBypassed"

class DeviceOnlineState(WireEnum):
    Online = "online"
    Stale = "stale"
    Offline = "offline"
    LegacyClient = "legacyClient"

class RemoteCommandType(WireEnum):
    DisableProxy = "disableProxy"
    EnableProxy = "enableProxy"

class RemoteCommandStatus(WireEnum):
    Pending = "pending"
    Delivered = "delivered"
    Executing = "executing"
    Succeeded = "succeeded"
    Failed = "failed"
    Expired = "expired"
    Cancelled = "cancelled"
    ResultUnknown = "resultUnknown"


class ResolveUnknownCommandRequest(Contract):
    reason: str

class RecoverDeviceCredentialRequest(Contract):
    hostname: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=1, max_length=256)

class RoutingRule(Contract):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)
    domain: str
    routeMode: RouteMode
    gatewayOrigin: str | None = None

class EndpointPolicy(Contract):
    schemaVersion: Int32
    serverInstanceId: UUID
    policyVersion: Int64
    enabled: bool
    routeMode: RouteMode
    gatewayOrigin: str | None = None
    allowInsecureGateway: bool
    pollIntervalSeconds: Int32
    heartbeatIntervalSeconds: Int32
    issuedAtUtc: datetime
    allowlistedBaseUrls: list[str] | None = None
    allowlistedDomains: list[str] | None = None
    routingRules: list[RoutingRule] | None = None

class PolicyClientState(Contract):
    appliedSchemaVersion: Annotated[int, Field(ge=1, le=2)] = Field(default=1, exclude_if=lambda value: value == 1)
    lastReceivedVersion: Int64 | None = None
    appliedVersion: Int64 | None = None
    applyStatus: PolicyApplyStatus
    lastErrorCode: str | None = None
    lastErrorSummary: str | None = None

class ProxyClientState(Contract):
    state: ProxyState
    listenEndpoint: str
    activeRouteCount: Int32
    auditState: AuditState

class DeviceEnrollmentRequest(Contract):
    schemaVersion: Int32
    deviceId: UUID
    hostname: str
    serviceVersion: str
    initialDeviceToken: str | None = Field(default=None, min_length=44, max_length=44, repr=False, strict=True)
    previousDeviceToken: str | None = Field(default=None, max_length=512, repr=False)
    preserveDeviceToken: bool = Field(default=False, strict=True)

class DeviceEnrollmentResponse(Contract):
    deviceId: UUID
    deviceToken: str
    enrolledAtUtc: datetime

class CredentialRotationPrepare(Contract):
    rotationId: UUID
    nextDeviceToken: str = Field(min_length=44, max_length=44, strict=True, repr=False)

class CredentialRotationCommit(Contract):
    rotationId: UUID

class RemoteCommandPayload(Contract):
    schemaVersion: Int32
    commandId: UUID
    deviceId: UUID
    type: RemoteCommandType
    issuedAtUtc: datetime
    expiresAtUtc: datetime

class SignedRemoteCommand(Contract):
    payload: RemoteCommandPayload
    signature: str

class RemoteCommandStatusUpdate(Contract):
    schemaVersion: Int32
    deviceId: UUID
    commandId: UUID
    status: RemoteCommandStatus
    observedAtUtc: datetime
    resultCode: str | None = None
    resultSummary: str | None = None

class EndpointEvent(Contract):
    eventId: UUID
    occurredAtUtc: datetime
    severity: EventSeverity
    type: str
    code: str
    summary: str
    userSid: str | None = None
    agentInstanceId: UUID | None = None
    details: dict[str, Any] | None = None

class EventBatchRequest(Contract):
    schemaVersion: Int32
    batchId: UUID
    deviceId: UUID
    events: list[EndpointEvent]

class EventBatchResponse(Contract):
    accepted: Int32
    duplicates: Int32
    rejected: Int32
    errors: list[ApiError]

class ApiError(Contract):
    code: str
    message: str
    traceId: str | None = None

class ApiErrorEnvelope(Contract):
    error: ApiError

class DeviceIdentity(Contract):
    deviceId: UUID
    hostname: str
    osVersion: str
    serviceVersion: str
    bootId: UUID

class EndpointUser(Contract):
    sid: str
    accountName: str

class AgentInventoryItem(Contract):
    instanceId: UUID
    userSid: str
    agentType: AgentType
    displayName: str
    version: str | None = None
    installMethod: InstallMethod
    discoveryConfidence: Int32
    installed: bool
    running: bool
    routerType: str | None = None
    ccSwitchVersion: str | None = None
    ccSwitchMode: str | None = None
    routeStatus: RouteStatus
    observedTargetOrigin: str | None = None
    lastSeenAtUtc: datetime

class HeartbeatRequest(Contract):
    schemaVersion: Int32
    heartbeatId: UUID
    observedAtUtc: datetime
    device: DeviceIdentity
    policy: PolicyClientState
    proxy: ProxyClientState
    users: list[EndpointUser]
    agents: list[AgentInventoryItem]

class HeartbeatResponse(Contract):
    serverTimeUtc: datetime
    acceptedPolicyVersion: Int64
    nextHeartbeatSeconds: Int32

class DeviceRuntimeState(Contract):
    supportedPolicySchemaVersion: Annotated[int, Field(ge=1, le=2)] = Field(default=1, exclude_if=lambda value: value == 1)
    serviceStartedAtUtc: datetime
    uptimeSeconds: Int64
    operationState: ClientOperationState
    proxyListenerAvailable: bool
    lastControlSyncAtUtc: datetime | None = None
    lastReconcileAtUtc: datetime | None = None
    lastReconcileResult: str | None = None
    lastReconcileErrorCode: str | None = None

class AgentEndpointAsset(Contract):
    assetId: UUID
    userSid: str
    agentFamily: str
    configurationSource: AgentConfigurationSource
    providerId: str | None = None
    endpointId: str | None = None
    isCurrent: bool
    configuredModel: str | None = None
    wireApi: AgentWireApi
    originalTargetBaseUrl: str | None = None
    effectiveConfiguredBaseUrl: str | None = None
    localRouteUrl: str | None = None
    allowlistBypassed: bool
    routeStatus: RouteStatus
    observedAtUtc: datetime
    verificationState: Literal["unverified", "observed", "unsupported", "error"] | None = Field(default=None, exclude_if=lambda value: value is None)
    verificationReasonCode: str | None = Field(default=None, exclude_if=lambda value: value is None)
    reloadRequired: bool = Field(default=False, exclude_if=lambda value: value is False)
    lastInferenceObservedAtUtc: datetime | None = Field(default=None, exclude_if=lambda value: value is None)
    observedPolicyVersion: Int64 | None = Field(default=None, exclude_if=lambda value: value is None)

class ProxyActivityAsset(Contract):
    assetId: UUID
    state: ProxyTrafficState
    lastRequestAtUtc: datetime | None = None
    lastSuccessAtUtc: datetime | None = None
    lastFailureAtUtc: datetime | None = None
    lastHttpStatusCode: Int32 | None = None
    lastOutcome: str | None = None
    lastErrorCode: str | None = None
    lastGatewayRoundTripMilliseconds: float | None = None
    requestCountSinceBoot: Int64
    successCountSinceBoot: Int64
    failureCountSinceBoot: Int64

class HeartbeatV2Request(Contract):
    schemaVersion: Int32
    heartbeatId: UUID
    observedAtUtc: datetime
    device: DeviceIdentity
    runtime: DeviceRuntimeState
    policy: PolicyClientState
    proxy: ProxyClientState
    users: list[EndpointUser]
    agents: list[AgentInventoryItem]
    endpoints: list[AgentEndpointAsset]
    activity: list[ProxyActivityAsset]
    statelessPolicyVersions: bool = Field(default=False, exclude_if=lambda value: not value)
    inventoryUnchanged: bool = Field(default=False, exclude_if=lambda value: not value)
    compactInventory: bool = Field(default=False, strict=True, exclude_if=lambda value: not value)
    ed25519Signatures: bool = Field(default=False, exclude_if=lambda value: not value)
    deviceTransportV2: bool = Field(default=False, strict=True, exclude_if=lambda value: not value)
    credentialRotationV1: bool = Field(default=False, strict=True, exclude_if=lambda value: not value)

class DeviceTransportV2Response(Contract):
    keyId: str
    key: str = Field(repr=False)

class CredentialRotationCapability(Contract):
    minAgeSeconds: Int32

class HeartbeatV2Response(Contract):
    serverTimeUtc: datetime
    acceptedPolicyVersion: Int64
    nextHeartbeatSeconds: Int32
    command: SignedRemoteCommand | None = None
    statelessPolicyVersions: bool = False
    lightweightInventory: bool = False
    compactInventory: bool = False
    deviceTransport: bool = False
    deviceTransportV2: DeviceTransportV2Response | None = Field(default=None, repr=False)
    credentialRotationV1: CredentialRotationCapability | None = Field(default=None, exclude_if=lambda value: value is None)

class PolicyUpdateRequest(Contract):
    expectedVersion: Int64
    enabled: bool
    routeMode: RouteMode
    gatewayOrigin: str | None = None
    allowInsecureGateway: bool
    pollIntervalSeconds: Int32
    heartbeatIntervalSeconds: Int32
    allowlistedBaseUrls: list[str] | None = None
    allowlistedDomains: list[str] | None = None
    routingRules: list[RoutingRule] | None = None

class DevicePolicyOverrides(Contract):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)
    routeMode: RouteMode | None = None
    gatewayOrigin: str | None = None
    allowInsecureGateway: bool | None = None
    allowlistedBaseUrls: list[str] | None = None
    allowlistedDomains: list[str] | None = None
    routingRules: list[RoutingRule] | None = None

    @model_validator(mode="after")
    def explicit_values(self):
        if any(getattr(self, key) is None for key in self.model_fields_set if key != "gatewayOrigin"):
            raise ValueError("Only gatewayOrigin can be null; omit fields to inherit.")
        return self

class DevicePolicyUpdateRequest(Contract):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)
    expectedVersion: Annotated[int, Field(ge=1, lt=2**63-1)]
    overrides: DevicePolicyOverrides

class DevicePolicyResetRequest(Contract):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)
    expectedVersion: Annotated[int, Field(ge=1, lt=2**63-1)]

class CreateRemoteCommandRequest(Contract):
    type: RemoteCommandType
    reason: str
    expiresInMinutes: Int32

class CreateRolloutRequest(Contract):
    type: RemoteCommandType
    reason: str = Field(min_length=1, max_length=256)
    expiresInMinutes: Annotated[int, Field(ge=1, le=1440)]
    maxPerSecond: Annotated[int, Field(ge=1, le=5000)]
    deviceIds: list[UUID] = Field(min_length=1, max_length=150000)
    confirmCount: Annotated[int, Field(ge=1, le=150000)]

class CreatePolicyRolloutRequest(Contract):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)
    policy: PolicyUpdateRequest
    reason: str = Field(min_length=1, max_length=256)
    maxPerSecond: Annotated[int, Field(ge=1, le=5000)]
    deviceIds: list[UUID] = Field(min_length=1, max_length=150000)
    confirmCount: Annotated[int, Field(ge=1, le=150000)]

class ExtendPolicyRolloutRequest(Contract):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)
    reason: str = Field(min_length=1, max_length=256)
    deviceIds: list[UUID] = Field(min_length=1, max_length=150000)
    confirmCount: Annotated[int, Field(ge=1, le=150000)]

class RolloutChangeRequest(Contract):
    reason: str = Field(min_length=1, max_length=256)


for _contract in (EndpointPolicy, PolicyClientState, ProxyClientState, DeviceEnrollmentRequest, DeviceEnrollmentResponse, RemoteCommandPayload, SignedRemoteCommand, RemoteCommandStatusUpdate, EndpointEvent, EventBatchRequest, EventBatchResponse, ApiError, ApiErrorEnvelope, DeviceIdentity, EndpointUser, AgentInventoryItem, HeartbeatRequest, HeartbeatResponse, DeviceRuntimeState, AgentEndpointAsset, ProxyActivityAsset, HeartbeatV2Request, HeartbeatV2Response, PolicyUpdateRequest, CreateRemoteCommandRequest):
    _contract.model_rebuild()
