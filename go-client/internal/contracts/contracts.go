package contracts

import (
	"encoding/json"
	"fmt"
	"time"
)

type RouteMode int

const (
	RouteModePassthroughOriginal RouteMode = 0
	RouteModeFixedGateway        RouteMode = 1
)

var RouteModeNames = []string{"passthroughOriginal", "fixedGateway"}

func (v RouteMode) MarshalJSON() ([]byte, error) {
	if int(v) < 0 || int(v) >= len(RouteModeNames) {
		return nil, fmt.Errorf("invalid RouteMode: %d", v)
	}
	return json.Marshal(RouteModeNames[v])
}
func (v *RouteMode) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		for i, n := range RouteModeNames {
			if s == n {
				*v = RouteMode(i)
				return nil
			}
		}
		return fmt.Errorf("invalid RouteMode: %s", s)
	}
	var i int
	if err := json.Unmarshal(b, &i); err != nil {
		return err
	}
	if i < 0 || i >= len(RouteModeNames) {
		return fmt.Errorf("invalid RouteMode: %d", i)
	}
	*v = RouteMode(i)
	return nil
}

type AgentType int

const (
	AgentTypeClaudeCode       AgentType = 0
	AgentTypeCodexCli         AgentType = 1
	AgentTypeQoderCli         AgentType = 2
	AgentTypeQoderIde         AgentType = 3
	AgentTypeCcSwitch         AgentType = 4
	AgentTypeUnknownCandidate AgentType = 5
	AgentTypeCodexIde         AgentType = 6
	AgentTypeCodexDesktop     AgentType = 7
	AgentTypeClaudeCli        AgentType = 8
	AgentTypeClaudeIde        AgentType = 9
	AgentTypeClaudeDesktop    AgentType = 10
	AgentTypeDeepSeekHarness  AgentType = 11
)

var AgentTypeNames = []string{"claudeCode", "codexCli", "qoderCli", "qoderIde", "ccSwitch", "unknownCandidate", "codexIde", "codexDesktop", "claudeCli", "claudeIde", "claudeDesktop", "deepseekHarness"}

func (v AgentType) MarshalJSON() ([]byte, error) {
	if int(v) < 0 || int(v) >= len(AgentTypeNames) {
		return nil, fmt.Errorf("invalid AgentType: %d", v)
	}
	return json.Marshal(AgentTypeNames[v])
}
func (v *AgentType) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		for i, n := range AgentTypeNames {
			if s == n {
				*v = AgentType(i)
				return nil
			}
		}
		return fmt.Errorf("invalid AgentType: %s", s)
	}
	var i int
	if err := json.Unmarshal(b, &i); err != nil {
		return err
	}
	if i < 0 || i >= len(AgentTypeNames) {
		return fmt.Errorf("invalid AgentType: %d", i)
	}
	*v = AgentType(i)
	return nil
}

type InstallMethod int

const (
	InstallMethodUnknown         InstallMethod = 0
	InstallMethodNative          InstallMethod = 1
	InstallMethodPortable        InstallMethod = 2
	InstallMethodNpm             InstallMethod = 3
	InstallMethodPnpm            InstallMethod = 4
	InstallMethodYarn            InstallMethod = 5
	InstallMethodPip             InstallMethod = 6
	InstallMethodPipx            InstallMethod = 7
	InstallMethodWinget          InstallMethod = 8
	InstallMethodChocolatey      InstallMethod = 9
	InstallMethodVsCodeExtension InstallMethod = 10
	InstallMethodMicrosoftStore  InstallMethod = 11
	InstallMethodJetBrainsPlugin InstallMethod = 12
)

var InstallMethodNames = []string{"unknown", "native", "portable", "npm", "pnpm", "yarn", "pip", "pipx", "winget", "chocolatey", "vsCodeExtension", "microsoftStore", "jetBrainsPlugin"}

func (v InstallMethod) MarshalJSON() ([]byte, error) {
	if int(v) < 0 || int(v) >= len(InstallMethodNames) {
		return nil, fmt.Errorf("invalid InstallMethod: %d", v)
	}
	return json.Marshal(InstallMethodNames[v])
}
func (v *InstallMethod) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		for i, n := range InstallMethodNames {
			if s == n {
				*v = InstallMethod(i)
				return nil
			}
		}
		return fmt.Errorf("invalid InstallMethod: %s", s)
	}
	var i int
	if err := json.Unmarshal(b, &i); err != nil {
		return err
	}
	if i < 0 || i >= len(InstallMethodNames) {
		return fmt.Errorf("invalid InstallMethod: %d", i)
	}
	*v = InstallMethod(i)
	return nil
}

type EvidenceStrength int

const (
	EvidenceStrengthWeak   EvidenceStrength = 0
	EvidenceStrengthMedium EvidenceStrength = 1
	EvidenceStrengthStrong EvidenceStrength = 2
)

var EvidenceStrengthNames = []string{"weak", "medium", "strong"}

func (v EvidenceStrength) MarshalJSON() ([]byte, error) {
	if int(v) < 0 || int(v) >= len(EvidenceStrengthNames) {
		return nil, fmt.Errorf("invalid EvidenceStrength: %d", v)
	}
	return json.Marshal(EvidenceStrengthNames[v])
}
func (v *EvidenceStrength) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		for i, n := range EvidenceStrengthNames {
			if s == n {
				*v = EvidenceStrength(i)
				return nil
			}
		}
		return fmt.Errorf("invalid EvidenceStrength: %s", s)
	}
	var i int
	if err := json.Unmarshal(b, &i); err != nil {
		return err
	}
	if i < 0 || i >= len(EvidenceStrengthNames) {
		return fmt.Errorf("invalid EvidenceStrength: %d", i)
	}
	*v = EvidenceStrength(i)
	return nil
}

type RouteStatus int

const (
	RouteStatusDiscovered      RouteStatus = 0
	RouteStatusPending         RouteStatus = 1
	RouteStatusRestartRequired RouteStatus = 2
	RouteStatusAttached        RouteStatus = 3
	RouteStatusNonCompliant    RouteStatus = 4
	RouteStatusUnsupported     RouteStatus = 5
	RouteStatusError           RouteStatus = 6
	RouteStatusBypassed        RouteStatus = 7
)

var RouteStatusNames = []string{"discovered", "pending", "restartRequired", "attached", "nonCompliant", "unsupported", "error", "bypassed"}

func (v RouteStatus) MarshalJSON() ([]byte, error) {
	if int(v) < 0 || int(v) >= len(RouteStatusNames) {
		return nil, fmt.Errorf("invalid RouteStatus: %d", v)
	}
	return json.Marshal(RouteStatusNames[v])
}
func (v *RouteStatus) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		for i, n := range RouteStatusNames {
			if s == n {
				*v = RouteStatus(i)
				return nil
			}
		}
		return fmt.Errorf("invalid RouteStatus: %s", s)
	}
	var i int
	if err := json.Unmarshal(b, &i); err != nil {
		return err
	}
	if i < 0 || i >= len(RouteStatusNames) {
		return fmt.Errorf("invalid RouteStatus: %d", i)
	}
	*v = RouteStatus(i)
	return nil
}

type PolicyApplyStatus int

const (
	PolicyApplyStatusUnknown  PolicyApplyStatus = 0
	PolicyApplyStatusPending  PolicyApplyStatus = 1
	PolicyApplyStatusApplied  PolicyApplyStatus = 2
	PolicyApplyStatusFailed   PolicyApplyStatus = 3
	PolicyApplyStatusDisabled PolicyApplyStatus = 4
)

var PolicyApplyStatusNames = []string{"unknown", "pending", "applied", "failed", "disabled"}

func (v PolicyApplyStatus) MarshalJSON() ([]byte, error) {
	if int(v) < 0 || int(v) >= len(PolicyApplyStatusNames) {
		return nil, fmt.Errorf("invalid PolicyApplyStatus: %d", v)
	}
	return json.Marshal(PolicyApplyStatusNames[v])
}
func (v *PolicyApplyStatus) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		for i, n := range PolicyApplyStatusNames {
			if s == n {
				*v = PolicyApplyStatus(i)
				return nil
			}
		}
		return fmt.Errorf("invalid PolicyApplyStatus: %s", s)
	}
	var i int
	if err := json.Unmarshal(b, &i); err != nil {
		return err
	}
	if i < 0 || i >= len(PolicyApplyStatusNames) {
		return fmt.Errorf("invalid PolicyApplyStatus: %d", i)
	}
	*v = PolicyApplyStatus(i)
	return nil
}

type ProxyState int

const (
	ProxyStateUnknown   ProxyState = 0
	ProxyStateStopped   ProxyState = 1
	ProxyStateStarting  ProxyState = 2
	ProxyStateListening ProxyState = 3
	ProxyStateDegraded  ProxyState = 4
)

var ProxyStateNames = []string{"unknown", "stopped", "starting", "listening", "degraded"}

func (v ProxyState) MarshalJSON() ([]byte, error) {
	if int(v) < 0 || int(v) >= len(ProxyStateNames) {
		return nil, fmt.Errorf("invalid ProxyState: %d", v)
	}
	return json.Marshal(ProxyStateNames[v])
}
func (v *ProxyState) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		for i, n := range ProxyStateNames {
			if s == n {
				*v = ProxyState(i)
				return nil
			}
		}
		return fmt.Errorf("invalid ProxyState: %s", s)
	}
	var i int
	if err := json.Unmarshal(b, &i); err != nil {
		return err
	}
	if i < 0 || i >= len(ProxyStateNames) {
		return fmt.Errorf("invalid ProxyState: %d", i)
	}
	*v = ProxyState(i)
	return nil
}

type AuditState int

const (
	AuditStateHealthy  AuditState = 0
	AuditStateDegraded AuditState = 1
	AuditStateDisabled AuditState = 2
)

var AuditStateNames = []string{"healthy", "degraded", "disabled"}

func (v AuditState) MarshalJSON() ([]byte, error) {
	if int(v) < 0 || int(v) >= len(AuditStateNames) {
		return nil, fmt.Errorf("invalid AuditState: %d", v)
	}
	return json.Marshal(AuditStateNames[v])
}
func (v *AuditState) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		for i, n := range AuditStateNames {
			if s == n {
				*v = AuditState(i)
				return nil
			}
		}
		return fmt.Errorf("invalid AuditState: %s", s)
	}
	var i int
	if err := json.Unmarshal(b, &i); err != nil {
		return err
	}
	if i < 0 || i >= len(AuditStateNames) {
		return fmt.Errorf("invalid AuditState: %d", i)
	}
	*v = AuditState(i)
	return nil
}

type EventSeverity int

const (
	EventSeverityInfo     EventSeverity = 0
	EventSeverityWarning  EventSeverity = 1
	EventSeverityError    EventSeverity = 2
	EventSeverityCritical EventSeverity = 3
)

var EventSeverityNames = []string{"info", "warning", "error", "critical"}

func (v EventSeverity) MarshalJSON() ([]byte, error) {
	if int(v) < 0 || int(v) >= len(EventSeverityNames) {
		return nil, fmt.Errorf("invalid EventSeverity: %d", v)
	}
	return json.Marshal(EventSeverityNames[v])
}
func (v *EventSeverity) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		for i, n := range EventSeverityNames {
			if s == n {
				*v = EventSeverity(i)
				return nil
			}
		}
		return fmt.Errorf("invalid EventSeverity: %s", s)
	}
	var i int
	if err := json.Unmarshal(b, &i); err != nil {
		return err
	}
	if i < 0 || i >= len(EventSeverityNames) {
		return fmt.Errorf("invalid EventSeverity: %d", i)
	}
	*v = EventSeverity(i)
	return nil
}

type ClientOperationState int

const (
	ClientOperationStateUnknown       ClientOperationState = 0
	ClientOperationStateEnabled       ClientOperationState = 1
	ClientOperationStateDisabled      ClientOperationState = 2
	ClientOperationStateDisableFailed ClientOperationState = 3
	ClientOperationStateEnableFailed  ClientOperationState = 4
)

var ClientOperationStateNames = []string{"unknown", "enabled", "disabled", "disableFailed", "enableFailed"}

func (v ClientOperationState) MarshalJSON() ([]byte, error) {
	if int(v) < 0 || int(v) >= len(ClientOperationStateNames) {
		return nil, fmt.Errorf("invalid ClientOperationState: %d", v)
	}
	return json.Marshal(ClientOperationStateNames[v])
}
func (v *ClientOperationState) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		for i, n := range ClientOperationStateNames {
			if s == n {
				*v = ClientOperationState(i)
				return nil
			}
		}
		return fmt.Errorf("invalid ClientOperationState: %s", s)
	}
	var i int
	if err := json.Unmarshal(b, &i); err != nil {
		return err
	}
	if i < 0 || i >= len(ClientOperationStateNames) {
		return fmt.Errorf("invalid ClientOperationState: %d", i)
	}
	*v = ClientOperationState(i)
	return nil
}

type AgentConfigurationSource int

const (
	AgentConfigurationSourceUnknown          AgentConfigurationSource = 0
	AgentConfigurationSourceDirect           AgentConfigurationSource = 1
	AgentConfigurationSourceCcSwitchProvider AgentConfigurationSource = 2
	AgentConfigurationSourceCcSwitchEndpoint AgentConfigurationSource = 3
)

var AgentConfigurationSourceNames = []string{"unknown", "direct", "ccSwitchProvider", "ccSwitchEndpoint"}

func (v AgentConfigurationSource) MarshalJSON() ([]byte, error) {
	if int(v) < 0 || int(v) >= len(AgentConfigurationSourceNames) {
		return nil, fmt.Errorf("invalid AgentConfigurationSource: %d", v)
	}
	return json.Marshal(AgentConfigurationSourceNames[v])
}
func (v *AgentConfigurationSource) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		for i, n := range AgentConfigurationSourceNames {
			if s == n {
				*v = AgentConfigurationSource(i)
				return nil
			}
		}
		return fmt.Errorf("invalid AgentConfigurationSource: %s", s)
	}
	var i int
	if err := json.Unmarshal(b, &i); err != nil {
		return err
	}
	if i < 0 || i >= len(AgentConfigurationSourceNames) {
		return fmt.Errorf("invalid AgentConfigurationSource: %d", i)
	}
	*v = AgentConfigurationSource(i)
	return nil
}

type AgentWireApi int

const (
	AgentWireApiUnknown           AgentWireApi = 0
	AgentWireApiAnthropicMessages AgentWireApi = 1
	AgentWireApiOpenAiResponses   AgentWireApi = 2
	AgentWireApiChatCompletions   AgentWireApi = 3
)

var AgentWireApiNames = []string{"unknown", "anthropicMessages", "openAiResponses", "chatCompletions"}

func (v AgentWireApi) MarshalJSON() ([]byte, error) {
	if int(v) < 0 || int(v) >= len(AgentWireApiNames) {
		return nil, fmt.Errorf("invalid AgentWireApi: %d", v)
	}
	return json.Marshal(AgentWireApiNames[v])
}
func (v *AgentWireApi) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		for i, n := range AgentWireApiNames {
			if s == n {
				*v = AgentWireApi(i)
				return nil
			}
		}
		return fmt.Errorf("invalid AgentWireApi: %s", s)
	}
	var i int
	if err := json.Unmarshal(b, &i); err != nil {
		return err
	}
	if i < 0 || i >= len(AgentWireApiNames) {
		return fmt.Errorf("invalid AgentWireApi: %d", i)
	}
	*v = AgentWireApi(i)
	return nil
}

type ProxyTrafficState int

const (
	ProxyTrafficStateNeverObserved           ProxyTrafficState = 0
	ProxyTrafficStateSucceeded               ProxyTrafficState = 1
	ProxyTrafficStateGatewayReachedWithError ProxyTrafficState = 2
	ProxyTrafficStateConnectionFailed        ProxyTrafficState = 3
	ProxyTrafficStateRouteFailed             ProxyTrafficState = 4
	ProxyTrafficStateAllowlistBypassed       ProxyTrafficState = 5
)

var ProxyTrafficStateNames = []string{"neverObserved", "succeeded", "gatewayReachedWithError", "connectionFailed", "routeFailed", "allowlistBypassed"}

func (v ProxyTrafficState) MarshalJSON() ([]byte, error) {
	if int(v) < 0 || int(v) >= len(ProxyTrafficStateNames) {
		return nil, fmt.Errorf("invalid ProxyTrafficState: %d", v)
	}
	return json.Marshal(ProxyTrafficStateNames[v])
}
func (v *ProxyTrafficState) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		for i, n := range ProxyTrafficStateNames {
			if s == n {
				*v = ProxyTrafficState(i)
				return nil
			}
		}
		return fmt.Errorf("invalid ProxyTrafficState: %s", s)
	}
	var i int
	if err := json.Unmarshal(b, &i); err != nil {
		return err
	}
	if i < 0 || i >= len(ProxyTrafficStateNames) {
		return fmt.Errorf("invalid ProxyTrafficState: %d", i)
	}
	*v = ProxyTrafficState(i)
	return nil
}

type DeviceOnlineState int

const (
	DeviceOnlineStateOnline       DeviceOnlineState = 0
	DeviceOnlineStateStale        DeviceOnlineState = 1
	DeviceOnlineStateOffline      DeviceOnlineState = 2
	DeviceOnlineStateLegacyClient DeviceOnlineState = 3
)

var DeviceOnlineStateNames = []string{"online", "stale", "offline", "legacyClient"}

func (v DeviceOnlineState) MarshalJSON() ([]byte, error) {
	if int(v) < 0 || int(v) >= len(DeviceOnlineStateNames) {
		return nil, fmt.Errorf("invalid DeviceOnlineState: %d", v)
	}
	return json.Marshal(DeviceOnlineStateNames[v])
}
func (v *DeviceOnlineState) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		for i, n := range DeviceOnlineStateNames {
			if s == n {
				*v = DeviceOnlineState(i)
				return nil
			}
		}
		return fmt.Errorf("invalid DeviceOnlineState: %s", s)
	}
	var i int
	if err := json.Unmarshal(b, &i); err != nil {
		return err
	}
	if i < 0 || i >= len(DeviceOnlineStateNames) {
		return fmt.Errorf("invalid DeviceOnlineState: %d", i)
	}
	*v = DeviceOnlineState(i)
	return nil
}

type RemoteCommandType int

const (
	RemoteCommandTypeDisableProxy RemoteCommandType = 0
	RemoteCommandTypeEnableProxy  RemoteCommandType = 1
)

var RemoteCommandTypeNames = []string{"disableProxy", "enableProxy"}

func (v RemoteCommandType) MarshalJSON() ([]byte, error) {
	if int(v) < 0 || int(v) >= len(RemoteCommandTypeNames) {
		return nil, fmt.Errorf("invalid RemoteCommandType: %d", v)
	}
	return json.Marshal(RemoteCommandTypeNames[v])
}
func (v *RemoteCommandType) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		for i, n := range RemoteCommandTypeNames {
			if s == n {
				*v = RemoteCommandType(i)
				return nil
			}
		}
		return fmt.Errorf("invalid RemoteCommandType: %s", s)
	}
	var i int
	if err := json.Unmarshal(b, &i); err != nil {
		return err
	}
	if i < 0 || i >= len(RemoteCommandTypeNames) {
		return fmt.Errorf("invalid RemoteCommandType: %d", i)
	}
	*v = RemoteCommandType(i)
	return nil
}

type RemoteCommandStatus int

const (
	RemoteCommandStatusPending   RemoteCommandStatus = 0
	RemoteCommandStatusDelivered RemoteCommandStatus = 1
	RemoteCommandStatusExecuting RemoteCommandStatus = 2
	RemoteCommandStatusSucceeded RemoteCommandStatus = 3
	RemoteCommandStatusFailed    RemoteCommandStatus = 4
	RemoteCommandStatusExpired   RemoteCommandStatus = 5
	RemoteCommandStatusCancelled RemoteCommandStatus = 6
)

var RemoteCommandStatusNames = []string{"pending", "delivered", "executing", "succeeded", "failed", "expired", "cancelled"}

func (v RemoteCommandStatus) MarshalJSON() ([]byte, error) {
	if int(v) < 0 || int(v) >= len(RemoteCommandStatusNames) {
		return nil, fmt.Errorf("invalid RemoteCommandStatus: %d", v)
	}
	return json.Marshal(RemoteCommandStatusNames[v])
}
func (v *RemoteCommandStatus) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		for i, n := range RemoteCommandStatusNames {
			if s == n {
				*v = RemoteCommandStatus(i)
				return nil
			}
		}
		return fmt.Errorf("invalid RemoteCommandStatus: %s", s)
	}
	var i int
	if err := json.Unmarshal(b, &i); err != nil {
		return err
	}
	if i < 0 || i >= len(RemoteCommandStatusNames) {
		return fmt.Errorf("invalid RemoteCommandStatus: %d", i)
	}
	*v = RemoteCommandStatus(i)
	return nil
}

type Policy struct {
	SchemaVersion            int       `json:"schemaVersion"`
	ServerInstanceID         string    `json:"serverInstanceId"`
	PolicyVersion            int64     `json:"policyVersion"`
	Enabled                  bool      `json:"enabled"`
	RouteMode                string    `json:"routeMode"`
	GatewayOrigin            *string   `json:"gatewayOrigin"`
	AllowInsecureGateway     bool      `json:"allowInsecureGateway"`
	PollIntervalSeconds      int       `json:"pollIntervalSeconds"`
	HeartbeatIntervalSeconds int       `json:"heartbeatIntervalSeconds"`
	IssuedAtUTC              time.Time `json:"issuedAtUtc"`
	AllowlistedBaseURLs      []string  `json:"allowlistedBaseUrls"`
}
type PolicyClientState struct {
	LastReceivedVersion *int64            `json:"lastReceivedVersion"`
	AppliedVersion      *int64            `json:"appliedVersion"`
	ApplyStatus         PolicyApplyStatus `json:"applyStatus"`
	LastErrorCode       *string           `json:"lastErrorCode"`
	LastErrorSummary    *string           `json:"lastErrorSummary"`
}
type ProxyClientState struct {
	State            ProxyState `json:"state"`
	ListenEndpoint   string     `json:"listenEndpoint"`
	ActiveRouteCount int        `json:"activeRouteCount"`
	AuditState       AuditState `json:"auditState"`
}
type DeviceEnrollmentRequest struct {
	SchemaVersion  int    `json:"schemaVersion"`
	DeviceID       string `json:"deviceId"`
	Hostname       string `json:"hostname"`
	ServiceVersion string `json:"serviceVersion"`
}
type DeviceEnrollmentResponse struct {
	DeviceID      string    `json:"deviceId"`
	DeviceToken   string    `json:"deviceToken"`
	EnrolledAtUTC time.Time `json:"enrolledAtUtc"`
}
type RemoteCommandPayload struct {
	SchemaVersion int               `json:"schemaVersion"`
	CommandID     string            `json:"commandId"`
	DeviceID      string            `json:"deviceId"`
	Type          RemoteCommandType `json:"type"`
	IssuedAtUTC   time.Time         `json:"issuedAtUtc"`
	ExpiresAtUTC  time.Time         `json:"expiresAtUtc"`
}
type SignedRemoteCommand struct {
	Payload   RemoteCommandPayload `json:"payload"`
	Signature string               `json:"signature"`
}
type RemoteCommandStatusUpdate struct {
	SchemaVersion int                 `json:"schemaVersion"`
	DeviceID      string              `json:"deviceId"`
	CommandID     string              `json:"commandId"`
	Status        RemoteCommandStatus `json:"status"`
	ObservedAtUTC time.Time           `json:"observedAtUtc"`
	ResultCode    *string             `json:"resultCode"`
	ResultSummary *string             `json:"resultSummary"`
}
type DeviceIdentity struct {
	DeviceID       string `json:"deviceId"`
	Hostname       string `json:"hostname"`
	OSVersion      string `json:"osVersion"`
	ServiceVersion string `json:"serviceVersion"`
	BootID         string `json:"bootId"`
}
type EndpointUser struct {
	SID         string `json:"sid"`
	AccountName string `json:"accountName"`
}
type AgentInventoryItem struct {
	InstanceID           string        `json:"instanceId"`
	UserSID              string        `json:"userSid"`
	AgentType            AgentType     `json:"agentType"`
	DisplayName          string        `json:"displayName"`
	Version              *string       `json:"version"`
	InstallMethod        InstallMethod `json:"installMethod"`
	DiscoveryConfidence  int           `json:"discoveryConfidence"`
	Installed            bool          `json:"installed"`
	Running              bool          `json:"running"`
	RouterType           *string       `json:"routerType"`
	CcSwitchVersion      *string       `json:"ccSwitchVersion"`
	CcSwitchMode         *string       `json:"ccSwitchMode"`
	RouteStatus          RouteStatus   `json:"routeStatus"`
	ObservedTargetOrigin *string       `json:"observedTargetOrigin"`
	LastSeenAtUTC        time.Time     `json:"lastSeenAtUtc"`
}
type HeartbeatRequest struct {
	SchemaVersion int                  `json:"schemaVersion"`
	HeartbeatID   string               `json:"heartbeatId"`
	ObservedAtUTC time.Time            `json:"observedAtUtc"`
	Device        DeviceIdentity       `json:"device"`
	Policy        PolicyClientState    `json:"policy"`
	Proxy         ProxyClientState     `json:"proxy"`
	Users         []EndpointUser       `json:"users"`
	Agents        []AgentInventoryItem `json:"agents"`
}
type HeartbeatResponse struct {
	ServerTimeUTC         time.Time `json:"serverTimeUtc"`
	AcceptedPolicyVersion int64     `json:"acceptedPolicyVersion"`
	NextHeartbeatSeconds  int       `json:"nextHeartbeatSeconds"`
}
type DeviceRuntimeState struct {
	ServiceStartedAtUTC    time.Time            `json:"serviceStartedAtUtc"`
	UptimeSeconds          int64                `json:"uptimeSeconds"`
	OperationState         ClientOperationState `json:"operationState"`
	ProxyListenerAvailable bool                 `json:"proxyListenerAvailable"`
	LastControlSyncAtUTC   *time.Time           `json:"lastControlSyncAtUtc"`
	LastReconcileAtUTC     *time.Time           `json:"lastReconcileAtUtc"`
	LastReconcileResult    *string              `json:"lastReconcileResult"`
	LastReconcileErrorCode *string              `json:"lastReconcileErrorCode"`
}
type AgentEndpointAsset struct {
	AssetID                    string                   `json:"assetId"`
	UserSID                    string                   `json:"userSid"`
	AgentFamily                string                   `json:"agentFamily"`
	ConfigurationSource        AgentConfigurationSource `json:"configurationSource"`
	ProviderID                 *string                  `json:"providerId"`
	EndpointID                 *string                  `json:"endpointId"`
	IsCurrent                  bool                     `json:"isCurrent"`
	ConfiguredModel            *string                  `json:"configuredModel"`
	WireAPI                    AgentWireApi             `json:"wireApi"`
	OriginalTargetBaseURL      *string                  `json:"originalTargetBaseUrl"`
	EffectiveConfiguredBaseURL *string                  `json:"effectiveConfiguredBaseUrl"`
	LocalRouteURL              *string                  `json:"localRouteUrl"`
	AllowlistBypassed          bool                     `json:"allowlistBypassed"`
	RouteStatus                RouteStatus              `json:"routeStatus"`
	ObservedAtUTC              time.Time                `json:"observedAtUtc"`
}
type ProxyActivityAsset struct {
	AssetID                          string            `json:"assetId"`
	State                            ProxyTrafficState `json:"state"`
	LastRequestAtUTC                 *time.Time        `json:"lastRequestAtUtc"`
	LastSuccessAtUTC                 *time.Time        `json:"lastSuccessAtUtc"`
	LastFailureAtUTC                 *time.Time        `json:"lastFailureAtUtc"`
	LastHttpStatusCode               *int              `json:"lastHttpStatusCode"`
	LastOutcome                      *string           `json:"lastOutcome"`
	LastErrorCode                    *string           `json:"lastErrorCode"`
	LastGatewayRoundTripMilliseconds *float64          `json:"lastGatewayRoundTripMilliseconds"`
	RequestCountSinceBoot            int64             `json:"requestCountSinceBoot"`
	SuccessCountSinceBoot            int64             `json:"successCountSinceBoot"`
	FailureCountSinceBoot            int64             `json:"failureCountSinceBoot"`
}
type HeartbeatV2Request struct {
	SchemaVersion int                  `json:"schemaVersion"`
	HeartbeatID   string               `json:"heartbeatId"`
	ObservedAtUTC time.Time            `json:"observedAtUtc"`
	Device        DeviceIdentity       `json:"device"`
	Runtime       DeviceRuntimeState   `json:"runtime"`
	Policy        PolicyClientState    `json:"policy"`
	Proxy         ProxyClientState     `json:"proxy"`
	Users         []EndpointUser       `json:"users"`
	Agents        []AgentInventoryItem `json:"agents"`
	Endpoints     []AgentEndpointAsset `json:"endpoints"`
	Activity      []ProxyActivityAsset `json:"activity"`
}
type HeartbeatV2Response struct {
	ServerTimeUTC         time.Time            `json:"serverTimeUtc"`
	AcceptedPolicyVersion int64                `json:"acceptedPolicyVersion"`
	NextHeartbeatSeconds  int                  `json:"nextHeartbeatSeconds"`
	Command               *SignedRemoteCommand `json:"command"`
}
type EndpointEvent struct {
	EventID         string                     `json:"eventId"`
	OccurredAtUTC   time.Time                  `json:"occurredAtUtc"`
	Severity        EventSeverity              `json:"severity"`
	Type            string                     `json:"type"`
	Code            string                     `json:"code"`
	Summary         string                     `json:"summary"`
	UserSID         *string                    `json:"userSid"`
	AgentInstanceID *string                    `json:"agentInstanceId"`
	Details         map[string]json.RawMessage `json:"details"`
}
type EventBatchRequest struct {
	SchemaVersion int             `json:"schemaVersion"`
	BatchID       string          `json:"batchId"`
	DeviceID      string          `json:"deviceId"`
	Events        []EndpointEvent `json:"events"`
}
type EventBatchResponse struct {
	Accepted   int        `json:"accepted"`
	Duplicates int        `json:"duplicates"`
	Rejected   int        `json:"rejected"`
	Errors     []ApiError `json:"errors"`
}
type ApiError struct {
	Code    string  `json:"code"`
	Message string  `json:"message"`
	TraceID *string `json:"traceId"`
}
type ApiErrorEnvelope struct {
	Error ApiError `json:"error"`
}
type Route struct {
	RouteID, UserSID                             string
	AgentType                                    int
	ProviderID, OriginalBaseURL, InjectedBaseURL string
	Status                                       int
	CreatedAtUTC, UpdatedAtUTC                   time.Time
}
