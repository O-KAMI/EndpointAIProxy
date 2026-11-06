package app

import (
	"net/url"
	"strings"
	"time"

	"endpointai/client/internal/configuration"
	"endpointai/client/internal/contracts"
)

type inferenceObservation struct {
	At                 time.Time
	PolicyVersion      int64
	RouteID            string
	Original, Injected string
}

func isInferenceRequest(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	for _, suffix := range []string{"messages", "responses", "chat/completions"} {
		if strings.HasSuffix(strings.TrimRight(u.Path, "/"), "/"+suffix) {
			return true
		}
	}
	return false
}

// Caller holds mu. File publication is not proof that an application reloaded it.
func (a *App) noteConfigurationChangesLocked(results []configuration.Result) {
	for _, r := range results {
		if !r.Changed {
			continue
		}
		id := stable(r.SID + "|" + family(contracts.Route{AgentType: r.AgentType, ProviderID: r.ProviderID}) + "|" + r.ProviderID)
		delete(a.inference, id)
		a.configurationChangedAt[id] = time.Now().UTC()
		if r.AgentType == 11 {
			a.reloadRequired[id] = true
		}
	}
}

func (a *App) verifyEndpoint(item *contracts.AgentEndpointAsset, routes []contracts.Route) {
	item.VerificationState = "unverified"
	item.LastInferenceObservedAtUTC = nil
	item.ObservedPolicyVersion = nil
	if item.RouteStatus == contracts.RouteStatusUnsupported {
		item.VerificationState = "unsupported"
	}
	if item.RouteStatus == contracts.RouteStatusError || item.RouteStatus == contracts.RouteStatusNonCompliant {
		item.VerificationState = "error"
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	item.ReloadRequired = a.reloadRequired[item.AssetID]
	observation, ok := a.inference[item.AssetID]
	if !ok || observation.PolicyVersion != a.policy.PolicyVersion {
		return
	}
	for _, route := range routes {
		if route.RouteID == observation.RouteID && route.Status == int(contracts.RouteStatusAttached) && route.OriginalBaseURL == observation.Original && route.InjectedBaseURL == observation.Injected && item.LocalRouteURL != nil && *item.LocalRouteURL == route.InjectedBaseURL {
			item.VerificationState = "observed"
			item.LastInferenceObservedAtUTC = ptr(observation.At)
			item.ObservedPolicyVersion = ptr(observation.PolicyVersion)
			return
		}
	}
}
