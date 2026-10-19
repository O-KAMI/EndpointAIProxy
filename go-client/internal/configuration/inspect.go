package configuration

import (
	"context"
	"encoding/json"
	"endpointai/client/internal/contracts"
	"errors"
	"github.com/pelletier/go-toml/v2"
	"os"
	"path/filepath"
	"strconv"
)

// Endpoint contains endpoint metadata only; credential values never leave the
// config parser. Source values match the public asset source enum.
type Endpoint struct {
	SID, Family, ProviderID, EndpointID, OriginalBaseURL, EffectiveBaseURL, LocalRouteURL, Model, Mode string
	Source                                                                                             int
	Current, Bypassed                                                                                  bool
	RouteStatus                                                                                        int
}

func (m *Manager) Inspect(ctx context.Context, profiles []Profile) ([]Endpoint, error) {
	routes, e := m.Store.ListRoutes(ctx)
	if e != nil {
		return nil, e
	}
	var out []Endpoint
	var errs []error
	dsh, dshErr := m.inspectDSHWithRoutes(ctx, profiles, routes)
	out = append(out, dsh...)
	if dshErr != nil {
		errs = append(errs, dshErr)
	}
	for _, p := range profiles {
		if e = ctx.Err(); e != nil {
			return out, e
		}
		path := filepath.Join(p.Home, ".cc-switch", "cc-switch.db")
		_, statErr := os.Lstat(path)
		hasCC := statErr == nil
		var cc CCInspection
		if hasCC {
			cc, e = InspectCC(ctx, path)
			if e != nil {
				errs = append(errs, e)
				continue
			}
		} else if !os.IsNotExist(statErr) {
			errs = append(errs, statErr)
			continue
		}
		for _, app := range []string{"claude", "codex"} {
			content, readErr := os.ReadFile(configPath(p, app))
			exists := readErr == nil
			if readErr != nil && !os.IsNotExist(readErr) {
				errs = append(errs, readErr)
				continue
			}
			live := ""
			if exists {
				t, err := transform(app, content, "http://127.0.0.1:18080/r/inspection", false)
				if err != nil {
					errs = append(errs, err)
					continue
				}
				live = t.Previous
			}
			proxy, present := cc.Proxies[app]
			mode, _ := DetectCCMode(app, proxy, present, live)
			mapped := false
			for _, provider := range cc.Providers {
				if provider.App != app {
					continue
				}
				mapped = true
				t, err := ccTransform(app, provider.Settings, "http://127.0.0.1:18080/r/inspection", false)
				if err != nil {
					errs = append(errs, err)
					continue
				}
				endpoint := m.inspectEndpoint(p, app, ccIdentity(provider), t.Previous, mode, 2, provider.Current, 4, routes)
				endpoint.Model = inspectModel(app, []byte(provider.Settings), true)
				out = append(out, endpoint)
			}
			for _, endpoint := range cc.Endpoints {
				if endpoint.App != app {
					continue
				}
				mapped = true
				asset := m.inspectEndpoint(p, app, endpointIdentity(endpoint), endpoint.URL, mode, 3, false, 4, routes)
				for _, provider := range cc.Providers {
					if provider.App == app && provider.ID == endpoint.ProviderID {
						asset.Current = provider.Current
						asset.Model = inspectModel(app, []byte(provider.Settings), true)
						break
					}
				}
				asset.EndpointID = fmtEndpointID(endpoint.ID)
				out = append(out, asset)
			}
			if !mapped && exists {
				agent := 0
				if app == "codex" {
					agent = 1
				}
				asset := m.inspectEndpoint(p, app, "direct", live, mode, 1, true, agent, routes)
				asset.Model = inspectModel(app, content, false)
				out = append(out, asset)
			}
		}
	}
	return out, errors.Join(errs...)
}
func (m *Manager) inspectEndpoint(p Profile, family, identity, effective, mode string, source int, current bool, agent int, routes []contracts.Route) Endpoint {
	original := effective
	if original == "" && family == "claude" {
		original = "https://api.anthropic.com"
	}
	if effective == "" {
		effective = original
	}
	out := Endpoint{SID: p.SID, Family: family, ProviderID: identity, OriginalBaseURL: original, EffectiveBaseURL: effective, Mode: mode, Source: source, Current: current, RouteStatus: 0}
	for _, r := range routes {
		if r.UserSID == p.SID && r.AgentType == agent && r.ProviderID == identity && sameURL(effective, r.InjectedBaseURL) {
			out.OriginalBaseURL = r.OriginalBaseURL
			out.LocalRouteURL = r.InjectedBaseURL
			out.RouteStatus = r.Status
			break
		}
	}
	if m.Allowlisted != nil && m.Allowlisted(out.OriginalBaseURL) {
		out.Bypassed = true
		if out.LocalRouteURL == "" {
			out.RouteStatus = 7
		}
	}
	if mode == "inconsistent" {
		out.RouteStatus = 4
	}
	if mode == "unsupported" {
		out.RouteStatus = 5
	}
	return out
}
func fmtEndpointID(id int64) string { return strconv.FormatInt(id, 10) }
func inspectModel(app string, b []byte, cc bool) string {
	if app == "claude" {
		var root struct {
			Model string `json:"model"`
			Env   struct {
				Model string `json:"ANTHROPIC_MODEL"`
			} `json:"env"`
		}
		if json.Unmarshal(b, &root) != nil {
			return ""
		}
		if root.Env.Model != "" {
			return root.Env.Model
		}
		return root.Model
	}
	if cc {
		var root struct {
			Config string `json:"config"`
		}
		if json.Unmarshal(b, &root) != nil {
			return ""
		}
		b = []byte(root.Config)
	}
	var root map[string]any
	if toml.Unmarshal(b, &root) != nil {
		return ""
	}
	model, _ := root["model"].(string)
	return model
}
