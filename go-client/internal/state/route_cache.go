package state

import (
	"context"
	"endpointai/client/internal/contracts"
)

// Only a writable, exclusively owned store has a route snapshot. Read-only
// diagnostics keep querying SQLite and never assume ownership of live state.
type routeSnapshot struct{ values map[string]contracts.Route }

func (s *Store) initializeRoutes(ctx context.Context) error {
	routes, e := s.ListRoutes(ctx)
	if e != nil {
		return e
	}
	values := make(map[string]contracts.Route, len(routes))
	for _, r := range routes {
		values[r.RouteID] = r
	}
	s.routes.Store(&routeSnapshot{values: values})
	return nil
}

// Called only under routeMu, after SQLite successfully commits the mutation.
// Immutable maps make forwarding reads independent of the SQLite connection.
func (s *Store) publishRoute(r contracts.Route) {
	current := s.routes.Load()
	if current == nil {
		return
	}
	values := make(map[string]contracts.Route, len(current.values)+1)
	for id, existing := range current.values {
		values[id] = existing
	}
	if existing, found := values[r.RouteID]; found {
		r.CreatedAtUTC = existing.CreatedAtUTC
	} else {
		r.CreatedAtUTC, _ = parse(format(r.CreatedAtUTC))
	}
	r.UpdatedAtUTC, _ = parse(format(r.UpdatedAtUTC))
	values[r.RouteID] = r
	s.routes.Store(&routeSnapshot{values: values})
}

func (s *Store) publishDeletion(id string) {
	current := s.routes.Load()
	if current == nil {
		return
	}
	values := make(map[string]contracts.Route, len(current.values))
	for existingID, r := range current.values {
		if existingID != id {
			values[existingID] = r
		}
	}
	s.routes.Store(&routeSnapshot{values: values})
}
