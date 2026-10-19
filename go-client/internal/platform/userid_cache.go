package platform

import (
	"context"
	"sync"
	"time"
)

type userIDEntry struct {
	value                   string
	refreshed, refreshAfter time.Time
}

type userIDCache struct {
	mu      sync.RWMutex
	entries map[string]userIDEntry
	active  map[string]bool
	slots   chan struct{}
	limit   int
}

func newUserIDCache(limit, parallel int) *userIDCache {
	return &userIDCache{entries: map[string]userIDEntry{}, active: map[string]bool{}, slots: make(chan struct{}, parallel), limit: limit}
}

// resolve has no operating-system calls, allocation or background scheduling.
// A miss preserves the existing failed-lookup fallback to the original SID.
func (c *userIDCache) resolve(sid string) string {
	c.mu.RLock()
	entry, ok := c.entries[sid]
	c.mu.RUnlock()
	if ok && entry.value != "" {
		return entry.value
	}
	return sid
}

// At most parallel lookups can be outstanding, even when the native resolver
// blocks. Repeated background refreshes merge by SID and skip entries until due.
func (c *userIDCache) refresh(ctx context.Context, sids []string, lookup func(string) (string, error)) {
	for _, sid := range sids {
		if ctx.Err() != nil {
			return
		}
		if sid == "" {
			continue
		}
		now := time.Now()
		c.mu.Lock()
		entry, exists := c.entries[sid]
		if c.active[sid] || exists && now.Before(entry.refreshAfter) {
			c.mu.Unlock()
			continue
		}
		select {
		case c.slots <- struct{}{}:
		default:
			c.mu.Unlock()
			return
		}
		c.active[sid] = true
		c.mu.Unlock()
		go func(sid string) {
			value := ""
			var err error
			if ctx.Err() == nil {
				value, err = lookup(sid)
			}
			c.mu.Lock()
			defer func() { <-c.slots; c.mu.Unlock() }()
			delete(c.active, sid)
			if ctx.Err() != nil {
				return
			}
			ttl := time.Hour
			if err != nil || value == "" {
				value = sid
				ttl = time.Minute
			}
			if _, exists := c.entries[sid]; !exists && len(c.entries) >= c.limit {
				oldest := ""
				var at time.Time
				for key, entry := range c.entries {
					if oldest == "" || entry.refreshed.Before(at) {
						oldest, at = key, entry.refreshed
					}
				}
				delete(c.entries, oldest)
			}
			now := time.Now()
			c.entries[sid] = userIDEntry{value: value, refreshed: now, refreshAfter: now.Add(ttl)}
		}(sid)
	}
}
