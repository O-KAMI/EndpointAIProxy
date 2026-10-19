package platform

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

func awaitUserID(t *testing.T, c *userIDCache, sid, want string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if c.resolve(sid) == want {
			c.mu.RLock()
			done := !c.active[sid]
			c.mu.RUnlock()
			if done {
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("lookup did not complete")
}

func TestUserIDCacheDoesNotResolveOnRequestAndMergesRefresh(t *testing.T) {
	c := newUserIDCache(4, 1)
	var calls atomic.Int32
	started, release := make(chan struct{}), make(chan struct{})
	lookup := func(s string) (string, error) { calls.Add(1); close(started); <-release; return "SF123456", nil }
	if got := c.resolve("SID"); got != "SID" || calls.Load() != 0 {
		t.Fatal("request performed native lookup")
	}
	c.refresh(context.Background(), []string{"SID"}, lookup)
	<-started
	for i := 0; i < 100; i++ {
		c.refresh(context.Background(), []string{"SID"}, lookup)
		if c.resolve("SID") != "SID" {
			t.Fatal("unexpected cache miss fallback")
		}
	}
	if calls.Load() != 1 {
		t.Fatal("concurrent refresh not merged")
	}
	close(release)
	awaitUserID(t, c, "SID", "SF123456")
	c.refresh(context.Background(), []string{"SID"}, lookup)
	if calls.Load() != 1 {
		t.Fatal("fresh success refreshed")
	}
	c.mu.RLock()
	ttl := c.entries["SID"].refreshAfter.Sub(c.entries["SID"].refreshed)
	c.mu.RUnlock()
	if ttl != time.Hour {
		t.Fatal("success TTL mismatch")
	}
}

func TestUserIDCacheCancellationBoundsAndFailureTTL(t *testing.T) {
	c := newUserIDCache(2, 1)
	ctx, cancel := context.WithCancel(context.Background())
	started, release := make(chan struct{}), make(chan struct{})
	c.refresh(ctx, []string{"blocked", "other"}, func(s string) (string, error) { close(started); <-release; return "late", nil })
	<-started
	cancel()
	before := time.Now()
	c.refresh(ctx, []string{"later"}, func(string) (string, error) { t.Error("cancelled lookup ran"); return "", nil })
	if time.Since(before) > time.Second {
		t.Fatal("cancelled refresh waited on native API")
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		c.mu.RLock()
		active := len(c.active)
		c.mu.RUnlock()
		if active == 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if c.resolve("blocked") != "blocked" {
		t.Fatal("late cancelled result cached")
	}
	c.refresh(context.Background(), []string{"failed"}, func(string) (string, error) { return "", errors.New("synthetic") })
	awaitUserID(t, c, "failed", "failed")
	c.mu.RLock()
	ttl := c.entries["failed"].refreshAfter.Sub(c.entries["failed"].refreshed)
	c.mu.RUnlock()
	if ttl != time.Minute {
		t.Fatal("failure TTL mismatch")
	}
	for i := 0; i < 4; i++ {
		sid := fmt.Sprint(i)
		c.refresh(context.Background(), []string{sid}, func(s string) (string, error) { return "user-" + s, nil })
		awaitUserID(t, c, sid, "user-"+sid)
	}
	c.mu.RLock()
	size := len(c.entries)
	c.mu.RUnlock()
	if size > 2 {
		t.Fatal("cache limit exceeded")
	}
}
