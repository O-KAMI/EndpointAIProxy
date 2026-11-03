package app

import (
	"context"
	"testing"
	"time"
)

func TestPendingCredentialRotationNeverTriggersReenrollment(t *testing.T) {
	f := newFakeControl(t)
	a := newControlApp(t, f)
	ctx := context.Background()
	if err := a.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	oldToken := a.credential.Token
	// Corrupt/incompatible pending work must stay visible, even when an
	// ordinary request also returns an authenticated 401 during backoff.
	if err := a.Store.SavePendingCredentialRotation(ctx, "", "synthetic-invalid-pending"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		f.mu.Lock()
		f.inner401 = true
		f.mu.Unlock()
		a.nextPolicy = time.Time{}
		a.nextHeartbeat = time.Now().Add(time.Hour)
		if err := a.Sync(ctx); err == nil {
			t.Fatal("pending failure hidden")
		}
		if !a.rotationPending || f.count("enroll") != 1 || a.credential.Token != oldToken {
			t.Fatal("pending rotation caused re-enrollment or credential replacement")
		}
	}
	if pending, err := a.Store.LoadPendingCredentialRotation(ctx); err != nil || pending == "" {
		t.Fatal("pending evidence lost", err)
	}
}
