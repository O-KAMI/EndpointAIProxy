package app

import (
	"context"
	"errors"
	"time"

	"endpointai/client/internal/contracts"
)

// Called with syncControl held, before ordinary requests and after a successful
// heartbeat. Pending work survives missing capabilities and process restarts.
func (a *App) rotateCredential(ctx context.Context, heartbeat *contracts.HeartbeatV2Response) error {
	if time.Now().Before(a.nextCredentialRotation) {
		return nil
	}
	changed, pending, err := a.Client.RotateCredential(ctx, a.deviceID, a.credential.Token, a.credential.EnrolledAtUTC, heartbeat)
	a.rotationPending = pending
	if changed {
		a.credential, err = a.Store.LoadCredential(ctx)
		if err == nil && a.credential == nil {
			err = errors.New("CONTROL_ROTATION_CREDENTIAL_MISSING")
		}
		if err == nil {
			a.Audit.Log("DEVICE_CREDENTIAL_ROTATED", map[string]any{"status": "completed"})
		}
	}
	if err != nil {
		a.credentialRotationRetries++
		a.nextCredentialRotation = time.Now().Add(controlRetryDelayFor(a.credentialRotationRetries, err))
	} else {
		a.credentialRotationRetries = 0
		a.nextCredentialRotation = time.Time{}
	}
	a.controlResult("credential_rotation", err)
	return err
}
