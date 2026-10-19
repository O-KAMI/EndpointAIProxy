package main

import (
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"io"
)

func validateHealth(r io.Reader, expectedVersion string, expectedDeviceID ...string) error {
	var health struct {
		Status         string `json:"status"`
		Version        string `json:"clientVersion"`
		Implementation string `json:"implementation"`
		DeviceID       string `json:"deviceId"`
	}
	d := json.NewDecoder(io.LimitReader(r, 64<<10))
	if err := d.Decode(&health); err != nil {
		return errors.New("invalid health response")
	}
	id, err := uuid.Parse(health.DeviceID)
	if err != nil || id == uuid.Nil || health.Status != "ok" || health.Version != expectedVersion || health.Implementation != "go" {
		return errors.New("client not ready")
	}
	if len(expectedDeviceID) > 0 && expectedDeviceID[0] != "" && health.DeviceID != expectedDeviceID[0] {
		return errors.New("migrated health identity mismatch")
	}
	var trailing any
	if d.Decode(&trailing) != io.EOF {
		return errors.New("invalid health response suffix")
	}
	return nil
}
