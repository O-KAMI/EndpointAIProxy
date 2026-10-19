package platform

import (
	"endpointai/client/internal/observability"
	"errors"
	"testing"
)

func TestStartupServiceCodes(t *testing.T) {
	if StartupCode(observability.Wrap("listener", "CLIENT_ENDPOINT_IN_USE", errors.New("private"))) != 2001 {
		t.Fatal("lost service-specific listener code")
	}
	if StartupCode(observability.Wrap("machine_key", "MACHINE_KEY_MISSING", errors.New("private"))) != 2003 {
		t.Fatal("lost key code")
	}
	if StartupCode(errors.New("raw secret")) != 1 {
		t.Fatal("unclassified startup failure changed")
	}
}
