package main

import (
	"encoding/json"
	"endpointai/client/internal/configuration"
	"errors"
	"strings"
	"testing"
)

func TestMaintenanceFailureDoesNotExportRawErrors(t *testing.T) {
	for _, err := range []error{errors.New("private-token=synthetic-secret"), &configuration.MutationError{Code: "private-token=synthetic-secret"}} {
		b, _ := json.Marshal(maintenanceFailureFields("detach_configuration", err))
		if strings.Contains(string(b), "synthetic-secret") || !strings.Contains(string(b), "CLIENT_MAINTENANCE_FAILED") {
			t.Fatal("raw failure escaped sanitization")
		}
	}
	fields := maintenanceFailureFields("detach_configuration", &configuration.MutationError{Code: "DETACH_CONFIG_CHANGED"})
	b, _ := json.Marshal(fields)
	if !strings.Contains(string(b), "DETACH_CONFIG_CHANGED") || !strings.Contains(string(b), "detach_configuration") {
		t.Fatal("fixed diagnostic code or stage missing")
	}
}
