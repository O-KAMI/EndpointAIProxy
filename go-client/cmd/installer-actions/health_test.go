package main

import (
	"strings"
	"testing"
)

func TestHealthRequiresOwnReadyVersionButAllowsOfflineControl(t *testing.T) {
	good := `{"status":"ok","clientVersion":"0.2.0","implementation":"go","deviceId":"7fc74a63-6799-4e7a-8c3c-98c2edc3157e","lastControlErrorCode":"CONTROL_OFFLINE"}`
	if err := validateHealth(strings.NewReader(good), "0.2.0"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		strings.ReplaceAll(good, `"go"`, `"dotnet"`),
		strings.ReplaceAll(good, `"ok"`, `"degraded"`),
		strings.ReplaceAll(good, `"0.2.0"`, `"0.1.22"`),
		strings.ReplaceAll(good, `7fc74a63-6799-4e7a-8c3c-98c2edc3157e`, `00000000-0000-0000-0000-000000000000`),
		good + `{}`, `not json`,
	} {
		if validateHealth(strings.NewReader(bad), "0.2.0") == nil {
			t.Fatal("accepted invalid readiness")
		}
	}
	if validateHealth(strings.NewReader(strings.ReplaceAll(good, "0.2.0", "0.3.0")), "0.3.0") != nil {
		t.Fatal("version injection ignored")
	}
}

func TestHealthBindsMigrationIdentity(t *testing.T) {
	body := `{"status":"ok","clientVersion":"0.2.2","implementation":"go","deviceId":"40000000-0000-0000-0000-000000000004"}`
	if err := validateHealth(strings.NewReader(body), "0.2.2", "50000000-0000-0000-0000-000000000005"); err == nil {
		t.Fatal("foreign identity accepted")
	}
	if err := validateHealth(strings.NewReader(body), "0.2.2", "40000000-0000-0000-0000-000000000004"); err != nil {
		t.Fatal(err)
	}
}
