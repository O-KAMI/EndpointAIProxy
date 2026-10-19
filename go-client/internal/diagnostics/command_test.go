package diagnostics

import (
	"strings"
	"testing"
	"time"
)

func TestWindowsCollectorsBoundAndSelectService(t *testing.T) {
	commands := commandsForOS("windows", 4*time.Hour)
	for _, needed := range []string{"queryex", "qc", "qfailure"} {
		found := false
		for _, c := range commands {
			if c.exe == "sc.exe" && c.args[0] == needed && c.args[1] == "SfEndpointAIProxy" {
				found = true
			}
		}
		if !found {
			t.Fatal("missing collector", needed)
		}
	}
	var events command
	for _, c := range commands {
		if c.name == "service-events" {
			events = c
		}
	}
	args := strings.Join(events.args, " ")
	for _, want := range []string{"Service Control Manager", "SfEndpointAIProxy", "14400000", "/c:100", "/e:Events"} {
		if !strings.Contains(args, want) {
			t.Fatal("unbounded or unfiltered event collection", want)
		}
	}
	var b boundedCommandOutput
	data := []byte(strings.Repeat("x", 128<<10))
	n, err := b.Write(data)
	if err != nil || n != len(data) || len(b.data) != 64<<10 || !b.truncated {
		t.Fatal("output bound not enforced")
	}
}

func TestWindowsDiagnosticFreeTextExcluded(t *testing.T) {
	raw := "SERVICE_NAME: SfEndpointAIProxy\nSTATE: 4 RUNNING\nBINARY_PATH_NAME: C:\\client.exe --token secret\nCOMMAND_LINE: bearer secret\nSERVICE_START_NAME: private-user\n"
	safe := sanitizeCommand("service-config", "windows", raw)
	if strings.Contains(safe, "secret") || strings.Contains(safe, "private-user") || !strings.Contains(safe, "4 RUNNING") {
		t.Fatal(safe)
	}
	xml := `<Events><Event><System><EventID>7036</EventID><Level>4</Level><EventRecordID>23</EventRecordID><TimeCreated SystemTime="2026-10-14T10:00:00Z"/></System><EventData><Data>SfEndpointAIProxy</Data><Data>secret</Data></EventData></Event><Event><System><EventID>9999</EventID></System><EventData><Data>OtherService</Data></EventData></Event></Events>`
	safe = sanitizeCommand("service-events", "windows", xml)
	if strings.Contains(safe, "secret") || strings.Contains(safe, "9999") || !strings.Contains(safe, "7036") {
		t.Fatal(safe)
	}
}
