package diagnostics

import (
	"encoding/json"
	"encoding/xml"
	"regexp"
	"strings"
)

// Consume all child output without retaining unbounded buffers or blocking its
// stdout pipe. CommandContext independently enforces the collector deadline.
type boundedCommandOutput struct {
	data      []byte
	truncated bool
}

func (b *boundedCommandOutput) Write(p []byte) (int, error) {
	n := len(p)
	remaining := (64 << 10) - len(b.data)
	if len(p) > remaining {
		p = p[:remaining]
		b.truncated = true
	}
	b.data = append(b.data, p...)
	return n, nil
}

func sanitizeCommand(name, goos, output string) string {
	if goos != "windows" {
		return output
	}
	if name == "service-events" {
		var events struct {
			Events []struct {
				System struct {
					ID       int    `xml:"EventID"`
					Level    int    `xml:"Level"`
					RecordID uint64 `xml:"EventRecordID"`
					Time     struct {
						Value string `xml:"SystemTime,attr"`
					} `xml:"TimeCreated"`
				} `xml:"System"`
				Data []string `xml:"EventData>Data"`
			} `xml:"Event"`
		}
		if xml.Unmarshal([]byte(output), &events) != nil {
			return "[event XML unavailable or truncated]"
		}
		rows := []map[string]any{}
		for _, event := range events.Events {
			matched := false
			for _, data := range event.Data {
				if data == "SfEndpointAIProxy" || data == "顺丰终端 AI 请求代理" {
					matched = true
				}
			}
			if matched {
				rows = append(rows, map[string]any{"eventId": event.System.ID, "level": event.System.Level, "recordId": event.System.RecordID, "timeUtc": event.System.Time.Value})
			}
		}
		raw, _ := json.Marshal(rows)
		return string(raw)
	}
	if name == "platform" {
		return regexp.MustCompile(`[^A-Za-z0-9 .\[\]\r\n-]`).ReplaceAllString(output, "")
	}
	var safe []string
	for _, line := range strings.Split(output, "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), ":")
		if !found {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		switch key {
		case "SERVICE_NAME":
			if value == "SfEndpointAIProxy" {
				safe = append(safe, key+": "+value)
			}
		case "TYPE", "STATE", "WIN32_EXIT_CODE", "SERVICE_EXIT_CODE", "CHECKPOINT", "WAIT_HINT", "PID", "FLAGS", "START_TYPE", "ERROR_CONTROL", "TAG", "RESET_PERIOD (in seconds)", "FAILURE_ACTIONS":
			if regexp.MustCompile(`^[A-Za-z0-9_(), .x-]{0,256}$`).MatchString(value) {
				safe = append(safe, key+": "+value)
			}
		case "BINARY_PATH_NAME", "SERVICE_START_NAME", "LOAD_ORDER_GROUP", "DEPENDENCIES", "DISPLAY_NAME", "REBOOT_MESSAGE", "COMMAND_LINE":
			// These free-text fields can contain usernames or credential arguments.
			safe = append(safe, key+": "+hashIdentifier(value))
		}
	}
	return strings.Join(safe, "\n")
}
