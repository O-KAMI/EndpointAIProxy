package platform

import "strings"

// ShortAccountName is a display/attribution value; SID remains the identity key.
func ShortAccountName(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(strings.ToUpper(value), "S-1-") || strings.EqualFold(value, "SID") {
		return ""
	}
	if i := strings.LastIndexAny(value, `/\`); i >= 0 {
		value = value[i+1:]
	}
	return strings.TrimPrefix(value, "macos:")
}
