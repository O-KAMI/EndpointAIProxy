package platform

import "endpointai/client/internal/observability"

// StartupCode is a stable service-specific code, independent of error text.
func StartupCode(err error) uint32 {
	switch observability.Classify(err).Code {
	case "CLIENT_ENDPOINT_IN_USE":
		return 2001
	case "DATA_ROOT_UNAVAILABLE":
		return 2002
	case "MACHINE_KEY_MISSING", "MACHINE_KEY_UNAVAILABLE":
		return 2003
	case "CLIENT_STATE_UNAVAILABLE":
		return 2004
	case "CLIENT_INSTANCE_LOCKED":
		return 2005
	case "CLIENT_LISTENER_FAILED":
		return 2006
	case "CLIENT_INITIALIZATION_FAILED":
		return 2007
	default:
		return 1
	}
}
