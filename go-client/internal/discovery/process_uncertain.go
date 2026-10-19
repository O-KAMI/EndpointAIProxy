package discovery

import (
	"endpointai/client/internal/platform"
	"path/filepath"
	"strings"
)

// A failed read cannot prove that Node is not DSH. Restrict uncertainty to the
// known owner; if ownership is unavailable, every supplied profile is affected.
// These samples remain local completeness signals and are never inventory.
func uncertainProcessSamples(profiles []platform.Profile, sid, path string) []sample {
	var out []sample
	for _, p := range profiles {
		owned := sid == p.SID || path != "" && strings.HasPrefix(strings.ToLower(path), strings.ToLower(p.Home+string(filepath.Separator)))
		if sid == "" || owned {
			out = append(out, sample{sid: p.SID, inspectionUnknown: true})
		}
	}
	return out
}
