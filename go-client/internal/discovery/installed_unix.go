//go:build !windows

package discovery

import (
	"context"
	"endpointai/client/internal/platform"
)

func installedSamples(ctx context.Context, profiles []platform.Profile) ([]sample, error) {
	return nil, nil
}
