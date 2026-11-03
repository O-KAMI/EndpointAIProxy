package contracts

// Desktop account support is pinned to reviewed packaged runtimes, not a
// semver range. CLI/API-key compatibility has its own independent gate.
func DSHDesktopAccountVersionSupported(version string) bool {
	return version == "0.2.1-rc.2" || version == "0.2.1-rc.3"
}
