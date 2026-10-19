package main

import (
	"fmt"
	"os"
)

// Injected with the same -X main.version value as the service executable.
var version = "0.2.0"

func main() {
	if e := execute(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, "EndpointAI installer action failed; see protected InstallerLogs for the stage.")
		os.Exit(1603)
	}
}
