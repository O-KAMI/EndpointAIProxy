//go:build !windows

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "Synthetic DPAPI interoperability requires Windows.")
	os.Exit(2)
}
