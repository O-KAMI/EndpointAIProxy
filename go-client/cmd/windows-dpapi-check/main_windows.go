package main

import (
	"endpointai/client/internal/protect"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	directory := flag.String("directory", "", "isolated fixture directory")
	mode := flag.String("mode", "", "write or verify synthetic fixture")
	flag.Parse()
	if *directory == "" || (*mode != "write" && *mode != "verify") || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "Expected -directory <temporary-directory> -mode write|verify")
		os.Exit(2)
	}
	p, err := protect.NewDPAPI()
	if err == nil && *mode == "write" {
		var blob []byte
		blob, err = p.Protect("synthetic-go-dpapi")
		if err == nil {
			err = os.WriteFile(filepath.Join(*directory, "go.blob"), blob, 0600)
		}
	} else if err == nil {
		var blob []byte
		blob, err = os.ReadFile(filepath.Join(*directory, "dotnet.blob"))
		if err == nil {
			var value string
			value, err = p.Unprotect(blob)
			if err == nil && value != "synthetic-dotnet-dpapi" {
				err = fmt.Errorf("synthetic fixture mismatch")
			}
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Synthetic DPAPI interoperability failed; values withheld.")
		os.Exit(1)
	}
}
