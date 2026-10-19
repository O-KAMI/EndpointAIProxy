//go:build !windows

package main

import "errors"

func execute(args []string) error { return errors.New("installer actions require Windows") }
