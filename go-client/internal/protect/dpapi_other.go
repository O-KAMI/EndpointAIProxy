//go:build !windows

package protect

import "errors"

type DPAPI struct{}

func NewDPAPI() (*DPAPI, error)                 { return nil, errors.New("DPAPI requires Windows") }
func (*DPAPI) Protect(string) ([]byte, error)   { return nil, errors.New("DPAPI requires Windows") }
func (*DPAPI) Unprotect([]byte) (string, error) { return "", errors.New("DPAPI requires Windows") }
