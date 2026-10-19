//go:build windows

package protect

import (
	"errors"
	"golang.org/x/sys/windows"
	"strings"
	"unsafe"
)

type DPAPI struct{}

func NewDPAPI() (*DPAPI, error) { return &DPAPI{}, nil }
func blob(b []byte) windows.DataBlob {
	v := windows.DataBlob{Size: uint32(len(b))}
	if len(b) > 0 {
		v.Data = &b[0]
	}
	return v
}
func (p *DPAPI) Protect(s string) ([]byte, error) {
	if strings.TrimSpace(s) == "" {
		return nil, errors.New("empty protected value")
	}
	return dpapi([]byte(s), true)
}
func (p *DPAPI) Unprotect(b []byte) (string, error) {
	out, e := dpapi(b, false)
	if e != nil {
		return "", e
	}
	defer clear(out)
	return string(out), nil
}
func dpapi(b []byte, encrypt bool) ([]byte, error) {
	in, entropy := blob(b), blob([]byte("SF.EndpointAI.Route.v1"))
	var out windows.DataBlob
	var err error
	if encrypt {
		err = windows.CryptProtectData(&in, nil, &entropy, 0, nil, windows.CRYPTPROTECT_LOCAL_MACHINE|windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	} else {
		err = windows.CryptUnprotectData(&in, nil, &entropy, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	}
	if err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	result := append([]byte(nil), unsafe.Slice(out.Data, out.Size)...)
	clear(unsafe.Slice(out.Data, out.Size))
	return result, nil
}
