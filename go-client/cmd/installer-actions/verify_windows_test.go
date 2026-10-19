package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWindowsListenerOwnershipAndProcessImage(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	pid := uint32(os.Getpid())
	if err = verifyListenerPID(pid, port); err != nil {
		t.Fatal(err)
	}
	if verifyListenerPID(pid+1, port) == nil {
		t.Fatal("accepted another process as listener owner")
	}
	image, err := processImage(pid)
	if err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(filepath.Clean(image), filepath.Clean(self)) {
		t.Fatal("process image mismatch")
	}
}
