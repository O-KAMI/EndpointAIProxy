package installguard

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGuardOwnershipAndCommit(t *testing.T) {
	root := t.TempDir()
	if Pending(root) {
		t.Fatal("fresh root pending")
	}
	if err := Begin(root, "one"); err != nil {
		t.Fatal(err)
	}
	if !Pending(root) {
		t.Fatal("guard inactive")
	}
	if err := Begin(root, "two"); err == nil {
		t.Fatal("overwrote another transaction")
	}
	if err := Release(root, "two"); err == nil {
		t.Fatal("released another transaction")
	}
	if err := Release(root, "one"); err != nil {
		t.Fatal(err)
	}
	if Pending(root) {
		t.Fatal("committed guard still active")
	}
}
func TestUnreadableOrMalformedMarkerIsPending(t *testing.T) {
	root := t.TempDir()
	os.Mkdir(filepath.Join(root, Filename), 0700)
	if !Pending(root) {
		t.Fatal("unsafe marker ignored")
	}
	if err := Release(root, "one"); err == nil {
		t.Fatal("unsafe marker removed")
	}
}
