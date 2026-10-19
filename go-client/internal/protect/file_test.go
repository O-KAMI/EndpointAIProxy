package protect

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"os"
	"path/filepath"
	"testing"
)

func TestDotNetFileKeyBlobLayout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "machine.key")
	key := bytes.Repeat([]byte{5}, 32)
	if e := os.WriteFile(path, key, 0600); e != nil {
		t.Fatal(e)
	}
	p, e := NewFileKey(path)
	if e != nil {
		t.Fatal(e)
	}
	// Independently construct the exact C# version/nonce/tag/ciphertext layout.
	block, _ := aes.NewCipher(key)
	a, _ := cipher.NewGCM(block)
	nonce := bytes.Repeat([]byte{9}, 12)
	sealed := a.Seal(nil, nonce, []byte("synthetic token"), nil)
	blob := append([]byte{1}, nonce...)
	blob = append(blob, sealed[len(sealed)-16:]...)
	blob = append(blob, sealed[:len(sealed)-16]...)
	actual, e := p.Unprotect(blob)
	if e != nil || actual != "synthetic token" {
		t.Fatalf("%q %v", actual, e)
	}
	out, e := p.Protect("synthetic token")
	if e != nil {
		t.Fatal(e)
	}
	plain, e := a.Open(nil, out[1:13], append(append([]byte{}, out[29:]...), out[13:29]...), nil)
	if e != nil || string(plain) != "synthetic token" {
		t.Fatalf("%q %v", plain, e)
	}
	out[13] ^= 1
	if _, e = p.Unprotect(out); e == nil {
		t.Fatal("accepted tampered blob")
	}
	if _, e = p.Unprotect([]byte{1}); e == nil {
		t.Fatal("accepted truncated blob")
	}
}
func TestMachineKeyPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "machine.key")
	a, e := NewFileKey(path)
	if e != nil {
		t.Fatal(e)
	}
	b, e := NewFileKey(path)
	if e != nil {
		t.Fatal(e)
	}
	v, e := a.Protect("synthetic")
	if e != nil {
		t.Fatal(e)
	}
	if s, e := b.Unprotect(v); e != nil || s != "synthetic" {
		t.Fatalf("%q %v", s, e)
	}
}
