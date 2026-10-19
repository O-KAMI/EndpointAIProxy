package protect

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// FileKey preserves the .NET format: version || nonce || tag || ciphertext.
type FileKey struct{ key [32]byte }

func NewFileKey(path string) (*FileKey, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("empty key path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	for _, candidate := range []string{filepath.Dir(path), path} {
		info, err := os.Lstat(candidate)
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("machine key path must not be a symbolic link")
		}
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		b = make([]byte, 32)
		if _, err = rand.Read(b); err != nil {
			return nil, err
		}
		f, e := os.CreateTemp(filepath.Dir(path), ".machine-key-*")
		if e != nil {
			return nil, e
		}
		defer os.Remove(f.Name())
		if e = f.Chmod(0600); e == nil {
			_, e = f.Write(b)
		}
		if e == nil {
			e = f.Sync()
		}
		ce := f.Close()
		if e != nil {
			return nil, e
		}
		if ce != nil {
			return nil, ce
		}
		// A hard link publishes a fully synced key without overwriting a concurrent creator.
		if e = os.Link(f.Name(), path); e != nil {
			if !os.IsExist(e) {
				return nil, e
			}
			b, err = os.ReadFile(path)
		} else {
			err = nil
		}
	}
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, errors.New("invalid machine key length")
	}
	p := &FileKey{}
	copy(p.key[:], b)
	clear(b)
	return p, nil
}
func (p *FileKey) aead() cipher.AEAD {
	b, _ := aes.NewCipher(p.key[:])
	a, _ := cipher.NewGCM(b)
	return a
}
func (p *FileKey) Protect(value string) ([]byte, error) {
	if strings.TrimSpace(value) == "" {
		return nil, errors.New("empty protected value")
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	cleartext := []byte(value)
	defer clear(cleartext)
	sealed := p.aead().Seal(nil, nonce, cleartext, nil)
	out := append([]byte{1}, nonce...)
	out = append(out, sealed[len(sealed)-16:]...)
	return append(out, sealed[:len(sealed)-16]...), nil
}
func (p *FileKey) Unprotect(b []byte) (string, error) {
	if len(b) < 29 || b[0] != 1 {
		return "", errors.New("invalid protected value format")
	}
	sealed := append(append([]byte{}, b[29:]...), b[13:29]...)
	plain, err := p.aead().Open(nil, b[1:13], sealed, nil)
	if err != nil {
		return "", err
	}
	defer clear(plain)
	return string(plain), nil
}
