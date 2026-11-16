// Package secretbox provides AES-256-GCM encryption for secrets stored at
// rest (Tavily API keys and the admin/proxy tokens) in the SQLite database.
//
// Stored values carry the prefix "enc:v1:" followed by base64url(nonce||ct).
// Values without the prefix are treated as legacy plaintext so existing
// databases keep working; callers are expected to re-encrypt on load/save.
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const Prefix = "enc:v1:"

type Cipher struct {
	aead cipher.AEAD
}

func New(key []byte) (*Cipher, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Cipher{aead: aead}, nil
}

// ParseKey decodes a base64 (std or url, padded or raw) 32-byte key.
func ParseKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == 32 {
			return b, nil
		}
	}
	return nil, errors.New("TPM_ENCRYPTION_KEY is not a base64-encoded 32-byte key")
}

// LoadOrCreateKeyFile reads a base64 key from path (0600). When the file does
// not exist it generates a fresh random key and writes it with 0600
// permissions. It reports whether the key was newly created. The key itself
// is never logged by this package.
func LoadOrCreateKeyFile(path string) (key []byte, created bool, err error) {
	if b, rerr := os.ReadFile(path); rerr == nil {
		k, perr := ParseKey(string(b))
		if perr != nil {
			return nil, false, fmt.Errorf("encryption key file %s: %w", path, perr)
		}
		return k, false, nil
	} else if !errors.Is(rerr, os.ErrNotExist) {
		return nil, false, rerr
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false, err
	}
	encoded := base64.StdEncoding.EncodeToString(k) + "\n"
	if err := os.WriteFile(path, []byte(encoded), 0o600); err != nil {
		return nil, false, err
	}
	return k, true, nil
}

func IsEncrypted(s string) bool { return strings.HasPrefix(s, Prefix) }

// Encrypt returns "" for "" so empty fields stay empty.
func (c *Cipher) Encrypt(plain string) (string, error) {
	if c == nil || plain == "" {
		return plain, nil
	}
	if IsEncrypted(plain) {
		return plain, nil
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := c.aead.Seal(nonce, nonce, []byte(plain), nil)
	return Prefix + base64.RawURLEncoding.EncodeToString(ct), nil
}

// Decrypt reverses Encrypt. Legacy plaintext (no prefix) is returned as-is.
func (c *Cipher) Decrypt(stored string) (string, error) {
	if c == nil || stored == "" || !IsEncrypted(stored) {
		return stored, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(stored, Prefix))
	if err != nil {
		return "", err
	}
	ns := c.aead.NonceSize()
	if len(raw) < ns {
		return "", errors.New("ciphertext too short")
	}
	pt, err := c.aead.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}
