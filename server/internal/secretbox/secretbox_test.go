package secretbox

import (
	"crypto/rand"
	"strings"
	"testing"
)

func testCipher(t *testing.T) *Cipher {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	c, err := New(k)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	c := testCipher(t)
	enc, err := c.Encrypt("tvly-secret-value")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(enc, Prefix) || strings.Contains(enc, "tvly-secret-value") {
		t.Fatalf("bad ciphertext form: %q", enc)
	}
	dec, err := c.Decrypt(enc)
	if err != nil || dec != "tvly-secret-value" {
		t.Fatalf("round trip failed: %q %v", dec, err)
	}
	// Legacy plaintext passes through.
	if dec, err := c.Decrypt("tvly-plain"); err != nil || dec != "tvly-plain" {
		t.Fatalf("legacy passthrough failed: %q %v", dec, err)
	}
	// Wrong key must fail, not return garbage.
	k2 := make([]byte, 32)
	c2, _ := New(k2)
	if _, err := c2.Decrypt(enc); err == nil {
		t.Fatal("expected decrypt failure with wrong key")
	}
}
