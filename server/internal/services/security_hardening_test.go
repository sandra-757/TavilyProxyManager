package services

import (
	"context"
	"crypto/rand"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"tavily-proxy/server/internal/db"
	"tavily-proxy/server/internal/models"
	"tavily-proxy/server/internal/secretbox"
)

func testCipher(t *testing.T) *secretbox.Cipher {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	c, err := secretbox.New(k)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func openTestDB(t *testing.T) (dbPath string, closeFn func()) {
	t.Helper()
	return filepath.Join(t.TempDir(), "app.db"), func() {}
}

func TestKeyService_EncryptsAtRest(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	database, err := db.Open(filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	keys := NewKeyService(database, logger).WithCipher(testCipher(t))

	const plain = "tvly-test-1234567890abcdef"
	if _, err := keys.Create(ctx, plain, "pool", 1000); err != nil {
		t.Fatal(err)
	}

	// Raw row must be ciphertext.
	var raw models.APIKey
	if err := database.WithContext(ctx).First(&raw).Error; err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(raw.Key, secretbox.Prefix) || strings.Contains(raw.Key, plain) {
		t.Fatalf("stored key is not encrypted: %q", raw.Key)
	}

	// Read paths return plaintext.
	list, err := keys.List(ctx)
	if err != nil || len(list) != 1 || list[0].Key != plain {
		t.Fatalf("list did not decrypt: %+v %v", list, err)
	}
	cands, err := keys.Candidates(ctx)
	if err != nil || len(cands) != 1 || cands[0].Key != plain {
		t.Fatalf("candidates did not decrypt: %+v %v", cands, err)
	}

	// Duplicate plaintext is rejected even though ciphertext differs.
	if _, err := keys.Create(ctx, plain, "dup", 1000); err == nil {
		t.Fatal("expected duplicate key rejection")
	}
}

func TestMasterKeyService_TokenTiersAndEncryption(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	database, err := db.Open(filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	master := NewMasterKeyService(database, logger).WithCipher(testCipher(t))
	if err := master.LoadOrCreate(ctx); err != nil {
		t.Fatal(err)
	}

	admin, proxy := master.Get(), master.GetProxy()
	if admin == "" || proxy == "" || admin == proxy {
		t.Fatalf("bad tokens: admin empty=%v proxy empty=%v equal=%v", admin == "", proxy == "", admin == proxy)
	}
	if !master.Authenticate(admin) || master.Authenticate(proxy) {
		t.Fatal("admin authentication tier is wrong")
	}
	if !master.AuthenticateProxy(proxy) || !master.AuthenticateProxy(admin) {
		t.Fatal("proxy authentication tier is wrong")
	}

	// Stored settings must be ciphertext.
	var rows []models.Setting
	if err := database.WithContext(ctx).Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Key == masterKeySettingKey || r.Key == proxyKeySettingKey {
			if !strings.HasPrefix(r.Value, secretbox.Prefix) {
				t.Fatalf("setting %s stored in plaintext", r.Key)
			}
			if strings.Contains(r.Value, admin) || strings.Contains(r.Value, proxy) {
				t.Fatalf("setting %s leaks token value", r.Key)
			}
		}
	}
}

func TestAuthLimiter_BlocksAfterThreshold(t *testing.T) {
	l := NewAuthLimiter(3, 60_000_000_000, 60_000_000_000)
	for i := 0; i < 3; i++ {
		if l.Blocked("1.2.3.4") {
			t.Fatalf("blocked too early at %d", i)
		}
		l.Fail("1.2.3.4")
	}
	if !l.Blocked("1.2.3.4") {
		t.Fatal("expected client to be blocked")
	}
	if l.Blocked("5.6.7.8") {
		t.Fatal("other client must not be blocked")
	}
	l2 := NewAuthLimiter(2, 60_000_000_000, 60_000_000_000)
	l2.Fail("9.9.9.9")
	l2.Success("9.9.9.9")
	l2.Fail("9.9.9.9")
	if l2.Blocked("9.9.9.9") {
		t.Fatal("success should clear failure history")
	}
}
