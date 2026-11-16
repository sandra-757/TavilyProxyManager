package services

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"tavily-proxy/server/internal/models"
	"tavily-proxy/server/internal/secretbox"

	"gorm.io/gorm"
)

const masterKeySettingKey = "master_key"
const proxyKeySettingKey = "proxy_key"

// MasterKeyService manages two tiers of tokens:
//
//   - Admin (master) key: full access, including the /api management plane.
//   - Proxy key: may only call the Tavily proxy endpoints and the MCP
//     endpoint. It is rejected by every /api route.
//
// Both values are stored encrypted at rest when a cipher is configured, and
// neither value is ever written to the log. A newly generated token is
// delivered exactly once through a 0600 initial-key file (when configured).
type MasterKeyService struct {
	db     *gorm.DB
	logger *slog.Logger

	cipher           *secretbox.Cipher
	initialAdminFile string
	initialProxyFile string

	mu       sync.RWMutex
	key      string
	proxyKey string
}

func NewMasterKeyService(db *gorm.DB, logger *slog.Logger) *MasterKeyService {
	return &MasterKeyService{db: db, logger: logger}
}

func (s *MasterKeyService) WithCipher(c *secretbox.Cipher) *MasterKeyService {
	s.cipher = c
	return s
}

// WithInitialKeyFiles sets where newly generated tokens are written (0600)
// for one-time retrieval by the operator. Values are never logged.
func (s *MasterKeyService) WithInitialKeyFiles(adminFile, proxyFile string) *MasterKeyService {
	s.initialAdminFile = adminFile
	s.initialProxyFile = proxyFile
	return s
}

func (s *MasterKeyService) encrypt(plain string) string {
	if s.cipher == nil {
		return plain
	}
	enc, err := s.cipher.Encrypt(plain)
	if err != nil {
		s.logger.Error("secret encryption failed", "err", err)
		return plain
	}
	return enc
}

func (s *MasterKeyService) decrypt(stored string) string {
	if s.cipher == nil {
		return stored
	}
	dec, err := s.cipher.Decrypt(stored)
	if err != nil {
		s.logger.Error("secret decryption failed", "err", err)
		return stored
	}
	return dec
}

func (s *MasterKeyService) writeInitialKeyFile(path, value string) {
	if path == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		s.logger.Error("initial key file dir failed", "err", err)
		return
	}
	if err := os.WriteFile(path, []byte(value+"\n"), 0o600); err != nil {
		s.logger.Error("initial key file write failed", "err", err)
		return
	}
	s.logger.Info("initial key written to file (retrieve it once, then delete the file)", "file", path)
}

// loadOrCreateOne loads one token setting, generating and persisting a new
// token when absent. Legacy plaintext values are re-encrypted in place when
// a cipher is configured.
func (s *MasterKeyService) loadOrCreateOne(ctx context.Context, settingKey, initialFile, label string) (string, error) {
	var setting models.Setting
	err := s.db.WithContext(ctx).First(&setting, "key = ?", settingKey).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return "", err
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		newKey, err := generateSecret(32)
		if err != nil {
			return "", err
		}
		setting = models.Setting{Key: settingKey, Value: s.encrypt(newKey)}
		if err := s.db.WithContext(ctx).Create(&setting).Error; err != nil {
			return "", err
		}
		// Never log the token value itself.
		s.logger.Info("generated new token", "kind", label)
		s.writeInitialKeyFile(initialFile, newKey)
		return newKey, nil
	}
	plain := s.decrypt(setting.Value)
	if s.cipher != nil && !secretbox.IsEncrypted(setting.Value) {
		// Migrate legacy plaintext to encrypted storage.
		setting.Value = s.encrypt(plain)
		if err := s.db.WithContext(ctx).Save(&setting).Error; err != nil {
			s.logger.Error("token encryption migration failed", "kind", label, "err", err)
		} else {
			s.logger.Info("migrated stored token to encrypted form", "kind", label)
		}
	}
	return plain, nil
}

func (s *MasterKeyService) LoadOrCreate(ctx context.Context) error {
	admin, err := s.loadOrCreateOne(ctx, masterKeySettingKey, s.initialAdminFile, "admin")
	if err != nil {
		return err
	}
	proxy, err := s.loadOrCreateOne(ctx, proxyKeySettingKey, s.initialProxyFile, "proxy")
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.key = admin
	s.proxyKey = proxy
	s.mu.Unlock()
	return nil
}

func (s *MasterKeyService) Get() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.key
}

func (s *MasterKeyService) GetProxy() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.proxyKey
}

func tokenEquals(current, token string) bool {
	if current == "" || token == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(current), []byte(token)) == 1
}

// Authenticate reports whether token is the admin (master) key. This is the
// only token accepted by the /api management plane.
func (s *MasterKeyService) Authenticate(token string) bool {
	return tokenEquals(s.Get(), token)
}

// AuthenticateProxy reports whether token may call the proxy/MCP surface:
// the proxy key, or the admin key (admin is a superset).
func (s *MasterKeyService) AuthenticateProxy(token string) bool {
	if tokenEquals(s.GetProxy(), token) {
		return true
	}
	return tokenEquals(s.Get(), token)
}

func (s *MasterKeyService) resetOne(ctx context.Context, settingKey string) (string, error) {
	newKey, err := generateSecret(32)
	if err != nil {
		return "", err
	}
	if err := s.db.WithContext(ctx).Save(&models.Setting{Key: settingKey, Value: s.encrypt(newKey)}).Error; err != nil {
		return "", err
	}
	return newKey, nil
}

func (s *MasterKeyService) Reset(ctx context.Context) (string, error) {
	newKey, err := s.resetOne(ctx, masterKeySettingKey)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	s.key = newKey
	s.mu.Unlock()
	return newKey, nil
}

func (s *MasterKeyService) ResetProxy(ctx context.Context) (string, error) {
	newKey, err := s.resetOne(ctx, proxyKeySettingKey)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	s.proxyKey = newKey
	s.mu.Unlock()
	return newKey, nil
}

func generateSecret(bytes int) (string, error) {
	if bytes <= 0 {
		return "", errors.New("invalid secret length")
	}
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
