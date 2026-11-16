package services

import (
	"context"
	"errors"
	"log/slog"
	"math/rand"
	"sort"
	"time"

	"tavily-proxy/server/internal/models"
	"tavily-proxy/server/internal/secretbox"

	"gorm.io/gorm"
)

type KeyService struct {
	db     *gorm.DB
	logger *slog.Logger
	cipher *secretbox.Cipher
}

func NewKeyService(db *gorm.DB, logger *slog.Logger) *KeyService {
	return &KeyService{db: db, logger: logger}
}

// WithCipher enables AES-GCM encryption of API keys at rest. Records are
// decrypted in memory on every read path; the database only ever holds the
// "enc:v1:" ciphertext form (legacy plaintext rows are re-encrypted on the
// next save of that record).
func (s *KeyService) WithCipher(c *secretbox.Cipher) *KeyService {
	s.cipher = c
	return s
}

func (s *KeyService) encryptKey(plain string) string {
	if s.cipher == nil {
		return plain
	}
	enc, err := s.cipher.Encrypt(plain)
	if err != nil {
		s.logger.Error("api key encryption failed", "err", err)
		return plain
	}
	return enc
}

func (s *KeyService) decryptRecord(k *models.APIKey) {
	if s.cipher == nil || k == nil {
		return
	}
	dec, err := s.cipher.Decrypt(k.Key)
	if err != nil {
		s.logger.Error("api key decryption failed", "key_id", k.ID, "err", err)
		return
	}
	k.Key = dec
}

func (s *KeyService) List(ctx context.Context) ([]models.APIKey, error) {
	var keys []models.APIKey
	if err := s.db.WithContext(ctx).Order("id desc").Find(&keys).Error; err != nil {
		return nil, err
	}
	for i := range keys {
		s.decryptRecord(&keys[i])
	}
	return keys, nil
}

var ErrDuplicateKey = errors.New("duplicate api key")

func (s *KeyService) Create(ctx context.Context, key, alias string, totalQuota int) (*models.APIKey, error) {
	if totalQuota <= 0 {
		totalQuota = 1000
	}
	if s.cipher != nil {
		// Ciphertext is randomised, so the DB unique index can no longer
		// detect duplicate plaintext keys; check explicitly instead.
		existing, err := s.List(ctx)
		if err != nil {
			return nil, err
		}
		for _, e := range existing {
			if e.Key == key {
				return nil, ErrDuplicateKey
			}
		}
	}
	record := models.APIKey{
		Key:        key,
		Alias:      alias,
		TotalQuota: totalQuota,
		UsedQuota:  0,
		IsActive:   true,
		IsInvalid:  false,
	}
	stored := record
	stored.Key = s.encryptKey(key)
	if err := s.db.WithContext(ctx).Create(&stored).Error; err != nil {
		return nil, err
	}
	record.ID = stored.ID
	record.CreatedAt = stored.CreatedAt
	record.UpdatedAt = stored.UpdatedAt
	return &record, nil
}

func (s *KeyService) Get(ctx context.Context, id uint) (*models.APIKey, error) {
	var key models.APIKey
	if err := s.db.WithContext(ctx).First(&key, id).Error; err != nil {
		return nil, err
	}
	s.decryptRecord(&key)
	return &key, nil
}

type KeyUpdate struct {
	Alias      *string `json:"alias"`
	TotalQuota *int    `json:"total_quota"`
	UsedQuota  *int    `json:"used_quota"`
	IsActive   *bool   `json:"is_active"`
	ResetQuota bool    `json:"reset_quota"`
	SyncUsage  bool    `json:"sync_usage"`
}

func (s *KeyService) Update(ctx context.Context, id uint, upd KeyUpdate) (*models.APIKey, error) {
	var key models.APIKey
	if err := s.db.WithContext(ctx).First(&key, id).Error; err != nil {
		return nil, err
	}
	if upd.Alias != nil {
		key.Alias = *upd.Alias
	}
	if upd.TotalQuota != nil && *upd.TotalQuota > 0 {
		key.TotalQuota = *upd.TotalQuota
	}
	if upd.UsedQuota != nil && *upd.UsedQuota >= 0 {
		key.UsedQuota = *upd.UsedQuota
	}
	if upd.IsActive != nil {
		if key.IsInvalid && *upd.IsActive {
			key.IsActive = false
		} else {
			key.IsActive = *upd.IsActive
		}
	}
	if upd.ResetQuota {
		key.UsedQuota = 0
	}

	plainKey := key.Key
	if s.cipher != nil {
		if dec, err := s.cipher.Decrypt(key.Key); err == nil {
			plainKey = dec
		}
	}
	key.Key = s.encryptKey(plainKey)
	if err := s.db.WithContext(ctx).Save(&key).Error; err != nil {
		return nil, err
	}
	key.Key = plainKey
	return &key, nil
}

func (s *KeyService) Delete(ctx context.Context, id uint) error {
	return s.db.WithContext(ctx).Delete(&models.APIKey{}, id).Error
}

func (s *KeyService) MarkInactive(ctx context.Context, id uint) error {
	return s.db.WithContext(ctx).Model(&models.APIKey{}).Where("id = ?", id).Update("is_active", false).Error
}

func (s *KeyService) MarkInvalid(ctx context.Context, id uint) error {
	return s.db.WithContext(ctx).Model(&models.APIKey{}).Where("id = ?", id).Updates(map[string]any{
		"is_active":  false,
		"is_invalid": true,
	}).Error
}

func (s *KeyService) MarkExhausted(ctx context.Context, id uint) error {
	return s.db.WithContext(ctx).Model(&models.APIKey{}).
		Where("id = ?", id).
		Update("used_quota", gorm.Expr("total_quota")).Error
}

func (s *KeyService) IncrementUsed(ctx context.Context, id uint) error {
	now := time.Now()
	return s.db.WithContext(ctx).Model(&models.APIKey{}).Where("id = ?", id).Updates(map[string]any{
		"used_quota":   gorm.Expr("CASE WHEN used_quota + 1 > total_quota THEN total_quota ELSE used_quota + 1 END"),
		"last_used_at": &now,
	}).Error
}

func (s *KeyService) ResetAllUsage(ctx context.Context) error {
	return s.db.WithContext(ctx).Model(&models.APIKey{}).Update("used_quota", 0).Error
}

func (s *KeyService) SetUsage(ctx context.Context, id uint, used int, total *int) error {
	updates := map[string]any{
		"used_quota": used,
	}
	if total != nil && *total > 0 {
		updates["total_quota"] = *total
		if used > *total {
			updates["used_quota"] = *total
		}
	}
	return s.db.WithContext(ctx).Model(&models.APIKey{}).Where("id = ?", id).Updates(updates).Error
}

func (s *KeyService) Candidates(ctx context.Context) ([]models.APIKey, error) {
	var keys []models.APIKey
	if err := s.db.WithContext(ctx).
		Where("is_active = ? AND is_invalid = ? AND used_quota < total_quota", true, false).
		Find(&keys).Error; err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, nil
	}
	for i := range keys {
		s.decryptRecord(&keys[i])
	}

	type scored struct {
		key       models.APIKey
		remaining int
	}
	scoredKeys := make([]scored, 0, len(keys))
	for _, k := range keys {
		scoredKeys = append(scoredKeys, scored{key: k, remaining: k.TotalQuota - k.UsedQuota})
	}

	sort.Slice(scoredKeys, func(i, j int) bool {
		return scoredKeys[i].remaining > scoredKeys[j].remaining
	})

	// Shuffle ties for fairness.
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	out := make([]models.APIKey, 0, len(scoredKeys))
	for i := 0; i < len(scoredKeys); {
		j := i + 1
		for j < len(scoredKeys) && scoredKeys[j].remaining == scoredKeys[i].remaining {
			j++
		}
		group := scoredKeys[i:j]
		rng.Shuffle(len(group), func(a, b int) { group[a], group[b] = group[b], group[a] })
		for _, item := range group {
			out = append(out, item.key)
		}
		i = j
	}
	return out, nil
}

// EncryptAllPlaintext rewrites any legacy plaintext API keys in the
// database to encrypted form. Called once at startup when a cipher is
// configured; a no-op afterwards.
func (s *KeyService) EncryptAllPlaintext(ctx context.Context) (int, error) {
	if s.cipher == nil {
		return 0, nil
	}
	var keys []models.APIKey
	if err := s.db.WithContext(ctx).Find(&keys).Error; err != nil {
		return 0, err
	}
	migrated := 0
	for _, k := range keys {
		if secretbox.IsEncrypted(k.Key) {
			continue
		}
		enc := s.encryptKey(k.Key)
		if enc == k.Key {
			continue
		}
		if err := s.db.WithContext(ctx).Model(&models.APIKey{}).Where("id = ?", k.ID).Update("key", enc).Error; err != nil {
			return migrated, err
		}
		migrated++
	}
	return migrated, nil
}

func (s *KeyService) FindByID(ctx context.Context, id uint) (*models.APIKey, error) {
	var key models.APIKey
	if err := s.db.WithContext(ctx).First(&key, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	s.decryptRecord(&key)
	return &key, nil
}

func (s *KeyService) DeleteInvalid(ctx context.Context) (int64, error) {
	result := s.db.WithContext(ctx).Where("is_invalid = ?", true).Delete(&models.APIKey{})
	return result.RowsAffected, result.Error
}
