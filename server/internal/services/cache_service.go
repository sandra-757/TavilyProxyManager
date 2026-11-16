package services

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"tavily-proxy/server/internal/models"

	"gorm.io/gorm"
)

type CacheService struct {
	db     *gorm.DB
	logger *slog.Logger
}

type CacheStats struct {
	Enabled        bool  `json:"enabled"`
	EntryCount     int64 `json:"entry_count"`
	TotalHits      int64 `json:"total_hits"`
	TotalSizeBytes int64 `json:"total_size_bytes"`
}

func NewCacheService(db *gorm.DB, logger *slog.Logger) *CacheService {
	return &CacheService{db: db, logger: logger}
}

func (s *CacheService) Lookup(ctx context.Context, cacheKey string) (*models.SearchCache, bool, error) {
	var entry models.SearchCache
	err := s.db.WithContext(ctx).
		Where("cache_key = ? AND expires_at > ?", cacheKey, time.Now()).
		First(&entry).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, false, nil
		}
		return nil, false, err
	}
	s.db.WithContext(ctx).Model(&entry).UpdateColumn("hit_count", gorm.Expr("hit_count + 1"))
	entry.HitCount++
	return &entry, true, nil
}

func (s *CacheService) Store(ctx context.Context, cacheKey, query, requestBody, responseBody string, statusCode int, ttl time.Duration) error {
	now := time.Now()
	expiresAt := now.Add(ttl)

	var existing models.SearchCache
	err := s.db.WithContext(ctx).Where("cache_key = ?", cacheKey).First(&existing).Error
	if err == nil {
		return s.db.WithContext(ctx).Model(&existing).Updates(map[string]any{
			"query":         query,
			"request_body":  requestBody,
			"response_body": responseBody,
			"status_code":   statusCode,
			"expires_at":    expiresAt,
			"hit_count":     0,
		}).Error
	}
	if err != gorm.ErrRecordNotFound {
		return err
	}

	entry := models.SearchCache{
		CacheKey:     cacheKey,
		Query:        query,
		RequestBody:  requestBody,
		ResponseBody: responseBody,
		StatusCode:   statusCode,
		HitCount:     0,
		ExpiresAt:    expiresAt,
		CreatedAt:    now,
	}
	return s.db.WithContext(ctx).Create(&entry).Error
}

func (s *CacheService) Stats(ctx context.Context) (CacheStats, error) {
	var stats CacheStats

	var entryCount int64
	if err := s.db.WithContext(ctx).Model(&models.SearchCache{}).
		Where("expires_at > ?", time.Now()).
		Count(&entryCount).Error; err != nil {
		return stats, err
	}
	stats.EntryCount = entryCount

	var totalHits *int64
	if err := s.db.WithContext(ctx).Model(&models.SearchCache{}).
		Select("COALESCE(SUM(hit_count), 0)").
		Scan(&totalHits).Error; err != nil {
		return stats, err
	}
	if totalHits != nil {
		stats.TotalHits = *totalHits
	}

	var totalSize *int64
	if err := s.db.WithContext(ctx).Model(&models.SearchCache{}).
		Where("expires_at > ?", time.Now()).
		Select("COALESCE(SUM(LENGTH(request_body) + LENGTH(response_body)), 0)").
		Scan(&totalSize).Error; err != nil {
		return stats, err
	}
	if totalSize != nil {
		stats.TotalSizeBytes = *totalSize
	}

	return stats, nil
}

func (s *CacheService) ClearAll(ctx context.Context) (int64, error) {
	result := s.db.WithContext(ctx).Where("1 = 1").Delete(&models.SearchCache{})
	return result.RowsAffected, result.Error
}

func (s *CacheService) CleanExpired(ctx context.Context) (int64, error) {
	result := s.db.WithContext(ctx).Where("expires_at <= ?", time.Now()).Delete(&models.SearchCache{})
	return result.RowsAffected, result.Error
}

// BuildCacheKey hashes the ENTIRE request body in canonical form (JSON
// object keys sorted, numbers preserved). The previous implementation
// hashed only six selected fields, so requests that differed in
// time_range, include_answer, chunks_per_source etc. collided and were
// served each other's results.
func (s *CacheService) BuildCacheKey(body []byte) (string, string) {
	var decoded any
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.UseNumber()
	if err := dec.Decode(&decoded); err != nil {
		return fmt.Sprintf("%x", sha256.Sum256(body)), ""
	}
	canonical, err := marshalCanonical(decoded)
	if err != nil {
		return fmt.Sprintf("%x", sha256.Sum256(body)), ""
	}
	query := ""
	if m, ok := decoded.(map[string]any); ok {
		query, _ = m["query"].(string)
	}
	return fmt.Sprintf("%x", sha256.Sum256(canonical)), query
}

// marshalCanonical renders a decoded JSON value deterministically: map
// keys sorted, json.Number preserved verbatim.
func marshalCanonical(v any) ([]byte, error) {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var sb strings.Builder
		sb.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				sb.WriteByte(',')
			}
			kb, _ := json.Marshal(k)
			sb.Write(kb)
			sb.WriteByte(':')
			vb, err := marshalCanonical(t[k])
			if err != nil {
				return nil, err
			}
			sb.Write(vb)
		}
		sb.WriteByte('}')
		return []byte(sb.String()), nil
	case []any:
		var sb strings.Builder
		sb.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				sb.WriteByte(',')
			}
			eb, err := marshalCanonical(e)
			if err != nil {
				return nil, err
			}
			sb.Write(eb)
		}
		sb.WriteByte(']')
		return []byte(sb.String()), nil
	default:
		return json.Marshal(v)
	}
}
