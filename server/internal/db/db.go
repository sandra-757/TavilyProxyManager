package db

import (
	"os"
	"path/filepath"

	"tavily-proxy/server/internal/models"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func Open(path string) (*gorm.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}

	database, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	// SQLite is a single-writer store: serialise access through one
	// connection, use WAL so readers do not block the writer, and wait
	// (instead of failing with "database is locked") on contention.
	sqlDB, err := database.DB()
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	sqlDB.SetConnMaxLifetime(0)
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA foreign_keys=ON",
	} {
		if _, err := sqlDB.Exec(pragma); err != nil {
			return nil, err
		}
	}

	if err := database.AutoMigrate(&models.APIKey{}, &models.RequestLog{}, &models.RequestStat{}, &models.Setting{}, &models.SearchCache{}); err != nil {
		return nil, err
	}
	return database, nil
}
