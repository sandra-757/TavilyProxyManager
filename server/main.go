package main

import (
	"context"
	"embed"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"path/filepath"

	"tavily-proxy/server/internal/config"
	"tavily-proxy/server/internal/db"
	"tavily-proxy/server/internal/httpserver"
	"tavily-proxy/server/internal/jobs"
	"tavily-proxy/server/internal/logger"
	"tavily-proxy/server/internal/secretbox"
	"tavily-proxy/server/internal/services"
)

//go:embed public
var embeddedPublic embed.FS

func main() {
	cfg := config.FromEnv()

	// Parse log level
	var level slog.Level
	switch strings.ToLower(cfg.LogLevel) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	// Build writer (stdout + optional file)
	var w io.Writer = os.Stdout
	var fileWriter *logger.DailyRotateWriter
	if cfg.LogDir != "" {
		fileWriter = logger.NewDailyRotateWriter(cfg.LogDir, "proxy")
		w = io.MultiWriter(os.Stdout, fileWriter)
	}

	slogLogger := slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level}))

	// Encryption at rest: resolve the data-encryption key before anything
	// touches stored secrets. TPM_ENCRYPTION_KEY wins; otherwise a key file
	// next to the database is loaded or created (0600). The key value is
	// never logged.
	dbDir := filepath.Dir(cfg.DatabasePath)
	var encKey []byte
	if cfg.EncryptionKey != "" {
		k, err := secretbox.ParseKey(cfg.EncryptionKey)
		if err != nil {
			slogLogger.Error("invalid TPM_ENCRYPTION_KEY", "err", err)
			os.Exit(1)
		}
		encKey = k
	} else {
		keyFile := cfg.EncryptionKeyFile
		if keyFile == "" {
			keyFile = filepath.Join(dbDir, "encryption.key")
		}
		k, created, err := secretbox.LoadOrCreateKeyFile(keyFile)
		if err != nil {
			slogLogger.Error("encryption key load failed", "err", err)
			os.Exit(1)
		}
		if created {
			slogLogger.Info("generated new encryption key file (keep it safe; losing it makes stored keys unreadable)", "file", keyFile)
		}
		encKey = k
	}
	cipher, err := secretbox.New(encKey)
	if err != nil {
		slogLogger.Error("encryption init failed", "err", err)
		os.Exit(1)
	}

	database, err := db.Open(cfg.DatabasePath)
	if err != nil {
		slogLogger.Error("db open failed", "err", err)
		os.Exit(1)
	}

	masterKeyService := services.NewMasterKeyService(database, slogLogger).
		WithCipher(cipher).
		WithInitialKeyFiles(filepath.Join(dbDir, "initial-admin-key.txt"), filepath.Join(dbDir, "initial-proxy-key.txt"))
	if err := masterKeyService.LoadOrCreate(context.Background()); err != nil {
		slogLogger.Error("master key init failed", "err", err)
		os.Exit(1)
	}

	settingsService := services.NewSettingsService(database)
	keyService := services.NewKeyService(database, slogLogger).WithCipher(cipher)

	if migrated, err := keyService.EncryptAllPlaintext(context.Background()); err != nil {
		slogLogger.Error("api key encryption migration failed", "err", err)
	} else if migrated > 0 {
		slogLogger.Info("migrated plaintext api keys to encrypted form", "count", migrated)
	}

	logService := services.NewLogService(database, slogLogger)
	statsService := services.NewStatsService(database)

	if err := statsService.BackfillFromLogsIfEmpty(context.Background()); err != nil {
		slogLogger.Error("stats backfill failed", "err", err)
	}

	tavilyProxy := services.NewTavilyProxy(cfg.TavilyBaseURL, cfg.UpstreamTimeout, keyService, logService, statsService, slogLogger).
		WithSettings(settingsService).
		WithMaxResponseBodyBytes(cfg.MaxResponseBodyBytes).
		WithMaxAttempts(cfg.ProxyMaxAttempts)
	cacheService := services.NewCacheService(database, slogLogger)
	tavilyProxy.WithCache(cacheService)
	quotaSyncService := services.NewQuotaSyncService(keyService, tavilyProxy, slogLogger)
	quotaSyncJob := services.NewQuotaSyncJobService(keyService, quotaSyncService, slogLogger)

	authLimiter := services.DefaultAuthLimiter()

	srv := httpserver.New(httpserver.Dependencies{
		AuthLimiter:      authLimiter,
		Database:         database,
		Config:           cfg,
		EmbeddedPublic:   embeddedPublic,
		MasterKeyService: masterKeyService,
		SettingsService:  settingsService,
		KeyService:       keyService,
		QuotaSyncService: quotaSyncService,
		QuotaSyncJob:     quotaSyncJob,
		LogService:       logService,
		StatsService:     statsService,
		CacheService:     cacheService,
		TavilyProxy:      tavilyProxy,
		Logger:           slogLogger,
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	jobs.StartMonthlyReset(ctx, keyService, slogLogger)
	jobs.StartAutoQuotaSync(ctx, settingsService, quotaSyncService, slogLogger)
	jobs.StartLogCleanup(ctx, settingsService, logService, slogLogger)
	jobs.StartCacheCleanup(ctx, cacheService, slogLogger)

	go func() {
		slogLogger.Info("server listening", "addr", cfg.ListenAddr)
		if err := srv.ListenAndServe(); err != nil {
			slogLogger.Error("http server stopped", "err", err)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	if fileWriter != nil {
		_ = fileWriter.Close()
	}
}
