package httpserver

import (
	"embed"
	"net/http"
	"time"

	"tavily-proxy/server/internal/config"
	"tavily-proxy/server/internal/services"

	"log/slog"

	"gorm.io/gorm"
)

type Dependencies struct {
	Config           config.Config
	EmbeddedPublic   embed.FS
	MasterKeyService *services.MasterKeyService
	SettingsService  *services.SettingsService
	KeyService       *services.KeyService
	QuotaSyncService *services.QuotaSyncService
	QuotaSyncJob     *services.QuotaSyncJobService
	LogService       *services.LogService
	StatsService     *services.StatsService
	CacheService     *services.CacheService
	TavilyProxy      *services.TavilyProxy
	AuthLimiter      *services.AuthLimiter
	Database         *gorm.DB
	Logger           *slog.Logger
}

func New(deps Dependencies) *http.Server {
	handler := NewRouter(deps)
	return &http.Server{
		Addr:              deps.Config.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		// Proxy calls may legitimately run long (upstream timeout plus
		// failover across keys), so WriteTimeout stays generous; the
		// header/read/idle limits are what close slow-loris style abuse.
		WriteTimeout:   600 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
}
