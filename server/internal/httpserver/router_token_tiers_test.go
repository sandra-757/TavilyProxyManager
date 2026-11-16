package httpserver

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"tavily-proxy/server/internal/db"
	"tavily-proxy/server/internal/services"
)

func TestTokenTiers_ProxyKeyCannotUseAdminAPI(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"request_id":"t","results":[]}`))
	}))
	t.Cleanup(upstream.Close)

	database, err := db.Open(filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := database.DB()
	t.Cleanup(func() { _ = sqlDB.Close() })

	ctx := context.Background()
	master := services.NewMasterKeyService(database, logger)
	if err := master.LoadOrCreate(ctx); err != nil {
		t.Fatal(err)
	}
	keys := services.NewKeyService(database, logger)
	if _, err := keys.Create(ctx, "tvly-pool-1234567890abcdef", "pool", 1000); err != nil {
		t.Fatal(err)
	}
	proxy := services.NewTavilyProxy(upstream.URL, 5*time.Second, keys, nil, nil, logger)
	router := NewRouter(Dependencies{MasterKeyService: master, TavilyProxy: proxy, KeyService: keys})

	do := func(method, path, token string) int {
		req := httptest.NewRequest(method, path, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w.Code
	}

	// Proxy token: admin API forbidden, proxy surface allowed.
	if code := do(http.MethodGet, "/api/keys", master.GetProxy()); code != http.StatusUnauthorized {
		t.Fatalf("proxy token on /api/keys: got %d want 401", code)
	}
	if code := do(http.MethodGet, "/api/settings/master-key", master.GetProxy()); code != http.StatusUnauthorized {
		t.Fatalf("proxy token on master-key endpoint: got %d want 401", code)
	}
	// Admin token: both surfaces allowed.
	if code := do(http.MethodGet, "/api/keys", master.Get()); code != http.StatusOK {
		t.Fatalf("admin token on /api/keys: got %d want 200", code)
	}
	// Proxy token can call a proxy endpoint (GET /usage goes upstream).
	if code := do(http.MethodGet, "/usage", master.GetProxy()); code != http.StatusOK {
		t.Fatalf("proxy token on /usage: got %d want 200", code)
	}
	// No token anywhere: 401.
	if code := do(http.MethodGet, "/api/keys", ""); code != http.StatusUnauthorized {
		t.Fatalf("no token on /api/keys: got %d want 401", code)
	}
}
