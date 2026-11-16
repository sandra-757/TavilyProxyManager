package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	ListenAddr      string
	DatabasePath    string
	TavilyBaseURL   string
	UpstreamTimeout time.Duration
	MCPStateless    bool
	MCPSessionTTL   time.Duration
	LogDir          string // log file directory; empty = stdout only
	LogLevel        string // debug/info/warn/error

	// Security hardening (fork).
	EncryptionKey        string // TPM_ENCRYPTION_KEY: base64 32-byte key; empty = use key file
	EncryptionKeyFile    string // TPM_ENCRYPTION_KEY_FILE; empty = <db dir>/encryption.key
	MaxRequestBodyBytes  int64  // MAX_REQUEST_BODY_BYTES, default 10 MiB
	MaxResponseBodyBytes int64  // MAX_RESPONSE_BODY_BYTES, default 50 MiB
}

func FromEnv() Config {
	listenAddr := getenv("LISTEN_ADDR", "")
	if listenAddr == "" {
		port := getenv("PORT", "8080")
		listenAddr = ":" + port
	}

	dbPath := getenvFirst("./server/data/app.db", "DB_PATH", "DATABASE_PATH")
	baseURL := getenv("TAVILY_BASE_URL", "https://api.tavily.com")
	timeout := getenvDuration("UPSTREAM_TIMEOUT", 150*time.Second)
	mcpStateless := getenvBool("MCP_STATELESS", true)
	mcpSessionTTL := getenvDuration("MCP_SESSION_TTL", 10*time.Minute)
	logDir := getenv("LOG_DIR", "")
	logLevel := getenv("LOG_LEVEL", "info")
	encryptionKey := getenv("TPM_ENCRYPTION_KEY", "")
	encryptionKeyFile := getenv("TPM_ENCRYPTION_KEY_FILE", "")
	maxReqBody := getenvInt64("MAX_REQUEST_BODY_BYTES", 10<<20)
	maxRespBody := getenvInt64("MAX_RESPONSE_BODY_BYTES", 50<<20)

	return Config{
		ListenAddr:           listenAddr,
		DatabasePath:         dbPath,
		TavilyBaseURL:        baseURL,
		UpstreamTimeout:      timeout,
		MCPStateless:         mcpStateless,
		MCPSessionTTL:        mcpSessionTTL,
		LogDir:               logDir,
		LogLevel:             logLevel,
		EncryptionKey:        encryptionKey,
		EncryptionKeyFile:    encryptionKeyFile,
		MaxRequestBodyBytes:  maxReqBody,
		MaxResponseBodyBytes: maxRespBody,
	}
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getenvFirst(def string, keys ...string) string {
	for _, key := range keys {
		if v := os.Getenv(key); v != "" {
			return v
		}
	}
	return def
}

func getenvDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
		if seconds, err := strconv.Atoi(v); err == nil {
			return time.Duration(seconds) * time.Second
		}
	}
	return def
}

func getenvInt64(key string, def int64) int64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func getenvBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		if parsed, err := strconv.ParseBool(v); err == nil {
			return parsed
		}
	}
	return def
}
