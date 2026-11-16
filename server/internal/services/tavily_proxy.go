package services

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"tavily-proxy/server/internal/models"
)

const DefaultMaxResponseBodyBytes int64 = 50 << 20

type TavilyProxy struct {
	baseURL string
	client  *http.Client

	maxResponseBodyBytes int64
	maxAttempts          int
	rateLimitCooldown    time.Duration

	settings *SettingsService
	cache    *CacheService
	keys     *KeyService
	logs     *LogService
	stats    *StatsService
	logger   *slog.Logger
}

type ProxyRequest struct {
	Method      string
	Path        string
	RawQuery    string
	Headers     http.Header
	Body        []byte
	ClientIP    string
	ContentType string
}

type ProxyResponse struct {
	StatusCode      int
	Headers         http.Header
	Body            []byte
	ProxyRequestID  string
	TavilyRequestID string
}

func NewTavilyProxy(baseURL string, timeout time.Duration, keys *KeyService, logs *LogService, stats *StatsService, logger *slog.Logger) *TavilyProxy {
	return &TavilyProxy{
		baseURL: strings.TrimRight(baseURL, "/"),
		client: &http.Client{
			Timeout: timeout,
		},
		maxResponseBodyBytes: DefaultMaxResponseBodyBytes,
		maxAttempts:          DefaultMaxAttempts,
		rateLimitCooldown:    DefaultRateLimitCooldown,
		keys:                 keys,
		logs:                 logs,
		stats:                stats,
		logger:               logger,
		settings:             nil,
	}
}

var ErrNoAvailableKeys = errors.New("no available keys")

// WithMaxResponseBodyBytes caps how much of an upstream response body is
// buffered in memory; larger responses are rejected instead of exhausting RAM.
func (p *TavilyProxy) WithMaxResponseBodyBytes(n int64) *TavilyProxy {
	if n > 0 {
		p.maxResponseBodyBytes = n
	}
	return p
}

const DefaultMaxAttempts = 5
const DefaultRateLimitCooldown = 60 * time.Second

// WithMaxAttempts caps how many pool keys a single client request may try
// (and therefore how long failover can keep it waiting).
func (p *TavilyProxy) WithMaxAttempts(n int) *TavilyProxy {
	if n > 0 {
		p.maxAttempts = n
	}
	return p
}

// WithRateLimitCooldown sets how long a key is deprioritised after a 429
// when the upstream sends no Retry-After header.
func (p *TavilyProxy) WithRateLimitCooldown(d time.Duration) *TavilyProxy {
	if d > 0 {
		p.rateLimitCooldown = d
	}
	return p
}

func (p *TavilyProxy) readBodyLimited(r io.Reader) ([]byte, error) {
	limit := p.maxResponseBodyBytes
	if limit <= 0 {
		limit = DefaultMaxResponseBodyBytes
	}
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("upstream response exceeds %d bytes", limit)
	}
	return body, nil
}

func (p *TavilyProxy) WithSettings(settings *SettingsService) *TavilyProxy {
	p.settings = settings
	return p
}

func (p *TavilyProxy) WithCache(cache *CacheService) *TavilyProxy {
	p.cache = cache
	return p
}

func (p *TavilyProxy) isRequestLoggingEnabled(ctx context.Context) bool {
	if p.settings == nil {
		return true
	}
	enabled, err := p.settings.GetBool(ctx, SettingRequestLoggingEnabled, true)
	if err != nil {
		return true
	}
	return enabled
}

func (p *TavilyProxy) Do(ctx context.Context, req ProxyRequest) (ProxyResponse, error) {
	const maxLogBytes = 32 * 1024

	proxyReqID := uuid.NewString()
	startTime := time.Now()

	p.logger.Info("proxy request started",
		"request_id", proxyReqID,
		"method", req.Method,
		"path", req.Path,
		"client_ip", req.ClientIP,
	)

	loggingEnabled := p.logs != nil && p.isRequestLoggingEnabled(ctx)
	captureBodies := strings.EqualFold(req.Method, http.MethodPost) && req.Path == "/search"
	requestBody, requestTruncated := "", false
	if loggingEnabled && captureBodies && len(req.Body) > 0 {
		requestBody, requestTruncated = truncateForLog(req.Body, maxLogBytes)
	}

	// Cache lookup for POST /search
	noCache := false
	if captureBodies && req.RawQuery != "" {
		if vals, err := url.ParseQuery(req.RawQuery); err == nil {
			noCache = strings.EqualFold(vals.Get("no_cache"), "true")
			vals.Del("no_cache")
			req.RawQuery = vals.Encode()
		}
	}

	if captureBodies && !noCache && p.cache != nil && p.isCacheEnabled(ctx) {
		cacheKey, query := p.cache.BuildCacheKey(req.Body)
		if entry, hit, err := p.cache.Lookup(ctx, cacheKey); err == nil && hit {
			createdAt := time.Now()
			if loggingEnabled {
				responseBody, responseTruncated := truncateForLog([]byte(entry.ResponseBody), maxLogBytes)
				_ = p.logs.Create(ctx, &models.RequestLog{
					RequestID:         proxyReqID,
					KeyUsed:           0,
					KeyAlias:          "",
					Endpoint:          req.Path,
					StatusCode:        entry.StatusCode,
					LatencyMs:         0,
					RequestBody:       requestBody,
					RequestTruncated:  requestTruncated,
					ResponseBody:      responseBody,
					ResponseTruncated: responseTruncated,
					CacheHit:          true,
					ClientIP:          req.ClientIP,
					CreatedAt:         createdAt,
				})
			}
			if p.stats != nil {
				_ = p.stats.RecordRequest(ctx, req.Path, createdAt)
			}
			p.logger.Info("cache hit", "query", query, "cache_key", cacheKey[:12])
			return ProxyResponse{
				StatusCode:     entry.StatusCode,
				Headers:        http.Header{"Content-Type": {"application/json"}},
				Body:           []byte(entry.ResponseBody),
				ProxyRequestID: proxyReqID,
			}, nil
		}
	}

	candidates, err := p.keys.Candidates(ctx)
	if err != nil {
		return ProxyResponse{}, err
	}

	if len(candidates) == 0 {
		p.logger.Warn("no available keys",
			"request_id", proxyReqID,
			"path", req.Path,
		)
		if captureBodies {
			createdAt := time.Now()
			if loggingEnabled {
				_ = p.logs.Create(ctx, &models.RequestLog{
					RequestID:         proxyReqID,
					KeyUsed:           0,
					KeyAlias:          "",
					Endpoint:          req.Path,
					StatusCode:        http.StatusServiceUnavailable,
					LatencyMs:         0,
					RequestBody:       requestBody,
					RequestTruncated:  requestTruncated,
					ResponseBody:      `{"error":"no_available_keys","message":"No active Tavily API keys with remaining quota."}`,
					ResponseTruncated: false,
					ClientIP:          req.ClientIP,
					CreatedAt:         createdAt,
				})
			}
			if p.stats != nil {
				_ = p.stats.RecordRequest(ctx, req.Path, createdAt)
			}
		}
		return ProxyResponse{}, ErrNoAvailableKeys
	}

	var lastErr error
	var lastRateLimitedResp ProxyResponse
	var hasRateLimitedResp bool
	var lastRateLimitedKeyID uint
	var lastRateLimitedKeyAlias string
	var lastRateLimitedLatency int64
	maxAttempts := p.maxAttempts
	if maxAttempts <= 0 {
		maxAttempts = DefaultMaxAttempts
	}
	attempts := 0
	for _, key := range candidates {
		if attempts >= maxAttempts {
			p.logger.Warn("proxy attempt budget exhausted",
				"request_id", proxyReqID,
				"max_attempts", maxAttempts,
			)
			break
		}
		attempts++

		// Pre-charge the estimated credit cost atomically so concurrent
		// requests cannot overspend the same key's remaining quota. The
		// reservation is settled against the actual cost afterwards, or
		// refunded when the call turns out not to be chargeable.
		estCredits := estimateCredits(req)
		reserved := 0
		if estCredits > 0 {
			ok, rerr := p.keys.Reserve(ctx, key.ID, estCredits)
			if rerr != nil {
				p.logger.Warn("quota reserve failed", "request_id", proxyReqID, "key_id", key.ID, "err", rerr)
			} else if !ok {
				continue
			} else {
				reserved = estCredits
			}
		}
		refund := func() {
			if reserved > 0 {
				if err := p.keys.IncrementUsedBy(ctx, key.ID, -reserved); err != nil {
					p.logger.Warn("quota refund failed", "request_id", proxyReqID, "key_id", key.ID, "err", err)
				}
				reserved = 0
			}
		}

		resp, status, latencyMs, tavilyReqID, err := p.tryKey(ctx, key.ID, key.Key, req, proxyReqID)

		if err != nil {
			refund()
			p.logger.Warn("upstream request failed",
				"request_id", proxyReqID,
				"key_id", key.ID,
				"key_alias", key.Alias,
				"err", err,
			)
			lastErr = err
			continue
		}

		switch status {
		case http.StatusUnauthorized:
			refund()
			p.logger.Warn("key marked invalid",
				"request_id", proxyReqID,
				"key_id", key.ID,
				"key_alias", key.Alias,
			)
			_ = p.keys.MarkInvalid(ctx, key.ID)
			continue
		case http.StatusTooManyRequests:
			refund()
			cooldown := p.rateLimitCooldown
			if ra := parseRetryAfter(resp.Headers.Get("Retry-After")); ra > 0 {
				cooldown = ra
			}
			p.keys.MarkRateLimited(key.ID, cooldown)
			p.logger.Warn("key rate limited",
				"request_id", proxyReqID,
				"key_id", key.ID,
				"key_alias", key.Alias,
				"status", status,
			)
			resp.ProxyRequestID = proxyReqID
			resp.TavilyRequestID = tavilyReqID
			lastRateLimitedResp = resp
			hasRateLimitedResp = true
			lastRateLimitedKeyID = key.ID
			lastRateLimitedKeyAlias = key.Alias
			lastRateLimitedLatency = latencyMs
			continue
		case 432, 433:
			p.logger.Warn("key quota exhausted",
				"request_id", proxyReqID,
				"key_id", key.ID,
				"key_alias", key.Alias,
				"status", status,
			)
			_ = p.keys.MarkExhausted(ctx, key.ID)
			continue
		}

		// Settle the reservation against the real cost: Tavily reports
		// usage.credits in successful responses; fall back to the
		// estimate when it does not. Non-2xx outcomes are not charged.
		if reserved > 0 {
			if status >= 200 && status < 300 {
				actual := estCredits
				if c, ok := creditsFromResponse(resp.Body); ok {
					actual = c
				}
				if delta := actual - reserved; delta != 0 {
					if err := p.keys.IncrementUsedBy(ctx, key.ID, delta); err != nil {
						p.logger.Warn("quota settle failed", "request_id", proxyReqID, "key_id", key.ID, "err", err)
					}
				}
			} else {
				refund()
			}
		}

		createdAt := time.Now()
		if loggingEnabled {
			if captureBodies {
				responseBody, responseTruncated := truncateForLog(resp.Body, maxLogBytes)
				_ = p.logs.Create(ctx, &models.RequestLog{
					RequestID:         proxyReqID,
					KeyUsed:           key.ID,
					KeyAlias:          key.Alias,
					Endpoint:          req.Path,
					StatusCode:        status,
					LatencyMs:         latencyMs,
					RequestBody:       requestBody,
					RequestTruncated:  requestTruncated,
					ResponseBody:      responseBody,
					ResponseTruncated: responseTruncated,
					ClientIP:          req.ClientIP,
					CreatedAt:         createdAt,
				})
			} else {
				_ = p.logs.Create(ctx, &models.RequestLog{
					RequestID:  proxyReqID,
					KeyUsed:    key.ID,
					KeyAlias:   key.Alias,
					Endpoint:   req.Path,
					StatusCode: status,
					LatencyMs:  latencyMs,
					ClientIP:   req.ClientIP,
					CreatedAt:  createdAt,
				})
			}
		}
		if p.stats != nil {
			_ = p.stats.RecordRequest(ctx, req.Path, createdAt)
		}

		// Store in cache after successful upstream response
		if captureBodies && status == http.StatusOK && p.cache != nil && p.isCacheEnabled(ctx) {
			cacheKey, query := p.cache.BuildCacheKey(req.Body)
			ttl := p.getCacheTTL(ctx)
			if err := p.cache.Store(ctx, cacheKey, query, string(req.Body), string(resp.Body), status, ttl); err != nil {
				p.logger.Warn("cache store failed", "err", err)
			}
		}

		resp.ProxyRequestID = proxyReqID
		resp.TavilyRequestID = tavilyReqID
		p.logger.Info("proxy request completed",
			"request_id", proxyReqID,
			"key_id", key.ID,
			"status", status,
			"latency_ms", time.Since(startTime).Milliseconds(),
		)
		return resp, nil
	}

	if hasRateLimitedResp {
		createdAt := time.Now()
		if loggingEnabled {
			if captureBodies {
				responseBody, responseTruncated := truncateForLog(lastRateLimitedResp.Body, maxLogBytes)
				_ = p.logs.Create(ctx, &models.RequestLog{
					RequestID:         proxyReqID,
					KeyUsed:           lastRateLimitedKeyID,
					KeyAlias:          lastRateLimitedKeyAlias,
					Endpoint:          req.Path,
					StatusCode:        lastRateLimitedResp.StatusCode,
					LatencyMs:         lastRateLimitedLatency,
					RequestBody:       requestBody,
					RequestTruncated:  requestTruncated,
					ResponseBody:      responseBody,
					ResponseTruncated: responseTruncated,
					ClientIP:          req.ClientIP,
					CreatedAt:         createdAt,
				})
			} else {
				_ = p.logs.Create(ctx, &models.RequestLog{
					RequestID:  proxyReqID,
					KeyUsed:    lastRateLimitedKeyID,
					KeyAlias:   lastRateLimitedKeyAlias,
					Endpoint:   req.Path,
					StatusCode: lastRateLimitedResp.StatusCode,
					LatencyMs:  lastRateLimitedLatency,
					ClientIP:   req.ClientIP,
					CreatedAt:  createdAt,
				})
			}
		}
		if p.stats != nil {
			_ = p.stats.RecordRequest(ctx, req.Path, createdAt)
		}
		p.logger.Warn("proxy request completed with rate limit",
			"request_id", proxyReqID,
			"key_id", lastRateLimitedKeyID,
			"status", lastRateLimitedResp.StatusCode,
			"latency_ms", time.Since(startTime).Milliseconds(),
		)
		return lastRateLimitedResp, nil
	}

	if captureBodies && lastErr != nil {
		p.logger.Error("all keys exhausted",
			"request_id", proxyReqID,
			"path", req.Path,
			"last_err", lastErr,
		)
		createdAt := time.Now()
		if loggingEnabled {
			_ = p.logs.Create(ctx, &models.RequestLog{
				RequestID:         proxyReqID,
				KeyUsed:           0,
				KeyAlias:          "",
				Endpoint:          req.Path,
				StatusCode:        http.StatusBadGateway,
				LatencyMs:         0,
				RequestBody:       requestBody,
				RequestTruncated:  requestTruncated,
				ResponseBody:      lastErr.Error(),
				ResponseTruncated: false,
				ClientIP:          req.ClientIP,
				CreatedAt:         createdAt,
			})
		}
		if p.stats != nil {
			_ = p.stats.RecordRequest(ctx, req.Path, createdAt)
		}
	} else if lastErr == nil {
		p.logger.Error("all keys exhausted",
			"request_id", proxyReqID,
			"path", req.Path,
		)
	}

	return ProxyResponse{}, ErrNoAvailableKeys
}

func truncateForLog(data []byte, maxBytes int) (string, bool) {
	if maxBytes <= 0 || len(data) <= maxBytes {
		return string(data), false
	}
	return string(data[:maxBytes]), true
}

func (p *TavilyProxy) tryKey(ctx context.Context, keyID uint, tavilyKey string, req ProxyRequest, proxyReqID string) (ProxyResponse, int, int64, string, error) {
	targetURL := p.baseURL + req.Path
	if req.RawQuery != "" {
		targetURL += "?" + req.RawQuery
	}

	upstreamReq, err := http.NewRequestWithContext(ctx, req.Method, targetURL, bytes.NewReader(req.Body))
	if err != nil {
		return ProxyResponse{}, 0, 0, "", err
	}

	copyHeaders(upstreamReq.Header, req.Headers)
	upstreamReq.Header.Del("Authorization")
	upstreamReq.Header.Set("Authorization", "Bearer "+tavilyKey)
	if req.ContentType != "" && upstreamReq.Header.Get("Content-Type") == "" {
		upstreamReq.Header.Set("Content-Type", req.ContentType)
	}
	upstreamReq.Header.Set("X-Proxy-Request-Id", proxyReqID)

	p.logger.Debug("sending upstream request",
		"request_id", proxyReqID,
		"method", req.Method,
		"url", targetURL,
		"key_id", keyID,
	)

	start := time.Now()
	upstreamResp, err := p.client.Do(upstreamReq)
	latencyMs := time.Since(start).Milliseconds()
	if err != nil {
		p.logger.Warn("upstream call error",
			"request_id", proxyReqID,
			"url", targetURL,
			"key_id", keyID,
			"latency_ms", latencyMs,
			"err", err,
		)
		return ProxyResponse{}, 0, latencyMs, "", err
	}
	defer upstreamResp.Body.Close()

	p.logger.Debug("upstream response received",
		"request_id", proxyReqID,
		"status", upstreamResp.StatusCode,
		"latency_ms", latencyMs,
		"key_id", keyID,
	)

	body, err := p.readBodyLimited(upstreamResp.Body)
	if err != nil {
		p.logger.Warn("upstream response read error",
			"request_id", proxyReqID,
			"key_id", keyID,
			"status", upstreamResp.StatusCode,
			"err", err,
		)
		return ProxyResponse{}, upstreamResp.StatusCode, latencyMs, "", err
	}

	requestID := extractRequestID(body)

	return ProxyResponse{
		StatusCode:     upstreamResp.StatusCode,
		Headers:        upstreamResp.Header.Clone(),
		Body:           body,
		ProxyRequestID: proxyReqID,
	}, upstreamResp.StatusCode, latencyMs, requestID, nil
}

// copyHeaders forwards client request headers upstream. Hop-by-hop headers
// (RFC 7230 §6.1), including any header named by Connection, describe the
// client's connection and must not be forwarded: Go's HTTP/2 transport rejects
// a request carrying e.g. "Connection: upgrade", which reverse proxies such as
// cloudflared add in front of this service.
func copyHeaders(dst http.Header, src http.Header) {
	connScoped := map[string]bool{}
	for _, v := range src.Values("Connection") {
		for _, name := range strings.Split(v, ",") {
			if name = strings.TrimSpace(name); name != "" {
				connScoped[strings.ToLower(name)] = true
			}
		}
	}
	for k, vv := range src {
		lk := strings.ToLower(k)
		switch lk {
		case "host", "content-length",
			"connection", "proxy-connection", "keep-alive", "proxy-authenticate",
			"proxy-authorization", "te", "trailer", "trailers", "transfer-encoding", "upgrade":
			continue
		}
		if connScoped[lk] {
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func extractRequestID(body []byte) string {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return ""
	}
	if v, ok := m["request_id"].(string); ok && v != "" {
		return v
	}
	if v, ok := m["requestId"].(string); ok && v != "" {
		return v
	}
	return ""
}

type usageResponse struct {
	Key struct {
		Usage int  `json:"usage"`
		Limit *int `json:"limit"`
	} `json:"key"`
	Account struct {
		PlanLimit *int `json:"plan_limit"`
	} `json:"account"`
}

type UpstreamStatusError struct {
	StatusCode int
	Body       string
}

func (e *UpstreamStatusError) Error() string {
	body := strings.TrimSpace(e.Body)
	if body == "" {
		return fmt.Sprintf("upstream status %d", e.StatusCode)
	}
	return fmt.Sprintf("upstream status %d: %s", e.StatusCode, body)
}

func (p *TavilyProxy) isCacheEnabled(ctx context.Context) bool {
	if p.settings == nil {
		return false
	}
	enabled, err := p.settings.GetBool(ctx, SettingCacheEnabled, false)
	if err != nil {
		return false
	}
	return enabled
}

func (p *TavilyProxy) getCacheTTL(ctx context.Context) time.Duration {
	if p.settings == nil {
		return 3600 * time.Second
	}
	seconds, err := p.settings.GetInt(ctx, SettingCacheTTLSeconds, 3600)
	if err != nil || seconds < 60 {
		return 3600 * time.Second
	}
	return time.Duration(seconds) * time.Second
}

func (p *TavilyProxy) GetUsage(ctx context.Context, tavilyKey string) (int, *int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.baseURL+"/usage", nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tavilyKey)

	resp, err := p.client.Do(req)
	if err != nil {
		p.logger.Warn("upstream usage request failed", "err", err)
		return 0, nil, err
	}
	defer resp.Body.Close()

	body, err := p.readBodyLimited(resp.Body)
	if err != nil {
		return 0, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return 0, nil, &UpstreamStatusError{StatusCode: resp.StatusCode, Body: string(body)}
	}

	var out usageResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return 0, nil, err
	}

	limit := out.Key.Limit
	if limit == nil {
		limit = out.Account.PlanLimit
	}
	return out.Key.Usage, limit, nil
}

// creditsFromResponse extracts Tavily's own accounting from a response
// body: {"usage": {"credits": N}}. It is the source of truth for how much
// a call actually cost.
func creditsFromResponse(body []byte) (int, bool) {
	var m struct {
		Usage *struct {
			Credits *int `json:"credits"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(body, &m); err != nil || m.Usage == nil || m.Usage.Credits == nil {
		return 0, false
	}
	if *m.Usage.Credits < 0 {
		return 0, false
	}
	return *m.Usage.Credits, true
}

// estimateCredits approximates Tavily's per-call credit cost from the
// request, used to pre-charge a reservation and as the accounting
// fallback when a response carries no usage block. Rules (Tavily pricing
// docs): basic search 1, advanced search 2; extract 1 credit per 5 URLs
// (basic) or 2 per 5 (advanced); other endpoints default to 1.
func estimateCredits(req ProxyRequest) int {
	if strings.EqualFold(req.Method, http.MethodGet) {
		return 0
	}
	var body map[string]any
	_ = json.Unmarshal(req.Body, &body)
	switch req.Path {
	case "/search":
		if d, _ := body["search_depth"].(string); strings.EqualFold(d, "advanced") {
			return 2
		}
		return 1
	case "/extract":
		urls, _ := body["urls"].([]any)
		n := len(urls)
		if n == 0 {
			return 1
		}
		per := 1
		if d, _ := body["extract_depth"].(string); strings.EqualFold(d, "advanced") {
			per = 2
		}
		return (n + 4) / 5 * per
	default:
		return 1
	}
}

// parseRetryAfter parses a Retry-After header value in seconds form.
func parseRetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	secs, err := strconv.Atoi(v)
	if err != nil || secs <= 0 {
		return 0
	}
	return time.Duration(secs) * time.Second
}
