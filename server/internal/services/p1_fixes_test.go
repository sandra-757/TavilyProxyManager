package services

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestCreditsFromResponse(t *testing.T) {
	if c, ok := creditsFromResponse([]byte(`{"usage":{"credits":3}}`)); !ok || c != 3 {
		t.Fatalf("expected 3 credits, got %d ok=%v", c, ok)
	}
	if _, ok := creditsFromResponse([]byte(`{"ok":true}`)); ok {
		t.Fatal("missing usage block must not parse")
	}
	if _, ok := creditsFromResponse([]byte(`{"usage":{"credits":-1}}`)); ok {
		t.Fatal("negative credits must be rejected")
	}
}

func TestEstimateCredits(t *testing.T) {
	cases := []struct {
		path, body string
		want       int
	}{
		{"/search", `{"query":"x"}`, 1},
		{"/search", `{"query":"x","search_depth":"advanced"}`, 2},
		{"/extract", `{"urls":["a","b","c","d","e","f"]}`, 2},
		{"/extract", `{"urls":["a"],"extract_depth":"advanced"}`, 2},
		{"/map", `{}`, 1},
	}
	for _, tc := range cases {
		got := estimateCredits(ProxyRequest{Method: "POST", Path: tc.path, Body: []byte(tc.body)})
		if got != tc.want {
			t.Errorf("%s %s: got %d want %d", tc.path, tc.body, got, tc.want)
		}
	}
	if got := estimateCredits(ProxyRequest{Method: "GET", Path: "/usage"}); got != 0 {
		t.Errorf("GET must be free, got %d", got)
	}
}

func TestProxy_AccountingUsesUsageCredits(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"usage":{"credits":3}}`))
	}))
	defer upstream.Close()

	ctx, keys, proxy := newTavilyProxyTestDeps(t, upstream.URL)
	k, err := keys.Create(ctx, "tvly-a", "a", 1000)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := proxy.Do(ctx, ProxyRequest{Method: "POST", Path: "/search", Body: []byte(`{"query":"x"}`)}); err != nil {
		t.Fatalf("do: %v", err)
	}
	got, err := keys.Get(ctx, k.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.UsedQuota != 3 {
		t.Fatalf("usage.credits=3 must be charged, used=%d", got.UsedQuota)
	}
}

func TestKeyService_ReserveAndRefund(t *testing.T) {
	ctx, keys, _ := newTavilyProxyTestDeps(t, "http://127.0.0.1:1")
	k, err := keys.Create(ctx, "tvly-a", "a", 2)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	ok, err := keys.Reserve(ctx, k.ID, 2)
	if err != nil || !ok {
		t.Fatalf("reserve 2/2: ok=%v err=%v", ok, err)
	}
	ok, err = keys.Reserve(ctx, k.ID, 1)
	if err != nil {
		t.Fatalf("reserve err: %v", err)
	}
	if ok {
		t.Fatal("reserve beyond quota must fail")
	}
	if err := keys.IncrementUsedBy(ctx, k.ID, -2); err != nil {
		t.Fatalf("refund: %v", err)
	}
	got, _ := keys.Get(ctx, k.ID)
	if got.UsedQuota != 0 {
		t.Fatalf("after refund used=%d want 0", got.UsedQuota)
	}
}

func TestProxy_RateLimitedKeyCoolingDown(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if bearerToken(r) == "tvly-429" {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate_limit"}`))
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	ctx, keys, proxy := newTavilyProxyTestDeps(t, upstream.URL)
	k1, _ := keys.Create(ctx, "tvly-429", "limited", 2000)
	_, _ = keys.Create(ctx, "tvly-ok", "ok", 1000)
	if _, err := proxy.Do(ctx, ProxyRequest{Method: "POST", Path: "/search", Body: []byte(`{"query":"x"}`)}); err != nil {
		t.Fatalf("do: %v", err)
	}
	cands, err := keys.Candidates(ctx)
	if err != nil {
		t.Fatalf("candidates: %v", err)
	}
	for _, c := range cands {
		if c.ID == k1.ID {
			t.Fatal("rate-limited key must be deprioritised while another key is available")
		}
	}
}

func TestProxy_MaxAttemptsCapsFailover(t *testing.T) {
	var calls int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&calls, 1)
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"rate_limit"}`))
	}))
	defer upstream.Close()

	ctx, keys, proxy := newTavilyProxyTestDeps(t, upstream.URL)
	for i := 0; i < 7; i++ {
		_, _ = keys.Create(ctx, "tvly-k"+string(rune(49+i)), "k", 1000)
	}
	_, _ = proxy.Do(ctx, ProxyRequest{Method: "POST", Path: "/search", Body: []byte(`{"query":"x"}`)})
	if got := atomic.LoadInt64(&calls); got != DefaultMaxAttempts {
		t.Fatalf("attempts=%d want cap %d", got, DefaultMaxAttempts)
	}
}

func TestBuildCacheKey_FullBody(t *testing.T) {
	cs := &CacheService{}
	a, _ := cs.BuildCacheKey([]byte(`{"query":"x","include_answer":true}`))
	b, _ := cs.BuildCacheKey([]byte(`{"query":"x","include_answer":false}`))
	if a == b {
		t.Fatal("requests differing only in include_answer must not share a cache key")
	}
	c, _ := cs.BuildCacheKey([]byte(`{"include_answer":true,"query":"x"}`))
	if a != c {
		t.Fatal("field order must not change the cache key")
	}
}

func TestResetAllUsage(t *testing.T) {
	ctx, keys, _ := newTavilyProxyTestDeps(t, "http://127.0.0.1:1")
	k, _ := keys.Create(ctx, "tvly-a", "a", 100)
	if err := keys.IncrementUsedBy(ctx, k.ID, 5); err != nil {
		t.Fatalf("increment: %v", err)
	}
	if err := keys.ResetAllUsage(ctx); err != nil {
		t.Fatalf("reset: %v", err)
	}
	got, _ := keys.Get(ctx, k.ID)
	if got.UsedQuota != 0 {
		t.Fatalf("used=%d want 0 after reset", got.UsedQuota)
	}
}

