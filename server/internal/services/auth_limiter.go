package services

import (
	"sync"
	"time"
)

// AuthLimiter is a small in-memory brute-force guard for token
// authentication. After maxFailures failed attempts from one client within
// window, that client is blocked for blockFor. Successful authentication
// clears the client's history. All methods are nil-safe so wiring is
// optional in tests.
type AuthLimiter struct {
	mu          sync.Mutex
	maxFailures int
	window      time.Duration
	blockFor    time.Duration
	entries     map[string]*authEntry
}

type authEntry struct {
	failures     []time.Time
	blockedUntil time.Time
}

func NewAuthLimiter(maxFailures int, window, blockFor time.Duration) *AuthLimiter {
	if maxFailures <= 0 {
		maxFailures = 20
	}
	if window <= 0 {
		window = 5 * time.Minute
	}
	if blockFor <= 0 {
		blockFor = 5 * time.Minute
	}
	return &AuthLimiter{
		maxFailures: maxFailures,
		window:      window,
		blockFor:    blockFor,
		entries:     make(map[string]*authEntry),
	}
}

func DefaultAuthLimiter() *AuthLimiter {
	return NewAuthLimiter(20, 5*time.Minute, 5*time.Minute)
}

func (l *AuthLimiter) Blocked(client string) bool {
	if l == nil || client == "" {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[client]
	return ok && time.Now().Before(e.blockedUntil)
}

func (l *AuthLimiter) Fail(client string) {
	if l == nil || client == "" {
		return
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[client]
	if !ok {
		e = &authEntry{}
		l.entries[client] = e
	}
	cutoff := now.Add(-l.window)
	kept := e.failures[:0]
	for _, t := range e.failures {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	e.failures = append(kept, now)
	if len(e.failures) >= l.maxFailures {
		e.blockedUntil = now.Add(l.blockFor)
		e.failures = nil
	}
}

func (l *AuthLimiter) Success(client string) {
	if l == nil || client == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, client)
}
