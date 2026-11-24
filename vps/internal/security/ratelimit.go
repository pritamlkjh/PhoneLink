package security

import (
	"net/http"
	"sync"
	"time"
)

// RateLimiter provides sliding-window rate limiting per remote IP or device
type RateLimiter struct {
	mu           sync.Mutex
	rateLimit    int           // max requests per window
	window       time.Duration // window duration
	clients      map[string]*clientBucket
	cleanupTimer *time.Ticker
}

type clientBucket struct {
	tokens    int
	lastReset time.Time
}

// NewRateLimiter creates a thread-safe rate limiter
func NewRateLimiter(rateLimit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		rateLimit:    rateLimit,
		window:       window,
		clients:      make(map[string]*clientBucket),
		cleanupTimer: time.NewTicker(5 * time.Minute),
	}

	go rl.cleanupLoop()

	return rl
}

func (rl *RateLimiter) cleanupLoop() {
	for range rl.cleanupTimer.C {
		rl.mu.Lock()
		now := time.Now()
		for ip, bucket := range rl.clients {
			if now.Sub(bucket.lastReset) > rl.window*2 {
				delete(rl.clients, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// Stop stops the background cleanup timer
func (rl *RateLimiter) Stop() {
	rl.cleanupTimer.Stop()
}

// Allow checks if the given key (e.g. IP address) is permitted to make a request
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	bucket, exists := rl.clients[key]

	if !exists || now.Sub(bucket.lastReset) >= rl.window {
		rl.clients[key] = &clientBucket{
			tokens:    1,
			lastReset: now,
		}
		return true
	}

	if bucket.tokens < rl.rateLimit {
		bucket.tokens++
		return true
	}

	return false
}

// Middleware wraps an http.Handler with rate limiting
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		// Strip port if present
		if colon := len(ip) - 1; colon >= 0 {
			for i := colon; i >= 0; i-- {
				if ip[i] == ':' {
					ip = ip[:i]
					break
				}
			}
		}

		if !rl.Allow(ip) {
			w.Header().Set("Retry-After", "60")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"Too Many Requests","status":429}`))
			return
		}

		next.ServeHTTP(w, r)
	})
}
