package security

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// RateLimiter provides sliding-window rate limiting per remote IP or device.
type RateLimiter struct {
	mu           sync.Mutex
	rateLimit    int           // max requests per window
	window       time.Duration // window duration
	clients      map[string]*clientBucket
	cleanupTimer *time.Ticker
	stopCh       chan struct{}
	stopOnce     sync.Once
}

type clientBucket struct {
	timestamps []time.Time
}

// NewRateLimiter creates a thread-safe sliding-window rate limiter.
func NewRateLimiter(rateLimit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		rateLimit:    rateLimit,
		window:       window,
		clients:      make(map[string]*clientBucket),
		cleanupTimer: time.NewTicker(5 * time.Minute),
		stopCh:       make(chan struct{}),
	}

	go rl.cleanupLoop()

	return rl
}

func (rl *RateLimiter) cleanupLoop() {
	for {
		select {
		case <-rl.cleanupTimer.C:
			rl.mu.Lock()
			cutoff := time.Now().Add(-rl.window)
			for ip, bucket := range rl.clients {
				pruned := pruneOldTimestamps(bucket.timestamps, cutoff)
				if len(pruned) == 0 {
					delete(rl.clients, ip)
				} else {
					bucket.timestamps = pruned
				}
			}
			rl.mu.Unlock()
		case <-rl.stopCh:
			return
		}
	}
}

// Stop stops the background cleanup timer and goroutine cleanly.
func (rl *RateLimiter) Stop() {
	rl.stopOnce.Do(func() {
		rl.cleanupTimer.Stop()
		close(rl.stopCh)
	})
}

func pruneOldTimestamps(ts []time.Time, cutoff time.Time) []time.Time {
	idx := 0
	for idx < len(ts) && ts[idx].Before(cutoff) {
		idx++
	}
	if idx == 0 {
		return ts
	}
	return append([]time.Time(nil), ts[idx:]...)
}

// Allow checks if the given key (e.g. IP address) is permitted under the sliding window.
func (rl *RateLimiter) Allow(key string) bool {
	if rl.rateLimit <= 0 {
		return true
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)
	bucket, exists := rl.clients[key]
	if !exists {
		bucket = &clientBucket{}
		rl.clients[key] = bucket
	}

	bucket.timestamps = pruneOldTimestamps(bucket.timestamps, cutoff)
	if len(bucket.timestamps) < rl.rateLimit {
		bucket.timestamps = append(bucket.timestamps, now)
		return true
	}

	return false
}

// ExtractClientIP strips any port cleanly (supporting IPv4 and bracketed IPv6).
func ExtractClientIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil && host != "" {
		return host
	}
	return remoteAddr
}

// Middleware wraps an http.Handler with sliding-window rate limiting.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := ExtractClientIP(r.RemoteAddr)

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
