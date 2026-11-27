package security

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRateLimiter(t *testing.T) {
	limit := 5
	rl := NewRateLimiter(limit, 1*time.Second)
	defer rl.Stop()

	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))

	ip := "192.168.1.100:12345"

	// First 'limit' requests must succeed
	for i := 0; i < limit; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = ip
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Request %d expected 200 OK, got %d", i+1, rec.Code)
		}
	}

	// Request 'limit + 1' must be rate-limited (429)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = ip
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("Expected 429 Too Many Requests on burst limit, got %d", rec.Code)
	}

	if retryAfter := rec.Header().Get("Retry-After"); retryAfter == "" {
		t.Error("Expected Retry-After header on 429 response")
	}
}

func TestSecurityHeaders(t *testing.T) {
	handler := SecurityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("Missing or invalid X-Content-Type-Options header")
	}
	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Errorf("Missing or invalid X-Frame-Options header")
	}
	if !strings.Contains(rec.Header().Get("Strict-Transport-Security"), "max-age=") {
		t.Errorf("Missing or invalid Strict-Transport-Security header")
	}
}

func TestHardenedTLSConfig(t *testing.T) {
	cfg := HardenedTLSConfig()
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("Expected MinVersion TLS 1.3 (%x), got %x", tls.VersionTLS13, cfg.MinVersion)
	}
	if !cfg.PreferServerCipherSuites {
		t.Errorf("Expected PreferServerCipherSuites to be true")
	}
}

func TestMaxBodySize(t *testing.T) {
	handler := SecurityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	// Create oversized reader (> 10MB)
	oversized := io.LimitReader(strings.NewReader(strings.Repeat("A", 1024*1024)), 11*1024*1024)
	req := httptest.NewRequest(http.MethodPost, "/upload", oversized)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Since LimitReader only had 1MB, let's create actual > 10MB payload:
	largeReader := &largeZeroReader{remaining: 11 * 1024 * 1024}
	req2 := httptest.NewRequest(http.MethodPost, "/upload", largeReader)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("Expected 413 Request Entity Too Large, got %d", rec2.Code)
	}
}

type largeZeroReader struct {
	remaining int64
}

func (r *largeZeroReader) Read(p []byte) (n int, err error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	toRead := int64(len(p))
	if toRead > r.remaining {
		toRead = r.remaining
	}
	r.remaining -= toRead
	for i := 0; i < int(toRead); i++ {
		p[i] = 'X'
	}
	return int(toRead), nil
}

func TestRateLimiterIPv6AndStop(t *testing.T) {
	if got := ExtractClientIP("[::1]:54321"); got != "::1" {
		t.Fatalf("expected IPv6 host ::1, got %q", got)
	}
	if got := ExtractClientIP("203.0.113.5:8080"); got != "203.0.113.5" {
		t.Fatalf("expected IPv4 host 203.0.113.5, got %q", got)
	}

	rl := NewRateLimiter(2, 150*time.Millisecond)
	defer rl.Stop()
	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/ok", nil)
		req.RemoteAddr = "[::1]:4242"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 on request %d, got %d", i+1, rec.Code)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/ok", nil)
	req.RemoteAddr = "[::1]:4243"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on 3rd IPv6 request, got %d", rec.Code)
	}

	rl.Stop()
	rl.Stop() // Idempotent stop must not panic
}

func TestRateLimiterHonorsProxyHeadersOnlyFromTrustedProxy(t *testing.T) {
	reqFromCaddy := httptest.NewRequest(http.MethodGet, "/ok", nil)
	reqFromCaddy.RemoteAddr = "127.0.0.1:50000"
	reqFromCaddy.Header.Set("X-Forwarded-For", "203.0.113.1, 198.51.100.77, 127.0.0.1")
	if got := ExtractRequestClientIP(reqFromCaddy); got != "198.51.100.77" {
		t.Fatalf("expected right-most untrusted X-Forwarded-For IP from trusted proxy, got %q", got)
	}

	reqSpoofed := httptest.NewRequest(http.MethodGet, "/ok", nil)
	reqSpoofed.RemoteAddr = "203.0.113.10:50000"
	reqSpoofed.Header.Set("X-Forwarded-For", "198.51.100.88")
	if got := ExtractRequestClientIP(reqSpoofed); got != "203.0.113.10" {
		t.Fatalf("expected untrusted X-Forwarded-For to be ignored, got %q", got)
	}
}
