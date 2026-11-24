package security

import (
	"crypto/tls"
	"net/http"
)

const (
	// MaxEnvelopeSizeBytes is the maximum permitted message size across the relay (10MB)
	MaxEnvelopeSizeBytes = 10 * 1024 * 1024
	// MaxHeaderSizeBytes is the maximum permitted HTTP header size (1MB)
	MaxHeaderSizeBytes = 1 * 1024 * 1024
)

// SecurityHeadersMiddleware adds defensive HTTP security headers to all responses
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		w.Header().Set("Pragma", "no-cache")

		// Enforce maximum body size
		r.Body = http.MaxBytesReader(w, r.Body, MaxEnvelopeSizeBytes)

		next.ServeHTTP(w, r)
	})
}

// HardenedTLSConfig returns a TLS 1.3-enforced tls.Config
func HardenedTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_128_GCM_SHA256,
		},
		PreferServerCipherSuites: true,
	}
}
