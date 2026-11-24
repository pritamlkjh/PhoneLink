package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHealthz(t *testing.T) {
	s := NewServer(DefaultConfig(), nil)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200 OK, got %d", rec.Code)
	}

	contentType := rec.Header().Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		t.Errorf("Expected Content-Type application/json, got %s", contentType)
	}

	var health HealthResponse
	if err := json.NewDecoder(rec.Body).Decode(&health); err != nil {
		t.Fatalf("Failed to decode JSON response: %v", err)
	}

	if health.Status != "OK" {
		t.Errorf("Expected status OK, got %s", health.Status)
	}
	if health.Service != Name {
		t.Errorf("Expected service %s, got %s", Name, health.Service)
	}
	if health.Version != Version {
		t.Errorf("Expected version %s, got %s", Version, health.Version)
	}
}

func TestVersion(t *testing.T) {
	s := NewServer(DefaultConfig(), nil)
	req := httptest.NewRequest(http.MethodGet, "/version", nil)
	rec := httptest.NewRecorder()

	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200 OK, got %d", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, Version) {
		t.Errorf("Expected version string in response body, got %s", body)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Port != 8443 {
		t.Errorf("Expected default port 8443, got %d", cfg.Port)
	}
	if cfg.ReadTimeout != 15*time.Second {
		t.Errorf("Expected read timeout 15s, got %v", cfg.ReadTimeout)
	}
}
