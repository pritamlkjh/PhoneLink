package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHandleInstallPage(t *testing.T) {
	cfg := DefaultConfig()
	s := NewServer(cfg, nil)

	req := httptest.NewRequest("GET", "/install", nil)
	rec := httptest.NewRecorder()

	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", rec.Code)
	}

	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("expected Content-Type text/html, got %s", ct)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "Tap Here to Download &amp; Install") {
		t.Errorf("expected download button in HTML body")
	}
	if !strings.Contains(body, "minSdk") && !strings.Contains(body, "Android 8.0") {
		t.Errorf("expected Android compatibility info in HTML body")
	}
}

func TestHandleDownloadApk(t *testing.T) {
	cfg := DefaultConfig()
	s := NewServer(cfg, nil)

	// Create a dummy APK file in a temporary location
	tmpDir := t.TempDir()
	dummyApk := filepath.Join(tmpDir, "PhoneLink.apk")
	if err := os.WriteFile(dummyApk, []byte("PK\x03\x04dummy-apk-bytes"), 0644); err != nil {
		t.Fatalf("failed to write dummy APK: %v", err)
	}

	origDir, _ := os.Getwd()
	_ = os.Chdir(tmpDir)
	defer func() { _ = os.Chdir(origDir) }()

	req := httptest.NewRequest("GET", "/download/PhoneLink.apk", nil)
	rec := httptest.NewRecorder()

	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", rec.Code)
	}

	ct := rec.Header().Get("Content-Type")
	if ct != "application/vnd.android.package-archive" {
		t.Errorf("expected Android APK Content-Type, got %s", ct)
	}

	disp := rec.Header().Get("Content-Disposition")
	if !strings.Contains(disp, "attachment") || !strings.Contains(disp, "PhoneLink.apk") {
		t.Errorf("expected attachment Content-Disposition, got %s", disp)
	}
}
