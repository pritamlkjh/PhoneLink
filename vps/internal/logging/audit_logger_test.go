package logging

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestStructuredLoggingEventEmission(t *testing.T) {
	var buf bytes.Buffer
	auditLogger, _ := CreateBufferLogger(&buf)

	auditLogger.LogAuthAttempt("127.0.0.1:54321", "abcdef0123456789abcdef0123456789")
	auditLogger.LogAuthSuccess("127.0.0.1:54321", "abcdef0123456789abcdef0123456789")
	auditLogger.LogConnection("127.0.0.1:54321", "abcdef0123456789abcdef0123456789")
	auditLogger.LogRelayForward("devA", "devB", 1024)
	auditLogger.LogDisconnect("127.0.0.1:54321", "abcdef0123456789abcdef0123456789", "client_closed")

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 5 {
		t.Fatalf("expected 5 log lines, got %d", len(lines))
	}

	expectedEvents := []string{
		EventAuthAttempt,
		EventAuthSuccess,
		EventSessionConnect,
		EventRelayForward,
		EventSessionDisconnect,
	}

	for i, line := range lines {
		var entry map[string]interface{}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("line %d is not valid JSON: %v", i, err)
		}
		if entry["event"] != expectedEvents[i] {
			t.Errorf("line %d: expected event %q, got %q", i, expectedEvents[i], entry["event"])
		}
	}
}

func TestPayloadAndSensitiveDataRedaction(t *testing.T) {
	var buf bytes.Buffer
	auditLogger, _ := CreateBufferLogger(&buf)

	// Attempt to log sensitive payload attributes
	sensitiveMetadata := map[string]interface{}{
		"safe_code":      400,
		"payload_bytes":  "FORBIDDEN_FILE_CONTENT_PLAINTEXT",
		"camera_frame":   "FORBIDDEN_JPEG_BYTES",
		"chunk_data":     "FORBIDDEN_CHUNK_BYTES",
		"private_key":    "FORBIDDEN_KEY_MATERIAL",
		"diagnostic_msg": "harmless diagnostic detail",
	}

	auditLogger.LogError("test_failure", errors.New("something went wrong"), sensitiveMetadata)

	logOutput := buf.String()

	// Verify safe fields exist
	if !strings.Contains(logOutput, "safe_code") {
		t.Errorf("expected safe_code in log output")
	}
	if !strings.Contains(logOutput, "harmless diagnostic detail") {
		t.Errorf("expected diagnostic_msg in log output")
	}

	// Verify all sensitive payload substrings are STRICTLY absent
	forbiddenStrings := []string{
		"FORBIDDEN_FILE_CONTENT_PLAINTEXT",
		"FORBIDDEN_JPEG_BYTES",
		"FORBIDDEN_CHUNK_BYTES",
		"FORBIDDEN_KEY_MATERIAL",
		"payload_bytes",
		"camera_frame",
		"chunk_data",
		"private_key",
	}

	for _, forbidden := range forbiddenStrings {
		if strings.Contains(logOutput, forbidden) {
			t.Fatalf("CRITICAL SECURITY VIOLATION: forbidden string %q found in log output: %s", forbidden, logOutput)
		}
	}
}

func TestAuthFailureMonitoringAndAlerting(t *testing.T) {
	var alertMu sync.Mutex
	var receivedAlerts []AlertEvent

	monitor := NewAuthFailureMonitor(3, 500*time.Millisecond, func(a AlertEvent) {
		alertMu.Lock()
		defer alertMu.Unlock()
		receivedAlerts = append(receivedAlerts, a)
	})

	logger := NewAuditLogger(nil, monitor)
	logger.SetAlertHandler(func(a AlertEvent) {
		alertMu.Lock()
		defer alertMu.Unlock()
		receivedAlerts = append(receivedAlerts, a)
	})

	sourceIP := "192.168.1.100"

	// 1st failure - no alert
	logger.LogAuthFailure(sourceIP, "dev-01", "invalid_signature")
	if monitor.GetFailureCount(sourceIP) != 1 {
		t.Fatalf("expected count 1, got %d", monitor.GetFailureCount(sourceIP))
	}
	alertMu.Lock()
	if len(receivedAlerts) != 0 {
		t.Fatalf("expected 0 alerts, got %d", len(receivedAlerts))
	}
	alertMu.Unlock()

	// 2nd failure - no alert
	logger.LogAuthFailure(sourceIP, "dev-01", "invalid_signature")
	if monitor.GetFailureCount(sourceIP) != 2 {
		t.Fatalf("expected count 2, got %d", monitor.GetFailureCount(sourceIP))
	}

	// 3rd failure - ALERT TRIGGERED!
	logger.LogAuthFailure(sourceIP, "dev-01", "invalid_signature")
	if monitor.GetFailureCount(sourceIP) != 3 {
		t.Fatalf("expected count 3, got %d", monitor.GetFailureCount(sourceIP))
	}

	alertMu.Lock()
	if len(receivedAlerts) == 0 {
		t.Fatalf("expected alert to be triggered on 3rd failure, but none was received!")
	}
	latestAlert := receivedAlerts[len(receivedAlerts)-1]
	alertMu.Unlock()

	if latestAlert.Type != AlertExcessiveAuthFailures {
		t.Errorf("expected alert type %s, got %s", AlertExcessiveAuthFailures, latestAlert.Type)
	}
	if latestAlert.Severity != "CRITICAL" {
		t.Errorf("expected severity CRITICAL, got %s", latestAlert.Severity)
	}

	// Successful auth resets count
	logger.LogAuthSuccess(sourceIP, "dev-01")
	if monitor.GetFailureCount(sourceIP) != 0 {
		t.Fatalf("expected count reset to 0 after success, got %d", monitor.GetFailureCount(sourceIP))
	}
}
