package integration

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pritamlkjh/phonelink/vps/internal/auth"
	"github.com/pritamlkjh/phonelink/vps/internal/logging"
	"github.com/pritamlkjh/phonelink/vps/internal/server"
)

// VPS-7: VPS Logging & Monitoring Integration Suite
// Acceptance criteria:
// 1. Structured logs for auth/connection/error events
// 2. File contents, camera frames, and message payloads never logged under normal and error conditions
// 3. Basic alerting on repeated auth failures
func TestVPS7LoggingAndMonitoring(t *testing.T) {
	// 1. Setup in-memory log buffer to capture all server log entries
	var logBuf bytes.Buffer
	logMu := &sync.Mutex{}

	threadSafeWriter := &synchronizedWriter{buf: &logBuf, mu: logMu}
	jsonHandler := slog.NewJSONHandler(threadSafeWriter, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	slogLogger := slog.New(jsonHandler)

	var alertMu sync.Mutex
	var triggeredAlerts []logging.AlertEvent

	srv := server.NewServer(server.DefaultConfig(), slogLogger)
	srv.AuditLogger().SetAlertHandler(func(alert logging.AlertEvent) {
		alertMu.Lock()
		defer alertMu.Unlock()
		triggeredAlerts = append(triggeredAlerts, alert)
	})

	httpServer := httptest.NewServer(srv.Handler())
	defer httpServer.Close()

	wsBaseURL := "ws" + strings.TrimPrefix(httpServer.URL, "http")

	// 2. Identity & Registration
	macPub, macPriv, _ := ed25519.GenerateKey(rand.Reader)
	macDeviceID := auth.DeriveDeviceID(macPub)

	andPub, andPriv, _ := ed25519.GenerateKey(rand.Reader)
	andDeviceID := auth.DeriveDeviceID(andPub)

	registerDevice(t, httpServer.URL, macDeviceID, "mac", base64.StdEncoding.EncodeToString(macPub), auth.AlgorithmEd25519)
	registerDevice(t, httpServer.URL, andDeviceID, "android", base64.StdEncoding.EncodeToString(andPub), auth.AlgorithmEd25519)

	macInitToken := authenticateEd25519(t, httpServer.URL, macDeviceID, macPriv)
	token := createPairingToken(t, httpServer.URL, macDeviceID, macInitToken)
	claimPairing(t, httpServer.URL, token, andDeviceID)

	// --- SUB-TEST 1: Structured Logs for Auth and Connections ---
	t.Run("StructuredLogsForAuthAndConnections", func(t *testing.T) {
		macToken := authenticateEd25519(t, httpServer.URL, macDeviceID, macPriv)
		andToken := authenticateEd25519(t, httpServer.URL, andDeviceID, andPriv)

		macConn, _, err := websocket.DefaultDialer.Dial(fmt.Sprintf("%s/ws/v1/connect?token=%s", wsBaseURL, macToken), nil)
		if err != nil {
			t.Fatalf("mac ws dial failed: %v", err)
		}
		defer macConn.Close()

		andConn, _, err := websocket.DefaultDialer.Dial(fmt.Sprintf("%s/ws/v1/connect?token=%s", wsBaseURL, andToken), nil)
		if err != nil {
			t.Fatalf("and ws dial failed: %v", err)
		}
		defer andConn.Close()

		_ = readPresenceEvent(t, macConn)
		_ = readPresenceEvent(t, andConn)
		_ = readPresenceEvent(t, macConn)

		// Forward a message through relay
		secretPayload := []byte("FORBIDDEN_FILE_CONTENT_SECRET_12345")
		_ = macConn.WriteMessage(websocket.BinaryMessage, secretPayload)
		_, _, _ = andConn.ReadMessage()

		logMu.Lock()
		logs := logBuf.String()
		logMu.Unlock()

		lines := strings.Split(strings.TrimSpace(logs), "\n")
		eventsFound := make(map[string]bool)

		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var entry map[string]interface{}
			if err := json.Unmarshal([]byte(line), &entry); err != nil {
				t.Fatalf("malformed log line (not json): %s", line)
			}
			if evt, ok := entry["event"].(string); ok {
				eventsFound[evt] = true
			}
		}

		if !eventsFound[logging.EventAuthAttempt] {
			t.Errorf("missing event %s in logs", logging.EventAuthAttempt)
		}
		if !eventsFound[logging.EventAuthSuccess] {
			t.Errorf("missing event %s in logs", logging.EventAuthSuccess)
		}
		if !eventsFound[logging.EventSessionConnect] {
			t.Errorf("missing event %s in logs", logging.EventSessionConnect)
		}
		if !eventsFound[logging.EventRelayForward] {
			t.Errorf("missing event %s in logs", logging.EventRelayForward)
		}
	})

	// --- SUB-TEST 2: Zero Payload / Frame / Content Logging Invariant ---
	t.Run("ZeroPayloadLoggingInvariant", func(t *testing.T) {
		// Verify neither normal relay nor error cases ever log payload contents
		logMu.Lock()
		allLogs := logBuf.String()
		logMu.Unlock()

		forbiddenPayloadStrings := []string{
			"FORBIDDEN_FILE_CONTENT_SECRET_12345",
			"SECRET_12345",
		}

		for _, forbidden := range forbiddenPayloadStrings {
			if strings.Contains(allLogs, forbidden) {
				t.Fatalf("CRITICAL PRIVACY VIOLATION: payload string %q was logged in relay logs!\nLogs:\n%s", forbidden, allLogs)
			}
		}
		t.Log("PASS: Zero payload bytes detected across all structured logs")
	})

	// --- SUB-TEST 3: Repeated Authentication Failure Alerting ---
	t.Run("RepeatedAuthFailureAlerting", func(t *testing.T) {
		unregisteredDeviceID := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

		// Send 5 invalid authentication requests to trigger the failure threshold
		for i := 1; i <= 5; i++ {
			verifyBody, _ := json.Marshal(map[string]interface{}{
				"device_id":    unregisteredDeviceID,
				"server_nonce": base64.StdEncoding.EncodeToString(make([]byte, 32)),
				"client_nonce": base64.StdEncoding.EncodeToString(make([]byte, 32)),
				"timestamp":    time.Now().Unix(),
				"signature":    base64.StdEncoding.EncodeToString(make([]byte, 64)),
			})
			resp, err := http.Post(httpServer.URL+"/api/v1/auth/verify", "application/json", bytes.NewReader(verifyBody))
			if err != nil {
				t.Fatalf("auth verify request %d failed: %v", i, err)
			}
			_ = resp.Body.Close()
		}

		alertMu.Lock()
		defer alertMu.Unlock()

		if len(triggeredAlerts) == 0 {
			t.Fatalf("expected alert for repeated auth failures, but zero alerts triggered!")
		}

		lastAlert := triggeredAlerts[len(triggeredAlerts)-1]
		if lastAlert.Type != logging.AlertExcessiveAuthFailures {
			t.Errorf("expected alert type %s, got %s", logging.AlertExcessiveAuthFailures, lastAlert.Type)
		}
		if lastAlert.Severity != "CRITICAL" {
			t.Errorf("expected severity CRITICAL, got %s", lastAlert.Severity)
		}
		t.Logf("PASS: Alert triggered cleanly: %s (Count: %d)", lastAlert.Message, lastAlert.Count)
	})
}

// synchronizedWriter for thread-safe buffer capturing in concurrent tests
type synchronizedWriter struct {
	buf *bytes.Buffer
	mu  *sync.Mutex
}

func (w *synchronizedWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}
