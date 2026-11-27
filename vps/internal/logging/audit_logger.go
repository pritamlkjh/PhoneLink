package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// Event types for structured auditing
const (
	EventAuthAttempt       = "auth.attempt"
	EventAuthSuccess       = "auth.success"
	EventAuthFailure       = "auth.failure"
	EventSessionConnect    = "session.connect"
	EventSessionDisconnect = "session.disconnect"
	EventRelayForward      = "relay.forward"
	EventSecurityAlert     = "security.alert"
	EventServerError       = "server.error"
)

// Alert types
const (
	AlertExcessiveAuthFailures = "ALERT_EXCESSIVE_AUTH_FAILURES"
	AlertTamperedRelayPayload  = "ALERT_TAMPERED_RELAY_PAYLOAD"
)

// Redacted key fragments that MUST never appear in log attributes (ARCH-4 / VPS-7)
var forbiddenKeySubstrings = []string{
	"payload", "content", "frame", "chunk", "data", "plaintext", "secret", "private_key",
}

// AlertEvent represents an emitted security alert
type AlertEvent struct {
	Type      string    `json:"type"`
	Severity  string    `json:"severity"`
	Source    string    `json:"source"`
	Count     int       `json:"count"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

// AuthFailureMonitor tracks consecutive / sliding-window authentication failures
type AuthFailureMonitor struct {
	mu           sync.Mutex
	failures     map[string][]time.Time
	threshold    int
	window       time.Duration
	alertHandler func(alert AlertEvent)
}

// NewAuthFailureMonitor initializes an auth failure monitor
func NewAuthFailureMonitor(threshold int, window time.Duration, alertHandler func(alert AlertEvent)) *AuthFailureMonitor {
	if threshold <= 0 {
		threshold = 5 // Default: 5 failures within window
	}
	if window <= 0 {
		window = 1 * time.Minute
	}
	return &AuthFailureMonitor{
		failures:     make(map[string][]time.Time),
		threshold:    threshold,
		window:       window,
		alertHandler: alertHandler,
	}
}

// RecordFailure records an authentication failure for a source (IP or device ID)
// Returns true if an alert was triggered.
func (m *AuthFailureMonitor) RecordFailure(source string, reason string) bool {
	var triggered bool
	var handler func(AlertEvent)
	var alert AlertEvent

	m.mu.Lock()
	now := time.Now()
	cutoff := now.Add(-m.window)

	// Clean up old failures
	var validTimes []time.Time
	for _, t := range m.failures[source] {
		if t.After(cutoff) {
			validTimes = append(validTimes, t)
		}
	}
	validTimes = append(validTimes, now)
	m.failures[source] = validTimes

	// Bound map size by pruning expired entries when table grows
	if len(m.failures) > 4096 {
		for k, times := range m.failures {
			if k == source {
				continue
			}
			hasRecent := false
			for _, t := range times {
				if t.After(cutoff) {
					hasRecent = true
					break
				}
			}
			if !hasRecent {
				delete(m.failures, k)
			}
		}
	}

	if len(validTimes) >= m.threshold {
		triggered = true
		handler = m.alertHandler
		alert = AlertEvent{
			Type:      AlertExcessiveAuthFailures,
			Severity:  "CRITICAL",
			Source:    source,
			Count:     len(validTimes),
			Message:   fmt.Sprintf("Repeated authentication failures detected: %d attempts within %v (last reason: %s)", len(validTimes), m.window, reason),
			Timestamp: now,
		}
	}
	m.mu.Unlock()

	if triggered && handler != nil {
		handler(alert)
	}
	return triggered
}

// RecordSuccess resets/clears failure tracking for a source upon successful authentication
func (m *AuthFailureMonitor) RecordSuccess(source string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.failures, source)
}

// GetFailureCount returns current active failure count for source
func (m *AuthFailureMonitor) GetFailureCount(source string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-m.window)
	count := 0
	for _, t := range m.failures[source] {
		if t.After(cutoff) {
			count++
		}
	}
	return count
}

// Reset clears all failure state
func (m *AuthFailureMonitor) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failures = make(map[string][]time.Time)
}

// AuditLogger provides privacy-preserving structured logging for VPS relay events
type AuditLogger struct {
	logger  *slog.Logger
	monitor *AuthFailureMonitor
}

// NewAuditLogger creates a new AuditLogger wrapping slog.Logger
func NewAuditLogger(logger *slog.Logger, monitor *AuthFailureMonitor) *AuditLogger {
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))
	}
	return &AuditLogger{
		logger:  logger,
		monitor: monitor,
	}
}

// Monitor returns the underlying AuthFailureMonitor
func (l *AuditLogger) Monitor() *AuthFailureMonitor {
	return l.monitor
}

// SetAlertHandler updates the alert handler callback
func (l *AuditLogger) SetAlertHandler(fn func(alert AlertEvent)) {
	if l.monitor != nil {
		l.monitor.mu.Lock()
		defer l.monitor.mu.Unlock()
		l.monitor.alertHandler = fn
	}
}

func normalizeRemoteHost(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil && host != "" {
		return host
	}
	return remoteAddr
}

// LogAuthAttempt logs an initial authentication request
func (l *AuditLogger) LogAuthAttempt(remoteAddr, deviceID string) {
	l.logger.Info("Authentication attempt",
		slog.String("event", EventAuthAttempt),
		slog.String("remote_addr", remoteAddr),
		slog.String("device_id", sanitizeDeviceID(deviceID)),
	)
}

// LogAuthSuccess logs successful verification and session issuance
func (l *AuditLogger) LogAuthSuccess(remoteAddr, deviceID string) {
	host := normalizeRemoteHost(remoteAddr)
	if l.monitor != nil {
		if host != "" {
			l.monitor.RecordSuccess(host)
		}
		if deviceID != "" {
			l.monitor.RecordSuccess(deviceID)
		}
	}
	l.logger.Info("Authentication succeeded",
		slog.String("event", EventAuthSuccess),
		slog.String("remote_addr", remoteAddr),
		slog.String("device_id", sanitizeDeviceID(deviceID)),
	)
}

// LogAuthFailure logs failed verification and checks the failure monitor for alerts
func (l *AuditLogger) LogAuthFailure(remoteAddr, deviceID, reason string) {
	alertTriggered := false
	var triggeredSource string
	host := normalizeRemoteHost(remoteAddr)

	if l.monitor != nil {
		if host != "" {
			if l.monitor.RecordFailure(host, reason) {
				alertTriggered = true
				triggeredSource = host
			}
		}
		if deviceID != "" && deviceID != host {
			if l.monitor.RecordFailure(deviceID, reason) {
				alertTriggered = true
				if triggeredSource == "" {
					triggeredSource = deviceID
				}
			}
		}
	}

	l.logger.Warn("Authentication failed",
		slog.String("event", EventAuthFailure),
		slog.String("remote_addr", remoteAddr),
		slog.String("device_id", sanitizeDeviceID(deviceID)),
		slog.String("reason", reason),
		slog.Bool("alert_triggered", alertTriggered),
	)

	if alertTriggered {
		l.LogAlert(AlertExcessiveAuthFailures, "CRITICAL", map[string]interface{}{
			"source": triggeredSource,
			"reason": reason,
		})
	}
}

// LogConnection logs WebSocket connection established
func (l *AuditLogger) LogConnection(remoteAddr, deviceID string) {
	l.logger.Info("WebSocket peer connected",
		slog.String("event", EventSessionConnect),
		slog.String("remote_addr", remoteAddr),
		slog.String("device_id", sanitizeDeviceID(deviceID)),
	)
}

// LogDisconnect logs WebSocket disconnect
func (l *AuditLogger) LogDisconnect(remoteAddr, deviceID, reason string) {
	l.logger.Info("WebSocket peer disconnected",
		slog.String("event", EventSessionDisconnect),
		slog.String("remote_addr", remoteAddr),
		slog.String("device_id", sanitizeDeviceID(deviceID)),
		slog.String("reason", reason),
	)
}

// LogRelayForward logs opaque frame forwarding.
// CRITICAL PRIVACY INVARIANT (VPS-7): Logs ONLY byte count and device endpoints.
// Never logs raw byte buffers, ciphertext slices, or payload contents.
func (l *AuditLogger) LogRelayForward(fromDeviceID, toDeviceID string, numBytes int) {
	l.logger.Debug("Relay forwarded frame",
		slog.String("event", EventRelayForward),
		slog.String("from_device", sanitizeDeviceID(fromDeviceID)),
		slog.String("to_device", sanitizeDeviceID(toDeviceID)),
		slog.Int("bytes", numBytes),
	)
}

// LogError logs a server error, strictly stripping any attributes that might hold payload data
func (l *AuditLogger) LogError(event string, err error, metadata map[string]interface{}) {
	var attrs []slog.Attr
	attrs = append(attrs, slog.String("event", EventServerError))
	attrs = append(attrs, slog.String("sub_event", event))
	if err != nil {
		attrs = append(attrs, slog.String("error", err.Error()))
	}

	for k, v := range metadata {
		if isForbiddenKey(k) {
			continue // Drop forbidden payload keys entirely!
		}
		attrs = append(attrs, slog.Any(k, v))
	}

	l.logger.LogAttrs(context.Background(), slog.LevelError, "Server error", attrs...)
}

// LogAlert logs an emitted security alert
func (l *AuditLogger) LogAlert(alertType, severity string, details map[string]interface{}) {
	var attrs []slog.Attr
	attrs = append(attrs, slog.String("event", EventSecurityAlert))
	attrs = append(attrs, slog.String("alert_type", alertType))
	attrs = append(attrs, slog.String("severity", severity))

	for k, v := range details {
		if isForbiddenKey(k) {
			continue
		}
		attrs = append(attrs, slog.Any(k, v))
	}

	l.logger.LogAttrs(context.Background(), slog.LevelError, "SECURITY ALERT TRIGGERED", attrs...)
}

// Helper to determine if a key is forbidden (payload / data / secret)
func isForbiddenKey(key string) bool {
	lower := strings.ToLower(key)
	for _, forbidden := range forbiddenKeySubstrings {
		if strings.Contains(lower, forbidden) {
			return true
		}
	}
	return false
}

// Helper to sanitize device IDs for logs
func sanitizeDeviceID(id string) string {
	if len(id) <= 16 {
		return id
	}
	return id[:8] + "..." + id[len(id)-8:]
}

// CreateBufferLogger creates an AuditLogger that writes JSON logs to a memory buffer for testing
func CreateBufferLogger(buf io.Writer) (*AuditLogger, *AuthFailureMonitor) {
	handler := slog.NewJSONHandler(buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	logger := slog.New(handler)
	monitor := NewAuthFailureMonitor(3, 10*time.Second, nil)
	return NewAuditLogger(logger, monitor), monitor
}
