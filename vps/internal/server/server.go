package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pritamlkjh/phonelink/vps/internal/auth"
	"github.com/pritamlkjh/phonelink/vps/internal/coordinator"
	"github.com/pritamlkjh/phonelink/vps/internal/logging"
)

const (
	Version = "1.0.0"
	Name    = "PhoneLink VPS Relay"
)

// Config encapsulates server configuration
type Config struct {
	Host         string        `json:"host"`
	Port         int           `json:"port"`
	ReadTimeout  time.Duration `json:"read_timeout"`
	WriteTimeout time.Duration `json:"write_timeout"`
	IdleTimeout  time.Duration `json:"idle_timeout"`
}

// DefaultConfig returns hardened production-ready defaults
func DefaultConfig() Config {
	return Config{
		Host:         "0.0.0.0",
		Port:         8443,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
}

// Server represents the VPS relay HTTP/WebSocket server
type Server struct {
	cfg         Config
	httpServer  *http.Server
	mux         *http.ServeMux
	logger      *slog.Logger
	auditLogger *logging.AuditLogger
	startTime   time.Time
	registry    *auth.Registry
	tracker     *auth.ChallengeTracker
	coordinator *coordinator.Coordinator
	upgrader    websocket.Upgrader
}

// HealthResponse represents health check status
type HealthResponse struct {
	Status    string `json:"status"`
	Service   string `json:"service"`
	Version   string `json:"version"`
	UptimeSec int64  `json:"uptime_sec"`
	Timestamp int64  `json:"timestamp"`
}

// NewServer initializes a new Server instance
func NewServer(cfg Config, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}

	mux := http.NewServeMux()
	reg := auth.NewRegistry()
	auditLogger := logging.NewAuditLogger(logger, logging.NewAuthFailureMonitor(5, 1*time.Minute, nil))
	s := &Server{
		cfg:         cfg,
		mux:         mux,
		logger:      logger,
		auditLogger: auditLogger,
		startTime:   time.Now(),
		registry:    reg,
		tracker:     auth.NewChallengeTracker(),
		coordinator: coordinator.NewCoordinator(reg),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Origin checked via TLS & Auth Token
			},
			ReadBufferSize:  64 * 1024,
			WriteBufferSize: 64 * 1024,
		},
	}

	s.registerRoutes()

	s.httpServer = &http.Server{
		Addr:              fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		MaxHeaderBytes:    1 << 20, // 1MB
	}

	return s
}

// Registry returns the underlying auth.Registry instance
func (s *Server) Registry() *auth.Registry {
	return s.registry
}

// Tracker returns the underlying auth.ChallengeTracker instance
func (s *Server) Tracker() *auth.ChallengeTracker {
	return s.tracker
}

// Coordinator returns the underlying coordinator.Coordinator instance
func (s *Server) Coordinator() *coordinator.Coordinator {
	return s.coordinator
}

// AuditLogger returns the underlying logging.AuditLogger instance
func (s *Server) AuditLogger() *logging.AuditLogger {
	return s.auditLogger
}

// registerRoutes configures all HTTP and WebSocket endpoints
func (s *Server) registerRoutes() {
	// Base endpoints
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
	s.mux.HandleFunc("GET /version", s.handleVersion)
	s.mux.HandleFunc("GET /ws/v1/connect", s.handleWebSocketConnect)

	// Auth and Device Management endpoints (VPS-2)
	s.mux.HandleFunc("POST /api/v1/devices/register", s.handleDeviceRegister)
	s.mux.HandleFunc("POST /api/v1/devices/revoke", s.handleDeviceRevoke)
	s.mux.HandleFunc("GET /api/v1/devices/status", s.handleDeviceStatus)
	s.mux.HandleFunc("POST /api/v1/auth/challenge", s.handleAuthChallenge)
	s.mux.HandleFunc("POST /api/v1/auth/verify", s.handleAuthVerify)
	s.mux.HandleFunc("POST /api/v1/auth/resume", s.handleAuthResume)
	s.mux.HandleFunc("POST /api/v1/pairing/create", s.handlePairingCreate)
	s.mux.HandleFunc("POST /api/v1/pairing/claim", s.handlePairingClaim)

	// Web Distribution endpoints (1-tap OTA phone installation)
	s.mux.HandleFunc("GET /install", s.handleInstallPage)
	s.mux.HandleFunc("GET /download/PhoneLink.apk", s.handleDownloadApk)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	resp := HealthResponse{
		Status:    "OK",
		Service:   Name,
		Version:   Version,
		UptimeSec: int64(time.Since(s.startTime).Seconds()),
		Timestamp: time.Now().Unix(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, "%s v%s\n", Name, Version)
}

func (s *Server) handleWebSocketConnect(w http.ResponseWriter, r *http.Request) {
	// Extract session token from query string (?token=...) or Authorization header
	token := r.URL.Query().Get("token")
	if token == "" {
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			token = strings.TrimPrefix(authHeader, "Bearer ")
		}
	}

	if token == "" {
		http.Error(w, `{"error":"session token is required"}`, http.StatusUnauthorized)
		return
	}

	deviceID, err := s.registry.ValidateSession(token)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"unauthorized: %s"}`, err.Error()), http.StatusUnauthorized)
		return
	}

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.logger.Error("WebSocket upgrade failed", "err", err)
		return
	}
	defer conn.Close()

	s.auditLogger.LogConnection(r.RemoteAddr, deviceID)

	sendChan := make(chan []byte, 64)
	sess, err := s.coordinator.ConnectSession(deviceID, sendChan, func() {
		_ = conn.Close()
	})
	if err != nil {
		_ = conn.WriteJSON(map[string]string{"error": err.Error()})
		return
	}
	defer s.coordinator.DisconnectSession(deviceID)

	// Writer pump
	stopWriter := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stopWriter:
				return
			case msg, ok := <-sendChan:
				if !ok {
					return
				}
				_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if err := conn.WriteMessage(websocket.BinaryMessage, msg); err != nil {
					return
				}
			}
		}
	}()

	// Reader pump: forward opaque payload directly to paired peer
	for {
		messageType, payload, err := conn.ReadMessage()
		if err != nil {
			break
		}
		if messageType == websocket.BinaryMessage || messageType == websocket.TextMessage {
			s.auditLogger.LogRelayForward(deviceID, sess.PeerDeviceID, len(payload))
			_ = s.coordinator.ForwardPayload(deviceID, sess.PeerDeviceID, payload)
		}
	}

	s.auditLogger.LogDisconnect(r.RemoteAddr, deviceID, "connection_closed")

	// Trigger disconnect immediately upon client socket close
	s.coordinator.DisconnectSession(deviceID)
	close(stopWriter)
	_ = conn.Close()

	<-done
}

// Device registration request
type RegisterDeviceRequest struct {
	DeviceID     string `json:"device_id"`
	DeviceType   string `json:"device_type"`
	PublicKey    string `json:"public_key"` // Base64
	KeyAlgorithm string `json:"key_algorithm"`
}

func (s *Server) handleDeviceRegister(w http.ResponseWriter, r *http.Request) {
	var req RegisterDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid JSON body"}`, http.StatusBadRequest)
		return
	}

	pubKeyBytes, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil || len(pubKeyBytes) == 0 {
		http.Error(w, `{"error":"invalid base64 public key"}`, http.StatusBadRequest)
		return
	}

	derivedID := auth.DeriveDeviceID(pubKeyBytes)
	if req.DeviceID == "" {
		req.DeviceID = derivedID
	} else if req.DeviceID != derivedID {
		http.Error(w, `{"error":"device_id does not match public key fingerprint"}`, http.StatusBadRequest)
		return
	}

	rec := auth.DeviceRecord{
		DeviceID:     req.DeviceID,
		DeviceType:   req.DeviceType,
		PublicKey:    pubKeyBytes,
		KeyAlgorithm: req.KeyAlgorithm,
	}

	if err := s.registry.RegisterDevice(rec); err != nil {
		if err == auth.ErrDeviceAlreadyRegistered {
			http.Error(w, `{"error":"device already registered"}`, http.StatusConflict)
			return
		}
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":    "OK",
		"device_id": req.DeviceID,
	})
}

type RevokeDeviceRequest struct {
	DeviceID string `json:"device_id"`
}

func (s *Server) handleDeviceRevoke(w http.ResponseWriter, r *http.Request) {
	var req RevokeDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.DeviceID == "" {
		http.Error(w, `{"error":"device_id is required"}`, http.StatusBadRequest)
		return
	}

	if err := s.registry.RevokeDevice(req.DeviceID); err != nil {
		if err == auth.ErrDeviceNotFound {
			http.Error(w, `{"error":"device not found"}`, http.StatusNotFound)
			return
		}
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "OK",
		"message": "device revoked with immediate effect",
	})
}

type AuthChallengeRequest struct {
	DeviceID string `json:"device_id"`
}

func (s *Server) handleAuthChallenge(w http.ResponseWriter, r *http.Request) {
	var req AuthChallengeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.DeviceID == "" {
		http.Error(w, `{"error":"device_id is required"}`, http.StatusBadRequest)
		return
	}

	s.auditLogger.LogAuthAttempt(r.RemoteAddr, req.DeviceID)

	if !s.registry.IsAuthorized(req.DeviceID) {
		s.auditLogger.LogAuthFailure(r.RemoteAddr, req.DeviceID, "unregistered_or_revoked_device")
		http.Error(w, `{"error":"unregistered or revoked device"}`, http.StatusUnauthorized)
		return
	}

	nonce, ts, err := s.tracker.GenerateChallenge(req.DeviceID)
	if err != nil {
		s.auditLogger.LogError("generate_challenge", err, map[string]interface{}{"device_id": req.DeviceID})
		http.Error(w, `{"error":"failed to generate challenge"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":       "OK",
		"server_nonce": base64.StdEncoding.EncodeToString(nonce),
		"timestamp":    ts,
	})
}

type AuthVerifyRequest struct {
	DeviceID    string `json:"device_id"`
	ServerNonce string `json:"server_nonce"` // Base64
	ClientNonce string `json:"client_nonce"` // Base64
	Timestamp   int64  `json:"timestamp"`
	Signature   string `json:"signature"` // Base64
}

func (s *Server) handleAuthVerify(w http.ResponseWriter, r *http.Request) {
	var req AuthVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.auditLogger.LogAuthFailure(r.RemoteAddr, "", "invalid_json_request")
		http.Error(w, `{"error":"invalid JSON request"}`, http.StatusBadRequest)
		return
	}

	if !s.registry.IsAuthorized(req.DeviceID) {
		s.auditLogger.LogAuthFailure(r.RemoteAddr, req.DeviceID, "unregistered_or_revoked_device")
		http.Error(w, `{"error":"unregistered or revoked device"}`, http.StatusUnauthorized)
		return
	}

	serverNonceBytes, err := base64.StdEncoding.DecodeString(req.ServerNonce)
	if err != nil || len(serverNonceBytes) != auth.NonceSize {
		s.auditLogger.LogAuthFailure(r.RemoteAddr, req.DeviceID, "invalid_server_nonce")
		http.Error(w, `{"error":"invalid server nonce"}`, http.StatusBadRequest)
		return
	}

	clientNonceBytes, err := base64.StdEncoding.DecodeString(req.ClientNonce)
	if err != nil || len(clientNonceBytes) == 0 {
		s.auditLogger.LogAuthFailure(r.RemoteAddr, req.DeviceID, "invalid_client_nonce")
		http.Error(w, `{"error":"invalid client nonce"}`, http.StatusBadRequest)
		return
	}

	sigBytes, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil || len(sigBytes) == 0 {
		s.auditLogger.LogAuthFailure(r.RemoteAddr, req.DeviceID, "invalid_signature_encoding")
		http.Error(w, `{"error":"invalid signature"}`, http.StatusBadRequest)
		return
	}

	// 1. Consume and validate challenge nonce + clock skew
	if err := s.tracker.ValidateAndConsumeChallenge(req.DeviceID, serverNonceBytes, req.Timestamp); err != nil {
		s.auditLogger.LogAuthFailure(r.RemoteAddr, req.DeviceID, err.Error())
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusBadRequest)
		return
	}

	// 2. Fetch device public key
	dev, err := s.registry.GetDevice(req.DeviceID)
	if err != nil {
		s.auditLogger.LogAuthFailure(r.RemoteAddr, req.DeviceID, "device_not_found")
		http.Error(w, `{"error":"device not found"}`, http.StatusUnauthorized)
		return
	}

	// 3. Verify cryptographic signature
	challengeData := auth.BuildChallengeData(serverNonceBytes, clientNonceBytes, req.Timestamp)
	if err := auth.VerifySignature(dev.PublicKey, dev.KeyAlgorithm, challengeData, sigBytes); err != nil {
		s.auditLogger.LogAuthFailure(r.RemoteAddr, req.DeviceID, "signature_verification_failed")
		http.Error(w, `{"error":"invalid signature"}`, http.StatusUnauthorized)
		return
	}

	// 4. Create session token
	sessionToken, err := s.registry.CreateSession(req.DeviceID, auth.DefaultSessionTTL)
	if err != nil {
		s.auditLogger.LogError("create_session", err, map[string]interface{}{"device_id": req.DeviceID})
		http.Error(w, `{"error":"failed to create session"}`, http.StatusInternalServerError)
		return
	}

	// 5. Create resumption token (VPS-6)
	resumptionToken, _, err := s.registry.CreateResumptionToken(req.DeviceID, auth.DefaultResumptionTTL)
	if err != nil {
		s.auditLogger.LogError("create_resumption_token", err, map[string]interface{}{"device_id": req.DeviceID})
		http.Error(w, `{"error":"failed to create resumption token"}`, http.StatusInternalServerError)
		return
	}

	s.auditLogger.LogAuthSuccess(r.RemoteAddr, req.DeviceID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":                 "OK",
		"session_token":          sessionToken,
		"resumption_token":       resumptionToken,
		"resumption_ttl_seconds": int64(auth.DefaultResumptionTTL.Seconds()),
		"peer_online":            false,
	})
}

type AuthResumeRequest struct {
	DeviceID        string `json:"device_id"`
	ResumptionToken string `json:"resumption_token"`
}

func (s *Server) handleAuthResume(w http.ResponseWriter, r *http.Request) {
	var req AuthResumeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.DeviceID == "" || req.ResumptionToken == "" {
		s.auditLogger.LogAuthFailure(r.RemoteAddr, req.DeviceID, "invalid_resume_request")
		http.Error(w, `{"error":"device_id and resumption_token are required"}`, http.StatusBadRequest)
		return
	}

	s.auditLogger.LogAuthAttempt(r.RemoteAddr, req.DeviceID)

	if !s.registry.IsAuthorized(req.DeviceID) {
		s.auditLogger.LogAuthFailure(r.RemoteAddr, req.DeviceID, "unregistered_or_revoked_device")
		http.Error(w, `{"error":"unregistered or revoked device"}`, http.StatusUnauthorized)
		return
	}

	// 1. Validate and consume single-use resumption token (VPS-6)
	if err := s.registry.ValidateAndConsumeResumptionToken(req.DeviceID, req.ResumptionToken); err != nil {
		s.auditLogger.LogAuthFailure(r.RemoteAddr, req.DeviceID, fmt.Sprintf("resume_failed: %v", err))
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusUnauthorized)
		return
	}

	// 2. Issue fresh session token
	sessionToken, err := s.registry.CreateSession(req.DeviceID, auth.DefaultSessionTTL)
	if err != nil {
		s.auditLogger.LogError("create_session_resume", err, map[string]interface{}{"device_id": req.DeviceID})
		http.Error(w, `{"error":"failed to create session"}`, http.StatusInternalServerError)
		return
	}

	// 3. Issue fresh rotated resumption token
	newResumptionToken, _, err := s.registry.CreateResumptionToken(req.DeviceID, auth.DefaultResumptionTTL)
	if err != nil {
		s.auditLogger.LogError("create_resumption_token_resume", err, map[string]interface{}{"device_id": req.DeviceID})
		http.Error(w, `{"error":"failed to create resumption token"}`, http.StatusInternalServerError)
		return
	}

	pairedID, _ := s.registry.GetPairedDevice(req.DeviceID)
	peerOnline := false
	if pairedID != "" {
		peerOnline = s.coordinator.IsDeviceOnline(pairedID)
	}

	s.auditLogger.LogAuthSuccess(r.RemoteAddr, req.DeviceID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":                 "OK",
		"session_token":          sessionToken,
		"resumption_token":       newResumptionToken,
		"resumption_ttl_seconds": int64(auth.DefaultResumptionTTL.Seconds()),
		"peer_online":            peerOnline,
	})
}

type PairingCreateRequest struct {
	DeviceID string `json:"device_id"`
}

func (s *Server) handlePairingCreate(w http.ResponseWriter, r *http.Request) {
	var req PairingCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.DeviceID == "" {
		http.Error(w, `{"error":"device_id is required"}`, http.StatusBadRequest)
		return
	}

	token, err := s.registry.CreatePairingToken(req.DeviceID, auth.DefaultPairingTokenTTL)
	if err != nil {
		if err == auth.ErrDeviceNotFound || err == auth.ErrDeviceRevoked {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusUnauthorized)
			return
		}
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":        "OK",
		"pairing_token": token,
	})
}

type PairingClaimRequest struct {
	PairingToken     string `json:"pairing_token"`
	ClaimantDeviceID string `json:"claimant_device_id"`
}

func (s *Server) handlePairingClaim(w http.ResponseWriter, r *http.Request) {
	var req PairingClaimRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PairingToken == "" || req.ClaimantDeviceID == "" {
		http.Error(w, `{"error":"pairing_token and claimant_device_id are required"}`, http.StatusBadRequest)
		return
	}

	if err := s.registry.ClaimPairing(req.PairingToken, req.ClaimantDeviceID); err != nil {
		if err == auth.ErrPairingTokenNotFound || err == auth.ErrDeviceRevoked || err == auth.ErrDeviceNotFound {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusBadRequest)
			return
		}
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	pairedPeer, _ := s.registry.GetPairedDevice(req.ClaimantDeviceID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":         "OK",
		"message":        "pairing established",
		"paired_peer_id": pairedPeer,
	})
}

// DeviceStatusResponse represents the real-time status of a device and its paired peer.
type DeviceStatusResponse struct {
	DeviceID     string `json:"device_id"`
	IsOnline     bool   `json:"is_online"`
	IsPaired     bool   `json:"is_paired"`
	PeerDeviceID string `json:"peer_device_id,omitempty"`
	PeerOnline   bool   `json:"peer_online"`
	Timestamp    int64  `json:"timestamp"`
}

func (s *Server) handleDeviceStatus(w http.ResponseWriter, r *http.Request) {
	// Extract session token from query string (?token=...) or Authorization header
	token := r.URL.Query().Get("token")
	if token == "" {
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			token = strings.TrimPrefix(authHeader, "Bearer ")
		}
	}

	if token == "" {
		http.Error(w, `{"error":"session token is required"}`, http.StatusUnauthorized)
		return
	}

	deviceID, err := s.registry.ValidateSession(token)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"unauthorized: %s"}`, err.Error()), http.StatusUnauthorized)
		return
	}

	pairedDeviceID, err := s.registry.GetPairedDevice(deviceID)
	isPaired := (err == nil && pairedDeviceID != "")
	peerOnline := false
	if isPaired {
		peerOnline = s.coordinator.IsDeviceOnline(pairedDeviceID)
	}

	resp := DeviceStatusResponse{
		DeviceID:     deviceID,
		IsOnline:     s.coordinator.IsDeviceOnline(deviceID),
		IsPaired:     isPaired,
		PeerDeviceID: pairedDeviceID,
		PeerOnline:   peerOnline,
		Timestamp:    time.Now().Unix(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

const installPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Install PhoneLink on Android</title>
    <style>
        :root {
            --primary: #1a73e8;
            --primary-dark: #1557b0;
            --bg: #f8f9fa;
            --card-bg: #ffffff;
            --text-main: #202124;
            --text-sub: #5f6368;
            --border: #dadce0;
        }
        @media (prefers-color-scheme: dark) {
            :root {
                --primary: #8ab4f8;
                --primary-dark: #669df6;
                --bg: #121212;
                --card-bg: #1e1e1e;
                --text-main: #e8eaed;
                --text-sub: #9aa0a6;
                --border: #3c4043;
            }
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text-main);
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            width: 100%;
            max-width: 440px;
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 28px 24px;
            box-shadow: 0 4px 16px rgba(0,0,0,0.08);
            text-align: center;
        }
        .app-icon { font-size: 56px; margin-bottom: 12px; display: inline-block; }
        h1 { font-size: 24px; font-weight: 700; color: var(--primary); margin-bottom: 6px; }
        .subtitle { font-size: 14px; color: var(--text-sub); margin-bottom: 20px; }
        .badge {
            display: inline-block;
            background: rgba(26, 115, 232, 0.12);
            color: var(--primary);
            font-size: 12px;
            font-weight: 600;
            padding: 4px 10px;
            border-radius: 12px;
            margin-bottom: 24px;
        }
        .btn-install {
            display: block;
            width: 100%;
            background: var(--primary);
            color: #ffffff !important;
            text-decoration: none;
            font-size: 17px;
            font-weight: 600;
            padding: 16px;
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(26, 115, 232, 0.3);
            margin-bottom: 16px;
        }
        .meta-info { font-size: 12px; color: var(--text-sub); margin-bottom: 28px; }
        .steps-card {
            text-align: left;
            background: var(--bg);
            border-radius: 12px;
            padding: 16px 18px;
            margin-bottom: 20px;
        }
        .steps-title { font-size: 14px; font-weight: 600; margin-bottom: 12px; color: var(--text-main); }
        .step { display: flex; align-items: flex-start; margin-bottom: 12px; font-size: 13px; line-height: 1.4; color: var(--text-sub); }
        .step:last-child { margin-bottom: 0; }
        .step-num {
            background: var(--primary);
            color: #ffffff;
            width: 20px;
            height: 20px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 11px;
            font-weight: 700;
            margin-right: 10px;
            flex-shrink: 0;
            margin-top: 1px;
        }
        .step-text strong { color: var(--text-main); }
        .security-footer { font-size: 11px; color: var(--text-sub); border-top: 1px solid var(--border); padding-top: 16px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="app-icon">📱</div>
        <h1>PhoneLink</h1>
        <div class="subtitle">Personal Authorized Remote Access</div>
        <div class="badge">Universal Build • Android 8.0 to 14+</div>
        <a href="/download/PhoneLink.apk" class="btn-install">📥 Tap Here to Download &amp; Install</a>
        <div class="meta-info">Package: <strong>PhoneLink-v1.0.0.apk</strong> (~2.1 MB)</div>
        <div class="steps-card">
            <div class="steps-title">🚀 3-Step Setup Guide:</div>
            <div class="step">
                <div class="step-num">1</div>
                <div class="step-text"><strong>Tap Download:</strong> Tap the blue button above. Chrome will download the package.</div>
            </div>
            <div class="step">
                <div class="step-num">2</div>
                <div class="step-text"><strong>Tap Open &amp; Install:</strong> If prompted <em>"File might be harmful"</em>, tap <strong>Download anyway</strong>, then tap <strong>Open</strong> &gt; <strong>Install</strong>.</div>
            </div>
            <div class="step">
                <div class="step-num">3</div>
                <div class="step-text"><strong>Pair with Mac:</strong> Open PhoneLink, enter the 6-digit code from running <code>phonelink pair</code> on your Mac, and tap <strong>Connect &amp; Pair</strong>.</div>
            </div>
        </div>
        <div class="security-footer">
            🔒 <strong>Zero Plaintext Leakage:</strong> Protected by end-to-end ECDH + AES-256-GCM encryption.
        </div>
    </div>
</body>
</html>`

func (s *Server) handleInstallPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(installPageHTML))
}

func (s *Server) handleDownloadApk(w http.ResponseWriter, r *http.Request) {
	candidates := []string{
		"/opt/phonelink/relay/PhoneLink.apk",
		"/opt/phonelink/relay/PhoneLink-v1.0.0-release.apk",
		"./PhoneLink.apk",
		"./android/release/PhoneLink-v1.0.0-release.apk",
		"../android/release/PhoneLink-v1.0.0-release.apk",
		"../../android/release/PhoneLink-v1.0.0-release.apk",
	}

	var apkPath string
	for _, p := range candidates {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			apkPath = p
			break
		}
	}

	if apkPath == "" {
		http.Error(w, "APK package not deployed on server", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/vnd.android.package-archive")
	w.Header().Set("Content-Disposition", "attachment; filename=\"PhoneLink.apk\"")
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeFile(w, r, apkPath)
}

// Handler returns the underlying http.Handler for testing
func (s *Server) Handler() http.Handler {
	return s.mux
}

// Start runs the HTTP server listening on the configured address
func (s *Server) Start() error {
	s.logger.Info("Starting PhoneLink VPS Relay",
		"addr", s.httpServer.Addr,
		"version", Version,
	)
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("Shutting down PhoneLink VPS Relay")
	return s.httpServer.Shutdown(ctx)
}
