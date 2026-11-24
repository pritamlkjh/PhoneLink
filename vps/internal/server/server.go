package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/pritamlkjh/phonelink/vps/internal/auth"
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
	cfg        Config
	httpServer *http.Server
	mux        *http.ServeMux
	logger     *slog.Logger
	startTime  time.Time
	registry   *auth.Registry
	tracker    *auth.ChallengeTracker
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
	s := &Server{
		cfg:       cfg,
		mux:       mux,
		logger:    logger,
		startTime: time.Now(),
		registry:  auth.NewRegistry(),
		tracker:   auth.NewChallengeTracker(),
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

// registerRoutes configures all HTTP and WebSocket endpoints
func (s *Server) registerRoutes() {
	// Base endpoints
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
	s.mux.HandleFunc("GET /version", s.handleVersion)
	s.mux.HandleFunc("GET /ws/v1/connect", s.handleWebSocketConnect)

	// Auth and Device Management endpoints (VPS-2)
	s.mux.HandleFunc("POST /api/v1/devices/register", s.handleDeviceRegister)
	s.mux.HandleFunc("POST /api/v1/devices/revoke", s.handleDeviceRevoke)
	s.mux.HandleFunc("POST /api/v1/auth/challenge", s.handleAuthChallenge)
	s.mux.HandleFunc("POST /api/v1/auth/verify", s.handleAuthVerify)
	s.mux.HandleFunc("POST /api/v1/pairing/create", s.handlePairingCreate)
	s.mux.HandleFunc("POST /api/v1/pairing/claim", s.handlePairingClaim)
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
	// WebSocket connection handler — handshake placeholder for VPS-2/3
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"message": "PhoneLink WebSocket Relay Endpoint Ready",
		"version": Version,
	})
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

	if !s.registry.IsAuthorized(req.DeviceID) {
		http.Error(w, `{"error":"unregistered or revoked device"}`, http.StatusUnauthorized)
		return
	}

	nonce, ts, err := s.tracker.GenerateChallenge(req.DeviceID)
	if err != nil {
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
		http.Error(w, `{"error":"invalid JSON request"}`, http.StatusBadRequest)
		return
	}

	if !s.registry.IsAuthorized(req.DeviceID) {
		http.Error(w, `{"error":"unregistered or revoked device"}`, http.StatusUnauthorized)
		return
	}

	serverNonceBytes, err := base64.StdEncoding.DecodeString(req.ServerNonce)
	if err != nil || len(serverNonceBytes) != auth.NonceSize {
		http.Error(w, `{"error":"invalid server nonce"}`, http.StatusBadRequest)
		return
	}

	clientNonceBytes, err := base64.StdEncoding.DecodeString(req.ClientNonce)
	if err != nil || len(clientNonceBytes) == 0 {
		http.Error(w, `{"error":"invalid client nonce"}`, http.StatusBadRequest)
		return
	}

	sigBytes, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil || len(sigBytes) == 0 {
		http.Error(w, `{"error":"invalid signature"}`, http.StatusBadRequest)
		return
	}

	// 1. Consume and validate challenge nonce + clock skew
	if err := s.tracker.ValidateAndConsumeChallenge(req.DeviceID, serverNonceBytes, req.Timestamp); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusBadRequest)
		return
	}

	// 2. Fetch device public key
	dev, err := s.registry.GetDevice(req.DeviceID)
	if err != nil {
		http.Error(w, `{"error":"device not found"}`, http.StatusUnauthorized)
		return
	}

	// 3. Verify cryptographic signature
	challengeData := auth.BuildChallengeData(serverNonceBytes, clientNonceBytes, req.Timestamp)
	if err := auth.VerifySignature(dev.PublicKey, dev.KeyAlgorithm, challengeData, sigBytes); err != nil {
		http.Error(w, `{"error":"invalid signature"}`, http.StatusUnauthorized)
		return
	}

	// 4. Create session token
	sessionToken, err := s.registry.CreateSession(req.DeviceID, auth.DefaultSessionTTL)
	if err != nil {
		http.Error(w, `{"error":"failed to create session"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":        "OK",
		"session_token": sessionToken,
		"peer_online":   false,
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
