package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pritamlkjh/phonelink/vps/internal/auth"
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

func TestDeviceRegistrationAndAuthLifecycle(t *testing.T) {
	s := NewServer(DefaultConfig(), nil)

	// Generate client Ed25519 keypair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	deviceID := auth.DeriveDeviceID(pub)
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	// Step 1: Attempt auth challenge before registration -> must return 401
	chReqBody, _ := json.Marshal(map[string]string{"device_id": deviceID})
	chReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/challenge", bytes.NewReader(chReqBody))
	chRec := httptest.NewRecorder()
	s.Handler().ServeHTTP(chRec, chReq)
	if chRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for unregistered device, got %d", chRec.Code)
	}

	// Step 2: Register device
	regReqBody, _ := json.Marshal(map[string]string{
		"device_id":     deviceID,
		"device_type":   auth.DeviceTypeMac,
		"public_key":    pubB64,
		"key_algorithm": auth.AlgorithmEd25519,
	})
	regReq := httptest.NewRequest(http.MethodPost, "/api/v1/devices/register", bytes.NewReader(regReqBody))
	regRec := httptest.NewRecorder()
	s.Handler().ServeHTTP(regRec, regReq)
	if regRec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created for registration, got %d: %s", regRec.Code, regRec.Body.String())
	}

	// Step 3: Request challenge now that device is registered -> 200 OK
	chReq = httptest.NewRequest(http.MethodPost, "/api/v1/auth/challenge", bytes.NewReader(chReqBody))
	chRec = httptest.NewRecorder()
	s.Handler().ServeHTTP(chRec, chReq)
	if chRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for challenge, got %d", chRec.Code)
	}

	var chResp struct {
		Status      string `json:"status"`
		ServerNonce string `json:"server_nonce"`
		Timestamp   int64  `json:"timestamp"`
	}
	if err := json.NewDecoder(chRec.Body).Decode(&chResp); err != nil {
		t.Fatalf("failed to decode challenge response: %v", err)
	}

	serverNonceBytes, err := base64.StdEncoding.DecodeString(chResp.ServerNonce)
	if err != nil || len(serverNonceBytes) != 32 {
		t.Fatalf("invalid server nonce received: %v", err)
	}

	// Step 4: Sign challenge
	clientNonce := make([]byte, 32)
	_, _ = rand.Read(clientNonce)
	challengeData := auth.BuildChallengeData(serverNonceBytes, clientNonce, chResp.Timestamp)
	sig := ed25519.Sign(priv, challengeData)

	// Step 5: Verify challenge via POST /api/v1/auth/verify -> 200 OK
	verifyReqBody, _ := json.Marshal(map[string]interface{}{
		"device_id":    deviceID,
		"server_nonce": chResp.ServerNonce,
		"client_nonce": base64.StdEncoding.EncodeToString(clientNonce),
		"timestamp":    chResp.Timestamp,
		"signature":    base64.StdEncoding.EncodeToString(sig),
	})
	verifyReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/verify", bytes.NewReader(verifyReqBody))
	verifyRec := httptest.NewRecorder()
	s.Handler().ServeHTTP(verifyRec, verifyReq)

	if verifyRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for auth verify, got %d: %s", verifyRec.Code, verifyRec.Body.String())
	}

	var verifyResp struct {
		Status       string `json:"status"`
		SessionToken string `json:"session_token"`
	}
	_ = json.NewDecoder(verifyRec.Body).Decode(&verifyResp)
	if verifyResp.SessionToken == "" {
		t.Fatalf("expected non-empty session token")
	}

	// Step 6: Revoke device via POST /api/v1/devices/revoke
	revokeReqBody, _ := json.Marshal(map[string]string{"device_id": deviceID})
	revokeReq := httptest.NewRequest(http.MethodPost, "/api/v1/devices/revoke", bytes.NewReader(revokeReqBody))
	revokeRec := httptest.NewRecorder()
	s.Handler().ServeHTTP(revokeRec, revokeReq)
	if revokeRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for revoke, got %d", revokeRec.Code)
	}

	// Step 7: Subsequent challenge request must immediately fail with 401 Unauthorized
	chReq = httptest.NewRequest(http.MethodPost, "/api/v1/auth/challenge", bytes.NewReader(chReqBody))
	chRec = httptest.NewRecorder()
	s.Handler().ServeHTTP(chRec, chReq)
	if chRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized post-revocation, got %d", chRec.Code)
	}
}

func TestWebSocketUnauthorizedWithoutValidToken(t *testing.T) {
	s := NewServer(DefaultConfig(), nil)

	// 1. Missing token
	req := httptest.NewRequest(http.MethodGet, "/ws/v1/connect", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized without token, got %d", rec.Code)
	}

	// 2. Invalid/expired token
	req = httptest.NewRequest(http.MethodGet, "/ws/v1/connect?token=invalid-fake-token", nil)
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized with invalid token, got %d", rec.Code)
	}
}

func TestDeviceStatusEndpoint(t *testing.T) {
	s := NewServer(DefaultConfig(), nil)

	// Generate Mac and Android keypairs
	macPub, _, _ := ed25519.GenerateKey(rand.Reader)
	macDeviceID := auth.DeriveDeviceID(macPub)

	andPub, _, _ := ed25519.GenerateKey(rand.Reader)
	andDeviceID := auth.DeriveDeviceID(andPub)

	// Register Mac
	_ = s.Registry().RegisterDevice(auth.DeviceRecord{
		DeviceID:     macDeviceID,
		DeviceType:   auth.DeviceTypeMac,
		PublicKey:    macPub,
		KeyAlgorithm: auth.AlgorithmEd25519,
	})

	// Register Android
	_ = s.Registry().RegisterDevice(auth.DeviceRecord{
		DeviceID:     andDeviceID,
		DeviceType:   auth.DeviceTypeAndroid,
		PublicKey:    andPub,
		KeyAlgorithm: auth.AlgorithmEd25519,
	})

	macToken, _ := s.Registry().CreateSession(macDeviceID, 1*time.Hour)

	// 1. Missing token -> 401
	req := httptest.NewRequest(http.MethodGet, "/api/v1/devices/status", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized for missing token, got %d", rec.Code)
	}

	// 2. Query Mac status before pairing
	req = httptest.NewRequest(http.MethodGet, "/api/v1/devices/status?token="+macToken, nil)
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var statusResp DeviceStatusResponse
	_ = json.NewDecoder(rec.Body).Decode(&statusResp)
	if statusResp.DeviceID != macDeviceID {
		t.Errorf("expected device_id %s, got %s", macDeviceID, statusResp.DeviceID)
	}
	if statusResp.IsPaired {
		t.Errorf("expected is_paired false before pairing")
	}
	if statusResp.PeerOnline {
		t.Errorf("expected peer_online false before pairing")
	}

	// 3. Pair Mac and Android
	_ = s.Registry().PairDevices(macDeviceID, andDeviceID)

	// 4. Query Mac status when paired, but peer offline
	req = httptest.NewRequest(http.MethodGet, "/api/v1/devices/status", nil)
	req.Header.Set("Authorization", "Bearer "+macToken)
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	statusResp = DeviceStatusResponse{}
	_ = json.NewDecoder(rec.Body).Decode(&statusResp)
	if !statusResp.IsPaired {
		t.Errorf("expected is_paired true after pairing")
	}
	if statusResp.PeerDeviceID != andDeviceID {
		t.Errorf("expected peer_device_id %s, got %s", andDeviceID, statusResp.PeerDeviceID)
	}
	if statusResp.PeerOnline {
		t.Errorf("expected peer_online false before Android connects")
	}

	// 5. Connect Android session in coordinator
	andSendChan := make(chan []byte, 10)
	_, err := s.Coordinator().ConnectSession(andDeviceID, andSendChan, nil)
	if err != nil {
		t.Fatalf("failed to connect Android session: %v", err)
	}

	// Query Mac status now -> peer_online must be true
	req = httptest.NewRequest(http.MethodGet, "/api/v1/devices/status?token="+macToken, nil)
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	statusResp = DeviceStatusResponse{}
	_ = json.NewDecoder(rec.Body).Decode(&statusResp)
	if !statusResp.PeerOnline {
		t.Errorf("expected peer_online true after Android connected")
	}

	// 6. Disconnect Android session -> peer_online must become false
	s.Coordinator().DisconnectSession(andDeviceID)

	req = httptest.NewRequest(http.MethodGet, "/api/v1/devices/status?token="+macToken, nil)
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	statusResp = DeviceStatusResponse{}
	_ = json.NewDecoder(rec.Body).Decode(&statusResp)
	if statusResp.PeerOnline {
		t.Errorf("expected peer_online false after Android disconnected")
	}
}

func TestAuthResumeEndpoint(t *testing.T) {
	s := NewServer(DefaultConfig(), nil)

	// Register test device with Ed25519
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	deviceID := auth.DeriveDeviceID(pub)
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	regReqBody, _ := json.Marshal(map[string]string{
		"device_id":     deviceID,
		"device_type":   auth.DeviceTypeAndroid,
		"public_key":    pubB64,
		"key_algorithm": auth.AlgorithmEd25519,
	})
	regReq := httptest.NewRequest(http.MethodPost, "/api/v1/devices/register", bytes.NewReader(regReqBody))
	regRec := httptest.NewRecorder()
	s.Handler().ServeHTTP(regRec, regReq)
	if regRec.Code != http.StatusCreated {
		t.Fatalf("registration failed: %d", regRec.Code)
	}

	// 1. Initial Challenge & Verify flow
	reqBody, _ := json.Marshal(map[string]string{"device_id": deviceID})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/challenge", bytes.NewReader(reqBody))
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("challenge failed: %d", rec.Code)
	}

	var chalResp map[string]interface{}
	_ = json.NewDecoder(rec.Body).Decode(&chalResp)
	serverNonceB64 := chalResp["server_nonce"].(string)
	serverNonce, _ := base64.StdEncoding.DecodeString(serverNonceB64)
	ts := int64(chalResp["timestamp"].(float64))

	clientNonce := make([]byte, 32)
	rand.Read(clientNonce)
	clientNonceB64 := base64.StdEncoding.EncodeToString(clientNonce)

	sigData := auth.BuildChallengeData(serverNonce, clientNonce, ts)
	sig := ed25519.Sign(priv, sigData)
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	verifyBody, _ := json.Marshal(AuthVerifyRequest{
		DeviceID:    deviceID,
		ServerNonce: serverNonceB64,
		ClientNonce: clientNonceB64,
		Timestamp:   ts,
		Signature:   sigB64,
	})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/verify", bytes.NewReader(verifyBody))
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify failed: %d: %s", rec.Code, rec.Body.String())
	}

	var verifyResp map[string]interface{}
	_ = json.NewDecoder(rec.Body).Decode(&verifyResp)
	sessionToken := verifyResp["session_token"].(string)
	resumptionToken := verifyResp["resumption_token"].(string)

	if sessionToken == "" || resumptionToken == "" {
		t.Fatalf("expected non-empty session_token and resumption_token")
	}

	// 2. Resume session using valid resumption token (VPS-6)
	resumeReqBody, _ := json.Marshal(AuthResumeRequest{
		DeviceID:        deviceID,
		ResumptionToken: resumptionToken,
	})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/resume", bytes.NewReader(resumeReqBody))
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for resume, got %d: %s", rec.Code, rec.Body.String())
	}

	var resumeResp map[string]interface{}
	_ = json.NewDecoder(rec.Body).Decode(&resumeResp)
	newSessionToken := resumeResp["session_token"].(string)
	newResumptionToken := resumeResp["resumption_token"].(string)

	if newSessionToken == "" || newResumptionToken == "" {
		t.Fatalf("expected fresh session_token and rotated resumption_token")
	}

	// 3. Verify the new session token is valid in the registry
	validatedID, err := s.Registry().ValidateSession(newSessionToken)
	if err != nil || validatedID != deviceID {
		t.Fatalf("new session token must be valid for device, err: %v", err)
	}

	// 4. Replay attack rejection: old resumption token must fail
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/resume", bytes.NewReader(resumeReqBody))
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for replayed resumption token, got %d", rec.Code)
	}

	// 5. Device revocation: revoking device prevents resuming
	_ = s.Registry().RevokeDevice(deviceID)
	resumeReq2, _ := json.Marshal(AuthResumeRequest{
		DeviceID:        deviceID,
		ResumptionToken: newResumptionToken,
	})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/resume", bytes.NewReader(resumeReq2))
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for revoked device on resume, got %d", rec.Code)
	}
}
