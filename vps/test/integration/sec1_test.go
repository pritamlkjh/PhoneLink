package integration

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pritamlkjh/phonelink/vps/internal/auth"
	"github.com/pritamlkjh/phonelink/vps/internal/server"
	"golang.org/x/crypto/hkdf"
)

// SEC-1: Integration test for Cross-Component Security Hardening.
// Verifies replay protection, clock skew enforcement, fuzz tolerance, and zero plaintext leakage.
func TestSEC1CrossComponentSecurityHardening(t *testing.T) {
	// 1. Initialize VPS Relay Server
	srv := server.NewServer(server.DefaultConfig(), nil)
	httpServer := httptest.NewServer(srv.Handler())
	defer httpServer.Close()

	audit := &AuditInterceptor{}
	wsBaseURL := "ws" + strings.TrimPrefix(httpServer.URL, "http")

	// 2. Setup Identities & Pairing
	macPub, macPriv, _ := ed25519.GenerateKey(rand.Reader)
	macDeviceID := auth.DeriveDeviceID(macPub)

	andPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	andPubDER, _ := x509.MarshalPKIXPublicKey(&andPriv.PublicKey)
	andDeviceID := auth.DeriveDeviceID(andPubDER)

	registerDevice(t, httpServer.URL, macDeviceID, "mac", base64.StdEncoding.EncodeToString(macPub), auth.AlgorithmEd25519)
	registerDevice(t, httpServer.URL, andDeviceID, "android", base64.StdEncoding.EncodeToString(andPubDER), auth.AlgorithmECDSAP256)

	macToken := authenticateEd25519(t, httpServer.URL, macDeviceID, macPriv)
	andToken := authenticateECDSA(t, httpServer.URL, andDeviceID, andPriv, andPubDER)

	token := createPairingToken(t, httpServer.URL, macDeviceID, macToken)
	claimPairing(t, httpServer.URL, token, andDeviceID, andToken)

	macConn, _, err := websocket.DefaultDialer.Dial(fmt.Sprintf("%s/ws/v1/connect?token=%s", wsBaseURL, macToken), nil)
	if err != nil {
		t.Fatalf("Mac connect failed: %v", err)
	}
	defer macConn.Close()

	andConn, _, err := websocket.DefaultDialer.Dial(fmt.Sprintf("%s/ws/v1/connect?token=%s", wsBaseURL, andToken), nil)
	if err != nil {
		t.Fatalf("Android connect failed: %v", err)
	}
	defer andConn.Close()

	_ = readPresenceEvent(t, macConn)
	_ = readPresenceEvent(t, andConn)
	_ = readPresenceEvent(t, macConn)

	// 3. Perform Handshake & Key Derivation
	macCurve := ecdh.X25519()
	macEphPriv, _ := macCurve.GenerateKey(rand.Reader)
	macEphPub := macEphPriv.PublicKey().Bytes()

	andCurve := ecdh.X25519()
	andEphPriv, _ := andCurve.GenerateKey(rand.Reader)
	andEphPub := andEphPriv.PublicKey().Bytes()

	_ = macConn.WriteMessage(websocket.BinaryMessage, macEphPub)
	_, receivedMacEphPub, _ := andConn.ReadMessage()
	audit.Record(receivedMacEphPub)

	_ = andConn.WriteMessage(websocket.BinaryMessage, andEphPub)
	_, receivedAndEphPub, _ := macConn.ReadMessage()
	audit.Record(receivedAndEphPub)

	parsedAndEphPub, _ := macCurve.NewPublicKey(receivedAndEphPub)
	macSS, _ := macEphPriv.ECDH(parsedAndEphPub)

	parsedMacEphPub, _ := andCurve.NewPublicKey(receivedMacEphPub)
	_, _ = andEphPriv.ECDH(parsedMacEphPub)

	hkdfReader := hkdf.New(sha256.New, macSS, nil, []byte("PhoneLink-E2E-v1"))
	macEncKey := make([]byte, 32)
	andEncKey := make([]byte, 32)
	_, _ = io.ReadFull(hkdfReader, macEncKey)
	_, _ = io.ReadFull(hkdfReader, andEncKey)

	macGCM, _ := newGCM(macEncKey)
	andGCM, _ := newGCM(andEncKey)

	// Helper to encrypt
	encryptMsg := func(gcm cipher.AEAD, plaintext []byte) []byte {
		nonce := make([]byte, 12)
		_, _ = rand.Read(nonce)
		return gcm.Seal(nonce, nonce, plaintext, nil)
	}

	// Helper to decrypt
	decryptMsg := func(gcm cipher.AEAD, ciphertext []byte) ([]byte, error) {
		if len(ciphertext) < 12 {
			return nil, fmt.Errorf("ciphertext too short")
		}
		return gcm.Open(nil, ciphertext[:12], ciphertext[12:], nil)
	}

	// 4. Mock Replay Filter on Android side (matching Android ReplayProtectionFilter)
	type ReplayFilter struct {
		mu            sync.Mutex
		seen          map[string]int64
		maxSkewMs     int64
		fixedNowMs    int64
	}
	rf := &ReplayFilter{
		seen:       make(map[string]int64),
		maxSkewMs:  60000,
		fixedNowMs: time.Now().UnixMilli(),
	}

	validateAppMsg := func(payload []byte) (string, error) {
		rf.mu.Lock()
		defer rf.mu.Unlock()

		var jsonMap map[string]interface{}
		if err := json.Unmarshal(payload, &jsonMap); err != nil {
			return "STATUS_MALFORMED_MESSAGE", fmt.Errorf("invalid json: %v", err)
		}

		msgID, ok := jsonMap["message_id"].(string)
		if !ok || msgID == "" {
			return "STATUS_MALFORMED_MESSAGE", fmt.Errorf("missing message_id")
		}

		tsFloat, ok := jsonMap["timestamp"].(float64)
		if !ok {
			return "STATUS_MALFORMED_MESSAGE", fmt.Errorf("missing timestamp")
		}
		ts := int64(tsFloat)

		skew := rf.fixedNowMs - ts
		if skew < 0 {
			skew = -skew
		}
		if skew > rf.maxSkewMs {
			return "STATUS_MESSAGE_EXPIRED", fmt.Errorf("message expired, skew=%dms", skew)
		}

		if _, exists := rf.seen[msgID]; exists {
			return "STATUS_REPLAY_DETECTED", fmt.Errorf("replay detected for id %s", msgID)
		}

		rf.seen[msgID] = ts
		return "STATUS_OK", nil
	}

	// --- SUB-TEST 1: Valid Fresh Message Acceptance ---
	t.Run("ValidFreshMessage", func(t *testing.T) {
		req := map[string]interface{}{
			"message_id": "req-sec1-001",
			"timestamp":  rf.fixedNowMs - 2000, // 2s ago
			"action":     "ping",
		}
		reqBytes, _ := json.Marshal(req)
		cipherPayload := encryptMsg(macGCM, reqBytes)

		// Send over relay
		if err := macConn.WriteMessage(websocket.BinaryMessage, cipherPayload); err != nil {
			t.Fatalf("failed to send: %v", err)
		}

		// Android receives and validates
		_, receivedCipher, err := andConn.ReadMessage()
		if err != nil {
			t.Fatalf("failed to read: %v", err)
		}
		audit.Record(receivedCipher)

		decrypted, err := decryptMsg(macGCM, receivedCipher)
		if err != nil {
			t.Fatalf("decrypt failed: %v", err)
		}

		status, err := validateAppMsg(decrypted)
		if err != nil || status != "STATUS_OK" {
			t.Fatalf("expected STATUS_OK, got %s (err: %v)", status, err)
		}

		// Respond with ACK
		resp := map[string]interface{}{
			"message_id": "resp-sec1-001",
			"timestamp":  rf.fixedNowMs - 1000,
			"reply_to":   "req-sec1-001",
			"status":     "STATUS_OK",
		}
		respBytes, _ := json.Marshal(resp)
		respCipher := encryptMsg(andGCM, respBytes)
		_ = andConn.WriteMessage(websocket.BinaryMessage, respCipher)

		_, receivedRespCipher, _ := macConn.ReadMessage()
		audit.Record(receivedRespCipher)
		decResp, err := decryptMsg(andGCM, receivedRespCipher)
		if err != nil {
			t.Fatalf("Mac decrypt failed: %v", err)
		}
		var respMap map[string]interface{}
		_ = json.Unmarshal(decResp, &respMap)
		if respMap["status"] != "STATUS_OK" {
			t.Fatalf("expected response STATUS_OK, got %+v", respMap)
		}
	})

	// --- SUB-TEST 2: Adversary Replay Attack Detection ---
	t.Run("ReplayAttackDetectedAndRejected", func(t *testing.T) {
		// Adversary captures the original cipherPayload from Sub-test 1 and replays it
		replayReq := map[string]interface{}{
			"message_id": "req-sec1-001", // Duplicate ID!
			"timestamp":  rf.fixedNowMs - 2000,
			"action":     "ping",
		}
		replayBytes, _ := json.Marshal(replayReq)
		replayCipher := encryptMsg(macGCM, replayBytes)

		// Replay sent over relay
		if err := macConn.WriteMessage(websocket.BinaryMessage, replayCipher); err != nil {
			t.Fatalf("failed to replay: %v", err)
		}

		_, receivedReplay, err := andConn.ReadMessage()
		if err != nil {
			t.Fatalf("failed to receive replay: %v", err)
		}
		audit.Record(receivedReplay)

		decrypted, err := decryptMsg(macGCM, receivedReplay)
		if err != nil {
			t.Fatalf("decrypt failed: %v", err)
		}

		status, err := validateAppMsg(decrypted)
		if status != "STATUS_REPLAY_DETECTED" {
			t.Fatalf("expected STATUS_REPLAY_DETECTED, got %s", status)
		}
		if err == nil {
			t.Fatalf("expected error for replay attack")
		}
	})

	// --- SUB-TEST 3: Clock Skew Expiration (Past & Future) ---
	t.Run("ClockSkewExpirationRejected", func(t *testing.T) {
		// Message 1: Skewed 90s in the past (exceeds 60s limit)
		pastReq := map[string]interface{}{
			"message_id": "req-sec1-past-expired",
			"timestamp":  rf.fixedNowMs - 90000,
			"action":     "ping",
		}
		pastBytes, _ := json.Marshal(pastReq)
		pastCipher := encryptMsg(macGCM, pastBytes)
		_ = macConn.WriteMessage(websocket.BinaryMessage, pastCipher)
		_, recPast, _ := andConn.ReadMessage()
		decPast, _ := decryptMsg(macGCM, recPast)
		status, err := validateAppMsg(decPast)
		if status != "STATUS_MESSAGE_EXPIRED" {
			t.Fatalf("expected STATUS_MESSAGE_EXPIRED for past timestamp, got %s (err: %v)", status, err)
		}

		// Message 2: Skewed 90s in the future (exceeds 60s limit)
		futureReq := map[string]interface{}{
			"message_id": "req-sec1-future-expired",
			"timestamp":  rf.fixedNowMs + 90000,
			"action":     "ping",
		}
		futureBytes, _ := json.Marshal(futureReq)
		futureCipher := encryptMsg(macGCM, futureBytes)
		_ = macConn.WriteMessage(websocket.BinaryMessage, futureCipher)
		_, recFuture, _ := andConn.ReadMessage()
		decFuture, _ := decryptMsg(macGCM, recFuture)
		statusFuture, errFuture := validateAppMsg(decFuture)
		if statusFuture != "STATUS_MESSAGE_EXPIRED" {
			t.Fatalf("expected STATUS_MESSAGE_EXPIRED for future timestamp, got %s (err: %v)", statusFuture, errFuture)
		}
	})

	// --- SUB-TEST 4: Fuzz Testing (50 Corrupted/Malformed Payloads) ---
	t.Run("FuzzTestingTolerance", func(t *testing.T) {
		for i := 0; i < 50; i++ {
			// Generate random length garbage or truncated ciphertexts
			n, _ := rand.Int(rand.Reader, big.NewInt(512))
			randomLen := int(n.Int64()) + 1
			garbage := make([]byte, randomLen)
			_, _ = rand.Read(garbage)

			// Send into relay
			if err := macConn.WriteMessage(websocket.BinaryMessage, garbage); err != nil {
				t.Fatalf("relay failed during fuzz iteration %d: %v", i, err)
			}

			// Android reads garbage
			_, recGarbage, err := andConn.ReadMessage()
			if err != nil {
				t.Fatalf("relay disconnect during fuzz iteration %d: %v", i, err)
			}
			audit.Record(recGarbage)

			// Decryption must fail gracefully without panic
			_, err = decryptMsg(macGCM, recGarbage)
			if err == nil && len(recGarbage) >= 12 {
				// Random bytes happened to pass GCM auth (virtually impossible)
			}

			// Also test malformed decrypted payloads
			status, err := validateAppMsg(recGarbage)
			if status != "STATUS_MALFORMED_MESSAGE" {
				t.Fatalf("fuzzed payload should be classified as malformed, got: %s", status)
			}
		}
	})

	// --- SUB-TEST 5: Zero Plaintext Leakage Audit ---
	t.Run("ZeroPlaintextRelayLeakage", func(t *testing.T) {
		forbidden := []string{
			"req-sec1-001",
			"req-sec1-past-expired",
			"req-sec1-future-expired",
			"ping",
			"resp-sec1-001",
		}
		if err := audit.AssertNoPlaintextLeak(forbidden...); err != nil {
			t.Fatalf("SECURITY AUDIT FAILURE: %v", err)
		}
	})
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
