package integration

import (
	"bytes"
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
	"net/http"
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

// AuditInterceptor monitors all bytes passing through the relay to verify zero plaintext leakage.
type AuditInterceptor struct {
	mu            sync.Mutex
	capturedBytes []byte
}

func (a *AuditInterceptor) Record(data []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.capturedBytes = append(a.capturedBytes, data...)
}

func (a *AuditInterceptor) AssertNoPlaintextLeak(forbiddenStrings ...string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	captured := string(a.capturedBytes)
	for _, s := range forbiddenStrings {
		if strings.Contains(captured, s) {
			return fmt.Errorf("CRITICAL SECURITY FAILURE: plaintext string %q detected in VPS relay buffers", s)
		}
	}
	return nil
}

func TestINT1FirstEndToEndEncryptedConnection(t *testing.T) {
	// 1. Initialize VPS Relay Server
	srv := server.NewServer(server.DefaultConfig(), nil)
	httpServer := httptest.NewServer(srv.Handler())
	defer httpServer.Close()

	audit := &AuditInterceptor{}

	// Convert http URL to ws URL
	wsBaseURL := "ws" + strings.TrimPrefix(httpServer.URL, "http")

	// 2. Generate Mac Client Identity (Ed25519 per ARCH-2 / MAC-2)
	macPub, macPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Mac identity: %v", err)
	}
	macDeviceID := auth.DeriveDeviceID(macPub)

	// 3. Generate Android Client Identity (ECDSA P-256 per ARCH-2 / AND-2)
	andPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Android identity: %v", err)
	}
	andPubDER, err := x509.MarshalPKIXPublicKey(&andPriv.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal Android public key: %v", err)
	}
	andDeviceID := auth.DeriveDeviceID(andPubDER)

	// 4. Register Both Devices via VPS API
	registerDevice(t, httpServer.URL, macDeviceID, "mac", base64.StdEncoding.EncodeToString(macPub), auth.AlgorithmEd25519)
	registerDevice(t, httpServer.URL, andDeviceID, "android", base64.StdEncoding.EncodeToString(andPubDER), auth.AlgorithmECDSAP256)

	// 5. Authenticate first, then Out-of-band Pairing Ceremony (Mac creates pairing token -> Android claims token)
	macSessionToken := authenticateEd25519(t, httpServer.URL, macDeviceID, macPriv)
	andSessionToken := authenticateECDSA(t, httpServer.URL, andDeviceID, andPriv, andPubDER)

	pairingToken := createPairingToken(t, httpServer.URL, macDeviceID, macSessionToken)
	claimPairing(t, httpServer.URL, pairingToken, andDeviceID)

	// Verify pairing is recognized symmetrically
	peerOfMac, err := srv.Registry().GetPairedDevice(macDeviceID)
	if err != nil || peerOfMac != andDeviceID {
		t.Fatalf("expected paired peer of Mac to be Android %s, got: %s", andDeviceID, peerOfMac)
	}
	peerOfAnd, err := srv.Registry().GetPairedDevice(andDeviceID)
	if err != nil || peerOfAnd != macDeviceID {
		t.Fatalf("expected paired peer of Android to be Mac %s, got: %s", macDeviceID, peerOfAnd)
	}

	// 6. Verify non-empty session tokens

	if macSessionToken == "" || andSessionToken == "" {
		t.Fatalf("session tokens must be non-empty")
	}

	// 7. Both Devices Establish WebSocket Connections
	macConn, _, err := websocket.DefaultDialer.Dial(fmt.Sprintf("%s/ws/v1/connect?token=%s", wsBaseURL, macSessionToken), nil)
	if err != nil {
		t.Fatalf("Mac WebSocket connect failed: %v", err)
	}
	defer macConn.Close()

	andConn, _, err := websocket.DefaultDialer.Dial(fmt.Sprintf("%s/ws/v1/connect?token=%s", wsBaseURL, andSessionToken), nil)
	if err != nil {
		t.Fatalf("Android WebSocket connect failed: %v", err)
	}
	defer andConn.Close()

	// 8. Verify Presence Notifications: Android receives status event about Mac, Mac receives status event about Android
	_ = readPresenceEvent(t, macConn) // Initial presence: Android is offline
	andEvent := readPresenceEvent(t, andConn) // Android connects, told Mac is online
	if !andEvent.IsOnline || andEvent.PeerDeviceID != macDeviceID {
		t.Fatalf("Android must be told Mac is online, got: %+v", andEvent)
	}
	macEvent2 := readPresenceEvent(t, macConn) // Mac receives notification that Android is now online
	if !macEvent2.IsOnline || macEvent2.PeerDeviceID != andDeviceID {
		t.Fatalf("Mac must be told Android is online, got: %+v", macEvent2)
	}

	// 9. Ephemeral Key Exchange over Relay (X25519 / Curve25519)
	macCurve := ecdh.X25519()
	macEphPriv, _ := macCurve.GenerateKey(rand.Reader)
	macEphPub := macEphPriv.PublicKey().Bytes()

	andCurve := ecdh.X25519()
	andEphPriv, _ := andCurve.GenerateKey(rand.Reader)
	andEphPub := andEphPriv.PublicKey().Bytes()

	// Mac sends ephemeral public key over relay
	if err := macConn.WriteMessage(websocket.BinaryMessage, macEphPub); err != nil {
		t.Fatalf("Mac failed to send ephemeral key: %v", err)
	}

	// Android receives Mac ephemeral public key
	_, receivedMacEphPub, err := andConn.ReadMessage()
	if err != nil || !bytes.Equal(receivedMacEphPub, macEphPub) {
		t.Fatalf("Android failed to receive Mac ephemeral key: %v", err)
	}
	audit.Record(receivedMacEphPub)

	// Android sends ephemeral public key over relay
	if err := andConn.WriteMessage(websocket.BinaryMessage, andEphPub); err != nil {
		t.Fatalf("Android failed to send ephemeral key: %v", err)
	}

	// Mac receives Android ephemeral public key
	_, receivedAndEphPub, err := macConn.ReadMessage()
	if err != nil || !bytes.Equal(receivedAndEphPub, andEphPub) {
		t.Fatalf("Mac failed to receive Android ephemeral key: %v", err)
	}
	audit.Record(receivedAndEphPub)

	// 10. Both Compute Shared Secret and Derive Directional Keys (HKDF-SHA256)
	parsedAndEphPub, _ := macCurve.NewPublicKey(receivedAndEphPub)
	macSS, _ := macEphPriv.ECDH(parsedAndEphPub)

	parsedMacEphPub, _ := andCurve.NewPublicKey(receivedMacEphPub)
	andSS, _ := andEphPriv.ECDH(parsedMacEphPub)

	if !bytes.Equal(macSS, andSS) {
		t.Fatalf("Diffie-Hellman shared secrets do not match!")
	}

	salt := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	macKM2A, macKA2M := deriveDirectionalKeys(macSS, salt)
	andKM2A, andKA2M := deriveDirectionalKeys(andSS, salt)

	if !bytes.Equal(macKM2A, andKM2A) {
		t.Fatalf("K_M2A mismatch between endpoints")
	}
	if !bytes.Equal(macKA2M, andKA2M) {
		t.Fatalf("K_A2M mismatch between endpoints")
	}

	// 11. End-to-End Encrypted Ping (Mac -> Android via Relay)
	pingSecretPlaintext := "PHONELINK_CONFIDENTIAL_E2E_PING_NONCE_7491823"
	pingCiphertext, err := encryptAESGCM(macKM2A, []byte(pingSecretPlaintext), []byte("seq-1"))
	if err != nil {
		t.Fatalf("failed to encrypt ping: %v", err)
	}

	// Verify pingCiphertext does NOT contain plaintext
	if bytes.Contains(pingCiphertext, []byte("PING")) {
		t.Fatalf("Ciphertext contains plaintext string PING!")
	}

	// Send ciphertext through VPS relay
	if err := macConn.WriteMessage(websocket.BinaryMessage, pingCiphertext); err != nil {
		t.Fatalf("Mac failed to send ciphertext: %v", err)
	}

	// Android receives ciphertext from relay
	_, receivedPingCiphertext, err := andConn.ReadMessage()
	if err != nil {
		t.Fatalf("Android failed to receive ciphertext: %v", err)
	}
	audit.Record(receivedPingCiphertext)

	// Android decrypts ciphertext with K_M2A
	decryptedPing, err := decryptAESGCM(andKM2A, receivedPingCiphertext, []byte("seq-1"))
	if err != nil {
		t.Fatalf("Android decryption failed: %v", err)
	}
	if string(decryptedPing) != pingSecretPlaintext {
		t.Fatalf("Decrypted ping does not match: expected %s, got %s", pingSecretPlaintext, string(decryptedPing))
	}

	// 12. End-to-End Encrypted Pong (Android -> Mac via Relay)
	pongSecretPlaintext := "PHONELINK_CONFIDENTIAL_E2E_PONG_NONCE_9381726"
	pongCiphertext, err := encryptAESGCM(andKA2M, []byte(pongSecretPlaintext), []byte("seq-2"))
	if err != nil {
		t.Fatalf("failed to encrypt pong: %v", err)
	}

	// Send ciphertext through VPS relay
	if err := andConn.WriteMessage(websocket.BinaryMessage, pongCiphertext); err != nil {
		t.Fatalf("Android failed to send reply ciphertext: %v", err)
	}

	// Mac receives ciphertext from relay
	_, receivedPongCiphertext, err := macConn.ReadMessage()
	if err != nil {
		t.Fatalf("Mac failed to receive reply ciphertext: %v", err)
	}
	audit.Record(receivedPongCiphertext)

	// Mac decrypts ciphertext with K_A2M
	decryptedPong, err := decryptAESGCM(macKA2M, receivedPongCiphertext, []byte("seq-2"))
	if err != nil {
		t.Fatalf("Mac decryption failed: %v", err)
	}
	if string(decryptedPong) != pongSecretPlaintext {
		t.Fatalf("Decrypted pong does not match: expected %s, got %s", pongSecretPlaintext, string(decryptedPong))
	}

	// 13. Plaintext Leakage Audit on VPS Relay
	// Assert that neither secret plaintext ever crossed the VPS in the clear
	if err := audit.AssertNoPlaintextLeak(
		pingSecretPlaintext,
		pongSecretPlaintext,
		"CONFIDENTIAL",
		"PING_NONCE",
		"PONG_NONCE",
	); err != nil {
		t.Fatalf("Audit failure: %v", err)
	}
}

// Helpers

func registerDevice(t *testing.T, baseURL, deviceID, devType, pubKeyB64, alg string) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{
		"device_id":     deviceID,
		"device_type":   devType,
		"public_key":    pubKeyB64,
		"key_algorithm": alg,
	})
	resp, err := http.Post(baseURL+"/api/v1/devices/register", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("failed to register device %s: %v", deviceID, err)
	}
	if resp.StatusCode != 201 && resp.StatusCode != 409 {
		t.Fatalf("failed to register device %s: status=%d", deviceID, resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func createPairingToken(t *testing.T, baseURL, deviceID, sessionToken string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"device_id": deviceID})
	req, err := http.NewRequest(http.MethodPost, baseURL+"/api/v1/pairing/create", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("failed to create pairing request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if sessionToken != "" {
		req.Header.Set("Authorization", "Bearer "+sessionToken)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to create pairing token: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("failed to create pairing token: status=%d", resp.StatusCode)
	}
	defer resp.Body.Close()
	var res map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&res)
	return res["pairing_token"]
}

func claimPairing(t *testing.T, baseURL, token, claimantID string) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{
		"pairing_token":      token,
		"claimant_device_id": claimantID,
	})
	resp, err := http.Post(baseURL+"/api/v1/pairing/claim", "application/json", bytes.NewReader(body))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("failed to claim pairing: %v", err)
	}
	_ = resp.Body.Close()
}

func authenticateEd25519(t *testing.T, baseURL, deviceID string, priv ed25519.PrivateKey) string {
	t.Helper()
	// 1. Challenge
	chBody, _ := json.Marshal(map[string]string{"device_id": deviceID})
	chResp, err := http.Post(baseURL+"/api/v1/auth/challenge", "application/json", bytes.NewReader(chBody))
	if err != nil || chResp.StatusCode != 200 {
		t.Fatalf("challenge failed for %s", deviceID)
	}
	var ch map[string]interface{}
	_ = json.NewDecoder(chResp.Body).Decode(&ch)
	_ = chResp.Body.Close()

	serverNonceBytes, _ := base64.StdEncoding.DecodeString(ch["server_nonce"].(string))
	timestamp := int64(ch["timestamp"].(float64))

	clientNonce := make([]byte, 32)
	_, _ = rand.Read(clientNonce)

	challengeData := auth.BuildChallengeData(serverNonceBytes, clientNonce, timestamp)
	sig := ed25519.Sign(priv, challengeData)

	// 2. Verify
	verBody, _ := json.Marshal(map[string]interface{}{
		"device_id":    deviceID,
		"server_nonce": ch["server_nonce"],
		"client_nonce": base64.StdEncoding.EncodeToString(clientNonce),
		"timestamp":    timestamp,
		"signature":    base64.StdEncoding.EncodeToString(sig),
	})
	verResp, err := http.Post(baseURL+"/api/v1/auth/verify", "application/json", bytes.NewReader(verBody))
	if err != nil || verResp.StatusCode != 200 {
		t.Fatalf("verify failed for %s", deviceID)
	}
	defer verResp.Body.Close()
	var ver map[string]interface{}
	_ = json.NewDecoder(verResp.Body).Decode(&ver)
	return ver["session_token"].(string)
}

func authenticateECDSA(t *testing.T, baseURL, deviceID string, priv *ecdsa.PrivateKey, pubDER []byte) string {
	t.Helper()
	chBody, _ := json.Marshal(map[string]string{"device_id": deviceID})
	chResp, err := http.Post(baseURL+"/api/v1/auth/challenge", "application/json", bytes.NewReader(chBody))
	if err != nil || chResp.StatusCode != 200 {
		t.Fatalf("challenge failed for %s", deviceID)
	}
	var ch map[string]interface{}
	_ = json.NewDecoder(chResp.Body).Decode(&ch)
	_ = chResp.Body.Close()

	serverNonceBytes, _ := base64.StdEncoding.DecodeString(ch["server_nonce"].(string))
	timestamp := int64(ch["timestamp"].(float64))

	clientNonce := make([]byte, 32)
	_, _ = rand.Read(clientNonce)

	challengeData := auth.BuildChallengeData(serverNonceBytes, clientNonce, timestamp)
	hash := sha256.Sum256(challengeData)
	sig, _ := ecdsa.SignASN1(rand.Reader, priv, hash[:])

	verBody, _ := json.Marshal(map[string]interface{}{
		"device_id":    deviceID,
		"server_nonce": ch["server_nonce"],
		"client_nonce": base64.StdEncoding.EncodeToString(clientNonce),
		"timestamp":    timestamp,
		"signature":    base64.StdEncoding.EncodeToString(sig),
	})
	verResp, err := http.Post(baseURL+"/api/v1/auth/verify", "application/json", bytes.NewReader(verBody))
	if err != nil || verResp.StatusCode != 200 {
		t.Fatalf("verify failed for %s", deviceID)
	}
	defer verResp.Body.Close()
	var ver map[string]interface{}
	_ = json.NewDecoder(verResp.Body).Decode(&ver)
	return ver["session_token"].(string)
}

type presenceMsg struct {
	Type         string `json:"type"`
	PeerDeviceID string `json:"peer_device_id"`
	IsOnline     bool   `json:"is_online"`
}

func readPresenceEvent(t *testing.T, conn *websocket.Conn) presenceMsg {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, msg, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("failed to read presence event: %v", err)
	}
	var event presenceMsg
	_ = json.Unmarshal(msg, &event)
	return event
}

func deriveDirectionalKeys(sharedSecret, salt []byte) ([]byte, []byte) {
	kM2A := make([]byte, 32)
	hM2A := hkdf.New(sha256.New, sharedSecret, salt, []byte("PhoneLink-M2A-v1"))
	_, _ = io.ReadFull(hM2A, kM2A)

	kA2M := make([]byte, 32)
	hA2M := hkdf.New(sha256.New, sharedSecret, salt, []byte("PhoneLink-A2M-v1"))
	_, _ = io.ReadFull(hA2M, kA2M)

	return kM2A, kA2M
}

func encryptAESGCM(key, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	c, err := cipher.NewGCMWithNonceSize(block, 12)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	_, _ = rand.Read(nonce)

	ciphertext := c.Seal(nil, nonce, plaintext, aad)
	out := make([]byte, len(nonce)+len(ciphertext))
	copy(out, nonce)
	copy(out[len(nonce):], ciphertext)
	return out, nil
}

func decryptAESGCM(key, payload, aad []byte) ([]byte, error) {
	if len(payload) < 12 {
		return nil, fmt.Errorf("payload too short")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	c, err := cipher.NewGCMWithNonceSize(block, 12)
	if err != nil {
		return nil, err
	}
	nonce := payload[:12]
	ciphertext := payload[12:]
	return c.Open(nil, nonce, ciphertext, aad)
}
