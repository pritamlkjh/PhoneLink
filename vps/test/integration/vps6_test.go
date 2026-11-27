package integration

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pritamlkjh/phonelink/vps/internal/auth"
	"github.com/pritamlkjh/phonelink/vps/internal/coordinator"
	"github.com/pritamlkjh/phonelink/vps/internal/server"
)

// VPS-6: VPS Session Resumption & Reconnection Handling
// Acceptance Criteria:
// 1. Session resumes after brief disconnect without full re-auth, within a defined token-validity window.
// 2. Resumption token accepted only within validity window (expired tokens rejected).
// 3. Resumption token is single-use (replay attacks rejected).
// 4. Revoked devices cannot resume sessions.
func TestVPS6SessionResumptionAndReconnection(t *testing.T) {
	srv := server.NewServer(server.DefaultConfig(), nil)
	httpServer := httptest.NewServer(srv.Handler())
	defer httpServer.Close()

	wsBaseURL := "ws" + strings.TrimPrefix(httpServer.URL, "http")

	// 1. Setup Identities & Pairing
	macPub, macPriv, _ := ed25519.GenerateKey(rand.Reader)
	macDeviceID := auth.DeriveDeviceID(macPub)

	andPub, andPriv, _ := ed25519.GenerateKey(rand.Reader)
	andDeviceID := auth.DeriveDeviceID(andPub)

	registerDevice(t, httpServer.URL, macDeviceID, "mac", base64.StdEncoding.EncodeToString(macPub), auth.AlgorithmEd25519)
	registerDevice(t, httpServer.URL, andDeviceID, "android", base64.StdEncoding.EncodeToString(andPub), auth.AlgorithmEd25519)

	macInitToken := authenticateWithResumption(t, httpServer.URL, macDeviceID, macPriv).SessionToken
	andInitToken := authenticateWithResumption(t, httpServer.URL, andDeviceID, andPriv).SessionToken
	pairingToken := createPairingToken(t, httpServer.URL, macDeviceID, macInitToken)
	claimPairing(t, httpServer.URL, pairingToken, andDeviceID, andInitToken)

	// --- SUB-TEST 1: Fast Session Resumption Without Full Re-Auth Handshake ---
	t.Run("FastSessionResumptionAfterDisconnect", func(t *testing.T) {
		// Authenticate Mac and Android via full challenge-response
		macAuthResp := authenticateWithResumption(t, httpServer.URL, macDeviceID, macPriv)
		andAuthResp := authenticateWithResumption(t, httpServer.URL, andDeviceID, andPriv)

		// Connect Mac WebSocket
		macWS, _, err := websocket.DefaultDialer.Dial(fmt.Sprintf("%s/ws/v1/connect?token=%s", wsBaseURL, macAuthResp.SessionToken), nil)
		if err != nil {
			t.Fatalf("Mac WebSocket connect failed: %v", err)
		}
		defer macWS.Close()

		// Read Mac's initial presence notification (peer offline)
		var macPresence coordinator.PeerStatusEvent
		_ = macWS.ReadJSON(&macPresence)

		// Connect Android WebSocket
		andWS, _, err := websocket.DefaultDialer.Dial(fmt.Sprintf("%s/ws/v1/connect?token=%s", wsBaseURL, andAuthResp.SessionToken), nil)
		if err != nil {
			t.Fatalf("Android WebSocket connect failed: %v", err)
		}

		// Mac should receive peer online event
		_ = macWS.ReadJSON(&macPresence)
		if !macPresence.IsOnline || macPresence.PeerDeviceID != andDeviceID {
			t.Fatalf("expected Android online event on Mac, got: %+v", macPresence)
		}

		// Simulate brief Android disconnect (e.g. Wi-Fi / Cellular handoff)
		_ = andWS.Close()

		// Mac receives peer offline event
		_ = macWS.ReadJSON(&macPresence)
		if macPresence.IsOnline {
			t.Fatalf("expected Android offline event on Mac, got: %+v", macPresence)
		}

		// Android resumes session using resumption token WITHOUT full ECDSA challenge-response!
		resumeReqBody, _ := json.Marshal(map[string]string{
			"device_id":        andDeviceID,
			"resumption_token": andAuthResp.ResumptionToken,
		})
		resp, err := http.Post(httpServer.URL+"/api/v1/auth/resume", "application/json", bytes.NewReader(resumeReqBody))
		if err != nil {
			t.Fatalf("resume request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK for resume, got %d", resp.StatusCode)
		}

		var resumeResp struct {
			Status          string `json:"status"`
			SessionToken    string `json:"session_token"`
			ResumptionToken string `json:"resumption_token"`
			PeerOnline      bool   `json:"peer_online"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&resumeResp)

		if resumeResp.SessionToken == "" || resumeResp.ResumptionToken == "" {
			t.Fatalf("resume response missing fresh tokens: %+v", resumeResp)
		}
		if !resumeResp.PeerOnline {
			t.Fatalf("expected peer_online=true on resume since Mac is connected")
		}

		// Reconnect Android WebSocket with resumed session token
		andWSResumed, _, err := websocket.DefaultDialer.Dial(fmt.Sprintf("%s/ws/v1/connect?token=%s", wsBaseURL, resumeResp.SessionToken), nil)
		if err != nil {
			t.Fatalf("resumed Android WebSocket connect failed: %v", err)
		}
		defer andWSResumed.Close()

		// Mac immediately observes Android restored online!
		_ = macWS.ReadJSON(&macPresence)
		if !macPresence.IsOnline || macPresence.PeerDeviceID != andDeviceID {
			t.Fatalf("expected restored Android online presence on Mac, got: %+v", macPresence)
		}

		// Verify bidirectional relay works smoothly across resumed session
		testPayload := []byte("ciphertext-resumed-payload-vps6")
		if err := andWSResumed.WriteMessage(websocket.BinaryMessage, testPayload); err != nil {
			t.Fatalf("write resumed message failed: %v", err)
		}

		_, receivedPayload, err := macWS.ReadMessage()
		if err != nil || !bytes.Equal(receivedPayload, testPayload) {
			t.Fatalf("Mac failed to receive payload across resumed session: %v", err)
		}
	})

	// --- SUB-TEST 2: Resumption Token Replay Rejection ---
	t.Run("ResumptionTokenReplayRejection", func(t *testing.T) {
		andAuthResp := authenticateWithResumption(t, httpServer.URL, andDeviceID, andPriv)

		resumeReqBody, _ := json.Marshal(map[string]string{
			"device_id":        andDeviceID,
			"resumption_token": andAuthResp.ResumptionToken,
		})

		// First resume attempt succeeds
		resp1, err := http.Post(httpServer.URL+"/api/v1/auth/resume", "application/json", bytes.NewReader(resumeReqBody))
		if err != nil || resp1.StatusCode != http.StatusOK {
			t.Fatalf("first resume attempt expected 200 OK, got: %v (code %d)", err, resp1.StatusCode)
		}
		resp1.Body.Close()

		// Replay attack: second resume attempt with same token MUST be rejected (401 Unauthorized)
		resp2, err := http.Post(httpServer.URL+"/api/v1/auth/resume", "application/json", bytes.NewReader(resumeReqBody))
		if err != nil {
			t.Fatalf("replay request failed: %v", err)
		}
		defer resp2.Body.Close()

		if resp2.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized on resumption token replay, got: %d", resp2.StatusCode)
		}
	})

	// --- SUB-TEST 3: Bounded Validity Window Expiration ---
	t.Run("ResumptionTokenExpirationEnforcement", func(t *testing.T) {
		// Manually inject an already-expired token directly into registry
		expiredToken, _, err := srv.Registry().CreateResumptionToken(andDeviceID, 1*time.Minute)
		if err != nil {
			t.Fatalf("failed to create token for expiration test: %v", err)
		}
		srv.Registry().ExpireResumptionTokenForTest(expiredToken)

		resumeReqBody, _ := json.Marshal(map[string]string{
			"device_id":        andDeviceID,
			"resumption_token": expiredToken,
		})
		resp, err := http.Post(httpServer.URL+"/api/v1/auth/resume", "application/json", bytes.NewReader(resumeReqBody))
		if err != nil {
			t.Fatalf("expired token resume request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized on expired resumption token, got: %d", resp.StatusCode)
		}
	})

	// --- SUB-TEST 4: Revocation Invalidates Resumption Tokens ---
	t.Run("DeviceRevocationBlocksResumption", func(t *testing.T) {
		andAuthResp := authenticateWithResumption(t, httpServer.URL, andDeviceID, andPriv)

		// Revoke Android device (authenticated via Android's Bearer token)
		revokeReqBody, _ := json.Marshal(map[string]string{"device_id": andDeviceID})
		revReq, err := http.NewRequest(http.MethodPost, httpServer.URL+"/api/v1/devices/revoke", bytes.NewReader(revokeReqBody))
		if err != nil {
			t.Fatalf("failed to construct revoke request: %v", err)
		}
		revReq.Header.Set("Content-Type", "application/json")
		revReq.Header.Set("Authorization", "Bearer "+andAuthResp.SessionToken)
		revResp, err := http.DefaultClient.Do(revReq)
		if err != nil || revResp.StatusCode != http.StatusOK {
			t.Fatalf("revocation failed: %v", err)
		}
		revResp.Body.Close()

		// Attempt resume with held token -> must be rejected
		resumeReqBody, _ := json.Marshal(map[string]string{
			"device_id":        andDeviceID,
			"resumption_token": andAuthResp.ResumptionToken,
		})
		resp, err := http.Post(httpServer.URL+"/api/v1/auth/resume", "application/json", bytes.NewReader(resumeReqBody))
		if err != nil {
			t.Fatalf("revoked device resume request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized on revoked device resume, got: %d", resp.StatusCode)
		}
	})
}

type AuthResponseWithResumption struct {
	SessionToken    string
	ResumptionToken string
}

func authenticateWithResumption(t *testing.T, baseURL, deviceID string, priv ed25519.PrivateKey) AuthResponseWithResumption {
	t.Helper()

	// 1. Request Challenge
	chReqBody, _ := json.Marshal(map[string]string{"device_id": deviceID})
	chResp, err := http.Post(baseURL+"/api/v1/auth/challenge", "application/json", bytes.NewReader(chReqBody))
	if err != nil || chResp.StatusCode != http.StatusOK {
		t.Fatalf("challenge failed: %v", err)
	}
	defer chResp.Body.Close()

	var chData struct {
		ServerNonce string `json:"server_nonce"`
		Timestamp   int64  `json:"timestamp"`
	}
	_ = json.NewDecoder(chResp.Body).Decode(&chData)

	serverNonceBytes, _ := base64.StdEncoding.DecodeString(chData.ServerNonce)
	clientNonce := make([]byte, 32)
	_, _ = rand.Read(clientNonce)

	challengeData := auth.BuildChallengeData(serverNonceBytes, clientNonce, chData.Timestamp)
	sig := ed25519.Sign(priv, challengeData)

	// 2. Verify
	verifyReqBody, _ := json.Marshal(map[string]interface{}{
		"device_id":    deviceID,
		"server_nonce": chData.ServerNonce,
		"client_nonce": base64.StdEncoding.EncodeToString(clientNonce),
		"timestamp":    chData.Timestamp,
		"signature":    base64.StdEncoding.EncodeToString(sig),
	})
	vResp, err := http.Post(baseURL+"/api/v1/auth/verify", "application/json", bytes.NewReader(verifyReqBody))
	if err != nil || vResp.StatusCode != http.StatusOK {
		t.Fatalf("verify failed: %v", err)
	}
	defer vResp.Body.Close()

	var vData struct {
		SessionToken    string `json:"session_token"`
		ResumptionToken string `json:"resumption_token"`
	}
	_ = json.NewDecoder(vResp.Body).Decode(&vData)

	return AuthResponseWithResumption{
		SessionToken:    vData.SessionToken,
		ResumptionToken: vData.ResumptionToken,
	}
}
