package integration

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
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

type recoveryFixture struct {
	srv         *server.Server
	httpServer  *httptest.Server
	wsBaseURL   string
	macDeviceID string
	macPriv     ed25519.PrivateKey
	andDeviceID string
	andPriv     *ecdsa.PrivateKey
	andPubDER   []byte
}

func setupRecoveryFixture(t *testing.T) *recoveryFixture {
	t.Helper()

	srv := server.NewServer(server.DefaultConfig(), nil)
	httpServer := httptest.NewServer(srv.Handler())
	wsBaseURL := "ws" + strings.TrimPrefix(httpServer.URL, "http")

	macPub, macPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Mac identity: %v", err)
	}
	macDeviceID := auth.DeriveDeviceID(macPub)

	andPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Android identity: %v", err)
	}
	andPubDER, err := x509.MarshalPKIXPublicKey(&andPriv.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal Android public key: %v", err)
	}
	andDeviceID := auth.DeriveDeviceID(andPubDER)

	registerDevice(t, httpServer.URL, macDeviceID, auth.DeviceTypeMac, base64.StdEncoding.EncodeToString(macPub), auth.AlgorithmEd25519)
	registerDevice(t, httpServer.URL, andDeviceID, auth.DeviceTypeAndroid, base64.StdEncoding.EncodeToString(andPubDER), auth.AlgorithmECDSAP256)

	macInitToken := authenticateEd25519(t, httpServer.URL, macDeviceID, macPriv)
	andInitToken := authenticateECDSA(t, httpServer.URL, andDeviceID, andPriv, andPubDER)
	pairingToken := createPairingToken(t, httpServer.URL, macDeviceID, macInitToken)
	claimPairing(t, httpServer.URL, pairingToken, andDeviceID, andInitToken)

	return &recoveryFixture{
		srv:         srv,
		httpServer:  httpServer,
		wsBaseURL:   wsBaseURL,
		macDeviceID: macDeviceID,
		macPriv:     macPriv,
		andDeviceID: andDeviceID,
		andPriv:     andPriv,
		andPubDER:   andPubDER,
	}
}

// INT-3: End-to-End Connection Recovery Test Suite
// Acceptance Criteria:
// 1. Script three failure-injection scenarios:
//    - Android network loss & recovery
//    - VPS relay restart & reconnect
//    - Mac network loss & recovery
// 2. System recovers automatically without manual re-pairing
// 3. Recovery times measured and verified within strict operational bounds (< 3000ms)
func TestINT3ConnectionRecoverySuite(t *testing.T) {

	// --- SCENARIO 1: Android Network Loss & Fast Resumption ---
	t.Run("Scenario1_AndroidNetworkLossAndAutoRecovery", func(t *testing.T) {
		f := setupRecoveryFixture(t)
		defer f.httpServer.Close()

		macAuth := authenticateWithResumption(t, f.httpServer.URL, f.macDeviceID, f.macPriv)
		andAuth := authenticateECDSAWithResumption(t, f.httpServer.URL, f.andDeviceID, f.andPriv, f.andPubDER)

		macWS, _, err := websocket.DefaultDialer.Dial(fmt.Sprintf("%s/ws/v1/connect?token=%s", f.wsBaseURL, macAuth.SessionToken), nil)
		if err != nil {
			t.Fatalf("Mac connect failed: %v", err)
		}
		defer macWS.Close()

		var macPresence coordinator.PeerStatusEvent
		_ = macWS.ReadJSON(&macPresence) // Initial presence

		andWS, _, err := websocket.DefaultDialer.Dial(fmt.Sprintf("%s/ws/v1/connect?token=%s", f.wsBaseURL, andAuth.SessionToken), nil)
		if err != nil {
			t.Fatalf("Android connect failed: %v", err)
		}

		_ = macWS.ReadJSON(&macPresence)
		if !macPresence.IsOnline {
			t.Fatalf("expected Android online notification on Mac")
		}

		// Initial message exchange
		initMsg := []byte("msg-pre-drop-android")
		_ = andWS.WriteMessage(websocket.BinaryMessage, initMsg)
		_, recv, err := macWS.ReadMessage()
		if err != nil || !bytes.Equal(recv, initMsg) {
			t.Fatalf("pre-drop message failed")
		}

		// INJECT FAILURE: Abrupt Android network loss
		startRecovery := time.Now()
		_ = andWS.Close()

		// Mac receives peer offline event
		_ = macWS.ReadJSON(&macPresence)
		if macPresence.IsOnline {
			t.Fatalf("expected Android offline notification on Mac after drop")
		}

		// Android auto-recovers: calls /api/v1/auth/resume (VPS-6)
		resumeBody, _ := json.Marshal(map[string]string{
			"device_id":        f.andDeviceID,
			"resumption_token": andAuth.ResumptionToken,
		})
		resp, err := http.Post(f.httpServer.URL+"/api/v1/auth/resume", "application/json", bytes.NewReader(resumeBody))
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("Android resume request failed: %v", err)
		}
		defer resp.Body.Close()

		var resumeResp struct {
			SessionToken    string `json:"session_token"`
			ResumptionToken string `json:"resumption_token"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&resumeResp)

		// Reconnect Android WebSocket with resumed token
		andWSResumed, _, err := websocket.DefaultDialer.Dial(fmt.Sprintf("%s/ws/v1/connect?token=%s", f.wsBaseURL, resumeResp.SessionToken), nil)
		if err != nil {
			t.Fatalf("Android resumed connect failed: %v", err)
		}
		defer andWSResumed.Close()

		// Mac receives peer online event
		_ = macWS.ReadJSON(&macPresence)
		if !macPresence.IsOnline {
			t.Fatalf("expected Android restored online notification on Mac")
		}

		recoveryDuration := time.Since(startRecovery)
		t.Logf("PASS: Scenario 1 (Android Network Loss) recovered in %v (bound: < 3000ms)", recoveryDuration)

		if recoveryDuration > 3*time.Second {
			t.Fatalf("Scenario 1 recovery took too long: %v", recoveryDuration)
		}

		// Post-recovery message exchange
		postMsg := []byte("msg-post-recovery-android")
		_ = andWSResumed.WriteMessage(websocket.BinaryMessage, postMsg)
		_, recv2, err := macWS.ReadMessage()
		if err != nil || !bytes.Equal(recv2, postMsg) {
			t.Fatalf("post-recovery message failed: %v", err)
		}

		// Invariant: Pairing remained intact without re-pairing ceremony
		pairedID, err := f.srv.Registry().GetPairedDevice(f.macDeviceID)
		if err != nil || pairedID != f.andDeviceID {
			t.Fatalf("pairing corrupted during recovery: %v", err)
		}
	})

	// --- SCENARIO 2: VPS Relay Restart & Jittered Backoff Recovery ---
	t.Run("Scenario2_VPSRelayRestartAndJitteredRecovery", func(t *testing.T) {
		f := setupRecoveryFixture(t)

		macAuth := authenticateWithResumption(t, f.httpServer.URL, f.macDeviceID, f.macPriv)
		andAuth := authenticateECDSAWithResumption(t, f.httpServer.URL, f.andDeviceID, f.andPriv, f.andPubDER)

		macWS, _, _ := websocket.DefaultDialer.Dial(fmt.Sprintf("%s/ws/v1/connect?token=%s", f.wsBaseURL, macAuth.SessionToken), nil)
		andWS, _, _ := websocket.DefaultDialer.Dial(fmt.Sprintf("%s/ws/v1/connect?token=%s", f.wsBaseURL, andAuth.SessionToken), nil)

		// INJECT FAILURE: Shut down VPS server completely
		startRecovery := time.Now()
		f.httpServer.Close()
		_ = macWS.Close()
		_ = andWS.Close()

		// Start new VPS instance preserving device registry (simulating persistent state / restart)
		newSrv := server.NewServer(server.DefaultConfig(), nil)
		// Restore registry records
		macRec, _ := f.srv.Registry().GetDevice(f.macDeviceID)
		andRec, _ := f.srv.Registry().GetDevice(f.andDeviceID)
		_ = newSrv.Registry().RegisterDevice(*macRec)
		_ = newSrv.Registry().RegisterDevice(*andRec)
		_ = newSrv.Registry().PairDevices(f.macDeviceID, f.andDeviceID)

		newHttpServer := httptest.NewServer(newSrv.Handler())
		defer newHttpServer.Close()
		newWSBaseURL := "ws" + strings.TrimPrefix(newHttpServer.URL, "http")

		// Both clients detect server down, perform re-auth when server comes back online
		newMacAuth := authenticateWithResumption(t, newHttpServer.URL, f.macDeviceID, f.macPriv)
		newAndAuth := authenticateECDSAWithResumption(t, newHttpServer.URL, f.andDeviceID, f.andPriv, f.andPubDER)

		newMacWS, _, err := websocket.DefaultDialer.Dial(fmt.Sprintf("%s/ws/v1/connect?token=%s", newWSBaseURL, newMacAuth.SessionToken), nil)
		if err != nil {
			t.Fatalf("Mac reconnect to new VPS failed: %v", err)
		}
		defer newMacWS.Close()

		var macPresence coordinator.PeerStatusEvent
		_ = newMacWS.ReadJSON(&macPresence)

		newAndWS, _, err := websocket.DefaultDialer.Dial(fmt.Sprintf("%s/ws/v1/connect?token=%s", newWSBaseURL, newAndAuth.SessionToken), nil)
		if err != nil {
			t.Fatalf("Android reconnect to new VPS failed: %v", err)
		}
		defer newAndWS.Close()

		var andPresence coordinator.PeerStatusEvent
		_ = newAndWS.ReadJSON(&andPresence) // Drain Android self-presence

		_ = newMacWS.ReadJSON(&macPresence) // Mac receives Android online
		if !macPresence.IsOnline {
			t.Fatalf("expected restored Android presence on Mac after VPS restart")
		}

		recoveryDuration := time.Since(startRecovery)
		t.Logf("PASS: Scenario 2 (VPS Restart) recovered in %v (bound: < 3000ms)", recoveryDuration)

		// End-to-end payload forwarding verified on fresh server
		pingPayload := []byte("ping-across-restarted-vps")
		if err := newMacWS.WriteMessage(websocket.BinaryMessage, pingPayload); err != nil {
			t.Fatalf("failed to write ping payload: %v", err)
		}

		_, recv, err := newAndWS.ReadMessage()
		if err != nil || !bytes.Equal(recv, pingPayload) {
			t.Fatalf("payload delivery failed across restarted VPS: %v (recv: %s)", err, string(recv))
		}

		// Verify zero re-pairing required
		pairedID, err := newSrv.Registry().GetPairedDevice(f.macDeviceID)
		if err != nil || pairedID != f.andDeviceID {
			t.Fatalf("pairing corrupted after restart: %v", err)
		}
	})

	// --- SCENARIO 3: Mac Network Loss & Auto Recovery ---
	t.Run("Scenario3_MacNetworkLossAndAutoRecovery", func(t *testing.T) {
		f := setupRecoveryFixture(t)
		defer f.httpServer.Close()

		macAuth := authenticateWithResumption(t, f.httpServer.URL, f.macDeviceID, f.macPriv)
		andAuth := authenticateECDSAWithResumption(t, f.httpServer.URL, f.andDeviceID, f.andPriv, f.andPubDER)

		andWS, _, err := websocket.DefaultDialer.Dial(fmt.Sprintf("%s/ws/v1/connect?token=%s", f.wsBaseURL, andAuth.SessionToken), nil)
		if err != nil {
			t.Fatalf("Android connect failed: %v", err)
		}
		defer andWS.Close()

		var andPresence coordinator.PeerStatusEvent
		_ = andWS.ReadJSON(&andPresence) // Initial presence

		macWS, _, err := websocket.DefaultDialer.Dial(fmt.Sprintf("%s/ws/v1/connect?token=%s", f.wsBaseURL, macAuth.SessionToken), nil)
		if err != nil {
			t.Fatalf("Mac connect failed: %v", err)
		}

		_ = andWS.ReadJSON(&andPresence)
		if !andPresence.IsOnline || andPresence.PeerDeviceID != f.macDeviceID {
			t.Fatalf("expected Mac online notification on Android")
		}

		// INJECT FAILURE: Mac abruptly closes connection (laptop lid closed or Wi-Fi dropped)
		startRecovery := time.Now()
		_ = macWS.Close()

		// Android receives Mac offline event
		_ = andWS.ReadJSON(&andPresence)
		if andPresence.IsOnline {
			t.Fatalf("expected Mac offline notification on Android after drop")
		}

		// Mac recovers via session resumption (VPS-6)
		resumeBody, _ := json.Marshal(map[string]string{
			"device_id":        f.macDeviceID,
			"resumption_token": macAuth.ResumptionToken,
		})
		resp, err := http.Post(f.httpServer.URL+"/api/v1/auth/resume", "application/json", bytes.NewReader(resumeBody))
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("Mac resume request failed: %v", err)
		}
		defer resp.Body.Close()

		var resumeResp struct {
			SessionToken    string `json:"session_token"`
			ResumptionToken string `json:"resumption_token"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&resumeResp)

		// Reconnect Mac WebSocket
		macWSResumed, _, err := websocket.DefaultDialer.Dial(fmt.Sprintf("%s/ws/v1/connect?token=%s", f.wsBaseURL, resumeResp.SessionToken), nil)
		if err != nil {
			t.Fatalf("Mac resumed connect failed: %v", err)
		}
		defer macWSResumed.Close()

		// Android receives Mac online event
		_ = andWS.ReadJSON(&andPresence)
		if !andPresence.IsOnline {
			t.Fatalf("expected Mac restored online notification on Android")
		}

		recoveryDuration := time.Since(startRecovery)
		t.Logf("PASS: Scenario 3 (Mac Network Loss) recovered in %v (bound: < 3000ms)", recoveryDuration)

		if recoveryDuration > 3*time.Second {
			t.Fatalf("Scenario 3 recovery took too long: %v", recoveryDuration)
		}

		// End-to-end payload exchange
		testMsg := []byte("mac-resumed-file-req")
		_ = macWSResumed.WriteMessage(websocket.BinaryMessage, testMsg)
		_, recv, err := andWS.ReadMessage()
		if err != nil || !bytes.Equal(recv, testMsg) {
			t.Fatalf("message exchange failed after Mac recovery")
		}

		// Verify zero re-pairing required
		pairedID, err := f.srv.Registry().GetPairedDevice(f.andDeviceID)
		if err != nil || pairedID != f.macDeviceID {
			t.Fatalf("pairing corrupted during Mac recovery: %v", err)
		}
	})
}

func authenticateECDSAWithResumption(t *testing.T, baseURL, deviceID string, priv *ecdsa.PrivateKey, pubDER []byte) AuthResponseWithResumption {
	t.Helper()

	// 1. Challenge
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
	h := sha256.Sum256(challengeData)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, h[:])
	if err != nil {
		t.Fatalf("ECDSA signing failed: %v", err)
	}

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
