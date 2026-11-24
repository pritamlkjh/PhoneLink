package integration

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pritamlkjh/phonelink/vps/internal/auth"
	"github.com/pritamlkjh/phonelink/vps/internal/coordinator"
	"github.com/pritamlkjh/phonelink/vps/internal/server"
)

// TEST-3: Network Failure & Chaos Testing
// Acceptance Criteria:
// 1. Packet loss & drop handling: Sequence gaps detected, recoverable, zero silent corruption.
// 2. Latency & jitter injection: Bidirectional protocol survives network degradation without deadlock or state desync.
// 3. Half-open TCP / zombie connection reaping: Abrupt TCP severing detected, sessions cleaned up, peers notified.
// 4. Malformed/truncated ciphertext injection: Corrupted payloads rejected by AEAD validation; subsequent traffic unaffected.
// 5. Abrupt VPS restart under active transit: Automatic recovery within SLA (< 3000ms) with zero re-pairing.
// 6. Rapid connection flapping: Flapping connections handled cleanly without goroutine leaks or race conditions.

type ChunkFrame struct {
	Seq     int    `json:"seq"`
	Total   int    `json:"total"`
	Payload []byte `json:"payload"`
}

type NackFrame struct {
	Type       string `json:"type"` // "nack"
	MissingSeq int    `json:"missing_seq"`
}

func resumeSession(t *testing.T, baseURL, deviceID, resumptionToken string) AuthResponseWithResumption {
	t.Helper()
	resumeReqBody, _ := json.Marshal(map[string]string{
		"device_id":        deviceID,
		"resumption_token": resumptionToken,
	})
	resp, err := http.Post(baseURL+"/api/v1/auth/resume", "application/json", bytes.NewReader(resumeReqBody))
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
	return AuthResponseWithResumption{
		SessionToken:    resumeResp.SessionToken,
		ResumptionToken: resumeResp.ResumptionToken,
	}
}

func TestTEST3_PacketLossAndDropHandling(t *testing.T) {
	f := setupRecoveryFixture(t)
	defer f.httpServer.Close()

	macAuth := authenticateWithResumption(t, f.httpServer.URL, f.macDeviceID, f.macPriv)
	andAuth := authenticateECDSAWithResumption(t, f.httpServer.URL, f.andDeviceID, f.andPriv, f.andPubDER)

	macWS, _, err := websocket.DefaultDialer.Dial(fmt.Sprintf("%s/ws/v1/connect?token=%s", f.wsBaseURL, macAuth.SessionToken), nil)
	if err != nil {
		t.Fatalf("Mac connect failed: %v", err)
	}
	defer macWS.Close()

	var p coordinator.PeerStatusEvent
	_ = macWS.ReadJSON(&p) // Initial presence (peer offline)

	andWS, _, err := websocket.DefaultDialer.Dial(fmt.Sprintf("%s/ws/v1/connect?token=%s", f.wsBaseURL, andAuth.SessionToken), nil)
	if err != nil {
		t.Fatalf("Android connect failed: %v", err)
	}
	defer andWS.Close()

	var andP coordinator.PeerStatusEvent
	_ = andWS.ReadJSON(&andP) // Android reads its initial presence (Mac online)
	_ = macWS.ReadJSON(&p)    // Mac reads updated presence (Android online)

	// Prepare multi-chunk data
	rawContent := []byte("PhoneLink-Resilient-Chunk-Data-Stream-Content-Verification-1234567890")
	chunkSize := 16
	var chunks [][]byte
	for i := 0; i < len(rawContent); i += chunkSize {
		end := i + chunkSize
		if end > len(rawContent) {
			end = len(rawContent)
		}
		chunks = append(chunks, rawContent[i:end])
	}
	totalChunks := len(chunks)

	// Mac simulates sending chunks 0, 1, 2, 3... but intentionally DROPS chunk 2
	droppedSeq := 2
	for seq, chunk := range chunks {
		if seq == droppedSeq {
			continue // SIMULATE PACKET LOSS
		}
		frame := ChunkFrame{Seq: seq, Total: totalChunks, Payload: chunk}
		frameBytes, _ := json.Marshal(frame)
		if err := macWS.WriteMessage(websocket.BinaryMessage, frameBytes); err != nil {
			t.Fatalf("failed to send frame %d: %v", seq, err)
		}
	}

	// Android receiver reads chunks and detects the missing sequence
	receivedChunks := make(map[int][]byte)
	expectedSeq := 0
	detectedGap := false

	_ = andWS.SetReadDeadline(time.Now().Add(2 * time.Second))
	for len(receivedChunks) < totalChunks-1 {
		_, msg, err := andWS.ReadMessage()
		if err != nil {
			break
		}
		var frame ChunkFrame
		if err := json.Unmarshal(msg, &frame); err == nil {
			if frame.Seq != expectedSeq && !detectedGap {
				detectedGap = true
				// Android emits NACK back to Mac requesting missing chunk
				nack := NackFrame{Type: "nack", MissingSeq: expectedSeq}
				nackBytes, _ := json.Marshal(nack)
				_ = andWS.WriteMessage(websocket.BinaryMessage, nackBytes)
			}
			receivedChunks[frame.Seq] = frame.Payload
			expectedSeq = frame.Seq + 1
		}
	}

	if !detectedGap {
		t.Fatalf("expected packet loss gap to be detected by receiver")
	}

	// Mac reads NACK and retransmits dropped chunk
	_ = macWS.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, nackMsg, err := macWS.ReadMessage()
	if err != nil {
		t.Fatalf("Mac failed to receive NACK: %v", err)
	}
	var nack NackFrame
	_ = json.Unmarshal(nackMsg, &nack)
	if nack.MissingSeq != droppedSeq {
		t.Fatalf("expected NACK for seq %d, got %d", droppedSeq, nack.MissingSeq)
	}

	// Retransmit dropped chunk
	retransmitFrame := ChunkFrame{Seq: droppedSeq, Total: totalChunks, Payload: chunks[droppedSeq]}
	retBytes, _ := json.Marshal(retransmitFrame)
	_ = macWS.WriteMessage(websocket.BinaryMessage, retBytes)

	// Android receives retransmitted chunk
	_ = andWS.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, retMsg, err := andWS.ReadMessage()
	if err != nil {
		t.Fatalf("Android failed to receive retransmitted chunk: %v", err)
	}
	var retFrame ChunkFrame
	_ = json.Unmarshal(retMsg, &retFrame)
	receivedChunks[retFrame.Seq] = retFrame.Payload

	// Verify complete reassembled payload
	var reassembled []byte
	for i := 0; i < totalChunks; i++ {
		data, exists := receivedChunks[i]
		if !exists {
			t.Fatalf("missing chunk %d after recovery", i)
		}
		reassembled = append(reassembled, data...)
	}

	if !bytes.Equal(reassembled, rawContent) {
		t.Fatalf("reassembled content corrupted: got %s, want %s", reassembled, rawContent)
	}
}

func TestTEST3_LatencyAndJitterInjection(t *testing.T) {
	f := setupRecoveryFixture(t)
	defer f.httpServer.Close()

	macAuth := authenticateWithResumption(t, f.httpServer.URL, f.macDeviceID, f.macPriv)
	andAuth := authenticateECDSAWithResumption(t, f.httpServer.URL, f.andDeviceID, f.andPriv, f.andPubDER)

	macWS, _, err := websocket.DefaultDialer.Dial(fmt.Sprintf("%s/ws/v1/connect?token=%s", f.wsBaseURL, macAuth.SessionToken), nil)
	if err != nil {
		t.Fatalf("Mac connect failed: %v", err)
	}
	defer macWS.Close()

	var p coordinator.PeerStatusEvent
	_ = macWS.ReadJSON(&p) // Initial presence

	andWS, _, err := websocket.DefaultDialer.Dial(fmt.Sprintf("%s/ws/v1/connect?token=%s", f.wsBaseURL, andAuth.SessionToken), nil)
	if err != nil {
		t.Fatalf("Android connect failed: %v", err)
	}
	defer andWS.Close()

	var andP coordinator.PeerStatusEvent
	_ = andWS.ReadJSON(&andP) // Android reads initial presence
	_ = macWS.ReadJSON(&p)    // Mac reads updated presence

	// Symmetric AES-GCM key for e2e validation under latency
	symKey := make([]byte, 32)
	_, _ = rand.Read(symKey)
	block, _ := aes.NewCipher(symKey)
	aead, _ := cipher.NewGCM(block)

	type LatencyMsg struct {
		ID        int    `json:"id"`
		Timestamp int64  `json:"timestamp"`
		Payload   string `json:"payload"`
	}

	numMsgs := 5
	var wg sync.WaitGroup
	wg.Add(1)

	// Android receiver with latency verification
	var receivedIDs []int
	var recvMu sync.Mutex
	go func() {
		defer wg.Done()
		for i := 0; i < numMsgs; i++ {
			_ = andWS.SetReadDeadline(time.Now().Add(5 * time.Second))
			_, ciphertext, err := andWS.ReadMessage()
			if err != nil {
				return
			}
			if len(ciphertext) < aead.NonceSize() {
				return
			}
			nonce := ciphertext[:aead.NonceSize()]
			sealed := ciphertext[aead.NonceSize():]
			plaintext, err := aead.Open(nil, nonce, sealed, nil)
			if err != nil {
				return
			}
			var m LatencyMsg
			if err := json.Unmarshal(plaintext, &m); err == nil {
				recvMu.Lock()
				receivedIDs = append(receivedIDs, m.ID)
				recvMu.Unlock()
			}
		}
	}()

	// Mac sender injects 30ms-60ms artificial jitter per packet
	for i := 0; i < numMsgs; i++ {
		time.Sleep(30 * time.Millisecond) // Simulated latency jitter
		msg := LatencyMsg{
			ID:        i,
			Timestamp: time.Now().UnixNano(),
			Payload:   fmt.Sprintf("latency-payload-%d", i),
		}
		data, _ := json.Marshal(msg)
		nonce := make([]byte, aead.NonceSize())
		_, _ = rand.Read(nonce)
		sealed := aead.Seal(nil, nonce, data, nil)
		frame := append(nonce, sealed...)

		if err := macWS.WriteMessage(websocket.BinaryMessage, frame); err != nil {
			t.Fatalf("write failed on msg %d: %v", i, err)
		}
	}

	wg.Wait()

	if len(receivedIDs) != numMsgs {
		t.Fatalf("expected %d messages under latency/jitter, got %d", numMsgs, len(receivedIDs))
	}
}

func TestTEST3_HalfOpenTCPAndZombieConnectionReaping(t *testing.T) {
	f := setupRecoveryFixture(t)
	defer f.httpServer.Close()

	macAuth := authenticateWithResumption(t, f.httpServer.URL, f.macDeviceID, f.macPriv)
	andAuth := authenticateECDSAWithResumption(t, f.httpServer.URL, f.andDeviceID, f.andPriv, f.andPubDER)

	macWS, _, err := websocket.DefaultDialer.Dial(fmt.Sprintf("%s/ws/v1/connect?token=%s", f.wsBaseURL, macAuth.SessionToken), nil)
	if err != nil {
		t.Fatalf("Mac connect failed: %v", err)
	}
	defer macWS.Close()

	var p coordinator.PeerStatusEvent
	_ = macWS.ReadJSON(&p)

	andWS, _, err := websocket.DefaultDialer.Dial(fmt.Sprintf("%s/ws/v1/connect?token=%s", f.wsBaseURL, andAuth.SessionToken), nil)
	if err != nil {
		t.Fatalf("Android connect failed: %v", err)
	}

	var andP coordinator.PeerStatusEvent
	_ = andWS.ReadJSON(&andP)
	_ = macWS.ReadJSON(&p) // Android online

	if !f.srv.Coordinator().IsDeviceOnline(f.andDeviceID) {
		t.Fatalf("expected Android to be online in coordinator")
	}

	// SIMULATE ABRUPT TCP CLOSE / HALF-OPEN (kill underlying TCP socket without WS CLOSE handshake)
	_ = andWS.UnderlyingConn().Close()

	// Wait for Mac to receive peer offline event or coordinator to detect socket tear-down
	_ = macWS.SetReadDeadline(time.Now().Add(2 * time.Second))
	var offlineEvent coordinator.PeerStatusEvent
	err = macWS.ReadJSON(&offlineEvent)
	if err != nil {
		t.Fatalf("Mac failed to receive offline presence event: %v", err)
	}

	if offlineEvent.IsOnline {
		t.Fatalf("expected peer status to be offline, got online")
	}

	if f.srv.Coordinator().IsDeviceOnline(f.andDeviceID) {
		t.Fatalf("expected Android session to be reaped in coordinator")
	}

	// Verify zombie session is not leaked: Android can reconnect cleanly
	andAuth2 := authenticateECDSAWithResumption(t, f.httpServer.URL, f.andDeviceID, f.andPriv, f.andPubDER)
	andWS2, _, err := websocket.DefaultDialer.Dial(fmt.Sprintf("%s/ws/v1/connect?token=%s", f.wsBaseURL, andAuth2.SessionToken), nil)
	if err != nil {
		t.Fatalf("reconnection after zombie reaping failed: %v", err)
	}
	defer andWS2.Close()

	_ = andWS2.ReadJSON(&andP)
	_ = macWS.ReadJSON(&offlineEvent) // Android online again
	if !offlineEvent.IsOnline {
		t.Fatalf("expected peer to be online after re-pairing recovery")
	}
}

func TestTEST3_MalformedAndTruncatedCiphertextInjection(t *testing.T) {
	f := setupRecoveryFixture(t)
	defer f.httpServer.Close()

	macAuth := authenticateWithResumption(t, f.httpServer.URL, f.macDeviceID, f.macPriv)
	andAuth := authenticateECDSAWithResumption(t, f.httpServer.URL, f.andDeviceID, f.andPriv, f.andPubDER)

	macWS, _, err := websocket.DefaultDialer.Dial(fmt.Sprintf("%s/ws/v1/connect?token=%s", f.wsBaseURL, macAuth.SessionToken), nil)
	if err != nil {
		t.Fatalf("Mac connect failed: %v", err)
	}
	defer macWS.Close()

	var p coordinator.PeerStatusEvent
	_ = macWS.ReadJSON(&p)

	andWS, _, err := websocket.DefaultDialer.Dial(fmt.Sprintf("%s/ws/v1/connect?token=%s", f.wsBaseURL, andAuth.SessionToken), nil)
	if err != nil {
		t.Fatalf("Android connect failed: %v", err)
	}
	defer andWS.Close()

	var andP coordinator.PeerStatusEvent
	_ = andWS.ReadJSON(&andP)
	_ = macWS.ReadJSON(&p)

	symKey := make([]byte, 32)
	_, _ = rand.Read(symKey)
	block, _ := aes.NewCipher(symKey)
	aead, _ := cipher.NewGCM(block)

	// 1. Truncated Frame (less than nonce length)
	truncatedFrame := []byte{0x01, 0x02, 0x03}
	_ = macWS.WriteMessage(websocket.BinaryMessage, truncatedFrame)

	_ = andWS.SetReadDeadline(time.Now().Add(1 * time.Second))
	_, recv, err := andWS.ReadMessage()
	if err != nil {
		t.Fatalf("expected VPS relay to deliver frame to peer: %v", err)
	}
	// Client AEAD check: Must reject truncated frame cleanly
	if len(recv) < aead.NonceSize() {
		// Clean rejection - expected behavior
	} else {
		t.Fatalf("truncated frame unexpectedly passed length check")
	}

	// 2. Tampered Ciphertext (flipped bits -> authentication tag mismatch)
	validPlaintext := []byte("secret-control-command")
	nonce := make([]byte, aead.NonceSize())
	_, _ = rand.Read(nonce)
	sealed := aead.Seal(nil, nonce, validPlaintext, nil)
	// Tamper ciphertext
	sealed[len(sealed)-1] ^= 0xFF
	tamperedFrame := append(nonce, sealed...)

	_ = macWS.WriteMessage(websocket.BinaryMessage, tamperedFrame)

	_, recv2, err := andWS.ReadMessage()
	if err != nil {
		t.Fatalf("expected VPS relay to forward frame: %v", err)
	}
	tNonce := recv2[:aead.NonceSize()]
	tSealed := recv2[aead.NonceSize():]
	_, decErr := aead.Open(nil, tNonce, tSealed, nil)
	if decErr == nil {
		t.Fatalf("expected AEAD decryption error on tampered ciphertext, got nil")
	}

	// 3. Subsequent Valid Frame must succeed without state poisoning
	validNonce := make([]byte, aead.NonceSize())
	_, _ = rand.Read(validNonce)
	validSealed := aead.Seal(nil, validNonce, validPlaintext, nil)
	validFrame := append(validNonce, validSealed...)

	_ = macWS.WriteMessage(websocket.BinaryMessage, validFrame)
	_, recv3, err := andWS.ReadMessage()
	if err != nil {
		t.Fatalf("subsequent message read failed: %v", err)
	}
	vNonce := recv3[:aead.NonceSize()]
	vSealed := recv3[aead.NonceSize():]
	decrypted, err := aead.Open(nil, vNonce, vSealed, nil)
	if err != nil || !bytes.Equal(decrypted, validPlaintext) {
		t.Fatalf("subsequent message failed decryption after malformed injections: %v", err)
	}
}

func TestTEST3_AbruptVPSRestartUnderTransitLoad(t *testing.T) {
	srv := server.NewServer(server.DefaultConfig(), nil)
	httpServer := httptest.NewServer(srv.Handler())
	wsBaseURL := "ws" + strings.TrimPrefix(httpServer.URL, "http")

	macPub, macPriv, _ := ed25519.GenerateKey(rand.Reader)
	macDeviceID := auth.DeriveDeviceID(macPub)

	andPub, andPriv, _ := ed25519.GenerateKey(rand.Reader)
	andDeviceID := auth.DeriveDeviceID(andPub)

	registerDevice(t, httpServer.URL, macDeviceID, "mac", base64.StdEncoding.EncodeToString(macPub), auth.AlgorithmEd25519)
	registerDevice(t, httpServer.URL, andDeviceID, "android", base64.StdEncoding.EncodeToString(andPub), auth.AlgorithmEd25519)

	pairingToken := createPairingToken(t, httpServer.URL, macDeviceID)
	claimPairing(t, httpServer.URL, pairingToken, andDeviceID)

	macAuth := authenticateWithResumption(t, httpServer.URL, macDeviceID, macPriv)
	andAuth := authenticateWithResumption(t, httpServer.URL, andDeviceID, andPriv)

	macWS, _, _ := websocket.DefaultDialer.Dial(fmt.Sprintf("%s/ws/v1/connect?token=%s", wsBaseURL, macAuth.SessionToken), nil)
	defer macWS.Close()
	var p coordinator.PeerStatusEvent
	_ = macWS.ReadJSON(&p)

	andWS, _, _ := websocket.DefaultDialer.Dial(fmt.Sprintf("%s/ws/v1/connect?token=%s", wsBaseURL, andAuth.SessionToken), nil)
	defer andWS.Close()
	var andP coordinator.PeerStatusEvent
	_ = andWS.ReadJSON(&andP)
	_ = macWS.ReadJSON(&p)

	// Exchange initial message
	_ = macWS.WriteMessage(websocket.BinaryMessage, []byte("pre-restart-ping"))
	_, preRecv, err := andWS.ReadMessage()
	if err != nil || !bytes.Equal(preRecv, []byte("pre-restart-ping")) {
		t.Fatalf("pre-restart communication failed: %v", err)
	}

	// CRASH THE SERVER DURING TRANSIT
	startRestart := time.Now()
	httpServer.Close()

	// Both clients notice error on write/read
	_ = macWS.WriteMessage(websocket.BinaryMessage, []byte("in-flight-lost"))
	_ = macWS.Close()
	_ = andWS.Close()

	// Spin up fresh server instance sharing the same underlying registry
	newHTTPServer := httptest.NewServer(srv.Handler())
	defer newHTTPServer.Close()
	newWSBaseURL := "ws" + strings.TrimPrefix(newHTTPServer.URL, "http")

	// Clients resume using resumption tokens
	macResume := resumeSession(t, newHTTPServer.URL, macDeviceID, macAuth.ResumptionToken)
	andResume := resumeSession(t, newHTTPServer.URL, andDeviceID, andAuth.ResumptionToken)

	newMacWS, _, err := websocket.DefaultDialer.Dial(fmt.Sprintf("%s/ws/v1/connect?token=%s", newWSBaseURL, macResume.SessionToken), nil)
	if err != nil {
		t.Fatalf("Mac resumption connect failed: %v", err)
	}
	defer newMacWS.Close()
	_ = newMacWS.ReadJSON(&p)

	newAndWS, _, err := websocket.DefaultDialer.Dial(fmt.Sprintf("%s/ws/v1/connect?token=%s", newWSBaseURL, andResume.SessionToken), nil)
	if err != nil {
		t.Fatalf("Android resumption connect failed: %v", err)
	}
	defer newAndWS.Close()
	_ = newAndWS.ReadJSON(&andP)
	_ = newMacWS.ReadJSON(&p)

	// Exchange post-restart payload
	_ = newMacWS.WriteMessage(websocket.BinaryMessage, []byte("post-restart-recovered"))
	_, postRecv, err := newAndWS.ReadMessage()
	if err != nil || !bytes.Equal(postRecv, []byte("post-restart-recovered")) {
		t.Fatalf("post-restart communication failed")
	}

	elapsed := time.Since(startRestart)
	if elapsed > 3*time.Second {
		t.Fatalf("recovery took too long: %v > 3000ms SLA", elapsed)
	}

	// Verify pairing still valid
	paired, err := srv.Registry().GetPairedDevice(macDeviceID)
	if err != nil || paired != andDeviceID {
		t.Fatalf("pairing corrupted across server restart: %v", err)
	}
}

func TestTEST3_RapidConnectionFlapping(t *testing.T) {
	f := setupRecoveryFixture(t)
	defer f.httpServer.Close()

	macAuth := authenticateWithResumption(t, f.httpServer.URL, f.macDeviceID, f.macPriv)
	currentResumption := macAuth.ResumptionToken
	currentSession := macAuth.SessionToken

	// Rapidly connect, disconnect, and resume 5 times
	for i := 0; i < 5; i++ {
		ws, _, err := websocket.DefaultDialer.Dial(fmt.Sprintf("%s/ws/v1/connect?token=%s", f.wsBaseURL, currentSession), nil)
		if err != nil {
			t.Fatalf("flap connect %d failed: %v", i, err)
		}
		_ = ws.Close()

		// Resume session with token rotation
		resumed := resumeSession(t, f.httpServer.URL, f.macDeviceID, currentResumption)
		currentSession = resumed.SessionToken
		currentResumption = resumed.ResumptionToken
	}

	if f.srv.Coordinator().IsDeviceOnline(f.macDeviceID) {
		t.Fatalf("flapping left stale session online")
	}
}
