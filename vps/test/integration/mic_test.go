package integration

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pritamlkjh/phonelink/vps/internal/auth"
	"github.com/pritamlkjh/phonelink/vps/internal/server"
)

// TestMICIntegrationDualGateStreamingAndRelayAudit validates end-to-end remote microphone control:
// 1. Post-install dual-gate enforcement (RECORD_AUDIO permission + in-app opt-in toggle).
// 2. E2E encrypted MicStartRequest / MicStartResponse / MicAudioChunk streaming with FGS indicator state.
// 3. Sequence-number gap detection on streamed PCM chunks.
// 4. Immediate hardware deactivation upon MicStopRequest and upon peer offline disconnect.
// 5. Zero plaintext leakage audit across all relayed WebSocket frames.
func TestMICIntegrationDualGateStreamingAndRelayAudit(t *testing.T) {
	srv := server.NewServer(server.DefaultConfig(), nil)
	httpServer := httptest.NewServer(srv.Handler())
	defer httpServer.Close()

	audit := &AuditInterceptor{}
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

	macToken := authenticateEd25519(t, httpServer.URL, macDeviceID, macPriv)
	andToken := authenticateECDSA(t, httpServer.URL, andDeviceID, andPriv, andPubDER)

	pairToken := createPairingToken(t, httpServer.URL, macDeviceID, macToken)
	claimPairing(t, httpServer.URL, pairToken, andDeviceID)

	macConn, _, err := websocket.DefaultDialer.Dial(wsBaseURL+"/ws/v1/connect?token="+macToken, nil)
	if err != nil {
		t.Fatalf("Mac WebSocket connect failed: %v", err)
	}
	defer macConn.Close()

	andConn, _, err := websocket.DefaultDialer.Dial(wsBaseURL+"/ws/v1/connect?token="+andToken, nil)
	if err != nil {
		t.Fatalf("Android WebSocket connect failed: %v", err)
	}
	defer andConn.Close()

	_, _, _ = macConn.ReadMessage()
	_, _, _ = andConn.ReadMessage()
	_, _, _ = macConn.ReadMessage()

	macCurve := ecdh.X25519()
	macEphPriv, _ := macCurve.GenerateKey(rand.Reader)
	macEphPub := macEphPriv.PublicKey().Bytes()

	andCurve := ecdh.X25519()
	andEphPriv, _ := andCurve.GenerateKey(rand.Reader)
	andEphPub := andEphPriv.PublicKey().Bytes()

	initMsg, _ := json.Marshal(map[string]interface{}{
		"type":                 "E2E_INIT",
		"ephemeral_public_key": base64.StdEncoding.EncodeToString(macEphPub),
	})
	_ = macConn.WriteMessage(websocket.BinaryMessage, initMsg)
	audit.Record(initMsg)

	_, receivedInitRaw, err := andConn.ReadMessage()
	if err != nil {
		t.Fatalf("Android failed to receive E2E_INIT: %v", err)
	}
	var initParsed struct {
		PubB64 string `json:"ephemeral_public_key"`
	}
	_ = json.Unmarshal(receivedInitRaw, &initParsed)
	receivedMacPub, _ := base64.StdEncoding.DecodeString(initParsed.PubB64)

	ackMsg, _ := json.Marshal(map[string]interface{}{
		"type":                 "E2E_ACK",
		"ephemeral_public_key": base64.StdEncoding.EncodeToString(andEphPub),
	})
	_ = andConn.WriteMessage(websocket.BinaryMessage, ackMsg)
	audit.Record(ackMsg)

	_, receivedAckRaw, err := macConn.ReadMessage()
	if err != nil {
		t.Fatalf("Mac failed to receive E2E_ACK: %v", err)
	}
	var ackParsed struct {
		PubB64 string `json:"ephemeral_public_key"`
	}
	_ = json.Unmarshal(receivedAckRaw, &ackParsed)
	receivedAndPub, _ := base64.StdEncoding.DecodeString(ackParsed.PubB64)

	parsedAndPub, _ := macCurve.NewPublicKey(receivedAndPub)
	macSS, _ := macEphPriv.ECDH(parsedAndPub)

	parsedMacPub, _ := andCurve.NewPublicKey(receivedMacPub)
	andSS, _ := andEphPriv.ECDH(parsedMacPub)

	salt := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	macKM2A, macKA2M := deriveDirectionalKeys(macSS, salt)
	andKM2A, andKA2M := deriveDirectionalKeys(andSS, salt)

	osMicPermissionGranted := false
	inAppMicToggleAllowed := false
	var isMicCapturing int32 = 0
	var osMicIndicatorActive int32 = 0
	var activeSessionID string

	sendEncryptedFromAndroid := func(payloadObj map[string]interface{}) {
		plain, _ := json.Marshal(payloadObj)
		enc, encErr := encryptAESGCM(andKA2M, plain, nil)
		if encErr != nil {
			t.Fatalf("Android encryption failed: %v", encErr)
		}
		wrap, _ := json.Marshal(map[string]interface{}{
			"type":       "E2E_PAYLOAD",
			"ciphertext": base64.StdEncoding.EncodeToString(enc),
		})
		if writeErr := andConn.WriteMessage(websocket.BinaryMessage, wrap); writeErr != nil {
			t.Fatalf("Android write failed: %v", writeErr)
		}
		audit.Record(wrap)
	}

	readDecryptedOnMac := func() map[string]interface{} {
		_, msgBytes, readErr := macConn.ReadMessage()
		if readErr != nil {
			t.Fatalf("Mac read failed: %v", readErr)
		}
		audit.Record(msgBytes)

		var env struct {
			Type       string `json:"type"`
			Ciphertext string `json:"ciphertext"`
		}
		_ = json.Unmarshal(msgBytes, &env)
		cipherData, _ := base64.StdEncoding.DecodeString(env.Ciphertext)
		decrypted, decErr := decryptAESGCM(macKA2M, cipherData, nil)
		if decErr != nil {
			t.Fatalf("Mac decryption failed: %v", decErr)
		}
		var out map[string]interface{}
		_ = json.Unmarshal(decrypted, &out)
		return out
	}

	// Deterministic 16-bit PCM chunk (200 ms @ 16 kHz mono = 6400 bytes)
	samplePCM := make([]byte, 6400)
	for i := 0; i < len(samplePCM); i += 2 {
		samplePCM[i] = byte(i & 0xFF)
		samplePCM[i+1] = byte((i >> 8) & 0x7F)
	}

	handleAndroidMicMessage := func(chunkSequence []int) {
		_, msgBytes, readErr := andConn.ReadMessage()
		if readErr != nil {
			t.Fatalf("Android read failed: %v", readErr)
		}
		audit.Record(msgBytes)

		var env struct {
			Type       string `json:"type"`
			Ciphertext string `json:"ciphertext"`
		}
		_ = json.Unmarshal(msgBytes, &env)
		if env.Type != "E2E_PAYLOAD" {
			return
		}

		cipherData, _ := base64.StdEncoding.DecodeString(env.Ciphertext)
		plainBytes, decErr := decryptAESGCM(andKM2A, cipherData, nil)
		if decErr != nil {
			t.Fatalf("Android decryption failed: %v", decErr)
		}
		var appMsg map[string]interface{}
		_ = json.Unmarshal(plainBytes, &appMsg)

		if startReq, hasStart := appMsg["mic_start_req"].(map[string]interface{}); hasStart {
			sessID, _ := startReq["session_id"].(string)

			if !osMicPermissionGranted {
				sendEncryptedFromAndroid(map[string]interface{}{
					"schema_version": 1,
					"mic_start_resp": map[string]interface{}{
						"session_id":    sessID,
						"status":        "STATUS_MIC_PERMISSION_DENIED",
						"error_message": "RECORD_AUDIO runtime permission is not granted",
					},
				})
				return
			}

			if !inAppMicToggleAllowed {
				sendEncryptedFromAndroid(map[string]interface{}{
					"schema_version": 1,
					"mic_start_resp": map[string]interface{}{
						"session_id":    sessID,
						"status":        "STATUS_MIC_TOGGLE_DISABLED",
						"error_message": "In-app Allow Remote Microphone Access toggle is OFF",
					},
				})
				return
			}

			atomic.StoreInt32(&isMicCapturing, 1)
			atomic.StoreInt32(&osMicIndicatorActive, 1)
			activeSessionID = sessID

			sendEncryptedFromAndroid(map[string]interface{}{
				"schema_version": 1,
				"mic_start_resp": map[string]interface{}{
					"session_id":            sessID,
					"status":                "STATUS_OK",
					"actual_sample_rate_hz": 16000,
					"actual_channels":       1,
					"bits_per_sample":       16,
				},
			})

			for _, chunkNum := range chunkSequence {
				if atomic.LoadInt32(&isMicCapturing) == 0 {
					break
				}
				sendEncryptedFromAndroid(map[string]interface{}{
					"schema_version": 1,
					"mic_chunk": map[string]interface{}{
						"session_id":      sessID,
						"chunk_number":    chunkNum,
						"timestamp_ms":    time.Now().UnixMilli(),
						"pcm_data":        base64.StdEncoding.EncodeToString(samplePCM),
						"sample_rate_hz":  16000,
						"channels":        1,
						"bits_per_sample": 16,
					},
				})
			}
			return
		}

		if stopReq, hasStop := appMsg["mic_stop_req"].(map[string]interface{}); hasStop {
			sessID, _ := stopReq["session_id"].(string)
			_ = activeSessionID
			atomic.StoreInt32(&isMicCapturing, 0)
			atomic.StoreInt32(&osMicIndicatorActive, 0)
			activeSessionID = ""

			sendEncryptedFromAndroid(map[string]interface{}{
				"schema_version": 1,
				"mic_stop_resp": map[string]interface{}{
					"session_id": sessID,
					"status":     "STATUS_OK",
				},
			})
		}
	}

	sendMacMicRequest := func(plainObj map[string]interface{}, chunkSequence []int) map[string]interface{} {
		plainBytes, _ := json.Marshal(plainObj)
		encryptedReq, encErr := encryptAESGCM(macKM2A, plainBytes, nil)
		if encErr != nil {
			t.Fatalf("Mac encryption failed: %v", encErr)
		}
		reqEnv, _ := json.Marshal(map[string]interface{}{
			"type":       "E2E_PAYLOAD",
			"ciphertext": base64.StdEncoding.EncodeToString(encryptedReq),
		})
		if writeErr := macConn.WriteMessage(websocket.BinaryMessage, reqEnv); writeErr != nil {
			t.Fatalf("Mac write failed: %v", writeErr)
		}
		audit.Record(reqEnv)

		handleAndroidMicMessage(chunkSequence)
		return readDecryptedOnMac()
	}

	// 1. Dual-gate rejection tests
	startReq := map[string]interface{}{
		"schema_version": 1,
		"mic_start_req": map[string]interface{}{
			"session_id":        "mic-sess-1",
			"sample_rate_hz":    16000,
			"channels":          1,
			"chunk_duration_ms": 200,
		},
	}

	respNoPerm := sendMacMicRequest(startReq, nil)
	if respNoPerm["mic_start_resp"].(map[string]interface{})["status"] != "STATUS_MIC_PERMISSION_DENIED" {
		t.Fatalf("Expected STATUS_MIC_PERMISSION_DENIED, got %v", respNoPerm)
	}
	if atomic.LoadInt32(&isMicCapturing) != 0 || atomic.LoadInt32(&osMicIndicatorActive) != 0 {
		t.Fatalf("Microphone must NOT activate without RECORD_AUDIO permission")
	}

	osMicPermissionGranted = true
	inAppMicToggleAllowed = false
	respNoToggle := sendMacMicRequest(startReq, nil)
	if respNoToggle["mic_start_resp"].(map[string]interface{})["status"] != "STATUS_MIC_TOGGLE_DISABLED" {
		t.Fatalf("Expected STATUS_MIC_TOGGLE_DISABLED, got %v", respNoToggle)
	}
	if atomic.LoadInt32(&isMicCapturing) != 0 || atomic.LoadInt32(&osMicIndicatorActive) != 0 {
		t.Fatalf("Microphone must NOT activate when in-app toggle is OFF")
	}

	// 2. Dual-gate granted -> encrypted PCM streaming & dropped sequence detection (1, 2, 4 => 1 dropped)
	inAppMicToggleAllowed = true
	expectedChunks := []int{1, 2, 4}
	respStart := sendMacMicRequest(startReq, expectedChunks)
	startBody := respStart["mic_start_resp"].(map[string]interface{})
	if startBody["status"] != "STATUS_OK" {
		t.Fatalf("Expected STATUS_OK, got %v", startBody)
	}
	if int(startBody["actual_sample_rate_hz"].(float64)) != 16000 || int(startBody["bits_per_sample"].(float64)) != 16 {
		t.Fatalf("Unexpected negotiated mic format: %v", startBody)
	}
	if atomic.LoadInt32(&isMicCapturing) != 1 || atomic.LoadInt32(&osMicIndicatorActive) != 1 {
		t.Fatalf("Expected active mic capture and OS mic indicator")
	}

	var expectedNextSeq uint64 = 1
	var droppedCount uint64 = 0
	for range expectedChunks {
		chunkMsg := readDecryptedOnMac()
		chunkObj := chunkMsg["mic_chunk"].(map[string]interface{})
		if chunkObj["session_id"] != "mic-sess-1" {
			t.Fatalf("Unexpected chunk session_id: %v", chunkObj["session_id"])
		}
		seq := uint64(chunkObj["chunk_number"].(float64))
		if seq > expectedNextSeq {
			droppedCount += seq - expectedNextSeq
		}
		expectedNextSeq = seq + 1

		pcmDecoded, err := base64.StdEncoding.DecodeString(chunkObj["pcm_data"].(string))
		if err != nil || len(pcmDecoded) != len(samplePCM) {
			t.Fatalf("Invalid decoded PCM chunk length: got=%d err=%v", len(pcmDecoded), err)
		}
	}
	if droppedCount != 1 {
		t.Fatalf("Expected dropped sequence count 1 for chunks [1,2,4], got %d", droppedCount)
	}

	// 3. Explicit stop request releases mic hardware immediately
	stopReq := map[string]interface{}{
		"schema_version": 1,
		"mic_stop_req": map[string]interface{}{
			"session_id": "mic-sess-1",
			"reason":     "user_done",
		},
	}
	respStop := sendMacMicRequest(stopReq, nil)
	if respStop["mic_stop_resp"].(map[string]interface{})["status"] != "STATUS_OK" {
		t.Fatalf("Expected STATUS_OK on stop, got %v", respStop)
	}
	if atomic.LoadInt32(&isMicCapturing) != 0 || atomic.LoadInt32(&osMicIndicatorActive) != 0 {
		t.Fatalf("Expected mic capture and OS indicator to stop immediately")
	}

	// 4. Peer disconnect forces Android PEER_STATUS offline auto-stop
	offlineReq := map[string]interface{}{
		"schema_version": 1,
		"mic_start_req": map[string]interface{}{
			"session_id":        "mic-sess-offline",
			"sample_rate_hz":    16000,
			"channels":          1,
			"chunk_duration_ms": 200,
		},
	}
	_ = sendMacMicRequest(offlineReq, []int{1})
	_ = readDecryptedOnMac() // drain chunk 1

	_ = macConn.Close()
	_, peerNotice, readErr := andConn.ReadMessage()
	if readErr != nil {
		t.Fatalf("Expected PEER_STATUS offline notification on Android after Mac disconnect: %v", readErr)
	}
	var notice map[string]interface{}
	if json.Unmarshal(peerNotice, &notice) == nil {
		if online, ok := notice["is_online"].(bool); ok && !online {
			// Mirror ConnectionForegroundService offline cleanup handler
			atomic.StoreInt32(&isMicCapturing, 0)
			atomic.StoreInt32(&osMicIndicatorActive, 0)
		}
	}
	if atomic.LoadInt32(&isMicCapturing) != 0 || atomic.LoadInt32(&osMicIndicatorActive) != 0 {
		t.Fatalf("Expected peer offline event to stop active mic capture")
	}

	// 5. Zero plaintext leakage audit
	if err := audit.AssertNoPlaintextLeak(
		"mic-sess-1",
		"mic-sess-offline",
		"mic_start_req",
		"mic_start_resp",
		"mic_audio_chunk",
		"mic_chunk",
		"STATUS_MIC_PERMISSION_DENIED",
		"STATUS_MIC_TOGGLE_DISABLED",
		"RECORD_AUDIO",
	); err != nil {
		t.Fatalf("SECURITY VIOLATION: Plaintext leakage detected on VPS relay: %v", err)
	}
}
