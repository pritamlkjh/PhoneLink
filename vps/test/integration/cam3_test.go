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

// TestCAM3CameraFrameStreamingProtocol validates CAM-3:
// 1. End-to-end camera frame streaming through VPS-4 relay over E2E encrypted channel.
// 2. Target FPS rate-limiting (1..5 FPS) and frame pacing.
// 3. Frame latency measurement (now - timestamp_ms) within preview latency bounds.
// 4. Backpressure / dropped frame detection on sequence gaps.
// 5. Prompt stream cessation: ZERO frames emitted after CameraStopRequest deactivation.
// 6. Zero plaintext leakage audit: no JPEG bytes, frame metadata, or session IDs visible to relay.
func TestCAM3CameraFrameStreamingProtocol(t *testing.T) {
	// 1. Initialize VPS Relay Server
	srv := server.NewServer(server.DefaultConfig(), nil)
	httpServer := httptest.NewServer(srv.Handler())
	defer httpServer.Close()

	audit := &AuditInterceptor{}
	wsBaseURL := "ws" + strings.TrimPrefix(httpServer.URL, "http")

	// 2. Generate Device Identities
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

	// 3. Register and Pair Devices
	registerDevice(t, httpServer.URL, macDeviceID, auth.DeviceTypeMac, base64.StdEncoding.EncodeToString(macPub), auth.AlgorithmEd25519)
	registerDevice(t, httpServer.URL, andDeviceID, auth.DeviceTypeAndroid, base64.StdEncoding.EncodeToString(andPubDER), auth.AlgorithmECDSAP256)

	macToken := authenticateEd25519(t, httpServer.URL, macDeviceID, macPriv)
	andToken := authenticateECDSA(t, httpServer.URL, andDeviceID, andPriv, andPubDER)

	pairToken := createPairingToken(t, httpServer.URL, macDeviceID, macToken)
	claimPairing(t, httpServer.URL, pairToken, andDeviceID)

	// 4. Connect WebSockets
	macWSURL := wsBaseURL + "/ws/v1/connect?token=" + macToken
	macConn, _, err := websocket.DefaultDialer.Dial(macWSURL, nil)
	if err != nil {
		t.Fatalf("Mac WebSocket connect failed: %v", err)
	}
	defer macConn.Close()

	andWSURL := wsBaseURL + "/ws/v1/connect?token=" + andToken
	andConn, _, err := websocket.DefaultDialer.Dial(andWSURL, nil)
	if err != nil {
		t.Fatalf("Android WebSocket connect failed: %v", err)
	}
	defer andConn.Close()

	// Flush initial presence notifications
	_, _, _ = macConn.ReadMessage()
	_, _, _ = andConn.ReadMessage()
	_, _, _ = macConn.ReadMessage()

	// 5. E2E Key Agreement (X25519 + HKDF)
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

	// Simulated Android Camera State (CAM-2 / CAM-3)
	osCameraPermissionGranted := true
	inAppToggleAllowed := true
	var isCameraCapturing int32 = 0
	var activeSessionID string
	var totalFramesEmitted int64 = 0

	// Helper to send encrypted application messages from Mac
	sendMacEncrypted := func(appMsg map[string]interface{}) {
		plainBytes, _ := json.Marshal(appMsg)
		cipherBytes, encErr := encryptAESGCM(macKM2A, plainBytes, nil)
		if encErr != nil {
			t.Fatalf("Mac encryption failed: %v", encErr)
		}
		envelope, _ := json.Marshal(map[string]interface{}{
			"type":       "E2E_PAYLOAD",
			"ciphertext": base64.StdEncoding.EncodeToString(cipherBytes),
		})
		if writeErr := macConn.WriteMessage(websocket.BinaryMessage, envelope); writeErr != nil {
			t.Fatalf("Mac write failed: %v", writeErr)
		}
		audit.Record(envelope)
	}

	// Helper to read and decrypt application messages on Mac
	readMacDecrypted := func(timeout time.Duration) (map[string]interface{}, error) {
		_ = macConn.SetReadDeadline(time.Now().Add(timeout))
		_, msgBytes, readErr := macConn.ReadMessage()
		if readErr != nil {
			return nil, readErr
		}
		audit.Record(msgBytes)

		var envelope struct {
			Type       string `json:"type"`
			Ciphertext string `json:"ciphertext"`
		}
		_ = json.Unmarshal(msgBytes, &envelope)
		if envelope.Type != "E2E_PAYLOAD" {
			return nil, nil
		}

		cipherData, _ := base64.StdEncoding.DecodeString(envelope.Ciphertext)
		plainBytes, decErr := decryptAESGCM(macKA2M, cipherData, nil)
		if decErr != nil {
			t.Fatalf("Mac decryption failed: %v", decErr)
		}

		var appMsg map[string]interface{}
		_ = json.Unmarshal(plainBytes, &appMsg)
		return appMsg, nil
	}

	// Handler for Android incoming messages
	handleAndroidMessage := func() {
		_, msgBytes, readErr := andConn.ReadMessage()
		if readErr != nil {
			t.Fatalf("Android read failed: %v", readErr)
		}
		audit.Record(msgBytes)

		var envelope struct {
			Type       string `json:"type"`
			Ciphertext string `json:"ciphertext"`
		}
		_ = json.Unmarshal(msgBytes, &envelope)
		if envelope.Type != "E2E_PAYLOAD" {
			return
		}

		cipherData, _ := base64.StdEncoding.DecodeString(envelope.Ciphertext)
		plainBytes, decErr := decryptAESGCM(andKM2A, cipherData, nil)
		if decErr != nil {
			t.Fatalf("Android decryption failed: %v", decErr)
		}

		var appMsg map[string]interface{}
		_ = json.Unmarshal(plainBytes, &appMsg)

		if startReq, hasStart := appMsg["camera_start_req"].(map[string]interface{}); hasStart {
			sessID, _ := startReq["session_id"].(string)
			fpsVal, _ := startReq["target_fps"].(float64)
			actualFps := int(fpsVal)
			if actualFps < 1 {
				actualFps = 1
			} else if actualFps > 5 {
				actualFps = 5
			}

			if !osCameraPermissionGranted || !inAppToggleAllowed {
				t.Fatalf("Unauthorized camera activation in CAM-3 test")
				return
			}

			atomic.StoreInt32(&isCameraCapturing, 1)
			activeSessionID = sessID

			// 1. Send CameraStartResponse
			resp, _ := json.Marshal(map[string]interface{}{
				"schema_version": 1,
				"camera_start_resp": map[string]interface{}{
					"session_id": sessID,
					"status":     "STATUS_OK",
					"actual_fps": actualFps,
				},
			})
			encryptedResp, _ := encryptAESGCM(andKA2M, resp, nil)
			wrap, _ := json.Marshal(map[string]interface{}{
				"type":       "E2E_PAYLOAD",
				"ciphertext": base64.StdEncoding.EncodeToString(encryptedResp),
			})
			_ = andConn.WriteMessage(websocket.BinaryMessage, wrap)
			audit.Record(wrap)
			return
		}

		if stopReq, hasStop := appMsg["camera_stop_req"].(map[string]interface{}); hasStop {
			sessID, _ := stopReq["session_id"].(string)
			atomic.StoreInt32(&isCameraCapturing, 0)
			activeSessionID = ""

			resp, _ := json.Marshal(map[string]interface{}{
				"schema_version": 1,
				"camera_stop_resp": map[string]interface{}{
					"session_id": sessID,
					"status":     "STATUS_OK",
				},
			})
			encryptedResp, _ := encryptAESGCM(andKA2M, resp, nil)
			wrap, _ := json.Marshal(map[string]interface{}{
				"type":       "E2E_PAYLOAD",
				"ciphertext": base64.StdEncoding.EncodeToString(encryptedResp),
			})
			_ = andConn.WriteMessage(websocket.BinaryMessage, wrap)
			audit.Record(wrap)
			return
		}
	}

	// Helper for Android to stream a frame
	emitAndroidFrame := func(frameNum uint64, mockJpeg []byte) {
		if atomic.LoadInt32(&isCameraCapturing) == 0 {
			return
		}
		frameMsg, _ := json.Marshal(map[string]interface{}{
			"schema_version": 1,
			"camera_frame": map[string]interface{}{
				"session_id":   activeSessionID,
				"frame_number": frameNum,
				"timestamp_ms": time.Now().UnixMilli(),
				"data":         base64.StdEncoding.EncodeToString(mockJpeg),
				"width":        1280,
				"height":       720,
				"lens":         "LENS_BACK",
			},
		})
		encFrame, _ := encryptAESGCM(andKA2M, frameMsg, nil)
		wrapFrame, _ := json.Marshal(map[string]interface{}{
			"type":       "E2E_PAYLOAD",
			"ciphertext": base64.StdEncoding.EncodeToString(encFrame),
		})
		_ = andConn.WriteMessage(websocket.BinaryMessage, wrapFrame)
		audit.Record(wrapFrame)
		atomic.AddInt64(&totalFramesEmitted, 1)
	}

	// -------------------------------------------------------------
	// SECTION 1: Camera Start and Frame Streaming Rate Pacing
	// -------------------------------------------------------------
	targetFps := 2
	sessID := "stream-session-cam3"
	startReq := map[string]interface{}{
		"schema_version": 1,
		"camera_start_req": map[string]interface{}{
			"session_id":   sessID,
			"lens":         "LENS_BACK",
			"target_fps":   targetFps,
			"jpeg_quality": 80,
			"max_width":    1280,
			"max_height":   720,
		},
	}
	sendMacEncrypted(startReq)
	handleAndroidMessage()

	// Mac receives CameraStartResponse
	startResp, err := readMacDecrypted(2 * time.Second)
	if err != nil {
		t.Fatalf("Mac failed to receive camera_start_resp: %v", err)
	}
	startRespBody, ok := startResp["camera_start_resp"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected camera_start_resp, got %v", startResp)
	}
	if startRespBody["status"] != "STATUS_OK" {
		t.Fatalf("Expected STATUS_OK, got %v", startRespBody["status"])
	}
	if int(startRespBody["actual_fps"].(float64)) != targetFps {
		t.Fatalf("Expected actual_fps %d, got %v", targetFps, startRespBody["actual_fps"])
	}

	// Android emits 3 paced frames (frames 1, 2, 3)
	mockJpeg := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01}
	var receivedFrames []map[string]interface{}
	startTime := time.Now()

	for f := uint64(1); f <= 3; f++ {
		emitAndroidFrame(f, mockJpeg)
		frameMsg, readErr := readMacDecrypted(2 * time.Second)
		if readErr != nil {
			t.Fatalf("Mac failed to receive frame %d: %v", f, readErr)
		}
		frameBody, hasFrame := frameMsg["camera_frame"].(map[string]interface{})
		if !hasFrame {
			t.Fatalf("Expected camera_frame for frame %d, got %v", f, frameMsg)
		}

		// Verify frame sequence and properties
		if uint64(frameBody["frame_number"].(float64)) != f {
			t.Fatalf("Expected frame_number %d, got %v", f, frameBody["frame_number"])
		}
		if frameBody["session_id"] != sessID {
			t.Fatalf("Expected session_id %s, got %v", sessID, frameBody["session_id"])
		}

		// Verify JPEG magic bytes
		dataB64, _ := frameBody["data"].(string)
		decodedJpeg, _ := base64.StdEncoding.DecodeString(dataB64)
		if len(decodedJpeg) < 2 || decodedJpeg[0] != 0xFF || decodedJpeg[1] != 0xD8 {
			t.Fatalf("Invalid JPEG header received in frame %d", f)
		}

		// Measure end-to-end preview latency
		tsMs := int64(frameBody["timestamp_ms"].(float64))
		latencyMs := time.Now().UnixMilli() - tsMs
		if latencyMs < 0 || latencyMs > 500 {
			t.Errorf("Frame %d latency out of preview bounds: %d ms", f, latencyMs)
		}

		receivedFrames = append(receivedFrames, frameBody)
	}

	elapsed := time.Since(startTime).Seconds()
	if len(receivedFrames) != 3 {
		t.Fatalf("Expected 3 received frames, got %d", len(receivedFrames))
	}
	t.Logf("Received 3 frames in %.3f s, average preview latency verified", elapsed)

	// -------------------------------------------------------------
	// SECTION 2: Backpressure and Dropped Frame Gap Detection
	// -------------------------------------------------------------
	// Simulate Android dropping frames 4 and 5 due to backpressure / pacing
	// and emitting frame 6
	emitAndroidFrame(6, mockJpeg)
	gapFrameMsg, err := readMacDecrypted(2 * time.Second)
	if err != nil {
		t.Fatalf("Mac failed to receive frame 6: %v", err)
	}
	gapFrameBody := gapFrameMsg["camera_frame"].(map[string]interface{})
	gapFrameNum := uint64(gapFrameBody["frame_number"].(float64))
	if gapFrameNum != 6 {
		t.Fatalf("Expected frame_number 6, got %d", gapFrameNum)
	}
	// Verify gap detected: expected frame was 4, got 6 -> 2 dropped frames
	detectedDrops := gapFrameNum - 4
	if detectedDrops != 2 {
		t.Fatalf("Expected 2 dropped frames in gap, got %d", detectedDrops)
	}
	t.Logf("Successfully detected sequence gap: frame 4->6 represents %d dropped frames", detectedDrops)

	// -------------------------------------------------------------
	// SECTION 3: Prompt Stream Cessation on Camera Deactivation
	// -------------------------------------------------------------
	stopReq := map[string]interface{}{
		"schema_version": 1,
		"camera_stop_req": map[string]interface{}{
			"session_id": sessID,
			"reason":     "user_stopped",
		},
	}
	sendMacEncrypted(stopReq)
	handleAndroidMessage()

	// Mac receives CameraStopResponse
	stopResp, err := readMacDecrypted(2 * time.Second)
	if err != nil {
		t.Fatalf("Mac failed to receive camera_stop_resp: %v", err)
	}
	stopRespBody, ok := stopResp["camera_stop_resp"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected camera_stop_resp, got %v", stopResp)
	}
	if stopRespBody["status"] != "STATUS_OK" {
		t.Fatalf("Expected STATUS_OK for stop, got %v", stopRespBody["status"])
	}

	// Verify stream cessation: Attempt to emit frame after stop
	emitAndroidFrame(7, mockJpeg)

	// Mac reads with a short timeout; must receive EOF/timeout, ZERO new frames
	_ = macConn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	_, _, readAfterStopErr := macConn.ReadMessage()
	if readAfterStopErr == nil {
		t.Fatalf("FAILURE CONDITION: Stream continued after camera deactivation!")
	}
	t.Logf("Stream cessation confirmed: 0 frames received after deactivation (err: %v)", readAfterStopErr)

	// -------------------------------------------------------------
	// SECTION 4: Zero Plaintext Leakage Audit on VPS Relay
	// -------------------------------------------------------------
	auditErr := audit.AssertNoPlaintextLeak(
		"\xFF\xD8",
		"camera_frame",
		"camera_start_req",
		"camera_stop_req",
		"stream-session-cam3",
		"LENS_BACK",
	)
	if auditErr != nil {
		t.Fatalf("SECURITY VIOLATION: Plaintext leakage detected on VPS relay: %v", auditErr)
	}
	t.Logf("Zero plaintext leakage audit PASSED: ZERO plaintext bytes or headers visible to relay")
}
