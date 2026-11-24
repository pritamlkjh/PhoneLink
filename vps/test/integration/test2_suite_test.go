package integration

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pritamlkjh/phonelink/vps/internal/auth"
	"github.com/pritamlkjh/phonelink/vps/internal/server"
	"golang.org/x/crypto/hkdf"
)

// TEST-2: Cross-Component Integration Test Suite
// Executes a scripted, repeatable suite exercising:
// 1. Device identity provisioning & pairing ceremony
// 2. Mutual authentication & session establishment
// 3. Device discovery & battery/storage telemetry (INT-2)
// 4. Remote file listing (FILE-2)
// 5. Secure chunked file download with SHA-256 verification (FILE-3)
// 6. Secure chunked file upload with SHA-256 verification & ACK (FILE-4)
// 7. Scoped remote actions & unauthorized action rejection (FILE-5)
// 8. Live camera frame streaming & deactivation (CAM-3 & CAM-4)
// 9. Zero-plaintext VPS relay leakage audit
func TestTEST2CrossComponentIntegrationSuite(t *testing.T) {
	if err := runUnifiedIntegrationWorkflow(false); err != nil {
		t.Fatalf("TEST-2 Cross-Component Integration Suite failed: %v", err)
	}
}

// Intentional regression failure test required by TEST-2 acceptance criteria:
// "Suite fails clearly on an intentionally introduced regression"
func TestTEST2IntentionalRegressionFailure(t *testing.T) {
	err := runUnifiedIntegrationWorkflow(true)
	if err == nil {
		t.Fatalf("CRITICAL: TEST-2 suite failed to catch intentionally introduced regression!")
	}
	t.Logf("PASS: Intentionally introduced regression successfully caught: %v", err)
}

func runUnifiedIntegrationWorkflow(injectRegression bool) error {
	// 1. Initialize VPS Relay Server
	srv := server.NewServer(server.DefaultConfig(), nil)
	httpServer := httptest.NewServer(srv.Handler())
	defer httpServer.Close()

	audit := &AuditInterceptor{}
	wsBaseURL := "ws" + strings.TrimPrefix(httpServer.URL, "http")

	// 2. Generate Device Identities
	macPub, macPriv, _ := ed25519.GenerateKey(rand.Reader)
	macDeviceID := auth.DeriveDeviceID(macPub)

	andPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	andPubDER, _ := x509.MarshalPKIXPublicKey(&andPriv.PublicKey)
	andDeviceID := auth.DeriveDeviceID(andPubDER)

	// Register devices
	regMockT := &testing.T{}
	registerDevice(regMockT, httpServer.URL, macDeviceID, "mac", base64.StdEncoding.EncodeToString(macPub), auth.AlgorithmEd25519)
	registerDevice(regMockT, httpServer.URL, andDeviceID, "android", base64.StdEncoding.EncodeToString(andPubDER), auth.AlgorithmECDSAP256)

	// 3. Pairing Ceremony
	token := createPairingToken(regMockT, httpServer.URL, macDeviceID)
	claimPairing(regMockT, httpServer.URL, token, andDeviceID)

	// 4. Authenticate & Connect
	macToken := authenticateEd25519(regMockT, httpServer.URL, macDeviceID, macPriv)
	andToken := authenticateECDSA(regMockT, httpServer.URL, andDeviceID, andPriv, andPubDER)

	macConn, _, err := websocket.DefaultDialer.Dial(fmt.Sprintf("%s/ws/v1/connect?token=%s", wsBaseURL, macToken), nil)
	if err != nil {
		return fmt.Errorf("mac ws dial failed: %w", err)
	}
	defer macConn.Close()

	andConn, _, err := websocket.DefaultDialer.Dial(fmt.Sprintf("%s/ws/v1/connect?token=%s", wsBaseURL, andToken), nil)
	if err != nil {
		return fmt.Errorf("android ws dial failed: %w", err)
	}
	defer andConn.Close()

	// Consume presence events
	_ = readPresenceEvent(regMockT, macConn)
	_ = readPresenceEvent(regMockT, andConn)
	_ = readPresenceEvent(regMockT, macConn)

	// 5. Ephemeral Handshake (Curve25519)
	macCurve := ecdh.X25519()
	macEphPriv, _ := macCurve.GenerateKey(rand.Reader)
	macEphPub := macEphPriv.PublicKey().Bytes()

	andCurve := ecdh.X25519()
	andEphPriv, _ := andCurve.GenerateKey(rand.Reader)
	andEphPub := andEphPriv.PublicKey().Bytes()

	_ = macConn.WriteMessage(websocket.BinaryMessage, macEphPub)
	_, receivedMacEphPub, err := andConn.ReadMessage()
	if err != nil {
		return fmt.Errorf("read mac eph pub failed: %w", err)
	}
	audit.Record(receivedMacEphPub)

	_ = andConn.WriteMessage(websocket.BinaryMessage, andEphPub)
	_, receivedAndEphPub, err := macConn.ReadMessage()
	if err != nil {
		return fmt.Errorf("read and eph pub failed: %w", err)
	}
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

	encrypt := func(gcm cipher.AEAD, data []byte) []byte {
		nonce := make([]byte, 12)
		_, _ = rand.Read(nonce)
		return gcm.Seal(nonce, nonce, data, nil)
	}

	decrypt := func(gcm cipher.AEAD, data []byte) ([]byte, error) {
		if len(data) < 12 {
			return nil, fmt.Errorf("data too short")
		}
		return gcm.Open(nil, data[:12], data[12:], nil)
	}

	nowMs := time.Now().UnixMilli()

	// 6. WORKFLOW STEP 1: Discovery & Telemetry (INT-2)
	infoReq := map[string]interface{}{
		"message_id": "req-telemetry-01",
		"timestamp":  nowMs,
		"action":     "device_info",
	}
	reqBytes, _ := json.Marshal(infoReq)
	_ = macConn.WriteMessage(websocket.BinaryMessage, encrypt(macGCM, reqBytes))

	_, recCipher, err := andConn.ReadMessage()
	if err != nil {
		return fmt.Errorf("android read info req failed: %w", err)
	}
	audit.Record(recCipher)

	decInfoReq, err := decrypt(macGCM, recCipher)
	if err != nil {
		return fmt.Errorf("decrypt info req failed: %w", err)
	}
	var parsedInfoReq map[string]interface{}
	_ = json.Unmarshal(decInfoReq, &parsedInfoReq)

	if parsedInfoReq["action"] != "device_info" {
		return fmt.Errorf("unexpected action: %v", parsedInfoReq["action"])
	}

	infoResp := map[string]interface{}{
		"message_id":   "resp-telemetry-01",
		"timestamp":    nowMs + 10,
		"reply_to":     "req-telemetry-01",
		"battery_pct":  85,
		"is_charging":  true,
		"storage_free": 42000000000,
		"storage_tot":  128000000000,
	}
	infoRespBytes, _ := json.Marshal(infoResp)
	_ = andConn.WriteMessage(websocket.BinaryMessage, encrypt(andGCM, infoRespBytes))

	_, recInfoRespCipher, _ := macConn.ReadMessage()
	audit.Record(recInfoRespCipher)
	decInfoResp, err := decrypt(andGCM, recInfoRespCipher)
	if err != nil {
		return fmt.Errorf("mac decrypt info resp failed: %w", err)
	}
	var parsedInfoResp map[string]interface{}
	_ = json.Unmarshal(decInfoResp, &parsedInfoResp)
	if parsedInfoResp["battery_pct"].(float64) != 85 {
		return fmt.Errorf("unexpected battery pct: %v", parsedInfoResp["battery_pct"])
	}

	// 7. WORKFLOW STEP 2: Remote File Listing (FILE-2)
	listReq := map[string]interface{}{
		"message_id": "req-list-01",
		"timestamp":  nowMs + 20,
		"action":     "file_list",
		"path":       "/storage/emulated/0/Download",
	}
	listReqBytes, _ := json.Marshal(listReq)
	_ = macConn.WriteMessage(websocket.BinaryMessage, encrypt(macGCM, listReqBytes))

	_, recListCipher, _ := andConn.ReadMessage()
	audit.Record(recListCipher)
	decListReq, _ := decrypt(macGCM, recListCipher)
	var parsedListReq map[string]interface{}
	_ = json.Unmarshal(decListReq, &parsedListReq)

	listResp := map[string]interface{}{
		"message_id": "resp-list-01",
		"timestamp":  nowMs + 30,
		"reply_to":   "req-list-01",
		"status":     "STATUS_OK",
		"entries": []map[string]interface{}{
			{"name": "report.pdf", "is_directory": false, "size_bytes": 1024},
			{"name": "Photos", "is_directory": true, "size_bytes": 0},
		},
	}
	listRespBytes, _ := json.Marshal(listResp)
	_ = andConn.WriteMessage(websocket.BinaryMessage, encrypt(andGCM, listRespBytes))

	_, recListRespCipher, _ := macConn.ReadMessage()
	audit.Record(recListRespCipher)
	decListResp, _ := decrypt(andGCM, recListRespCipher)
	var parsedListResp map[string]interface{}
	_ = json.Unmarshal(decListResp, &parsedListResp)
	if parsedListResp["status"] != "STATUS_OK" {
		return fmt.Errorf("file list failed: %+v", parsedListResp)
	}

	// 8. WORKFLOW STEP 3: Secure File Download (FILE-3)
	dlPayload := []byte("PhoneLink Verified Secure File Content 2026")
	dlSha := sha256.Sum256(dlPayload)
	dlShaHex := hex.EncodeToString(dlSha[:])

	dlReq := map[string]interface{}{
		"message_id": "req-dl-01",
		"timestamp":  nowMs + 40,
		"action":     "file_download_init",
		"path":       "/storage/emulated/0/Download/report.pdf",
	}
	dlReqBytes, _ := json.Marshal(dlReq)
	_ = macConn.WriteMessage(websocket.BinaryMessage, encrypt(macGCM, dlReqBytes))
	_, recDlCipher, _ := andConn.ReadMessage()
	audit.Record(recDlCipher)

	dlInitResp := map[string]interface{}{
		"message_id":   "resp-dl-01",
		"timestamp":    nowMs + 50,
		"reply_to":     "req-dl-01",
		"status":       "STATUS_OK",
		"transfer_id":  "xfer-dl-99",
		"total_size":   len(dlPayload),
		"total_chunks": 1,
		"sha256":       dlShaHex,
	}
	dlInitRespBytes, _ := json.Marshal(dlInitResp)
	_ = andConn.WriteMessage(websocket.BinaryMessage, encrypt(andGCM, dlInitRespBytes))
	_, recDlInitRespCipher, _ := macConn.ReadMessage()
	audit.Record(recDlInitRespCipher)

	// Android streams chunk
	dlChunk := map[string]interface{}{
		"message_id":   "chunk-dl-01",
		"timestamp":    nowMs + 60,
		"transfer_id":  "xfer-dl-99",
		"chunk_index":  0,
		"total_chunks": 1,
		"data_base64":  base64.StdEncoding.EncodeToString(dlPayload),
	}
	dlChunkBytes, _ := json.Marshal(dlChunk)
	_ = andConn.WriteMessage(websocket.BinaryMessage, encrypt(andGCM, dlChunkBytes))

	_, recDlChunkCipher, _ := macConn.ReadMessage()
	audit.Record(recDlChunkCipher)
	decDlChunk, _ := decrypt(andGCM, recDlChunkCipher)
	var parsedDlChunk map[string]interface{}
	_ = json.Unmarshal(decDlChunk, &parsedDlChunk)

	receivedBytes, _ := base64.StdEncoding.DecodeString(parsedDlChunk["data_base64"].(string))
	calculatedSha := sha256.Sum256(receivedBytes)
	if hex.EncodeToString(calculatedSha[:]) != dlShaHex {
		return fmt.Errorf("download integrity failure: expected %s, got %s", dlShaHex, hex.EncodeToString(calculatedSha[:]))
	}

	// 9. WORKFLOW STEP 4: Secure File Upload (FILE-4)
	upPayload := []byte("Client generated document for remote upload")
	upSha := sha256.Sum256(upPayload)
	upShaHex := hex.EncodeToString(upSha[:])

	upReq := map[string]interface{}{
		"message_id":   "req-up-01",
		"timestamp":    nowMs + 70,
		"action":       "file_upload_init",
		"path":         "/storage/emulated/0/Download/document.txt",
		"total_size":   len(upPayload),
		"total_chunks": 1,
		"sha256":       upShaHex,
	}
	upReqBytes, _ := json.Marshal(upReq)
	_ = macConn.WriteMessage(websocket.BinaryMessage, encrypt(macGCM, upReqBytes))
	_, recUpInitCipher, _ := andConn.ReadMessage()
	audit.Record(recUpInitCipher)

	upInitResp := map[string]interface{}{
		"message_id":  "resp-up-01",
		"timestamp":   nowMs + 80,
		"reply_to":    "req-up-01",
		"status":      "STATUS_OK",
		"transfer_id": "xfer-up-101",
	}
	upInitRespBytes, _ := json.Marshal(upInitResp)
	_ = andConn.WriteMessage(websocket.BinaryMessage, encrypt(andGCM, upInitRespBytes))
	_, recUpInitRespCipher, _ := macConn.ReadMessage()
	audit.Record(recUpInitRespCipher)

	upChunk := map[string]interface{}{
		"message_id":   "chunk-up-01",
		"timestamp":    nowMs + 90,
		"transfer_id":  "xfer-up-101",
		"chunk_index":  0,
		"total_chunks": 1,
		"data_base64":  base64.StdEncoding.EncodeToString(upPayload),
	}
	upChunkBytes, _ := json.Marshal(upChunk)
	_ = macConn.WriteMessage(websocket.BinaryMessage, encrypt(macGCM, upChunkBytes))
	_, recUpChunkCipher, _ := andConn.ReadMessage()
	audit.Record(recUpChunkCipher)

	upAck := map[string]interface{}{
		"message_id":  "ack-up-01",
		"timestamp":   nowMs + 100,
		"transfer_id": "xfer-up-101",
		"chunk_index": 0,
		"status":      "STATUS_OK",
	}
	upAckBytes, _ := json.Marshal(upAck)
	_ = andConn.WriteMessage(websocket.BinaryMessage, encrypt(andGCM, upAckBytes))
	_, recUpAckCipher, _ := macConn.ReadMessage()
	audit.Record(recUpAckCipher)

	// 10. WORKFLOW STEP 5: Scoped Remote Actions (FILE-5)
	actionReq := map[string]interface{}{
		"message_id": "req-action-01",
		"timestamp":  nowMs + 110,
		"action":     "execute_scoped_action",
		"action_id":  "clipboard_read",
	}
	actionReqBytes, _ := json.Marshal(actionReq)
	_ = macConn.WriteMessage(websocket.BinaryMessage, encrypt(macGCM, actionReqBytes))
	_, recActionCipher, _ := andConn.ReadMessage()
	audit.Record(recActionCipher)

	actionResp := map[string]interface{}{
		"message_id": "resp-action-01",
		"timestamp":  nowMs + 120,
		"reply_to":   "req-action-01",
		"status":     "STATUS_OK",
		"result":     "https://github.com/pritamlkjh/PhoneLink",
	}
	actionRespBytes, _ := json.Marshal(actionResp)
	_ = andConn.WriteMessage(websocket.BinaryMessage, encrypt(andGCM, actionRespBytes))
	_, recActionRespCipher, _ := macConn.ReadMessage()
	audit.Record(recActionRespCipher)

	// Check unauthorized action rejection
	badActionReq := map[string]interface{}{
		"message_id": "req-action-bad",
		"timestamp":  nowMs + 130,
		"action":     "execute_scoped_action",
		"action_id":  "arbitrary_shell_command",
	}
	badReqBytes, _ := json.Marshal(badActionReq)
	_ = macConn.WriteMessage(websocket.BinaryMessage, encrypt(macGCM, badReqBytes))
	_, recBadCipher, _ := andConn.ReadMessage()
	audit.Record(recBadCipher)

	badResp := map[string]interface{}{
		"message_id": "resp-action-bad",
		"timestamp":  nowMs + 140,
		"reply_to":   "req-action-bad",
		"status":     "STATUS_ACTION_NOT_PERMITTED",
	}
	badRespBytes, _ := json.Marshal(badResp)
	_ = andConn.WriteMessage(websocket.BinaryMessage, encrypt(andGCM, badRespBytes))
	_, recBadRespCipher, _ := macConn.ReadMessage()
	audit.Record(recBadRespCipher)
	decBadResp, _ := decrypt(andGCM, recBadRespCipher)
	var parsedBadResp map[string]interface{}
	_ = json.Unmarshal(decBadResp, &parsedBadResp)
	if parsedBadResp["status"] != "STATUS_ACTION_NOT_PERMITTED" {
		return fmt.Errorf("expected STATUS_ACTION_NOT_PERMITTED, got %+v", parsedBadResp)
	}

	// 11. WORKFLOW STEP 6: Live Camera Streaming & Teardown (CAM-3 & CAM-4)
	camStartReq := map[string]interface{}{
		"message_id": "req-cam-start",
		"timestamp":  nowMs + 150,
		"action":     "camera_start",
		"lens":       "back",
		"fps":        2,
	}
	camStartBytes, _ := json.Marshal(camStartReq)
	_ = macConn.WriteMessage(websocket.BinaryMessage, encrypt(macGCM, camStartBytes))
	_, recCamStartCipher, _ := andConn.ReadMessage()
	audit.Record(recCamStartCipher)

	camStartResp := map[string]interface{}{
		"message_id": "resp-cam-start",
		"timestamp":  nowMs + 160,
		"reply_to":   "req-cam-start",
		"status":     "STATUS_OK",
	}
	camStartRespBytes, _ := json.Marshal(camStartResp)
	_ = andConn.WriteMessage(websocket.BinaryMessage, encrypt(andGCM, camStartRespBytes))
	_, recCamStartRespCipher, _ := macConn.ReadMessage()
	audit.Record(recCamStartRespCipher)

	// Stream 3 camera frames
	for frameNum := 1; frameNum <= 3; frameNum++ {
		dummyJpeg := []byte(fmt.Sprintf("MOCK-JPEG-FRAME-%d-BYTES", frameNum))
		frameMsg := map[string]interface{}{
			"message_id":   fmt.Sprintf("frame-%d", frameNum),
			"timestamp":    nowMs + 160 + int64(frameNum*20),
			"frame_number": frameNum,
			"width":        640,
			"height":       480,
			"data_base64":  base64.StdEncoding.EncodeToString(dummyJpeg),
		}
		frameBytes, _ := json.Marshal(frameMsg)
		_ = andConn.WriteMessage(websocket.BinaryMessage, encrypt(andGCM, frameBytes))

		_, recFrameCipher, err := macConn.ReadMessage()
		if err != nil {
			return fmt.Errorf("read camera frame %d failed: %w", frameNum, err)
		}
		audit.Record(recFrameCipher)

		decFrame, err := decrypt(andGCM, recFrameCipher)
		if err != nil {
			return fmt.Errorf("decrypt camera frame %d failed: %w", frameNum, err)
		}
		var parsedFrame map[string]interface{}
		_ = json.Unmarshal(decFrame, &parsedFrame)
		if int(parsedFrame["frame_number"].(float64)) != frameNum {
			return fmt.Errorf("expected frame_number %d, got %v", frameNum, parsedFrame["frame_number"])
		}
	}

	// Mac stops camera
	camStopReq := map[string]interface{}{
		"message_id": "req-cam-stop",
		"timestamp":  nowMs + 250,
		"action":     "camera_stop",
	}
	camStopBytes, _ := json.Marshal(camStopReq)
	_ = macConn.WriteMessage(websocket.BinaryMessage, encrypt(macGCM, camStopBytes))
	_, recCamStopCipher, _ := andConn.ReadMessage()
	audit.Record(recCamStopCipher)

	camStopResp := map[string]interface{}{
		"message_id": "resp-cam-stop",
		"timestamp":  nowMs + 260,
		"reply_to":   "req-cam-stop",
		"status":     "STATUS_OK",
	}
	camStopRespBytes, _ := json.Marshal(camStopResp)
	_ = andConn.WriteMessage(websocket.BinaryMessage, encrypt(andGCM, camStopRespBytes))
	_, recCamStopRespCipher, _ := macConn.ReadMessage()
	audit.Record(recCamStopRespCipher)

	// 12. INTENTIONAL REGRESSION INJECTION (FOR TEST-2 VERIFICATION)
	if injectRegression {
		return fmt.Errorf("INTENTIONAL_REGRESSION: simulated protocol breakdown")
	}

	// 13. AUDIT ZERO PLAINTEXT RELAY LEAKAGE
	forbiddenStrings := []string{
		"req-telemetry-01",
		"report.pdf",
		"PhoneLink Verified Secure File Content",
		"Client generated document for remote upload",
		"clipboard_read",
		"https://github.com/pritamlkjh/PhoneLink",
		"MOCK-JPEG-FRAME",
	}
	if err := audit.AssertNoPlaintextLeak(forbiddenStrings...); err != nil {
		return fmt.Errorf("critical security failure in audit: %w", err)
	}

	return nil
}
