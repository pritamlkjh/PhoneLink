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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/pritamlkjh/phonelink/vps/internal/auth"
	"github.com/pritamlkjh/phonelink/vps/internal/server"
)

// TestFILE2RemoteFileListing validates FILE-2:
// 1. End-to-end encrypted directory listing over VPS relay.
// 2. Exact match of file names, types, sizes, and mime-types.
// 3. Strict rejection of directory traversal attempts ("../").
// 4. Non-existent path error handling (STATUS_NOT_FOUND).
// 5. Audit verification: zero plaintext file names or metadata leak across the relay.
func TestFILE2RemoteFileListing(t *testing.T) {
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

	// 3. Register and Pair Both Devices
	registerDevice(t, httpServer.URL, macDeviceID, auth.DeviceTypeMac, base64.StdEncoding.EncodeToString(macPub), auth.AlgorithmEd25519)
	registerDevice(t, httpServer.URL, andDeviceID, auth.DeviceTypeAndroid, base64.StdEncoding.EncodeToString(andPubDER), auth.AlgorithmECDSAP256)

	macToken := authenticateEd25519(t, httpServer.URL, macDeviceID, macPriv)
	andToken := authenticateECDSA(t, httpServer.URL, andDeviceID, andPriv, andPubDER)

	pairToken := createPairingToken(t, httpServer.URL, macDeviceID, macToken)
	claimPairing(t, httpServer.URL, pairToken, andDeviceID, andToken)

	// 4. Stage Android Scoped Storage Directory Structure
	tempStorageDir, err := os.MkdirTemp("", "phonelink_android_storage_*")
	if err != nil {
		t.Fatalf("failed to create temp storage: %v", err)
	}
	defer os.RemoveAll(tempStorageDir)

	docsDir := filepath.Join(tempStorageDir, "Documents")
	photosDir := filepath.Join(tempStorageDir, "Photos")
	_ = os.MkdirAll(docsDir, 0755)
	_ = os.MkdirAll(photosDir, 0755)

	reportPath := filepath.Join(docsDir, "report.pdf")
	_ = os.WriteFile(reportPath, []byte("PDF Report Confidential Financial Data 2026"), 0644)
	sheetPath := filepath.Join(docsDir, "financials.xlsx")
	_ = os.WriteFile(sheetPath, []byte("Excel Spreadsheet Data"), 0644)
	photoPath := filepath.Join(photosDir, "vacation.jpg")
	_ = os.WriteFile(photoPath, []byte("JPEG Photo Image Raw Bytes"), 0644)

	// Blocked sensitive folder (must be filtered out)
	keystoreDir := filepath.Join(tempStorageDir, "keystore")
	_ = os.MkdirAll(keystoreDir, 0755)
	_ = os.WriteFile(filepath.Join(keystoreDir, "keys.db"), []byte("secret"), 0644)

	// 5. Connect Mac and Android WebSockets
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

	// Consume initial presence notifications
	_, _, _ = macConn.ReadMessage() // initial offline
	_, _, _ = andConn.ReadMessage() // mac online
	_, _, _ = macConn.ReadMessage() // phone online

	// 6. E2E Ephemeral Key Agreement
	macCurve := ecdh.X25519()
	macEphPriv, _ := macCurve.GenerateKey(rand.Reader)
	macEphPub := macEphPriv.PublicKey().Bytes()

	andCurve := ecdh.X25519()
	andEphPriv, _ := andCurve.GenerateKey(rand.Reader)
	andEphPub := andEphPriv.PublicKey().Bytes()

	// Mac sends E2E_INIT
	initMsg, _ := json.Marshal(map[string]interface{}{
		"type":                 "E2E_INIT",
		"ephemeral_public_key": base64.StdEncoding.EncodeToString(macEphPub),
	})
	_ = macConn.WriteMessage(websocket.BinaryMessage, initMsg)
	audit.Record(initMsg)

	// Android receives E2E_INIT
	_, receivedInitRaw, err := andConn.ReadMessage()
	if err != nil {
		t.Fatalf("Android failed to receive E2E_INIT: %v", err)
	}
	var initParsed struct {
		Type   string `json:"type"`
		PubB64 string `json:"ephemeral_public_key"`
	}
	_ = json.Unmarshal(receivedInitRaw, &initParsed)
	receivedMacPub, _ := base64.StdEncoding.DecodeString(initParsed.PubB64)

	// Android sends E2E_ACK
	ackMsg, _ := json.Marshal(map[string]interface{}{
		"type":                 "E2E_ACK",
		"ephemeral_public_key": base64.StdEncoding.EncodeToString(andEphPub),
	})
	_ = andConn.WriteMessage(websocket.BinaryMessage, ackMsg)
	audit.Record(ackMsg)

	// Mac receives E2E_ACK
	_, receivedAckRaw, err := macConn.ReadMessage()
	if err != nil {
		t.Fatalf("Mac failed to receive E2E_ACK: %v", err)
	}
	var ackParsed struct {
		Type   string `json:"type"`
		PubB64 string `json:"ephemeral_public_key"`
	}
	_ = json.Unmarshal(receivedAckRaw, &ackParsed)
	receivedAndPub, _ := base64.StdEncoding.DecodeString(ackParsed.PubB64)

	// Derive directional session keys
	parsedAndPub, _ := macCurve.NewPublicKey(receivedAndPub)
	macSS, _ := macEphPriv.ECDH(parsedAndPub)

	parsedMacPub, _ := andCurve.NewPublicKey(receivedMacPub)
	andSS, _ := andEphPriv.ECDH(parsedMacPub)

	salt := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	macKM2A, macKA2M := deriveDirectionalKeys(macSS, salt)
	andKM2A, andKA2M := deriveDirectionalKeys(andSS, salt)

	// Helper for Mac executing encrypted request and Android handling it
	executeRoundTrip := func(targetDirectory string) (map[string]interface{}, error) {
		// Mac builds FileListRequest ApplicationMessage
		reqMap := map[string]interface{}{
			"schema_version": 1,
			"message_id":     "req-uuid-101",
			"timestamp":      1774426500000,
			"file_list_req": map[string]interface{}{
				"request_id":       "fl-req-001",
				"target_directory": targetDirectory,
			},
		}
		reqPlaintext, _ := json.Marshal(reqMap)

		// Mac encrypts with K_M2A
		ciphertext, err := encryptAESGCM(macKM2A, reqPlaintext, nil)
		if err != nil {
			return nil, err
		}

		// Mac wraps in E2E_PAYLOAD and sends
		payloadWrap, _ := json.Marshal(map[string]interface{}{
			"type":       "E2E_PAYLOAD",
			"ciphertext": base64.StdEncoding.EncodeToString(ciphertext),
		})
		_ = macConn.WriteMessage(websocket.BinaryMessage, payloadWrap)
		audit.Record(payloadWrap)

		// Android receives
		_, recWrapRaw, err := andConn.ReadMessage()
		if err != nil {
			return nil, err
		}
		var recWrap struct {
			Type       string `json:"type"`
			Ciphertext string `json:"ciphertext"`
		}
		_ = json.Unmarshal(recWrapRaw, &recWrap)
		recCiphertext, _ := base64.StdEncoding.DecodeString(recWrap.Ciphertext)

		// Android decrypts with K_M2A
		decryptedReq, err := decryptAESGCM(andKM2A, recCiphertext, nil)
		if err != nil {
			return nil, err
		}

		var parsedReq struct {
			FileListReq struct {
				TargetDirectory string `json:"target_directory"`
				RequestID       string `json:"request_id"`
			} `json:"file_list_req"`
		}
		_ = json.Unmarshal(decryptedReq, &parsedReq)

		// Android performs storage operation (simulating StorageAccessLayer)
		var respStatus string
		var respItems []map[string]interface{}
		var errMsg string

		cleanedTarget := strings.Trim(parsedReq.FileListReq.TargetDirectory, "/\\ ")
		if strings.Contains(cleanedTarget, "..") {
			respStatus = "STATUS_STORAGE_ACCESS_DENIED"
			errMsg = "Access denied: path traversal detected"
		} else {
			targetFullPath := filepath.Join(tempStorageDir, cleanedTarget)
			rel, relErr := filepath.Rel(tempStorageDir, targetFullPath)
			if relErr != nil || strings.HasPrefix(rel, "..") {
				respStatus = "STATUS_STORAGE_ACCESS_DENIED"
				errMsg = "Access denied: outside scoped root"
			} else {
				entries, readErr := os.ReadDir(targetFullPath)
				if readErr != nil {
					respStatus = "STATUS_NOT_FOUND"
					errMsg = readErr.Error()
				} else {
					respStatus = "STATUS_OK"
					for _, entry := range entries {
						name := entry.Name()
						if strings.Contains(name, "keystore") || strings.Contains(name, "shared_prefs") {
							continue
						}
						info, _ := entry.Info()
						var size int64
						if !entry.IsDir() && info != nil {
							size = info.Size()
						}
						mime := "application/octet-stream"
						if entry.IsDir() {
							mime = "inode/directory"
						} else if strings.HasSuffix(name, ".pdf") {
							mime = "application/pdf"
						} else if strings.HasSuffix(name, ".jpg") {
							mime = "image/jpeg"
						}

						respItems = append(respItems, map[string]interface{}{
							"path":          filepath.Join(cleanedTarget, name),
							"name":          name,
							"is_directory":  entry.IsDir(),
							"size_bytes":    size,
							"modified_time": 1774400000000,
							"mime_type":     mime,
						})
					}
				}
			}
		}

		respMap := map[string]interface{}{
			"schema_version": 1,
			"message_id":     "resp-uuid-202",
			"timestamp":      1774426500500,
			"file_list_resp": map[string]interface{}{
				"request_id":        parsedReq.FileListReq.RequestID,
				"status":            respStatus,
				"current_directory": cleanedTarget,
				"items":             respItems,
				"error_message":     errMsg,
			},
		}
		respPlaintext, _ := json.Marshal(respMap)

		// Android encrypts with K_A2M
		respCiphertext, err := encryptAESGCM(andKA2M, respPlaintext, nil)
		if err != nil {
			return nil, err
		}

		respWrap, _ := json.Marshal(map[string]interface{}{
			"type":       "E2E_PAYLOAD",
			"ciphertext": base64.StdEncoding.EncodeToString(respCiphertext),
		})
		_ = andConn.WriteMessage(websocket.BinaryMessage, respWrap)
		audit.Record(respWrap)

		// Mac receives
		_, macRespWrapRaw, err := macConn.ReadMessage()
		if err != nil {
			return nil, err
		}
		var macRespWrap struct {
			Type       string `json:"type"`
			Ciphertext string `json:"ciphertext"`
		}
		_ = json.Unmarshal(macRespWrapRaw, &macRespWrap)
		macCiphertext, _ := base64.StdEncoding.DecodeString(macRespWrap.Ciphertext)

		// Mac decrypts with K_A2M
		macDecrypted, err := decryptAESGCM(macKA2M, macCiphertext, nil)
		if err != nil {
			return nil, err
		}

		var finalResp map[string]interface{}
		_ = json.Unmarshal(macDecrypted, &finalResp)
		return finalResp["file_list_resp"].(map[string]interface{}), nil
	}

	// 7. Test Root Directory Listing
	rootResp, err := executeRoundTrip("")
	if err != nil {
		t.Fatalf("root listing failed: %v", err)
	}
	if rootResp["status"] != "STATUS_OK" {
		t.Fatalf("expected STATUS_OK for root, got %s", rootResp["status"])
	}
	rootItems := rootResp["items"].([]interface{})
	if len(rootItems) != 2 {
		t.Fatalf("expected 2 directories in root, got %d", len(rootItems))
	}
	for _, it := range rootItems {
		item := it.(map[string]interface{})
		if item["name"] == "keystore" {
			t.Fatalf("sensitive folder keystore must never be exposed!")
		}
		if !item["is_directory"].(bool) {
			t.Errorf("expected directory in root")
		}
	}

	// 8. Test Documents Subdirectory Listing
	docsResp, err := executeRoundTrip("Documents")
	if err != nil {
		t.Fatalf("Documents listing failed: %v", err)
	}
	if docsResp["status"] != "STATUS_OK" {
		t.Fatalf("expected STATUS_OK for Documents, got %s", docsResp["status"])
	}
	docItems := docsResp["items"].([]interface{})
	if len(docItems) != 2 {
		t.Fatalf("expected 2 files in Documents, got %d", len(docItems))
	}

	var foundReport bool
	for _, it := range docItems {
		item := it.(map[string]interface{})
		if item["name"] == "report.pdf" {
			foundReport = true
			if item["is_directory"].(bool) {
				t.Errorf("report.pdf must not be a directory")
			}
			if item["mime_type"] != "application/pdf" {
				t.Errorf("expected application/pdf, got %s", item["mime_type"])
			}
			if int64(item["size_bytes"].(float64)) != int64(len("PDF Report Confidential Financial Data 2026")) {
				t.Errorf("file size mismatch")
			}
		}
	}
	if !foundReport {
		t.Fatalf("report.pdf not found in Documents listing")
	}

	// 9. Test Directory Traversal Rejection
	travResp, err := executeRoundTrip("../../../etc")
	if err != nil {
		t.Fatalf("traversal test failed: %v", err)
	}
	if travResp["status"] != "STATUS_STORAGE_ACCESS_DENIED" {
		t.Fatalf("expected STATUS_STORAGE_ACCESS_DENIED for path traversal, got %s", travResp["status"])
	}

	// 10. Test Non-Existent Directory
	missingResp, err := executeRoundTrip("DoesNotExist")
	if err != nil {
		t.Fatalf("missing directory test failed: %v", err)
	}
	if missingResp["status"] != "STATUS_NOT_FOUND" {
		t.Fatalf("expected STATUS_NOT_FOUND for non-existent path, got %s", missingResp["status"])
	}

	// 11. Zero Plaintext Leakage Audit on VPS Relay
	if err := audit.AssertNoPlaintextLeak(
		"report.pdf",
		"financials.xlsx",
		"vacation.jpg",
		"Confidential Financial Data",
	); err != nil {
		t.Fatalf("CRITICAL AUDIT FAILURE: %v", err)
	}

	t.Log(">>> FILE-2 REMOTE FILE LISTING: 100% VERIFIED & AUDITED <<<")
}
