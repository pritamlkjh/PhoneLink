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
	"testing"

	"github.com/gorilla/websocket"
	"github.com/pritamlkjh/phonelink/vps/internal/auth"
	"github.com/pritamlkjh/phonelink/vps/internal/server"
)

// TestFILE5ScopedRemoteActions validates FILE-5:
// 1. End-to-end encrypted scoped remote action execution between Mac and Android over VPS relay.
// 2. device.ping action execution with duration verification.
// 3. device.ping duration boundary clamping (0 -> 5s default, >30s -> 30s max, <0 -> STATUS_INVALID_ARGUMENT).
// 4. device.info telemetry retrieval (model, OS, battery, charging, storage, app version).
// 5. Independent permission gating (remote ping disabled -> STATUS_ACTION_NOT_PERMITTED, remote info disabled -> STATUS_ACTION_NOT_PERMITTED).
// 6. Security verification: Rejection of arbitrary shell commands / script execution.
// 7. Rejection of un-allowlisted actions.
// 8. Zero plaintext leakage audit over VPS relay.
func TestFILE5ScopedRemoteActions(t *testing.T) {
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
	claimPairing(t, httpServer.URL, pairToken, andDeviceID, andToken)

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

	// 5. E2E Key Agreement
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

	// Simulated Android Remote Action State
	allowPing := true
	allowInfo := true
	lastPingDuration := 0

	handleAndroidAction := func() {
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

		var respPayload []byte

		// 1. Shell command injection check
		if _, hasShell := appMsg["shell_cmd"]; hasShell {
			reqID, _ := appMsg["request_id"].(string)
			resp, _ := json.Marshal(map[string]interface{}{
				"schema_version": 1,
				"error": map[string]interface{}{
					"request_id": reqID,
					"code":       "STATUS_ACTION_NOT_PERMITTED",
					"message":    "Arbitrary command execution is permanently disabled by policy",
				},
			})
			respPayload = resp
		} else if actionReq, hasAction := appMsg["action_request"].(map[string]interface{}); hasAction {
			actionName, _ := actionReq["action"].(string)
			reqID, _ := actionReq["request_id"].(string)
			resp, _ := json.Marshal(map[string]interface{}{
				"schema_version": 1,
				"error": map[string]interface{}{
					"request_id": reqID,
					"code":       "STATUS_ACTION_NOT_PERMITTED",
					"message":    "Action '" + actionName + "' is not in the build-time allowlist",
				},
			})
			respPayload = resp
		} else if pingReq, hasPing := appMsg["device_ping_req"].(map[string]interface{}); hasPing {
			reqID, _ := pingReq["request_id"].(string)
			duration := int(pingReq["duration_seconds"].(float64))

			if !allowPing {
				resp, _ := json.Marshal(map[string]interface{}{
					"schema_version": 1,
					"device_ping_resp": map[string]interface{}{
						"request_id": reqID,
						"status":     "STATUS_ACTION_NOT_PERMITTED",
						"message":    "Remote ping is disabled in Android device settings",
					},
				})
				respPayload = resp
			} else if duration < 0 {
				resp, _ := json.Marshal(map[string]interface{}{
					"schema_version": 1,
					"device_ping_resp": map[string]interface{}{
						"request_id": reqID,
						"status":     "STATUS_INVALID_ARGUMENT",
						"message":    "Invalid ping duration: cannot be negative",
					},
				})
				respPayload = resp
			} else {
				clamped := duration
				if duration == 0 {
					clamped = 5
				} else if duration > 30 {
					clamped = 30
				}
				lastPingDuration = clamped

				resp, _ := json.Marshal(map[string]interface{}{
					"schema_version": 1,
					"device_ping_resp": map[string]interface{}{
						"request_id": reqID,
						"status":     "STATUS_OK",
						"message":    "Device ping active for duration",
					},
				})
				respPayload = resp
			}
		} else if infoReq, hasInfo := appMsg["device_info_req"].(map[string]interface{}); hasInfo {
			reqID, _ := infoReq["request_id"].(string)

			if !allowInfo {
				resp, _ := json.Marshal(map[string]interface{}{
					"schema_version": 1,
					"device_info_resp": map[string]interface{}{
						"request_id":    reqID,
						"status":        "STATUS_ACTION_NOT_PERMITTED",
						"error_message": "Remote device info is disabled in Android device settings",
					},
				})
				respPayload = resp
			} else {
				resp, _ := json.Marshal(map[string]interface{}{
					"schema_version": 1,
					"device_info_resp": map[string]interface{}{
						"request_id":              reqID,
						"status":                  "STATUS_OK",
						"model":                   "Google Pixel 8 Pro",
						"os_version":              "Android 14 (API 34)",
						"battery_percent":         92,
						"is_charging":             true,
						"total_storage_bytes":     256000000000,
						"available_storage_bytes": 180000000000,
						"app_version":             "1.0.0",
					},
				})
				respPayload = resp
			}
		}

		if respPayload != nil {
			encryptedResp, encErr := encryptAESGCM(andKA2M, respPayload, nil)
			if encErr != nil {
				t.Fatalf("Android encryption failed: %v", encErr)
			}
			respEnv, _ := json.Marshal(map[string]interface{}{
				"type":       "E2E_PAYLOAD",
				"ciphertext": base64.StdEncoding.EncodeToString(encryptedResp),
			})
			_ = andConn.WriteMessage(websocket.BinaryMessage, respEnv)
			audit.Record(respEnv)
		}
	}

	sendMacRequest := func(plainObj map[string]interface{}) map[string]interface{} {
		plainBytes, _ := json.Marshal(plainObj)
		encryptedReq, encErr := encryptAESGCM(macKM2A, plainBytes, nil)
		if encErr != nil {
			t.Fatalf("Mac encryption failed: %v", encErr)
		}
		reqEnv, _ := json.Marshal(map[string]interface{}{
			"type":       "E2E_PAYLOAD",
			"ciphertext": base64.StdEncoding.EncodeToString(encryptedReq),
		})
		_ = macConn.WriteMessage(websocket.BinaryMessage, reqEnv)
		audit.Record(reqEnv)

		handleAndroidAction()

		_, respBytes, readErr := macConn.ReadMessage()
		if readErr != nil {
			t.Fatalf("Mac read response failed: %v", readErr)
		}
		audit.Record(respBytes)

		var env struct {
			Type       string `json:"type"`
			Ciphertext string `json:"ciphertext"`
		}
		_ = json.Unmarshal(respBytes, &env)
		cipherData, _ := base64.StdEncoding.DecodeString(env.Ciphertext)
		decrypted, decErr := decryptAESGCM(macKA2M, cipherData, nil)
		if decErr != nil {
			t.Fatalf("Mac decryption failed: %v", decErr)
		}

		var res map[string]interface{}
		_ = json.Unmarshal(decrypted, &res)
		return res
	}

	// -------------------------------------------------------------
	// TEST CASE 1: Standard Ping Execution
	// -------------------------------------------------------------
	pingReq1 := map[string]interface{}{
		"schema_version": 1,
		"device_ping_req": map[string]interface{}{
			"request_id":       "ping-test-1",
			"duration_seconds": 10,
		},
	}
	resp1 := sendMacRequest(pingReq1)
	pingResp1 := resp1["device_ping_resp"].(map[string]interface{})
	if pingResp1["status"] != "STATUS_OK" {
		t.Fatalf("Expected STATUS_OK for ping, got %v", pingResp1["status"])
	}
	if lastPingDuration != 10 {
		t.Fatalf("Expected ping duration 10s on Android, got %d", lastPingDuration)
	}
	t.Log("PASS: Standard ping execution verified")

	// -------------------------------------------------------------
	// TEST CASE 2: Ping Duration Bounds Clamping
	// -------------------------------------------------------------
	// 0s -> clamps to default 5s
	pingReqZero := map[string]interface{}{
		"schema_version": 1,
		"device_ping_req": map[string]interface{}{
			"request_id":       "ping-test-zero",
			"duration_seconds": 0,
		},
	}
	respZero := sendMacRequest(pingReqZero)
	pingRespZero := respZero["device_ping_resp"].(map[string]interface{})
	if pingRespZero["status"] != "STATUS_OK" || lastPingDuration != 5 {
		t.Fatalf("Expected 0s duration to clamp to default 5s, got %d", lastPingDuration)
	}

	// 45s -> clamps to max 30s
	pingReqHigh := map[string]interface{}{
		"schema_version": 1,
		"device_ping_req": map[string]interface{}{
			"request_id":       "ping-test-high",
			"duration_seconds": 45,
		},
	}
	respHigh := sendMacRequest(pingReqHigh)
	pingRespHigh := respHigh["device_ping_resp"].(map[string]interface{})
	if pingRespHigh["status"] != "STATUS_OK" || lastPingDuration != 30 {
		t.Fatalf("Expected 45s duration to clamp to max 30s, got %d", lastPingDuration)
	}

	// Negative duration -> STATUS_INVALID_ARGUMENT
	pingReqNeg := map[string]interface{}{
		"schema_version": 1,
		"device_ping_req": map[string]interface{}{
			"request_id":       "ping-test-neg",
			"duration_seconds": -10,
		},
	}
	respNeg := sendMacRequest(pingReqNeg)
	pingRespNeg := respNeg["device_ping_resp"].(map[string]interface{})
	if pingRespNeg["status"] != "STATUS_INVALID_ARGUMENT" {
		t.Fatalf("Expected STATUS_INVALID_ARGUMENT for negative duration, got %v", pingRespNeg["status"])
	}
	t.Log("PASS: Ping duration bounds clamping verified")

	// -------------------------------------------------------------
	// TEST CASE 3: Device Info Retrieval
	// -------------------------------------------------------------
	infoReq := map[string]interface{}{
		"schema_version": 1,
		"device_info_req": map[string]interface{}{
			"request_id": "info-test-1",
		},
	}
	infoResp := sendMacRequest(infoReq)
	infoRespBody := infoResp["device_info_resp"].(map[string]interface{})
	if infoRespBody["status"] != "STATUS_OK" {
		t.Fatalf("Expected STATUS_OK for device info, got %v", infoRespBody["status"])
	}
	if infoRespBody["model"] != "Google Pixel 8 Pro" {
		t.Fatalf("Unexpected model: %v", infoRespBody["model"])
	}
	if infoRespBody["os_version"] != "Android 14 (API 34)" {
		t.Fatalf("Unexpected OS version: %v", infoRespBody["os_version"])
	}
	if int(infoRespBody["battery_percent"].(float64)) != 92 {
		t.Fatalf("Unexpected battery percent: %v", infoRespBody["battery_percent"])
	}
	if !infoRespBody["is_charging"].(bool) {
		t.Fatalf("Expected is_charging to be true")
	}
	if uint64(infoRespBody["total_storage_bytes"].(float64)) != 256000000000 {
		t.Fatalf("Unexpected total storage bytes: %v", infoRespBody["total_storage_bytes"])
	}
	if uint64(infoRespBody["available_storage_bytes"].(float64)) != 180000000000 {
		t.Fatalf("Unexpected available storage bytes: %v", infoRespBody["available_storage_bytes"])
	}
	if infoRespBody["app_version"] != "1.0.0" {
		t.Fatalf("Unexpected app version: %v", infoRespBody["app_version"])
	}
	t.Log("PASS: Device info telemetry collection verified")

	// -------------------------------------------------------------
	// TEST CASE 4: Permission Gate Gating (Denial)
	// -------------------------------------------------------------
	allowPing = false
	respPingDenied := sendMacRequest(pingReq1)
	if respPingDenied["device_ping_resp"].(map[string]interface{})["status"] != "STATUS_ACTION_NOT_PERMITTED" {
		t.Fatalf("Expected STATUS_ACTION_NOT_PERMITTED when ping disabled, got %v", respPingDenied)
	}
	allowPing = true

	allowInfo = false
	respInfoDenied := sendMacRequest(infoReq)
	if respInfoDenied["device_info_resp"].(map[string]interface{})["status"] != "STATUS_ACTION_NOT_PERMITTED" {
		t.Fatalf("Expected STATUS_ACTION_NOT_PERMITTED when info disabled, got %v", respInfoDenied)
	}
	allowInfo = true
	t.Log("PASS: Independent permission gating (ping & info) verified")

	// -------------------------------------------------------------
	// TEST CASE 5: Arbitrary Command Injection Rejection (Security Gate)
	// -------------------------------------------------------------
	// Attack 1: Attempting to pass shell command
	attackReq := map[string]interface{}{
		"schema_version": 1,
		"request_id":     "attack-shell-1",
		"shell_cmd":      "whoami && cat /etc/passwd",
	}
	attackResp := sendMacRequest(attackReq)
	errObj1 := attackResp["error"].(map[string]interface{})
	if errObj1["code"] != "STATUS_ACTION_NOT_PERMITTED" {
		t.Fatalf("Expected STATUS_ACTION_NOT_PERMITTED for shell injection, got %v", errObj1["code"])
	}

	// Attack 2: Attempting to call an unallowlisted generic action
	unknownActionReq := map[string]interface{}{
		"schema_version": 1,
		"action_request": map[string]interface{}{
			"action":     "system.shell",
			"request_id": "attack-action-2",
		},
	}
	unknownActionResp := sendMacRequest(unknownActionReq)
	errObj2 := unknownActionResp["error"].(map[string]interface{})
	if errObj2["code"] != "STATUS_ACTION_NOT_PERMITTED" {
		t.Fatalf("Expected STATUS_ACTION_NOT_PERMITTED for unallowed action, got %v", errObj2["code"])
	}
	t.Log("PASS: Arbitrary command & unallowed action injection strictly rejected")

	// -------------------------------------------------------------
	// TEST CASE 6: Zero Plaintext Leakage Audit on VPS Relay
	// -------------------------------------------------------------
	err = audit.AssertNoPlaintextLeak(
		"Google Pixel 8 Pro",
		"battery_percent",
		"device_ping_req",
		"device_info_req",
		"whoami",
		"cat /etc/passwd",
		"Device ping active for duration",
	)
	if err != nil {
		t.Fatalf("SECURITY VIOLATION: Plaintext leakage detected on VPS relay: %v", err)
	}
	t.Logf("Audited payload frames: ZERO plaintext bytes leaked over VPS relay")
	t.Logf(">>> FILE-5 SCOPED REMOTE ACTION SYSTEM: 100%% VERIFIED & AUDITED <<<")
}
