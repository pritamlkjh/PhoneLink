package integration

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
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

// TestINT2DeviceDiscoveryAndStatusReporting validates INT-2:
// 1. Initial paired offline status reporting via REST and WebSocket.
// 2. Real-time connect latency bound (< 1000ms) from phone connection to Mac notification.
// 3. Real-time disconnect latency bound (< 1000ms) from phone disconnect to Mac notification.
// 4. REST endpoint (/api/v1/devices/status) reflection of peer online/offline state.
// 5. Multi-cycle rapid connectivity toggling with 100% ordered presence transitions.
func TestINT2DeviceDiscoveryAndStatusReporting(t *testing.T) {
	// 1. Initialize VPS Relay Server
	srv := server.NewServer(server.DefaultConfig(), nil)
	httpServer := httptest.NewServer(srv.Handler())
	defer httpServer.Close()

	wsBaseURL := "ws" + strings.TrimPrefix(httpServer.URL, "http")

	// 2. Generate Mac and Android Device Identities
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

	// 3. Register Both Devices
	registerDevice(t, httpServer.URL, macDeviceID, auth.DeviceTypeMac, base64.StdEncoding.EncodeToString(macPub), auth.AlgorithmEd25519)
	registerDevice(t, httpServer.URL, andDeviceID, auth.DeviceTypeAndroid, base64.StdEncoding.EncodeToString(andPubDER), auth.AlgorithmECDSAP256)

	// 4. Authenticate Both Devices and Acquire Session Tokens
	macToken := authenticateEd25519(t, httpServer.URL, macDeviceID, macPriv)
	andToken := authenticateECDSA(t, httpServer.URL, andDeviceID, andPriv, andPubDER)

	// 5. Verify Unpaired Status via REST
	statusReq, _ := http.NewRequest(http.MethodGet, httpServer.URL+"/api/v1/devices/status", nil)
	statusReq.Header.Set("Authorization", "Bearer "+macToken)
	resp, err := http.DefaultClient.Do(statusReq)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("failed to query status: %v", err)
	}
	var status server.DeviceStatusResponse
	_ = json.NewDecoder(resp.Body).Decode(&status)
	_ = resp.Body.Close()

	if status.IsPaired {
		t.Errorf("expected is_paired false before pairing")
	}
	if status.PeerOnline {
		t.Errorf("expected peer_online false before pairing")
	}

	// 6. Complete Out-of-Band Pairing Ceremony
	pairToken := createPairingToken(t, httpServer.URL, macDeviceID, macToken)
	claimPairing(t, httpServer.URL, pairToken, andDeviceID)

	// 7. Verify Paired but Offline Status via REST
	statusReq, _ = http.NewRequest(http.MethodGet, httpServer.URL+"/api/v1/devices/status", nil)
	statusReq.Header.Set("Authorization", "Bearer "+macToken)
	resp, err = http.DefaultClient.Do(statusReq)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("failed to query status: %v", err)
	}
	status = server.DeviceStatusResponse{}
	_ = json.NewDecoder(resp.Body).Decode(&status)
	_ = resp.Body.Close()

	if !status.IsPaired {
		t.Errorf("expected is_paired true after pairing")
	}
	if status.PeerDeviceID != andDeviceID {
		t.Errorf("expected peer_device_id %s, got %s", andDeviceID, status.PeerDeviceID)
	}
	if status.PeerOnline {
		t.Errorf("expected peer_online false before phone connects")
	}

	// 8. Connect Mac Client via WebSocket
	macWSURL := wsBaseURL + "/ws/v1/connect?token=" + macToken
	macConn, _, err := websocket.DefaultDialer.Dial(macWSURL, nil)
	if err != nil {
		t.Fatalf("Mac WebSocket dial failed: %v", err)
	}
	defer macConn.Close()

	// Mac must immediately receive initial offline presence event
	_, initialPresenceRaw, err := macConn.ReadMessage()
	if err != nil {
		t.Fatalf("Mac failed to receive initial presence: %v", err)
	}
	var initialPresence coordinator.PeerStatusEvent
	if err := json.Unmarshal(initialPresenceRaw, &initialPresence); err != nil {
		t.Fatalf("failed to unmarshal initial presence: %v", err)
	}
	if initialPresence.IsOnline {
		t.Errorf("expected phone offline initially, got online")
	}
	if initialPresence.PeerDeviceID != andDeviceID {
		t.Errorf("expected peer %s, got %s", andDeviceID, initialPresence.PeerDeviceID)
	}

	// 9. TEST CONNECT LATENCY BOUND:
	// Android connects. Measure latency until Mac receives PEER_STATUS(is_online: true)
	andWSURL := wsBaseURL + "/ws/v1/connect?token=" + andToken
	tConnectStart := time.Now()

	andConn, _, err := websocket.DefaultDialer.Dial(andWSURL, nil)
	if err != nil {
		t.Fatalf("Android WebSocket dial failed: %v", err)
	}

	// Android receives initial presence (Mac is online)
	_, andPresenceRaw, err := andConn.ReadMessage()
	if err != nil {
		t.Fatalf("Android failed to receive initial presence: %v", err)
	}
	var andPresence coordinator.PeerStatusEvent
	_ = json.Unmarshal(andPresenceRaw, &andPresence)
	if !andPresence.IsOnline {
		t.Errorf("Android expected Mac to be online, got offline")
	}

	// Mac receives peer online event
	_, onlinePresenceRaw, err := macConn.ReadMessage()
	if err != nil {
		t.Fatalf("Mac failed to receive online event: %v", err)
	}
	tConnectDuration := time.Since(tConnectStart)

	var onlinePresence coordinator.PeerStatusEvent
	if err := json.Unmarshal(onlinePresenceRaw, &onlinePresence); err != nil {
		t.Fatalf("failed to parse online event: %v", err)
	}
	if !onlinePresence.IsOnline {
		t.Errorf("expected phone to be online")
	}

	t.Logf("Measured Android Connect -> Mac Presence Notification Latency: %v", tConnectDuration)
	const maxAllowedLatency = 1000 * time.Millisecond
	if tConnectDuration > maxAllowedLatency {
		t.Fatalf("Connect presence latency %v exceeded maximum allowed bound of %v", tConnectDuration, maxAllowedLatency)
	}

	// REST check: status must now report peer_online: true
	statusReq, _ = http.NewRequest(http.MethodGet, httpServer.URL+"/api/v1/devices/status", nil)
	statusReq.Header.Set("Authorization", "Bearer "+macToken)
	resp, _ = http.DefaultClient.Do(statusReq)
	status = server.DeviceStatusResponse{}
	_ = json.NewDecoder(resp.Body).Decode(&status)
	_ = resp.Body.Close()
	if !status.PeerOnline {
		t.Errorf("REST status did not reflect phone online")
	}

	// 10. TEST DISCONNECT LATENCY BOUND:
	// Android disconnects. Measure latency until Mac receives PEER_STATUS(is_online: false)
	tDisconnectStart := time.Now()
	_ = andConn.Close()

	_, offlinePresenceRaw, err := macConn.ReadMessage()
	if err != nil {
		t.Fatalf("Mac failed to receive offline event: %v", err)
	}
	tDisconnectDuration := time.Since(tDisconnectStart)

	var offlinePresence coordinator.PeerStatusEvent
	if err := json.Unmarshal(offlinePresenceRaw, &offlinePresence); err != nil {
		t.Fatalf("failed to parse offline event: %v", err)
	}
	if offlinePresence.IsOnline {
		t.Errorf("expected phone to be offline after disconnect")
	}

	t.Logf("Measured Android Disconnect -> Mac Presence Notification Latency: %v", tDisconnectDuration)
	if tDisconnectDuration > maxAllowedLatency {
		t.Fatalf("Disconnect presence latency %v exceeded maximum allowed bound of %v", tDisconnectDuration, maxAllowedLatency)
	}

	// REST check: status must now report peer_online: false
	statusReq, _ = http.NewRequest(http.MethodGet, httpServer.URL+"/api/v1/devices/status", nil)
	statusReq.Header.Set("Authorization", "Bearer "+macToken)
	resp, _ = http.DefaultClient.Do(statusReq)
	status = server.DeviceStatusResponse{}
	_ = json.NewDecoder(resp.Body).Decode(&status)
	_ = resp.Body.Close()
	if status.PeerOnline {
		t.Errorf("REST status did not reflect phone offline")
	}

	// 11. MULTI-CYCLE TOGGLE RESILIENCE TEST:
	// Verify 3 rapid connect/disconnect cycles
	for cycle := 1; cycle <= 3; cycle++ {
		cConn, _, err := websocket.DefaultDialer.Dial(andWSURL, nil)
		if err != nil {
			t.Fatalf("cycle %d connect failed: %v", cycle, err)
		}
		// Discard android's own initial presence
		_, _, _ = cConn.ReadMessage()

		// Mac receives online
		_, raw, err := macConn.ReadMessage()
		if err != nil {
			t.Fatalf("cycle %d online read failed: %v", cycle, err)
		}
		var evt coordinator.PeerStatusEvent
		_ = json.Unmarshal(raw, &evt)
		if !evt.IsOnline {
			t.Fatalf("cycle %d expected online, got offline", cycle)
		}

		// Disconnect
		_ = cConn.Close()

		// Mac receives offline
		_, raw, err = macConn.ReadMessage()
		if err != nil {
			t.Fatalf("cycle %d offline read failed: %v", cycle, err)
		}
		_ = json.Unmarshal(raw, &evt)
		if evt.IsOnline {
			t.Fatalf("cycle %d expected offline, got online", cycle)
		}
	}

	t.Log(">>> INT-2 DEVICE DISCOVERY & STATUS REPORTING: 100% VERIFIED <<<")
}
