package coordinator

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/pritamlkjh/phonelink/vps/internal/auth"
)

func setupTestPair(t *testing.T) (*auth.Registry, *Coordinator, string, string) {
	t.Helper()
	reg := auth.NewRegistry()
	coord := NewCoordinator(reg)

	macID := "mac-device-id-001"
	andID := "and-device-id-002"

	_ = reg.RegisterDevice(auth.DeviceRecord{
		DeviceID:     macID,
		DeviceType:   auth.DeviceTypeMac,
		PublicKey:    []byte("dummy-mac-pubkey-bytes-12345678"),
		KeyAlgorithm: auth.AlgorithmEd25519,
	})
	_ = reg.RegisterDevice(auth.DeviceRecord{
		DeviceID:     andID,
		DeviceType:   auth.DeviceTypeAndroid,
		PublicKey:    []byte("dummy-and-pubkey-bytes-12345678"),
		KeyAlgorithm: auth.AlgorithmECDSAP256,
	})

	_ = reg.PairDevices(macID, andID)
	return reg, coord, macID, andID
}

func TestConnectAndPresenceNotifications(t *testing.T) {
	_, coord, macID, andID := setupTestPair(t)

	macChan := make(chan []byte, 10)
	andChan := make(chan []byte, 10)

	// 1. Mac connects first
	_, err := coord.ConnectSession(macID, macChan, nil)
	if err != nil {
		t.Fatalf("failed to connect Mac session: %v", err)
	}

	if !coord.IsDeviceOnline(macID) {
		t.Fatalf("Mac should be reported online")
	}
	if coord.IsDeviceOnline(andID) {
		t.Fatalf("Android should be reported offline")
	}

	// Mac should have received initial status: Android is offline
	msg1 := <-macChan
	var status1 PeerStatusEvent
	_ = json.Unmarshal(msg1, &status1)
	if status1.IsOnline {
		t.Fatalf("Android should initially be reported offline to Mac")
	}

	// 2. Android connects
	_, err = coord.ConnectSession(andID, andChan, nil)
	if err != nil {
		t.Fatalf("failed to connect Android session: %v", err)
	}

	if !coord.IsDeviceOnline(andID) {
		t.Fatalf("Android should be reported online")
	}

	// Android should receive status: Mac is online
	andMsg := <-andChan
	var andStatus PeerStatusEvent
	_ = json.Unmarshal(andMsg, &andStatus)
	if !andStatus.IsOnline || andStatus.PeerDeviceID != macID {
		t.Fatalf("Android should be told Mac is online, got: %+v", andStatus)
	}

	// Mac should receive status update: Android is now online
	macMsg2 := <-macChan
	var macStatus2 PeerStatusEvent
	_ = json.Unmarshal(macMsg2, &macStatus2)
	if !macStatus2.IsOnline || macStatus2.PeerDeviceID != andID {
		t.Fatalf("Mac should be told Android is now online, got: %+v", macStatus2)
	}
}

func TestOpaquePayloadRelaying(t *testing.T) {
	_, coord, macID, andID := setupTestPair(t)

	macChan := make(chan []byte, 10)
	andChan := make(chan []byte, 10)

	_, _ = coord.ConnectSession(macID, macChan, nil)
	_, _ = coord.ConnectSession(andID, andChan, nil)

	// Drain initial presence events
	<-macChan
	<-macChan
	<-andChan

	// Mac sends encrypted ciphertext to Android
	ciphertextPayload := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04}
	err := coord.ForwardPayload(macID, andID, ciphertextPayload)
	if err != nil {
		t.Fatalf("forward payload failed: %v", err)
	}

	// Android receives verbatim
	received := <-andChan
	if !bytes.Equal(received, ciphertextPayload) {
		t.Fatalf("Android did not receive exact verbatim payload: got %v", received)
	}

	// Android replies
	replyPayload := []byte{0xCA, 0xFE, 0xBA, 0xBE, 0x05, 0x06, 0x07, 0x08}
	err = coord.ForwardPayload(andID, macID, replyPayload)
	if err != nil {
		t.Fatalf("reply forward failed: %v", err)
	}

	receivedMac := <-macChan
	if !bytes.Equal(receivedMac, replyPayload) {
		t.Fatalf("Mac did not receive exact verbatim reply: got %v", receivedMac)
	}
}

func TestAdversarialCrossPairingRejection(t *testing.T) {
	reg, coord, macID, andID := setupTestPair(t)

	// Register an unrelated 3rd device
	attackerID := "attacker-device-007"
	_ = reg.RegisterDevice(auth.DeviceRecord{
		DeviceID:     attackerID,
		DeviceType:   auth.DeviceTypeMac,
		PublicKey:    []byte("attacker-pubkey-bytes"),
		KeyAlgorithm: auth.AlgorithmEd25519,
	})

	macChan := make(chan []byte, 10)
	andChan := make(chan []byte, 10)
	attackerChan := make(chan []byte, 10)

	_, _ = coord.ConnectSession(macID, macChan, nil)
	_, _ = coord.ConnectSession(andID, andChan, nil)

	// Attacker tries to connect without being paired
	_, err := coord.ConnectSession(attackerID, attackerChan, nil)
	if !errors.Is(err, ErrDeviceNotPaired) {
		t.Fatalf("unpaired device should not be able to connect session, got: %v", err)
	}

	// Attacker tries to forward payload to Android
	err = coord.ForwardPayload(attackerID, andID, []byte("injected-malicious-packet"))
	if err != ErrSessionNotFound {
		t.Fatalf("unconnected attacker should fail with ErrSessionNotFound, got: %v", err)
	}

	// Even if attacker was paired with a different device B, sending to Android must fail
	otherID := "other-target-008"
	_ = reg.RegisterDevice(auth.DeviceRecord{
		DeviceID:     otherID,
		DeviceType:   auth.DeviceTypeAndroid,
		PublicKey:    []byte("other-pubkey-bytes"),
		KeyAlgorithm: auth.AlgorithmECDSAP256,
	})
	_ = reg.PairDevices(attackerID, otherID)

	_, err = coord.ConnectSession(attackerID, attackerChan, nil)
	if err != nil {
		t.Fatalf("attacker should connect to its own session: %v", err)
	}

	// Now attacker tries to forward to andID (not its pair!)
	err = coord.ForwardPayload(attackerID, andID, []byte("spoofed-payload"))
	if err != ErrUnauthorizedRecipient {
		t.Fatalf("expected ErrUnauthorizedRecipient when attempting cross-pair relay, got: %v", err)
	}
}

func TestDisconnectNotification(t *testing.T) {
	_, coord, macID, andID := setupTestPair(t)

	macChan := make(chan []byte, 10)
	andChan := make(chan []byte, 10)

	_, _ = coord.ConnectSession(macID, macChan, nil)
	_, _ = coord.ConnectSession(andID, andChan, nil)

	// Drain initial presence events
	<-macChan
	<-macChan
	<-andChan

	// Android disconnects
	coord.DisconnectSession(andID)

	if coord.IsDeviceOnline(andID) {
		t.Fatalf("Android should be marked offline")
	}

	// Mac must receive offline notification
	macMsg := <-macChan
	var status PeerStatusEvent
	_ = json.Unmarshal(macMsg, &status)
	if status.IsOnline || status.PeerDeviceID != andID {
		t.Fatalf("Mac should receive offline notification for Android, got: %+v", status)
	}

	// Forwarding to offline peer must return ErrPeerOffline
	err := coord.ForwardPayload(macID, andID, []byte("hello"))
	if err != ErrPeerOffline {
		t.Fatalf("expected ErrPeerOffline, got: %v", err)
	}
}

func TestDisconnectIfSessionDoesNotEvictNewSession(t *testing.T) {
	_, coord, macID, andID := setupTestPair(t)

	oldAndChan := make(chan []byte, 10)
	newAndChan := make(chan []byte, 10)
	macChan := make(chan []byte, 10)

	_, _ = coord.ConnectSession(macID, macChan, nil)
	oldClosed := false
	oldSess, err := coord.ConnectSession(andID, oldAndChan, func() { oldClosed = true })
	if err != nil {
		t.Fatalf("failed to connect old session: %v", err)
	}

	// Drain initial online events
	<-macChan
	<-macChan

	// New session reconnects before old session's defer runs
	newSess, err := coord.ConnectSession(andID, newAndChan, nil)
	if err != nil {
		t.Fatalf("failed to connect replacement session: %v", err)
	}
	if !oldClosed {
		t.Fatalf("expected prior session CloseFunc to be invoked on replacement")
	}

	// Drain initial self PEER_STATUS notification emitted on new session attach
	<-newAndChan

	// Old goroutine exits and calls DisconnectIfSession(andID, oldSess)
	coord.DisconnectIfSession(andID, oldSess)

	if !coord.IsDeviceOnline(andID) {
		t.Fatalf("new session was evicted by stale DisconnectIfSession")
	}

	// Verify ForwardPayload reaches newAndChan
	payload := []byte("still-alive")
	if err := coord.ForwardPayload(macID, andID, payload); err != nil {
		t.Fatalf("expected forward to active replacement session to succeed, got: %v", err)
	}
	got := <-newAndChan
	if !bytes.Equal(got, payload) {
		t.Fatalf("expected %q, got %q", payload, got)
	}

	// Disconnecting matching newSess removes it cleanly
	coord.DisconnectIfSession(andID, newSess)
	if coord.IsDeviceOnline(andID) {
		t.Fatalf("expected matching session disconnect to mark device offline")
	}
}

func TestTerminateAllAndRevokedForwardBlocked(t *testing.T) {
	reg, coord, macID, andID := setupTestPair(t)

	macClosed := false
	andClosed := false
	_, _ = coord.ConnectSession(macID, make(chan []byte, 4), func() { macClosed = true })
	_, _ = coord.ConnectSession(andID, make(chan []byte, 4), func() { andClosed = true })

	_ = reg.RevokeDevice(andID)
	if err := coord.ForwardPayload(macID, andID, []byte("blocked")); err != ErrPeerOffline {
		t.Fatalf("expected revoked target to block ForwardPayload, got %v", err)
	}

	coord.TerminateAll()
	if !macClosed || !andClosed {
		t.Fatalf("expected TerminateAll to close all active sessions (mac=%v, and=%v)", macClosed, andClosed)
	}
	if coord.IsDeviceOnline(macID) || coord.IsDeviceOnline(andID) {
		t.Fatalf("expected no active sessions after TerminateAll")
	}
}
