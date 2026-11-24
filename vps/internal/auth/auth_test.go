package auth

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"testing"
	"time"
)

func generateTestECDSAKey(t *testing.T) (*ecdsa.PrivateKey, []byte, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal ECDSA public key: %v", err)
	}

	deviceID := DeriveDeviceID(pubDER)
	return priv, pubDER, deviceID
}

func generateTestEd25519Key(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}
	deviceID := DeriveDeviceID(pub)
	return priv, pub, deviceID
}

func TestRegisterAndGetDevice(t *testing.T) {
	reg := NewRegistry()
	_, pubDER, deviceID := generateTestECDSAKey(t)

	rec := DeviceRecord{
		DeviceID:     deviceID,
		DeviceType:   DeviceTypeAndroid,
		PublicKey:    pubDER,
		KeyAlgorithm: AlgorithmECDSAP256,
	}

	if err := reg.RegisterDevice(rec); err != nil {
		t.Fatalf("failed to register device: %v", err)
	}

	// Duplicate registration must fail
	if err := reg.RegisterDevice(rec); err != ErrDeviceAlreadyRegistered {
		t.Fatalf("expected ErrDeviceAlreadyRegistered, got: %v", err)
	}

	// Fetch device
	fetched, err := reg.GetDevice(deviceID)
	if err != nil {
		t.Fatalf("failed to get device: %v", err)
	}
	if fetched.DeviceID != deviceID {
		t.Fatalf("expected device ID %s, got %s", deviceID, fetched.DeviceID)
	}
	if !reg.IsAuthorized(deviceID) {
		t.Fatalf("expected device to be authorized")
	}
}

func TestUnregisteredDeviceRejected(t *testing.T) {
	reg := NewRegistry()
	_, err := reg.GetDevice("non-existent-device-id")
	if err != ErrDeviceNotFound {
		t.Fatalf("expected ErrDeviceNotFound, got: %v", err)
	}
	if reg.IsAuthorized("non-existent-device-id") {
		t.Fatalf("unregistered device must not be authorized")
	}

	_, err = reg.CreateSession("non-existent-device-id", time.Hour)
	if err != ErrDeviceNotFound {
		t.Fatalf("expected ErrDeviceNotFound for session creation, got: %v", err)
	}
}

func TestImmediateRevocation(t *testing.T) {
	reg := NewRegistry()
	_, pubDER, deviceID := generateTestECDSAKey(t)

	rec := DeviceRecord{
		DeviceID:     deviceID,
		DeviceType:   DeviceTypeMac,
		PublicKey:    pubDER,
		KeyAlgorithm: AlgorithmECDSAP256,
	}

	if err := reg.RegisterDevice(rec); err != nil {
		t.Fatalf("register failed: %v", err)
	}

	sessionToken, err := reg.CreateSession(deviceID, time.Hour)
	if err != nil {
		t.Fatalf("create session failed: %v", err)
	}

	// Session is valid before revocation
	valDevID, err := reg.ValidateSession(sessionToken)
	if err != nil || valDevID != deviceID {
		t.Fatalf("session should be valid, got devID=%s, err=%v", valDevID, err)
	}

	// Revoke device
	if err := reg.RevokeDevice(deviceID); err != nil {
		t.Fatalf("revoke failed: %v", err)
	}

	// Immediate effect checks:
	// 1. Device is no longer authorized
	if reg.IsAuthorized(deviceID) {
		t.Fatalf("revoked device must NOT be authorized")
	}

	// 2. Existing session is immediately invalidated
	_, err = reg.ValidateSession(sessionToken)
	if err != ErrSessionNotFound && err != ErrDeviceRevoked {
		t.Fatalf("expected session invalidation after device revocation, got: %v", err)
	}

	// 3. New session creation is rejected
	_, err = reg.CreateSession(deviceID, time.Hour)
	if err != ErrDeviceRevoked {
		t.Fatalf("expected ErrDeviceRevoked for new session, got: %v", err)
	}
}

func TestChallengeHandshakeECDSA(t *testing.T) {
	reg := NewRegistry()
	tracker := NewChallengeTracker()

	priv, pubDER, deviceID := generateTestECDSAKey(t)
	if err := reg.RegisterDevice(DeviceRecord{
		DeviceID:     deviceID,
		DeviceType:   DeviceTypeAndroid,
		PublicKey:    pubDER,
		KeyAlgorithm: AlgorithmECDSAP256,
	}); err != nil {
		t.Fatalf("register failed: %v", err)
	}

	// 1. Generate challenge
	serverNonce, timestamp, err := tracker.GenerateChallenge(deviceID)
	if err != nil {
		t.Fatalf("generate challenge failed: %v", err)
	}
	if len(serverNonce) != 32 {
		t.Fatalf("expected 32-byte server nonce, got %d", len(serverNonce))
	}

	// 2. Client signs challenge
	clientNonce := make([]byte, 32)
	_, _ = rand.Read(clientNonce)
	challengeData := BuildChallengeData(serverNonce, clientNonce, timestamp)

	hash := sha256.Sum256(challengeData)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, hash[:])
	if err != nil {
		t.Fatalf("failed to sign challenge: %v", err)
	}

	// 3. Server validates & consumes challenge
	if err := tracker.ValidateAndConsumeChallenge(deviceID, serverNonce, timestamp); err != nil {
		t.Fatalf("validate challenge failed: %v", err)
	}

	// 4. Server verifies cryptographic signature
	dev, err := reg.GetDevice(deviceID)
	if err != nil {
		t.Fatalf("failed to get device: %v", err)
	}

	if err := VerifySignature(dev.PublicKey, dev.KeyAlgorithm, challengeData, sig); err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}

	// 5. Issue session
	sessionToken, err := reg.CreateSession(deviceID, 24*time.Hour)
	if err != nil {
		t.Fatalf("session creation failed: %v", err)
	}
	if sessionToken == "" {
		t.Fatalf("expected non-empty session token")
	}

	// 6. Replay attempt: try consuming same challenge again -> must fail
	if err := tracker.ValidateAndConsumeChallenge(deviceID, serverNonce, timestamp); err == nil {
		t.Fatalf("replaying already consumed nonce must fail")
	}
}

func TestChallengeHandshakeEd25519(t *testing.T) {
	reg := NewRegistry()
	tracker := NewChallengeTracker()

	priv, pub, deviceID := generateTestEd25519Key(t)
	if err := reg.RegisterDevice(DeviceRecord{
		DeviceID:     deviceID,
		DeviceType:   DeviceTypeMac,
		PublicKey:    pub,
		KeyAlgorithm: AlgorithmEd25519,
	}); err != nil {
		t.Fatalf("register failed: %v", err)
	}

	serverNonce, timestamp, err := tracker.GenerateChallenge(deviceID)
	if err != nil {
		t.Fatalf("generate challenge failed: %v", err)
	}

	clientNonce := make([]byte, 32)
	_, _ = rand.Read(clientNonce)
	challengeData := BuildChallengeData(serverNonce, clientNonce, timestamp)

	sig := ed25519.Sign(priv, challengeData)

	if err := tracker.ValidateAndConsumeChallenge(deviceID, serverNonce, timestamp); err != nil {
		t.Fatalf("validate challenge failed: %v", err)
	}

	dev, _ := reg.GetDevice(deviceID)
	if err := VerifySignature(dev.PublicKey, dev.KeyAlgorithm, challengeData, sig); err != nil {
		t.Fatalf("Ed25519 signature verification failed: %v", err)
	}
}

func TestTamperedSignatureRejection(t *testing.T) {
	_, pubDER, deviceID := generateTestECDSAKey(t)
	serverNonce := make([]byte, 32)
	clientNonce := make([]byte, 32)
	timestamp := time.Now().Unix()
	challengeData := BuildChallengeData(serverNonce, clientNonce, timestamp)

	// Corrupt signature bytes
	badSig := []byte("invalid-signature-bytes")

	err := VerifySignature(pubDER, AlgorithmECDSAP256, challengeData, badSig)
	if err == nil {
		t.Fatalf("tampered signature must be rejected")
	}
	_ = deviceID
}

func TestClockSkewRejection(t *testing.T) {
	tracker := NewChallengeTracker()
	deviceID := "test-clock-skew-device"
	serverNonce, _, err := tracker.GenerateChallenge(deviceID)
	if err != nil {
		t.Fatalf("failed to generate challenge: %v", err)
	}

	// Client timestamp skewed by 31 seconds into future
	skewedTimestamp := time.Now().Unix() + 31
	err = tracker.ValidateAndConsumeChallenge(deviceID, serverNonce, skewedTimestamp)
	if err == nil {
		t.Fatalf("expected clock skew rejection when skew > 30s")
	}
}

func TestPairingCeremonyAndRevocation(t *testing.T) {
	reg := NewRegistry()
	_, macPub, macID := generateTestEd25519Key(t)
	_, andPub, andID := generateTestECDSAKey(t)

	_ = reg.RegisterDevice(DeviceRecord{DeviceID: macID, DeviceType: DeviceTypeMac, PublicKey: macPub, KeyAlgorithm: AlgorithmEd25519})
	_ = reg.RegisterDevice(DeviceRecord{DeviceID: andID, DeviceType: DeviceTypeAndroid, PublicKey: andPub, KeyAlgorithm: AlgorithmECDSAP256})

	// Mac creates pairing token
	token, err := reg.CreatePairingToken(macID, 5*time.Minute)
	if err != nil {
		t.Fatalf("failed to create pairing token: %v", err)
	}

	// Android claims pairing token
	if err := reg.ClaimPairing(token, andID); err != nil {
		t.Fatalf("failed to claim pairing: %v", err)
	}

	// Check paired peer IDs
	pairedPeer, err := reg.GetPairedDevice(macID)
	if err != nil || pairedPeer != andID {
		t.Fatalf("expected paired peer to be Android %s, got %s (err: %v)", andID, pairedPeer, err)
	}

	pairedPeer2, err := reg.GetPairedDevice(andID)
	if err != nil || pairedPeer2 != macID {
		t.Fatalf("expected paired peer to be Mac %s, got %s (err: %v)", macID, pairedPeer2, err)
	}

	// Token cannot be reused
	if err := reg.ClaimPairing(token, andID); err != ErrPairingTokenNotFound {
		t.Fatalf("pairing token reuse must fail, got: %v", err)
	}

	// Revoke Mac -> Android can no longer access paired device
	_ = reg.RevokeDevice(macID)
	_, err = reg.GetPairedDevice(andID)
	if err == nil {
		t.Fatalf("expected error getting paired peer when peer is revoked")
	}
}

func TestResumptionTokenLifecycleAndValidation(t *testing.T) {
	reg := NewRegistry()
	_, pubDER, deviceID := generateTestECDSAKey(t)

	_ = reg.RegisterDevice(DeviceRecord{
		DeviceID:     deviceID,
		DeviceType:   DeviceTypeAndroid,
		PublicKey:    pubDER,
		KeyAlgorithm: AlgorithmECDSAP256,
	})

	// 1. Create resumption token with 5-minute validity window
	resToken, expiresAt, err := reg.CreateResumptionToken(deviceID, 5*time.Minute)
	if err != nil {
		t.Fatalf("failed to create resumption token: %v", err)
	}
	if len(resToken) != 64 {
		t.Fatalf("expected 64-char hex token, got %d", len(resToken))
	}
	if time.Until(expiresAt) <= 0 || time.Until(expiresAt) > 5*time.Minute {
		t.Fatalf("unexpected expiresAt: %v", expiresAt)
	}

	// 2. Consume valid resumption token successfully
	if err := reg.ValidateAndConsumeResumptionToken(deviceID, resToken); err != nil {
		t.Fatalf("expected valid consumption, got: %v", err)
	}

	// 3. Replay attack: reusing the same token must fail immediately
	if err := reg.ValidateAndConsumeResumptionToken(deviceID, resToken); err != ErrResumptionTokenNotFound {
		t.Fatalf("expected ErrResumptionTokenNotFound on reused token, got: %v", err)
	}

	// 4. Token expiration: expired token must be rejected
	expiredToken, _, err := reg.CreateResumptionToken(deviceID, -1*time.Second)
	if err != nil {
		t.Fatalf("failed to create expired token: %v", err)
	}
	if err := reg.ValidateAndConsumeResumptionToken(deviceID, expiredToken); err != ErrResumptionTokenNotFound {
		t.Fatalf("expected ErrResumptionTokenNotFound on expired token, got: %v", err)
	}

	// 5. Wrong device ID: another authorized device attempting to use this device's token must fail
	_, pubDER2, deviceID2 := generateTestECDSAKey(t)
	_ = reg.RegisterDevice(DeviceRecord{
		DeviceID:     deviceID2,
		DeviceType:   DeviceTypeAndroid,
		PublicKey:    pubDER2,
		KeyAlgorithm: AlgorithmECDSAP256,
	})
	token3, _, _ := reg.CreateResumptionToken(deviceID, 5*time.Minute)
	if err := reg.ValidateAndConsumeResumptionToken(deviceID2, token3); err != ErrResumptionTokenNotFound {
		t.Fatalf("expected ErrResumptionTokenNotFound for mismatched device, got: %v", err)
	}

	// 6. Revocation: revoking device invalidates all held resumption tokens
	token4, _, _ := reg.CreateResumptionToken(deviceID, 5*time.Minute)
	if err := reg.RevokeDevice(deviceID); err != nil {
		t.Fatalf("failed to revoke device: %v", err)
	}
	if err := reg.ValidateAndConsumeResumptionToken(deviceID, token4); err != ErrDeviceRevoked {
		t.Fatalf("expected ErrDeviceRevoked after device revocation, got: %v", err)
	}
}
