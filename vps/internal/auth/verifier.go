package auth

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"
)

var (
	ErrClockSkewExceeded  = errors.New("client timestamp clock skew exceeds 30 seconds")
	ErrInvalidNonce       = errors.New("invalid or expired server nonce")
	ErrReplayDetected     = errors.New("server nonce has already been consumed (replay detected)")
	ErrInvalidSignature   = errors.New("cryptographic signature verification failed")
	ErrUnsupportedKeyAlg  = errors.New("unsupported key algorithm")
	ErrDeviceIDMismatch   = errors.New("device ID does not match public key fingerprint")
)

const (
	NonceSize              = 32
	MaxClockSkewSeconds    = 30
	ChallengeValidityDuration = 60 * time.Second
)

type activeChallenge struct {
	serverNonce []byte
	issuedAt    time.Time
}

// ChallengeTracker manages single-use authentication challenges and enforces replay protection.
type ChallengeTracker struct {
	mu         sync.Mutex
	challenges map[string]map[string]activeChallenge // deviceID -> hex(nonce) -> activeChallenge
}

// NewChallengeTracker initializes a new ChallengeTracker.
func NewChallengeTracker() *ChallengeTracker {
	ct := &ChallengeTracker{
		challenges: make(map[string]map[string]activeChallenge),
	}
	go ct.startJanitor(30 * time.Second)
	return ct
}

func (ct *ChallengeTracker) startJanitor(interval time.Duration) {
	ticker := time.NewTicker(interval)
	for range ticker.C {
		ct.cleanupExpired()
	}
}

func (ct *ChallengeTracker) cleanupExpired() {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	now := time.Now()
	for devID, nonces := range ct.challenges {
		for nonceHex, ch := range nonces {
			if now.Sub(ch.issuedAt) > ChallengeValidityDuration {
				delete(nonces, nonceHex)
			}
		}
		if len(nonces) == 0 {
			delete(ct.challenges, devID)
		}
	}
}

// GenerateChallenge creates a 32-byte cryptographically secure server nonce and records it.
func (ct *ChallengeTracker) GenerateChallenge(deviceID string) ([]byte, int64, error) {
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, 0, fmt.Errorf("failed to generate random server nonce: %w", err)
	}

	now := time.Now()
	timestamp := now.Unix()

	ct.mu.Lock()
	defer ct.mu.Unlock()

	if ct.challenges[deviceID] == nil {
		ct.challenges[deviceID] = make(map[string]activeChallenge)
	}

	ct.challenges[deviceID][hex.EncodeToString(nonce)] = activeChallenge{
		serverNonce: nonce,
		issuedAt:    now,
	}

	return nonce, timestamp, nil
}

// ValidateAndConsumeChallenge verifies that the nonce was issued to this device, is unexpired,
// satisfies clock-skew constraints, and consumes it so it cannot be reused.
func (ct *ChallengeTracker) ValidateAndConsumeChallenge(deviceID string, serverNonce []byte, clientTimestamp int64) error {
	now := time.Now()

	// Normalize client timestamp: if in milliseconds (> 10^11), convert to seconds
	clientSec := clientTimestamp
	if clientTimestamp > 1_000_000_000_000 {
		clientSec = clientTimestamp / 1000
	}

	skew := math.Abs(float64(now.Unix() - clientSec))
	if skew > MaxClockSkewSeconds {
		return fmt.Errorf("%w: server=%d client=%d skew=%.1fs", ErrClockSkewExceeded, now.Unix(), clientSec, skew)
	}

	ct.mu.Lock()
	defer ct.mu.Unlock()

	deviceNonces, ok := ct.challenges[deviceID]
	if !ok {
		return ErrInvalidNonce
	}

	nonceHex := hex.EncodeToString(serverNonce)
	ch, exists := deviceNonces[nonceHex]
	if !exists {
		return ErrInvalidNonce
	}

	// Consume immediately
	delete(deviceNonces, nonceHex)
	if len(deviceNonces) == 0 {
		delete(ct.challenges, deviceID)
	}

	if now.Sub(ch.issuedAt) > ChallengeValidityDuration {
		return ErrInvalidNonce
	}

	return nil
}

// DeriveDeviceID computes HEX(SHA-256(publicKey)).
func DeriveDeviceID(publicKey []byte) string {
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:])
}

// BuildChallengeData constructs the canonical challenge byte slice:
// serverNonce || clientNonce || 8-byte big-endian timestamp
func BuildChallengeData(serverNonce, clientNonce []byte, timestamp int64) []byte {
	buf := make([]byte, len(serverNonce)+len(clientNonce)+8)
	copy(buf[0:], serverNonce)
	copy(buf[len(serverNonce):], clientNonce)
	binary.BigEndian.PutUint64(buf[len(serverNonce)+len(clientNonce):], uint64(timestamp))
	return buf
}

// VerifySignature validates a signature over the challenge payload.
// Supports AlgorithmECDSAP256 (SHA256withECDSA / ASN.1 DER) and AlgorithmEd25519.
func VerifySignature(publicKey []byte, keyAlgorithm string, challengeData, signature []byte) error {
	switch keyAlgorithm {
	case AlgorithmEd25519:
		if len(publicKey) != ed25519.PublicKeySize {
			return fmt.Errorf("%w: Ed25519 public key must be 32 bytes, got %d", ErrInvalidPublicKey, len(publicKey))
		}
		if !ed25519.Verify(publicKey, challengeData, signature) {
			return ErrInvalidSignature
		}
		return nil

	case AlgorithmECDSAP256:
		// Attempt parsing SubjectPublicKeyInfo (X.509 PKIX DER)
		parsedKey, err := x509.ParsePKIXPublicKey(publicKey)
		if err != nil {
			return fmt.Errorf("%w: failed to parse ECDSA PKIX public key: %v", ErrInvalidPublicKey, err)
		}

		ecdsaPub, ok := parsedKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: key is not ECDSA public key", ErrInvalidPublicKey)
		}

		hash := sha256.Sum256(challengeData)
		if !ecdsa.VerifyASN1(ecdsaPub, hash[:], signature) {
			return ErrInvalidSignature
		}
		return nil

	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedKeyAlg, keyAlgorithm)
	}
}
