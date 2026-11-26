package auth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	ErrDeviceAlreadyRegistered = errors.New("device already registered")
	ErrDeviceNotFound          = errors.New("device not found in registry")
	ErrDeviceRevoked           = errors.New("device has been revoked")
	ErrInvalidDeviceID         = errors.New("invalid device ID")
	ErrInvalidPublicKey        = errors.New("invalid public key")
	ErrSessionNotFound         = errors.New("session not found or expired")
	ErrSessionRevoked          = errors.New("session has been revoked")
	ErrResumptionTokenNotFound = errors.New("resumption token not found or expired")
	ErrResumptionTokenUsed     = errors.New("resumption token already used")
	ErrPairingTokenNotFound    = errors.New("pairing token not found or expired")
	ErrCannotPairSelf          = errors.New("cannot pair device with itself")
)

const (
	AlgorithmECDSAP256 = "ECDSA_P256"
	AlgorithmEd25519   = "ED25519"

	DeviceTypeMac     = "mac"
	DeviceTypeAndroid = "android"

	DefaultSessionTTL      = 24 * time.Hour
	DefaultResumptionTTL   = 5 * time.Minute
	DefaultPairingTokenTTL = 5 * time.Minute
)

// DeviceRecord holds authorized device metadata.
// Security invariant: never stores raw private keys.
type DeviceRecord struct {
	DeviceID       string     `json:"device_id"`
	DeviceType     string     `json:"device_type"`
	PublicKey      []byte     `json:"public_key"`
	KeyAlgorithm   string     `json:"key_algorithm"`
	RegisteredAt   time.Time  `json:"registered_at"`
	Revoked        bool       `json:"revoked"`
	RevokedAt      *time.Time `json:"revoked_at,omitempty"`
	PairedDeviceID string     `json:"paired_device_id,omitempty"`
}

// SessionRecord holds active authenticated session information.
type SessionRecord struct {
	Token     string    `json:"token"`
	DeviceID  string    `json:"device_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Revoked   bool      `json:"revoked"`
}

// PairingTokenRecord holds temporary out-of-band pairing tokens.
type PairingTokenRecord struct {
	Token             string    `json:"token"`
	InitiatorDeviceID string    `json:"initiator_device_id"`
	CreatedAt         time.Time `json:"created_at"`
	ExpiresAt         time.Time `json:"expires_at"`
	Used              bool      `json:"used"`
}

// ResumptionTokenRecord holds bounded-validity session resumption tokens (VPS-6).
type ResumptionTokenRecord struct {
	Token     string    `json:"token"`
	DeviceID  string    `json:"device_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Used      bool      `json:"used"`
}

// Registry provides thread-safe management of authorized devices, sessions, and pairings.
type Registry struct {
	mu                     sync.RWMutex
	devices                map[string]*DeviceRecord
	sessions               map[string]*SessionRecord         // token -> SessionRecord
	deviceSessions         map[string]map[string]struct{}    // deviceID -> set of tokens
	resumptionTokens       map[string]*ResumptionTokenRecord // token -> ResumptionTokenRecord
	deviceResumptionTokens map[string]map[string]struct{}    // deviceID -> set of resumption tokens
	pairingTokens          map[string]*PairingTokenRecord    // token -> PairingTokenRecord
	stateFilePath          string
	stopCh                 chan struct{}
	stopOnce               sync.Once
}

type persistedRegistryState struct {
	Devices          map[string]*DeviceRecord          `json:"devices"`
	ResumptionTokens map[string]*ResumptionTokenRecord `json:"resumption_tokens,omitempty"`
}

// NewRegistry initializes an empty in-memory Registry with background expired-token cleanup.
func NewRegistry() *Registry {
	return newRegistryWithState("")
}

// NewPersistentRegistry initializes a Registry backed by an atomic JSON state file on disk.
func NewPersistentRegistry(stateFilePath string) (*Registry, error) {
	if stateFilePath == "" {
		return nil, errors.New("state file path cannot be empty")
	}
	dir := filepath.Dir(stateFilePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create state dir: %w", err)
	}
	reg := newRegistryWithState(stateFilePath)
	if err := reg.loadFromDisk(); err != nil {
		reg.Stop()
		return nil, err
	}
	return reg, nil
}

func newRegistryWithState(stateFilePath string) *Registry {
	reg := &Registry{
		devices:                make(map[string]*DeviceRecord),
		sessions:               make(map[string]*SessionRecord),
		deviceSessions:         make(map[string]map[string]struct{}),
		resumptionTokens:       make(map[string]*ResumptionTokenRecord),
		deviceResumptionTokens: make(map[string]map[string]struct{}),
		pairingTokens:          make(map[string]*PairingTokenRecord),
		stateFilePath:          stateFilePath,
		stopCh:                 make(chan struct{}),
	}
	go reg.janitorLoop(1 * time.Minute)
	return reg
}

// Stop halts the background token cleanup goroutine cleanly.
func (r *Registry) Stop() {
	r.stopOnce.Do(func() {
		close(r.stopCh)
	})
}

func (r *Registry) janitorLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			r.PruneExpired()
		case <-r.stopCh:
			return
		}
	}
}

// PruneExpired removes expired or consumed sessions and ephemeral tokens to bound memory usage.
func (r *Registry) PruneExpired() {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	for token, sess := range r.sessions {
		if sess.Revoked || now.After(sess.ExpiresAt) {
			if set, ok := r.deviceSessions[sess.DeviceID]; ok {
				delete(set, token)
				if len(set) == 0 {
					delete(r.deviceSessions, sess.DeviceID)
				}
			}
			delete(r.sessions, token)
		}
	}
	for token, res := range r.resumptionTokens {
		if res.Used || now.After(res.ExpiresAt) {
			if set, ok := r.deviceResumptionTokens[res.DeviceID]; ok {
				delete(set, token)
				if len(set) == 0 {
					delete(r.deviceResumptionTokens, res.DeviceID)
				}
			}
			delete(r.resumptionTokens, token)
		}
	}
	for token, pt := range r.pairingTokens {
		if pt.Used || now.After(pt.ExpiresAt) {
			delete(r.pairingTokens, token)
		}
	}
}

func (r *Registry) loadFromDisk() error {
	if r.stateFilePath == "" {
		return nil
	}
	data, err := os.ReadFile(r.stateFilePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("failed to read registry state: %w", err)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil
	}
	var state persistedRegistryState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("failed to decode registry state: %w", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	for id, rec := range state.Devices {
		if rec != nil {
			r.devices[id] = rec
		}
	}
	for tok, res := range state.ResumptionTokens {
		if res != nil && !res.Used && !now.After(res.ExpiresAt) {
			r.resumptionTokens[tok] = res
			if r.deviceResumptionTokens[res.DeviceID] == nil {
				r.deviceResumptionTokens[res.DeviceID] = make(map[string]struct{})
			}
			r.deviceResumptionTokens[res.DeviceID][tok] = struct{}{}
		}
	}
	return nil
}

func (r *Registry) persistLocked() error {
	if r.stateFilePath == "" {
		return nil
	}
	now := time.Now()
	snapshot := persistedRegistryState{
		Devices:          make(map[string]*DeviceRecord, len(r.devices)),
		ResumptionTokens: make(map[string]*ResumptionTokenRecord),
	}
	for id, rec := range r.devices {
		cp := *rec
		snapshot.Devices[id] = &cp
	}
	for tok, res := range r.resumptionTokens {
		if res != nil && !res.Used && !now.After(res.ExpiresAt) {
			cp := *res
			snapshot.ResumptionTokens[tok] = &cp
		}
	}
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal registry state: %w", err)
	}
	tmpFile, err := os.CreateTemp(filepath.Dir(r.stateFilePath), "registry_state_*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp state file: %w", err)
	}
	tmpPath := tmpFile.Name()
	cleanupTmp := func() { _ = os.Remove(tmpPath) }
	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		cleanupTmp()
		return fmt.Errorf("failed to write temp state file: %w", err)
	}
	if err := tmpFile.Chmod(0600); err != nil {
		_ = tmpFile.Close()
		cleanupTmp()
		return fmt.Errorf("failed to chmod temp state file: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		cleanupTmp()
		return fmt.Errorf("failed to sync temp state file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		cleanupTmp()
		return fmt.Errorf("failed to close temp state file: %w", err)
	}
	if err := os.Rename(tmpPath, r.stateFilePath); err != nil {
		cleanupTmp()
		return fmt.Errorf("failed to rename state file: %w", err)
	}
	return nil
}

// unpairPeerLocked symmetrically clears any existing pairing link held by dev before re-pairing.
func (r *Registry) unpairPeerLocked(dev *DeviceRecord) {
	if dev == nil || dev.PairedDeviceID == "" {
		return
	}
	if oldPeer, ok := r.devices[dev.PairedDeviceID]; ok && oldPeer.PairedDeviceID == dev.DeviceID {
		oldPeer.PairedDeviceID = ""
	}
	dev.PairedDeviceID = ""
}

// RegisterDevice registers a new authorized device.
func (r *Registry) RegisterDevice(record DeviceRecord) error {
	if record.DeviceID == "" {
		return ErrInvalidDeviceID
	}
	if len(record.PublicKey) == 0 {
		return ErrInvalidPublicKey
	}
	if record.KeyAlgorithm == "" {
		record.KeyAlgorithm = AlgorithmECDSAP256
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.devices[record.DeviceID]; exists {
		return ErrDeviceAlreadyRegistered
	}

	if record.RegisteredAt.IsZero() {
		record.RegisteredAt = time.Now()
	}

	recCopy := record
	r.devices[record.DeviceID] = &recCopy
	_ = r.persistLocked()
	return nil
}

// GetDevice retrieves a device record by device ID.
func (r *Registry) GetDevice(deviceID string) (*DeviceRecord, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rec, exists := r.devices[deviceID]
	if !exists {
		return nil, ErrDeviceNotFound
	}

	recCopy := *rec
	return &recCopy, nil
}

// IsAuthorized checks whether a device is registered and not revoked.
func (r *Registry) IsAuthorized(deviceID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rec, exists := r.devices[deviceID]
	if !exists {
		return false
	}
	return !rec.Revoked
}

// RevokeDevice revokes a device with immediate effect.
// Also revokes all active sessions for that device.
func (r *Registry) RevokeDevice(deviceID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	rec, exists := r.devices[deviceID]
	if !exists {
		return ErrDeviceNotFound
	}

	now := time.Now()
	rec.Revoked = true
	rec.RevokedAt = &now

	// Revoke all active sessions immediately
	if tokens, ok := r.deviceSessions[deviceID]; ok {
		for token := range tokens {
			if sess, sessOk := r.sessions[token]; sessOk {
				sess.Revoked = true
			}
			delete(r.sessions, token)
		}
		delete(r.deviceSessions, deviceID)
	}

	// Revoke all resumption tokens immediately (VPS-6)
	if tokens, ok := r.deviceResumptionTokens[deviceID]; ok {
		for token := range tokens {
			if res, resOk := r.resumptionTokens[token]; resOk {
				res.Used = true
			}
			delete(r.resumptionTokens, token)
		}
		delete(r.deviceResumptionTokens, deviceID)
	}

	_ = r.persistLocked()
	return nil
}

// CreateSession generates a new session token for an authorized device.
func (r *Registry) CreateSession(deviceID string, ttl time.Duration) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	rec, exists := r.devices[deviceID]
	if !exists {
		return "", ErrDeviceNotFound
	}
	if rec.Revoked {
		return "", ErrDeviceRevoked
	}

	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate session token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)

	now := time.Now()
	sess := &SessionRecord{
		Token:     token,
		DeviceID:  deviceID,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
		Revoked:   false,
	}

	r.sessions[token] = sess
	if r.deviceSessions[deviceID] == nil {
		r.deviceSessions[deviceID] = make(map[string]struct{})
	}
	r.deviceSessions[deviceID][token] = struct{}{}

	return token, nil
}

// ValidateSession verifies a session token and returns the device ID if valid.
func (r *Registry) ValidateSession(token string) (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	sess, exists := r.sessions[token]
	if !exists {
		return "", ErrSessionNotFound
	}
	if sess.Revoked || time.Now().After(sess.ExpiresAt) {
		return "", ErrSessionNotFound
	}

	// Verify device is still authorized
	dev, devExists := r.devices[sess.DeviceID]
	if !devExists {
		return "", ErrDeviceNotFound
	}
	if dev.Revoked {
		return "", ErrDeviceRevoked
	}

	return sess.DeviceID, nil
}

// RevokeSession invalidates a specific session token immediately.
func (r *Registry) RevokeSession(token string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	sess, exists := r.sessions[token]
	if !exists {
		return ErrSessionNotFound
	}

	sess.Revoked = true
	if tokens, ok := r.deviceSessions[sess.DeviceID]; ok {
		delete(tokens, token)
	}
	delete(r.sessions, token)
	return nil
}

// CreateResumptionToken generates a bounded-validity resumption token for an authorized device (VPS-6).
func (r *Registry) CreateResumptionToken(deviceID string, ttl time.Duration) (string, time.Time, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	rec, exists := r.devices[deviceID]
	if !exists {
		return "", time.Time{}, ErrDeviceNotFound
	}
	if rec.Revoked {
		return "", time.Time{}, ErrDeviceRevoked
	}

	if ttl <= 0 {
		ttl = DefaultResumptionTTL
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", time.Time{}, fmt.Errorf("failed to generate resumption token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)

	now := time.Now()
	expiresAt := now.Add(ttl)
	res := &ResumptionTokenRecord{
		Token:     token,
		DeviceID:  deviceID,
		CreatedAt: now,
		ExpiresAt: expiresAt,
		Used:      false,
	}

	r.resumptionTokens[token] = res
	if r.deviceResumptionTokens[deviceID] == nil {
		r.deviceResumptionTokens[deviceID] = make(map[string]struct{})
	}
	r.deviceResumptionTokens[deviceID][token] = struct{}{}
	_ = r.persistLocked()

	return token, expiresAt, nil
}

// ExpireResumptionTokenForTest backdates a resumption token's expiration for unit and integration tests.
func (r *Registry) ExpireResumptionTokenForTest(token string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if res, exists := r.resumptionTokens[token]; exists {
		res.ExpiresAt = time.Now().Add(-1 * time.Second)
	}
}

// ValidateAndConsumeResumptionToken verifies and consumes a single-use resumption token (VPS-6).
func (r *Registry) ValidateAndConsumeResumptionToken(deviceID, token string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	rec, exists := r.devices[deviceID]
	if !exists {
		return ErrDeviceNotFound
	}
	if rec.Revoked {
		return ErrDeviceRevoked
	}

	res, exists := r.resumptionTokens[token]
	if !exists || res.DeviceID != deviceID {
		return ErrResumptionTokenNotFound
	}

	if res.Used {
		return ErrResumptionTokenUsed
	}

	if time.Now().After(res.ExpiresAt) {
		delete(r.resumptionTokens, token)
		if tokens, ok := r.deviceResumptionTokens[deviceID]; ok {
			delete(tokens, token)
		}
		return ErrResumptionTokenNotFound
	}

	// Mark used and remove immediately to prevent token replay
	res.Used = true
	delete(r.resumptionTokens, token)
	if tokens, ok := r.deviceResumptionTokens[deviceID]; ok {
		delete(tokens, token)
	}
	_ = r.persistLocked()

	return nil
}

// CreatePairingToken creates a temporary token for an out-of-band pairing ceremony.
func (r *Registry) CreatePairingToken(initiatorDeviceID string, ttl time.Duration) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	dev, exists := r.devices[initiatorDeviceID]
	if !exists {
		return "", ErrDeviceNotFound
	}
	if dev.Revoked {
		return "", ErrDeviceRevoked
	}

	if ttl <= 0 {
		ttl = DefaultPairingTokenTTL
	}

	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate pairing token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)

	now := time.Now()
	r.pairingTokens[token] = &PairingTokenRecord{
		Token:             token,
		InitiatorDeviceID: initiatorDeviceID,
		CreatedAt:         now,
		ExpiresAt:         now.Add(ttl),
		Used:              false,
	}

	return token, nil
}

// ClaimPairing allows a claimant device to pair with the initiator using a valid pairing token.
func (r *Registry) ClaimPairing(token, claimantDeviceID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	claimant, exists := r.devices[claimantDeviceID]
	if !exists {
		return ErrDeviceNotFound
	}
	if claimant.Revoked {
		return ErrDeviceRevoked
	}

	now := time.Now()
	var pt *PairingTokenRecord
	cleanToken := strings.ToLower(strings.TrimSpace(token))
	if record, exists := r.pairingTokens[cleanToken]; exists && !record.Used && !now.After(record.ExpiresAt) {
		pt = record
	} else if len(cleanToken) >= 6 {
		var matches []*PairingTokenRecord
		for _, record := range r.pairingTokens {
			if record.Used || now.After(record.ExpiresAt) {
				continue
			}
			if strings.HasPrefix(strings.ToLower(record.Token), cleanToken) {
				matches = append(matches, record)
			}
		}
		// Reject ambiguous short-code prefix collisions deterministically
		if len(matches) == 1 {
			pt = matches[0]
		}
	}

	if pt == nil || pt.Used || now.After(pt.ExpiresAt) {
		return ErrPairingTokenNotFound
	}

	if pt.InitiatorDeviceID == claimantDeviceID {
		return ErrCannotPairSelf
	}

	initiator, exists := r.devices[pt.InitiatorDeviceID]
	if !exists || initiator.Revoked {
		return ErrDeviceNotFound
	}

	// Symmetrically unlink any previous peers before establishing the new pairing
	if initiator.PairedDeviceID != claimantDeviceID {
		r.unpairPeerLocked(initiator)
	}
	if claimant.PairedDeviceID != pt.InitiatorDeviceID {
		r.unpairPeerLocked(claimant)
	}

	// Link devices symmetrically
	initiator.PairedDeviceID = claimantDeviceID
	claimant.PairedDeviceID = pt.InitiatorDeviceID
	pt.Used = true

	_ = r.persistLocked()
	return nil
}

// PairDevices manually pairs two registered devices.
func (r *Registry) PairDevices(deviceID1, deviceID2 string) error {
	if deviceID1 == deviceID2 {
		return ErrCannotPairSelf
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	dev1, exists1 := r.devices[deviceID1]
	if !exists1 {
		return fmt.Errorf("device 1: %w", ErrDeviceNotFound)
	}
	if dev1.Revoked {
		return fmt.Errorf("device 1: %w", ErrDeviceRevoked)
	}

	dev2, exists2 := r.devices[deviceID2]
	if !exists2 {
		return fmt.Errorf("device 2: %w", ErrDeviceNotFound)
	}
	if dev2.Revoked {
		return fmt.Errorf("device 2: %w", ErrDeviceRevoked)
	}

	if dev1.PairedDeviceID != deviceID2 {
		r.unpairPeerLocked(dev1)
	}
	if dev2.PairedDeviceID != deviceID1 {
		r.unpairPeerLocked(dev2)
	}

	dev1.PairedDeviceID = deviceID2
	dev2.PairedDeviceID = deviceID1
	_ = r.persistLocked()
	return nil
}

// GetPairedDevice returns the paired peer's device ID.
func (r *Registry) GetPairedDevice(deviceID string) (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	dev, exists := r.devices[deviceID]
	if !exists {
		return "", ErrDeviceNotFound
	}
	if dev.Revoked {
		return "", ErrDeviceRevoked
	}
	if dev.PairedDeviceID == "" {
		return "", errors.New("device is not paired with any peer")
	}

	// Verify paired peer is also registered and not revoked
	peer, peerExists := r.devices[dev.PairedDeviceID]
	if !peerExists || peer.Revoked {
		return "", errors.New("paired peer device is not authorized or has been revoked")
	}

	return dev.PairedDeviceID, nil
}
