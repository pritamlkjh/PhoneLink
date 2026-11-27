package coordinator

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/pritamlkjh/phonelink/vps/internal/auth"
)

var (
	ErrDeviceNotAuthorized    = errors.New("device not authorized or revoked")
	ErrDeviceNotPaired        = errors.New("device is not paired with any peer")
	ErrPeerOffline            = errors.New("paired peer is offline")
	ErrUnauthorizedRecipient  = errors.New("unauthorized recipient: sender can only relay to authorized paired peer")
	ErrSessionNotFound        = errors.New("active session not found for device")
	ErrSessionAlreadyActive   = errors.New("session already active for device")
)

// PeerStatusEvent represents peer presence notification
type PeerStatusEvent struct {
	Type         string `json:"type"` // "PEER_STATUS"
	PeerDeviceID string `json:"peer_device_id"`
	IsOnline     bool   `json:"is_online"`
	Timestamp    int64  `json:"timestamp"`
}

// Session represents an active device connection
type Session struct {
	DeviceID     string
	PeerDeviceID string
	ConnectedAt  time.Time
	SendChan     chan []byte
	CloseFunc    func()
}

// Coordinator manages connected device sessions and relays opaque ciphertext payloads.
// Low-Trust Guarantee: The coordinator never decrypts, parses, or retains application payloads.
type Coordinator struct {
	mu             sync.RWMutex
	registry       *auth.Registry
	activeSessions map[string]*Session // deviceID -> Session
}

// NewCoordinator initializes a new Coordinator with an auth registry.
func NewCoordinator(registry *auth.Registry) *Coordinator {
	return &Coordinator{
		registry:       registry,
		activeSessions: make(map[string]*Session),
	}
}

// ConnectSession registers an active connection for an authorized device.
func (c *Coordinator) ConnectSession(deviceID string, sendChan chan []byte, closeFunc func()) (*Session, error) {
	var priorClose func()
	c.mu.Lock()
	if !c.registry.IsAuthorized(deviceID) {
		c.mu.Unlock()
		return nil, ErrDeviceNotAuthorized
	}

	pairedDeviceID, err := c.registry.GetPairedDevice(deviceID)
	if err != nil {
		c.mu.Unlock()
		return nil, fmt.Errorf("%w: %v", ErrDeviceNotPaired, err)
	}

	// Replace prior session if present; close outside mutex to avoid deadlock
	if prior, exists := c.activeSessions[deviceID]; exists {
		priorClose = prior.CloseFunc
		delete(c.activeSessions, deviceID)
	}

	sess := &Session{
		DeviceID:     deviceID,
		PeerDeviceID: pairedDeviceID,
		ConnectedAt:  time.Now(),
		SendChan:     sendChan,
		CloseFunc:    closeFunc,
	}
	c.activeSessions[deviceID] = sess

	// Check if paired peer is online and enqueue initial PEER_STATUS under c.mu
	// so connect/disconnect presence ordering stays consistent.
	peerSess, peerOnline := c.activeSessions[pairedDeviceID]

	nowUnix := time.Now().Unix()
	selfStatusEvent, _ := json.Marshal(PeerStatusEvent{
		Type:         "PEER_STATUS",
		PeerDeviceID: pairedDeviceID,
		IsOnline:     peerOnline,
		Timestamp:    nowUnix,
	})
	select {
	case sendChan <- selfStatusEvent:
	default:
	}

	if peerOnline && peerSess != nil {
		peerStatusEvent, _ := json.Marshal(PeerStatusEvent{
			Type:         "PEER_STATUS",
			PeerDeviceID: deviceID,
			IsOnline:     true,
			Timestamp:    nowUnix,
		})
		select {
		case peerSess.SendChan <- peerStatusEvent:
		default:
		}
	}
	c.mu.Unlock()

	if priorClose != nil {
		priorClose()
	}

	return sess, nil
}

// DisconnectSession unregisters the active session for deviceID and notifies the peer.
func (c *Coordinator) DisconnectSession(deviceID string) {
	c.DisconnectIfSession(deviceID, nil)
}

// TerminateSession forcibly disconnects an active session (calling CloseFunc) and notifies the peer.
func (c *Coordinator) TerminateSession(deviceID string) {
	c.mu.RLock()
	sess, exists := c.activeSessions[deviceID]
	var closeFn func()
	if exists && sess != nil {
		closeFn = sess.CloseFunc
	}
	c.mu.RUnlock()

	c.DisconnectIfSession(deviceID, sess)
	if closeFn != nil {
		closeFn()
	}
}

// DisconnectIfSession unregisters the session only if expected is nil or matches
// the currently registered *Session pointer, preventing stale socket teardowns
// from evicting newly reconnected sessions.
func (c *Coordinator) DisconnectIfSession(deviceID string, expected *Session) {
	c.mu.Lock()
	sess, exists := c.activeSessions[deviceID]
	if !exists || (expected != nil && sess != expected) {
		c.mu.Unlock()
		return
	}

	pairedDeviceID := sess.PeerDeviceID
	delete(c.activeSessions, deviceID)
	peerSess, peerOnline := c.activeSessions[pairedDeviceID]
	if peerOnline && peerSess != nil {
		peerStatusEvent, _ := json.Marshal(PeerStatusEvent{
			Type:         "PEER_STATUS",
			PeerDeviceID: deviceID,
			IsOnline:     false,
			Timestamp:    time.Now().Unix(),
		})
		select {
		case peerSess.SendChan <- peerStatusEvent:
		default:
		}
	}
	c.mu.Unlock()
}

// TerminateAll closes and clears all active sessions (used during graceful server shutdown).
func (c *Coordinator) TerminateAll() {
	c.mu.Lock()
	closeFns := make([]func(), 0, len(c.activeSessions))
	for id, sess := range c.activeSessions {
		if sess != nil && sess.CloseFunc != nil {
			closeFns = append(closeFns, sess.CloseFunc)
		}
		delete(c.activeSessions, id)
	}
	c.mu.Unlock()

	for _, fn := range closeFns {
		fn()
	}
}

// IsDeviceOnline returns true if the device currently has an active session.
func (c *Coordinator) IsDeviceOnline(deviceID string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, exists := c.activeSessions[deviceID]
	return exists
}

// ForwardPayload relays an opaque payload from sourceDeviceID to targetDeviceID.
// Strictly enforces mutual authorization: targetDeviceID MUST be sourceDeviceID's paired peer.
func (c *Coordinator) ForwardPayload(sourceDeviceID, targetDeviceID string, payload []byte) error {
	c.mu.RLock()
	if !c.registry.IsAuthorized(sourceDeviceID) {
		c.mu.RUnlock()
		return ErrDeviceNotAuthorized
	}
	sourceSess, sourceExists := c.activeSessions[sourceDeviceID]
	if !sourceExists {
		c.mu.RUnlock()
		return ErrSessionNotFound
	}

	if sourceSess.PeerDeviceID != targetDeviceID {
		c.mu.RUnlock()
		return ErrUnauthorizedRecipient
	}

	peerSess, peerExists := c.activeSessions[targetDeviceID]
	if !peerExists || !c.registry.IsAuthorized(targetDeviceID) {
		c.mu.RUnlock()
		return ErrPeerOffline
	}
	c.mu.RUnlock()

	// Forward verbatim without looking inside; use a short bounded timer to avoid blocking
	// the sender's read loop or leaking time.After timers on every message.
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()

	select {
	case peerSess.SendChan <- payload:
		return nil
	case <-timer.C:
		return errors.New("peer send channel buffer full: timed out")
	}
}
