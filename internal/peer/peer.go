package peer

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	ErrNilPeer              = errors.New("peer cannot be nil")
	ErrNilPublicKey         = errors.New("public key cannot be nil")
	ErrInvalidHandle        = errors.New("invalid handle: must be 3-20 characters of alphanumeric, underscore, or hyphen")
	ErrDuplicateFingerprint = errors.New("peer with this fingerprint is already registered")
	ErrDuplicateHandle      = errors.New("handle is already taken")
	ErrPeerNotFound         = errors.New("peer not found")
	ErrInvalidPresence      = errors.New("invalid presence state")
)

// PresenceState represents the current presence status of a peer.
type PresenceState string

const (
	PresenceOnline       PresenceState = "online"
	PresenceActive       PresenceState = "active"
	PresenceIdle         PresenceState = "idle"
	PresenceDisconnected PresenceState = "disconnected"
)

// Peer represents an authenticated connected SSH peer whose identity is pinned
// to their SSH public key fingerprint.
type Peer struct {
	mu          sync.RWMutex
	pubKey      ssh.PublicKey
	fingerprint string
	handle      string
	presence    PresenceState
	connectedAt time.Time
	lastActive  time.Time
}

// ValidateHandle checks if a handle meets the naming rules:
// length 3-20 characters, consisting only of alphanumeric characters, underscores, and hyphens.
func ValidateHandle(handle string) error {
	if len(handle) < 3 || len(handle) > 20 {
		return ErrInvalidHandle
	}
	for i := 0; i < len(handle); i++ {
		b := handle[i]
		if !((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_' || b == '-') {
			return ErrInvalidHandle
		}
	}
	return nil
}

// FingerprintKey computes the SHA-256 identity fingerprint of an SSH public key,
// matching SHA256(ssh.MarshalAuthorizedKey(pubKey)) as specified in GEMINI.md.
func FingerprintKey(pubKey ssh.PublicKey) string {
	if pubKey == nil {
		return ""
	}
	h := sha256.Sum256(ssh.MarshalAuthorizedKey(pubKey))
	return hex.EncodeToString(h[:])
}

// NewPeer creates a new Peer instance bound to the provided public key and handle.
func NewPeer(pubKey ssh.PublicKey, handle string) (*Peer, error) {
	if pubKey == nil {
		return nil, ErrNilPublicKey
	}
	if err := ValidateHandle(handle); err != nil {
		return nil, err
	}

	fp := FingerprintKey(pubKey)
	now := time.Now()

	return &Peer{
		pubKey:      pubKey,
		fingerprint: fp,
		handle:      handle,
		presence:    PresenceOnline,
		connectedAt: now,
		lastActive:  now,
	}, nil
}

// Fingerprint returns the immutable SHA-256 fingerprint of the peer's public key.
func (p *Peer) Fingerprint() string {
	return p.fingerprint
}

// PublicKey returns the peer's SSH public key.
func (p *Peer) PublicKey() ssh.PublicKey {
	return p.pubKey
}

// Handle returns the peer's current handle.
func (p *Peer) Handle() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.handle
}

// SetHandle updates the peer's handle after validation.
func (p *Peer) SetHandle(handle string) error {
	if err := ValidateHandle(handle); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.handle = handle
	return nil
}

// Presence returns the peer's current presence state.
func (p *Peer) Presence() PresenceState {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.presence
}

// SetPresence updates the peer's presence state if it is a valid state.
func (p *Peer) SetPresence(state PresenceState) error {
	switch state {
	case PresenceOnline, PresenceActive, PresenceIdle, PresenceDisconnected:
	default:
		return ErrInvalidPresence
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.presence = state
	return nil
}

// ConnectedAt returns the time the peer connected.
func (p *Peer) ConnectedAt() time.Time {
	return p.connectedAt
}

// LastActive returns the timestamp of the peer's last recorded activity.
func (p *Peer) LastActive() time.Time {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.lastActive
}

// Touch updates the peer's last active timestamp to the current time.
func (p *Peer) Touch() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lastActive = time.Now()
}

// IsOnline returns true if the peer's presence is online.
func (p *Peer) IsOnline() bool {
	return p.Presence() == PresenceOnline
}

// IsActive returns true if the peer's presence is active.
func (p *Peer) IsActive() bool {
	return p.Presence() == PresenceActive
}

// IsIdle returns true if the peer's presence is idle.
func (p *Peer) IsIdle() bool {
	return p.Presence() == PresenceIdle
}

// IsDisconnected returns true if the peer's presence is disconnected.
func (p *Peer) IsDisconnected() bool {
	return p.Presence() == PresenceDisconnected
}

// String returns a human-readable representation of the peer.
func (p *Peer) String() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	fpPrefix := p.fingerprint
	if len(fpPrefix) > 8 {
		fpPrefix = fpPrefix[:8]
	}
	return p.handle + " (" + fpPrefix + ")"
}
