package peer

import (
	"strings"
	"sync"
)

// Registry manages the thread-safe roster of active peers, ensuring unique handles
// and unique public key fingerprints.
type Registry struct {
	mu            sync.RWMutex
	byFingerprint map[string]*Peer
	byHandle      map[string]*Peer // normalized (lowercased) handle -> *Peer
}

// NewRegistry initializes an empty thread-safe peer registry.
func NewRegistry() *Registry {
	return &Registry{
		byFingerprint: make(map[string]*Peer),
		byHandle:      make(map[string]*Peer),
	}
}

// Register adds a peer to the registry. Returns an error if the peer is nil,
// if its fingerprint is already registered, or if its handle collides with an existing peer.
func (r *Registry) Register(p *Peer) error {
	if p == nil {
		return ErrNilPeer
	}

	fp := p.Fingerprint()
	if fp == "" {
		return ErrNilPublicKey
	}

	handle := p.Handle()
	if err := ValidateHandle(handle); err != nil {
		return err
	}

	normHandle := strings.ToLower(handle)

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.byFingerprint[fp]; exists {
		return ErrDuplicateFingerprint
	}

	if _, exists := r.byHandle[normHandle]; exists {
		return ErrDuplicateHandle
	}

	r.byFingerprint[fp] = p
	r.byHandle[normHandle] = p
	return nil
}

// Unregister removes a peer by fingerprint from the registry.
// Returns ErrPeerNotFound if the peer does not exist.
func (r *Registry) Unregister(fingerprint string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	p, exists := r.byFingerprint[fingerprint]
	if !exists {
		return ErrPeerNotFound
	}

	delete(r.byFingerprint, fingerprint)
	delete(r.byHandle, strings.ToLower(p.Handle()))
	return nil
}

// Get looks up a peer by public key fingerprint.
func (r *Registry) Get(fingerprint string) (*Peer, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	p, exists := r.byFingerprint[fingerprint]
	return p, exists
}

// GetByHandle looks up a peer by handle using case-insensitive comparison.
func (r *Registry) GetByHandle(handle string) (*Peer, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	p, exists := r.byHandle[strings.ToLower(handle)]
	return p, exists
}

// UpdateHandle updates the handle of an existing peer identified by fingerprint.
// It verifies format, rejects collisions with other peers, allows keeping or re-casing
// the current handle, and updates the registry lookup map atomically.
func (r *Registry) UpdateHandle(fingerprint, newHandle string) error {
	if err := ValidateHandle(newHandle); err != nil {
		return err
	}

	normNew := strings.ToLower(newHandle)

	r.mu.Lock()
	defer r.mu.Unlock()

	p, exists := r.byFingerprint[fingerprint]
	if !exists {
		return ErrPeerNotFound
	}

	if existing, exists := r.byHandle[normNew]; exists {
		if existing.Fingerprint() != fingerprint {
			return ErrDuplicateHandle
		}
	}

	oldNorm := strings.ToLower(p.Handle())
	if oldNorm != normNew {
		delete(r.byHandle, oldNorm)
	}

	if err := p.SetHandle(newHandle); err != nil {
		return err
	}

	r.byHandle[normNew] = p
	return nil
}

// List returns a point-in-time snapshot slice of all currently registered peers.
func (r *Registry) List() []*Peer {
	r.mu.RLock()
	defer r.mu.RUnlock()

	peers := make([]*Peer, 0, len(r.byFingerprint))
	for _, p := range r.byFingerprint {
		peers = append(peers, p)
	}
	return peers
}

// Count returns the number of currently registered peers.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return len(r.byFingerprint)
}
