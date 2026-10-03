package channel

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"

	"git.delikesance.cloud/delikesance/shh/internal/crypto"
	"golang.org/x/crypto/chacha20poly1305"
)

// NonceSize is the standard ChaCha20-Poly1305 nonce length in bytes (96 bits / 12 bytes).
const NonceSize = 12

// DefaultBufferCapacity is the default capacity for the channel's message ring buffer.
const DefaultBufferCapacity = 100

var (
	// ErrClosedChannel is returned when attempting operations on a closed channel.
	ErrClosedChannel = errors.New("channel is closed")
	// ErrInvalidNonce is returned when a nonce has an invalid size or format.
	ErrInvalidNonce = errors.New("invalid nonce")
	// ErrReplayNonce is returned when a nonce replay or out-of-order sequence counter is detected.
	ErrReplayNonce = errors.New("nonce replay or out-of-order sequence detected")
	// ErrDecryptionFail is returned when payload authentication or decryption fails.
	ErrDecryptionFail = errors.New("payload decryption failed or message tampered")
	// ErrInvalidKey is returned when the shared key length is not 32 bytes.
	ErrInvalidKey = errors.New("shared key must be 32 bytes")
)

// Memclr explicitly overwrites a byte slice with zeros using crypto.Memclr.
func Memclr(b []byte) {
	crypto.Memclr(b)
}

// Channel represents an end-to-end encrypted direct-message channel between two peers.
// It maintains ephemeral state, monotonic sequence nonces, replay protection, and in-memory ring-buffers.
type Channel struct {
	mu        sync.RWMutex
	selfFP    string
	peerFP    string
	sharedKey []byte
	sendSeq   uint64
	recvSeq   uint64
	buffer    *RingBuffer
	closed    bool
	aead      cipher.AEAD
}

// NewChannel initializes a new ephemeral channel between selfFP and peerFP using the provided shared symmetric key.
func NewChannel(selfFP, peerFP string, sharedKey []byte) *Channel {
	return NewChannelWithCapacity(selfFP, peerFP, sharedKey, DefaultBufferCapacity)
}

// NewChannelWithCapacity initializes a channel with a custom ring buffer capacity.
func NewChannelWithCapacity(selfFP, peerFP string, sharedKey []byte, bufferCapacity int) *Channel {
	c := &Channel{
		selfFP:    selfFP,
		peerFP:    peerFP,
		sharedKey: sharedKey,
		buffer:    NewRingBuffer(bufferCapacity),
	}
	if len(sharedKey) == chacha20poly1305.KeySize {
		if aead, err := chacha20poly1305.New(sharedKey); err == nil {
			c.aead = aead
		}
	}
	return c
}

// SelfFP returns the local peer's public key fingerprint.
func (c *Channel) SelfFP() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.selfFP
}

// PeerFP returns the remote peer's public key fingerprint.
func (c *Channel) PeerFP() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.peerFP
}

// SharedKey returns the channel's shared symmetric key slice.
func (c *Channel) SharedKey() []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sharedKey
}

// IsClosed returns true if the channel has been closed.
func (c *Channel) IsClosed() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.closed
}

// Buffer returns the internal message RingBuffer.
func (c *Channel) Buffer() *RingBuffer {
	return c.buffer
}

// Messages returns all buffered messages in chronological order.
func (c *Channel) Messages() []*Message {
	if c.buffer == nil {
		return nil
	}
	return c.buffer.Messages()
}

// Push adds a message to the channel's ring buffer.
func (c *Channel) Push(msg *Message) {
	if c.buffer != nil {
		c.buffer.Push(msg)
	}
}

// SendSeq returns the current outbound sequence counter.
func (c *Channel) SendSeq() uint64 {
	return atomic.LoadUint64(&c.sendSeq)
}

// RecvSeq returns the highest valid inbound sequence counter received.
func (c *Channel) RecvSeq() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.recvSeq
}

// NextNonce increments the atomic sequence counter and returns a 12-byte 96-bit big-endian nonce.
// The upper 4 bytes are zeroes, and the lower 8 bytes contain the 64-bit sequence counter.
func (c *Channel) NextNonce() []byte {
	seq := atomic.AddUint64(&c.sendSeq, 1)
	return crypto.NonceFromCounter(seq)
}

// VerifyNonce validates an incoming nonce against replay attacks.
// It rejects duplicates, out-of-order sequences, invalid formats, or nonces on a closed channel.
// Returns true if the nonce is valid and strictly greater than the highest previously received sequence.
func (c *Channel) VerifyNonce(nonce []byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return false
	}

	if len(nonce) != NonceSize {
		return false
	}

	// Verify upper 4 bytes are 0
	if nonce[0] != 0 || nonce[1] != 0 || nonce[2] != 0 || nonce[3] != 0 {
		return false
	}

	seq := binary.BigEndian.Uint64(nonce[4:12])
	if seq == 0 || seq <= c.recvSeq {
		return false
	}

	c.recvSeq = seq
	return true
}

// Seal encrypts a plaintext payload using ChaCha20-Poly1305 and the next monotonic sequence nonce.
// Returns the 12-byte nonce, the ciphertext (with attached Poly1305 authentication tag), or an error.
func (c *Channel) Seal(plaintext []byte) ([]byte, []byte, error) {
	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return nil, nil, ErrClosedChannel
	}
	aead := c.aead
	c.mu.RUnlock()

	if aead == nil {
		return nil, nil, ErrInvalidKey
	}

	nonce := c.NextNonce()
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	return nonce, ciphertext, nil
}

// Open verifies the inbound nonce against replay attacks and decrypts ciphertext using ChaCha20-Poly1305.
// It ensures sequence counter state is only committed if payload authentication succeeds,
// preventing replay counter desync attacks from tampered or injected frames.
func (c *Channel) Open(nonce []byte, ciphertext []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil, ErrClosedChannel
	}

	if c.aead == nil {
		return nil, ErrInvalidKey
	}

	if len(nonce) != NonceSize {
		return nil, ErrInvalidNonce
	}

	// Verify upper 4 bytes are 0
	if nonce[0] != 0 || nonce[1] != 0 || nonce[2] != 0 || nonce[3] != 0 {
		return nil, ErrInvalidNonce
	}

	seq := binary.BigEndian.Uint64(nonce[4:12])
	if seq == 0 || seq <= c.recvSeq {
		return nil, ErrReplayNonce
	}

	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFail
	}

	c.recvSeq = seq
	return plaintext, nil
}

// Close securely tears down the channel:
// - Marks the channel as closed.
// - Zeroes the shared key material using Memclr.
// - Clears the in-memory ring buffer and wipes all message contents.
// Close is idempotent and safe for concurrent calls.
func (c *Channel) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return
	}
	c.closed = true

	// Clear ring buffer and wipe message contents
	if c.buffer != nil {
		c.buffer.Clear()
	}

	// Scrub shared key material in memory
	Memclr(c.sharedKey)
	c.aead = nil
}
