package crypto

import (
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// NonceFromCounter generates a 12-byte (96-bit) nonce from a 64-bit monotonic sequence counter.
// The first 4 bytes are zero-padded, and the remaining 8 bytes encode the counter in big-endian order.
func NonceFromCounter(counter uint64) []byte {
	nonce := make([]byte, chacha20poly1305.NonceSize)
	binary.BigEndian.PutUint64(nonce[4:], counter)
	return nonce
}

// Seal encrypts and authenticates plaintext along with additional authenticated data (ad)
// using ChaCha20-Poly1305 (RFC 8439) with the given key and nonce.
func Seal(key, nonce, plaintext, ad []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("invalid key size: expected %d bytes, got %d", chacha20poly1305.KeySize, len(key))
	}
	if len(nonce) != chacha20poly1305.NonceSize {
		return nil, fmt.Errorf("invalid nonce size: expected %d bytes, got %d", chacha20poly1305.NonceSize, len(nonce))
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create chacha20poly1305 cipher: %w", err)
	}

	return aead.Seal(nil, nonce, plaintext, ad), nil
}

// Open decrypts and verifies ciphertext along with additional authenticated data (ad)
// using ChaCha20-Poly1305 (RFC 8439) with the given key and nonce.
func Open(key, nonce, ciphertext, ad []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("invalid key size: expected %d bytes, got %d", chacha20poly1305.KeySize, len(key))
	}
	if len(nonce) != chacha20poly1305.NonceSize {
		return nil, fmt.Errorf("invalid nonce size: expected %d bytes, got %d", chacha20poly1305.NonceSize, len(nonce))
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create chacha20poly1305 cipher: %w", err)
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, ad)
	if err != nil {
		return nil, errors.New("authentication or decryption failed")
	}

	return plaintext, nil
}
