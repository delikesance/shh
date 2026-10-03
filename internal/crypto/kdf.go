package crypto

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// DeriveChannelKey derives a 32-byte symmetric key for ChaCha20-Poly1305
// from a shared secret and salt using RFC 5869 HKDF-SHA256 (extract & expand).
func DeriveChannelKey(sharedSecret, salt []byte, info string) ([]byte, error) {
	if len(sharedSecret) == 0 {
		return nil, errors.New("shared secret cannot be empty")
	}

	reader := hkdf.New(sha256.New, sharedSecret, salt, []byte(info))
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, fmt.Errorf("hkdf key derivation failed: %w", err)
	}
	return key, nil
}
