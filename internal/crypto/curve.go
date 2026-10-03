package crypto

import (
	"crypto/ecdh"
	"crypto/sha512"
	"errors"
	"fmt"

	"filippo.io/edwards25519"
)

// Ed25519PublicKeyToX25519 converts an Ed25519 public key (32-byte compressed Edwards y-coordinate)
// into a Montgomery X25519 u-coordinate using birational curve equivalence.
func Ed25519PublicKeyToX25519(pubKey []byte) ([]byte, error) {
	if len(pubKey) != 32 {
		return nil, fmt.Errorf("invalid ed25519 public key length: expected 32 bytes, got %d", len(pubKey))
	}

	point, err := new(edwards25519.Point).SetBytes(pubKey)
	if err != nil {
		return nil, fmt.Errorf("invalid ed25519 public key point: %w", err)
	}

	return point.BytesMontgomery(), nil
}

// Ed25519PrivateKeyToX25519 converts an Ed25519 private key (64 bytes: 32-byte seed + 32-byte pubkey)
// or 32-byte seed into an X25519 private key.
// It hashes the seed using SHA-512 and clamps the lower 32 bytes according to RFC 7748 / RFC 8032.
func Ed25519PrivateKeyToX25519(privKey []byte) ([]byte, error) {
	var seed []byte
	switch len(privKey) {
	case 32:
		seed = privKey
	case 64:
		seed = privKey[:32]
	default:
		return nil, fmt.Errorf("invalid ed25519 private key length: expected 32 or 64 bytes, got %d", len(privKey))
	}

	h := sha512.Sum512(seed)
	defer Memclr(h[:])

	x25519Priv := make([]byte, 32)
	copy(x25519Priv, h[:32])

	// Clamping as per RFC 7748 section 5:
	x25519Priv[0] &= 248  // clear lowest 3 bits
	x25519Priv[31] &= 127 // clear bit 255
	x25519Priv[31] |= 64  // set bit 254

	return x25519Priv, nil
}

// ComputeSharedSecret performs Diffie-Hellman key exchange (X25519) between our private key
// and peer's public key using crypto/ecdh.
func ComputeSharedSecret(privKeyX25519, peerPubKeyX25519 []byte) ([]byte, error) {
	if len(privKeyX25519) != 32 {
		return nil, fmt.Errorf("invalid x25519 private key length: expected 32 bytes, got %d", len(privKeyX25519))
	}
	if len(peerPubKeyX25519) != 32 {
		return nil, fmt.Errorf("invalid x25519 public key length: expected 32 bytes, got %d", len(peerPubKeyX25519))
	}

	curve := ecdh.X25519()
	priv, err := curve.NewPrivateKey(privKeyX25519)
	if err != nil {
		return nil, fmt.Errorf("invalid x25519 private key: %w", err)
	}

	pub, err := curve.NewPublicKey(peerPubKeyX25519)
	if err != nil {
		return nil, fmt.Errorf("invalid x25519 public key: %w", err)
	}

	secret, err := priv.ECDH(pub)
	if err != nil {
		return nil, errors.New("failed to compute ecdh shared secret")
	}

	return secret, nil
}
