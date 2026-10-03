package crypto_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"filippo.io/edwards25519"

	"git.delikesance.cloud/delikesance/shh/internal/crypto"
)

func TestEd25519PublicKeyToX25519(t *testing.T) {
	t.Run("converts valid Ed25519 public key to Montgomery X25519 coordinate", func(t *testing.T) {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate ed25519 key: %v", err)
		}

		x25519Pub, err := crypto.Ed25519PublicKeyToX25519(pub)
		if err != nil {
			t.Fatalf("unexpected error converting public key: %v", err)
		}

		if len(x25519Pub) != 32 {
			t.Fatalf("expected 32 bytes, got %d", len(x25519Pub))
		}

		// Verify against direct edwards25519 Point.BytesMontgomery()
		point, err := new(edwards25519.Point).SetBytes(pub)
		if err != nil {
			t.Fatalf("edwards25519.SetBytes failed: %v", err)
		}
		expectedMont := point.BytesMontgomery()

		if !bytes.Equal(x25519Pub, expectedMont) {
			t.Errorf("mismatch between Ed25519PublicKeyToX25519 and BytesMontgomery():\ngot:      %x\nexpected: %x", x25519Pub, expectedMont)
		}
	})

	t.Run("rejects invalid public key lengths", func(t *testing.T) {
		invalidLengths := [][]byte{
			nil,
			{},
			make([]byte, 16),
			make([]byte, 31),
			make([]byte, 33),
			make([]byte, 64),
		}

		for _, invalid := range invalidLengths {
			if _, err := crypto.Ed25519PublicKeyToX25519(invalid); err == nil {
				t.Errorf("expected error for public key length %d, got nil", len(invalid))
			}
		}
	})

	t.Run("rejects invalid Edwards point", func(t *testing.T) {
		// y = 2 is not on the curve (x^2 is not a quadratic residue in GF(2^255-19))
		invalidPoint := make([]byte, 32)
		invalidPoint[0] = 2

		if _, err := crypto.Ed25519PublicKeyToX25519(invalidPoint); err == nil {
			t.Error("expected error for invalid Edwards point, got nil")
		}
	})
}

func TestEd25519PrivateKeyToX25519(t *testing.T) {
	t.Run("converts 64-byte Ed25519 private key and 32-byte seed identically", func(t *testing.T) {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate ed25519 key: %v", err)
		}

		// Convert from 64-byte private key
		x25519FromPriv, err := crypto.Ed25519PrivateKeyToX25519(priv)
		if err != nil {
			t.Fatalf("failed to convert from 64-byte private key: %v", err)
		}

		// Convert from 32-byte seed
		seed := priv.Seed()
		x25519FromSeed, err := crypto.Ed25519PrivateKeyToX25519(seed)
		if err != nil {
			t.Fatalf("failed to convert from 32-byte seed: %v", err)
		}

		if len(x25519FromPriv) != 32 {
			t.Fatalf("expected 32 bytes, got %d", len(x25519FromPriv))
		}

		if !bytes.Equal(x25519FromPriv, x25519FromSeed) {
			t.Errorf("mismatch between private key conversion and seed conversion:\npriv: %x\nseed: %x", x25519FromPriv, x25519FromSeed)
		}

		// Verify clamping:
		// RFC 7748 / RFC 8032:
		// bits 0, 1, 2 of byte 0 are cleared
		if x25519FromPriv[0]&7 != 0 {
			t.Errorf("byte 0 lowest 3 bits must be cleared, got: %08b", x25519FromPriv[0])
		}
		// bit 7 of byte 31 is cleared
		if x25519FromPriv[31]&128 != 0 {
			t.Errorf("byte 31 bit 7 must be cleared, got: %08b", x25519FromPriv[31])
		}
		// bit 6 of byte 31 is set
		if x25519FromPriv[31]&64 == 0 {
			t.Errorf("byte 31 bit 6 must be set, got: %08b", x25519FromPriv[31])
		}

		// Verify that public key derived from converted X25519 private key matches converted Ed25519 public key!
		curve := ecdh.X25519()
		ecdhPriv, err := curve.NewPrivateKey(x25519FromPriv)
		if err != nil {
			t.Fatalf("failed to load x25519 private key into crypto/ecdh: %v", err)
		}
		expectedPub := ecdhPriv.PublicKey().Bytes()

		x25519Pub, err := crypto.Ed25519PublicKeyToX25519(pub)
		if err != nil {
			t.Fatalf("failed to convert ed25519 public key: %v", err)
		}

		if !bytes.Equal(x25519Pub, expectedPub) {
			t.Errorf("ECDH public key does not match converted Ed25519 public key:\ngot:      %x\nexpected: %x", x25519Pub, expectedPub)
		}
	})

	t.Run("rejects invalid private key lengths", func(t *testing.T) {
		invalidLengths := [][]byte{
			nil,
			{},
			make([]byte, 16),
			make([]byte, 31),
			make([]byte, 33),
			make([]byte, 48),
			make([]byte, 65),
		}

		for _, invalid := range invalidLengths {
			if _, err := crypto.Ed25519PrivateKeyToX25519(invalid); err == nil {
				t.Errorf("expected error for private key length %d, got nil", len(invalid))
			}
		}
	})
}

func TestECDHKeyExchange(t *testing.T) {
	t.Run("two converted keypairs yield identical shared secret", func(t *testing.T) {
		// Peer A (Alice)
		pubA, privA, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate key A: %v", err)
		}
		pubAX25519, err := crypto.Ed25519PublicKeyToX25519(pubA)
		if err != nil {
			t.Fatalf("failed to convert pub A: %v", err)
		}
		privAX25519, err := crypto.Ed25519PrivateKeyToX25519(privA)
		if err != nil {
			t.Fatalf("failed to convert priv A: %v", err)
		}

		// Peer B (Bob)
		pubB, privB, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate key B: %v", err)
		}
		pubBX25519, err := crypto.Ed25519PublicKeyToX25519(pubB)
		if err != nil {
			t.Fatalf("failed to convert pub B: %v", err)
		}
		privBX25519, err := crypto.Ed25519PrivateKeyToX25519(privB)
		if err != nil {
			t.Fatalf("failed to convert priv B: %v", err)
		}

		// Alice computes shared secret using Bob's public key
		secretA, err := crypto.ComputeSharedSecret(privAX25519, pubBX25519)
		if err != nil {
			t.Fatalf("Alice failed to compute shared secret: %v", err)
		}

		// Bob computes shared secret using Alice's public key
		secretB, err := crypto.ComputeSharedSecret(privBX25519, pubAX25519)
		if err != nil {
			t.Fatalf("Bob failed to compute shared secret: %v", err)
		}

		if len(secretA) != 32 {
			t.Fatalf("expected 32-byte secret, got %d", len(secretA))
		}

		if !bytes.Equal(secretA, secretB) {
			t.Fatalf("shared secrets do not match:\nAlice: %x\nBob:   %x", secretA, secretB)
		}

		// Verify against direct crypto/ecdh execution
		curve := ecdh.X25519()
		alicePriv, _ := curve.NewPrivateKey(privAX25519)
		bobPub, _ := curve.NewPublicKey(pubBX25519)
		directSecret, err := alicePriv.ECDH(bobPub)
		if err != nil {
			t.Fatalf("direct ecdh failed: %v", err)
		}

		if !bytes.Equal(secretA, directSecret) {
			t.Errorf("shared secret mismatch with direct ecdh:\ngot:      %x\nexpected: %x", secretA, directSecret)
		}
	})

	t.Run("rejects invalid keys in ComputeSharedSecret", func(t *testing.T) {
		validKey := make([]byte, 32)
		validKey[0] = 1

		// Invalid private key length
		if _, err := crypto.ComputeSharedSecret(make([]byte, 16), validKey); err == nil {
			t.Error("expected error for invalid private key length")
		}

		// Invalid public key length
		if _, err := crypto.ComputeSharedSecret(validKey, make([]byte, 16)); err == nil {
			t.Error("expected error for invalid public key length")
		}

		// Low order point (all zeros) causes ECDH to return error
		lowOrderPub := make([]byte, 32)
		if _, err := crypto.ComputeSharedSecret(validKey, lowOrderPub); err == nil {
			t.Error("expected error for low-order public key point")
		}
	})
}
