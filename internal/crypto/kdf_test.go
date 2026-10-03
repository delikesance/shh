package crypto_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"git.delikesance.cloud/delikesance/shh/internal/crypto"
)

func TestDeriveChannelKey(t *testing.T) {
	info := "shh-dm-chacha20-poly1305"

	t.Run("derives 32-byte channel key successfully", func(t *testing.T) {
		secret := make([]byte, 32)
		rand.Read(secret)
		salt := make([]byte, 32)
		rand.Read(salt)

		key, err := crypto.DeriveChannelKey(secret, salt, info)
		if err != nil {
			t.Fatalf("unexpected error deriving key: %v", err)
		}

		if len(key) != 32 {
			t.Fatalf("expected 32-byte key, got %d bytes", len(key))
		}

		// Verify non-zero
		allZero := true
		for _, b := range key {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			t.Fatal("derived key is all zeros")
		}
	})

	t.Run("is deterministic for identical inputs", func(t *testing.T) {
		secret := []byte("01234567890123456789012345678901")
		salt := []byte("salt-for-testing-hkdf-sha256-32b")

		key1, err1 := crypto.DeriveChannelKey(secret, salt, info)
		if err1 != nil {
			t.Fatalf("key1 derivation failed: %v", err1)
		}

		key2, err2 := crypto.DeriveChannelKey(secret, salt, info)
		if err2 != nil {
			t.Fatalf("key2 derivation failed: %v", err2)
		}

		if !bytes.Equal(key1, key2) {
			t.Fatalf("expected deterministic output for identical inputs:\nkey1: %x\nkey2: %x", key1, key2)
		}
	})

	t.Run("produces distinct keys for different salts", func(t *testing.T) {
		secret := []byte("01234567890123456789012345678901")
		salt1 := []byte("salt-alpha----------------------")
		salt2 := []byte("salt-bravo----------------------")

		key1, err1 := crypto.DeriveChannelKey(secret, salt1, info)
		if err1 != nil {
			t.Fatalf("key1 error: %v", err1)
		}
		key2, err2 := crypto.DeriveChannelKey(secret, salt2, info)
		if err2 != nil {
			t.Fatalf("key2 error: %v", err2)
		}

		if bytes.Equal(key1, key2) {
			t.Fatal("different salts produced identical keys")
		}
	})

	t.Run("produces distinct keys for different info strings", func(t *testing.T) {
		secret := []byte("01234567890123456789012345678901")
		salt := []byte("salt----------------------------")

		key1, err1 := crypto.DeriveChannelKey(secret, salt, "info-1")
		if err1 != nil {
			t.Fatalf("key1 error: %v", err1)
		}
		key2, err2 := crypto.DeriveChannelKey(secret, salt, "info-2")
		if err2 != nil {
			t.Fatalf("key2 error: %v", err2)
		}

		if bytes.Equal(key1, key2) {
			t.Fatal("different info strings produced identical keys")
		}
	})

	t.Run("produces distinct keys for different secrets", func(t *testing.T) {
		secret1 := []byte("secret-one----------------------")
		secret2 := []byte("secret-two----------------------")
		salt := []byte("salt----------------------------")

		key1, err1 := crypto.DeriveChannelKey(secret1, salt, info)
		if err1 != nil {
			t.Fatalf("key1 error: %v", err1)
		}
		key2, err2 := crypto.DeriveChannelKey(secret2, salt, info)
		if err2 != nil {
			t.Fatalf("key2 error: %v", err2)
		}

		if bytes.Equal(key1, key2) {
			t.Fatal("different secrets produced identical keys")
		}
	})

	t.Run("handles nil and empty salt per RFC 5869", func(t *testing.T) {
		secret := []byte("secret-for-nil-salt-test-------")

		keyNilSalt, err := crypto.DeriveChannelKey(secret, nil, info)
		if err != nil {
			t.Fatalf("derivation with nil salt failed: %v", err)
		}
		if len(keyNilSalt) != 32 {
			t.Fatalf("expected 32 bytes with nil salt, got %d", len(keyNilSalt))
		}

		keyEmptySalt, err := crypto.DeriveChannelKey(secret, []byte{}, info)
		if err != nil {
			t.Fatalf("derivation with empty salt failed: %v", err)
		}

		// Per RFC 5869, nil or empty salt defaults to hashLen zeros
		if !bytes.Equal(keyNilSalt, keyEmptySalt) {
			t.Errorf("expected nil salt and empty salt to be equivalent:\nnil:   %x\nempty: %x", keyNilSalt, keyEmptySalt)
		}
	})

	t.Run("rejects empty shared secret", func(t *testing.T) {
		salt := []byte("salt----------------------------")

		if _, err := crypto.DeriveChannelKey(nil, salt, info); err == nil {
			t.Error("expected error for nil shared secret, got nil")
		}

		if _, err := crypto.DeriveChannelKey([]byte{}, salt, info); err == nil {
			t.Error("expected error for empty shared secret, got nil")
		}
	})
}
