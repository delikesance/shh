package crypto_test

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"math"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"

	"git.delikesance.cloud/delikesance/shh/internal/crypto"
)

func TestNonceFromCounter(t *testing.T) {
	t.Run("generates 12-byte nonce matching counter encoding", func(t *testing.T) {
		counters := []uint64{
			0,
			1,
			42,
			1000,
			0x0102030405060708,
			math.MaxUint64,
		}

		for _, c := range counters {
			nonce := crypto.NonceFromCounter(c)
			if len(nonce) != chacha20poly1305.NonceSize {
				t.Fatalf("expected nonce size %d, got %d", chacha20poly1305.NonceSize, len(nonce))
			}

			// Leading 4 bytes should be 0
			for i := 0; i < 4; i++ {
				if nonce[i] != 0 {
					t.Fatalf("expected nonce[%d] to be 0, got %d", i, nonce[i])
				}
			}

			// Trailing 8 bytes should be counter in big-endian
			parsedCounter := binary.BigEndian.Uint64(nonce[4:])
			if parsedCounter != c {
				t.Fatalf("expected counter %d, got %d", c, parsedCounter)
			}
		}
	})

	t.Run("monotonic counters generate distinct nonces", func(t *testing.T) {
		n1 := crypto.NonceFromCounter(100)
		n2 := crypto.NonceFromCounter(101)

		if bytes.Equal(n1, n2) {
			t.Fatal("consecutive counters generated identical nonces")
		}
	})
}

func TestSealAndOpen(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	rand.Read(key)
	nonce := crypto.NonceFromCounter(1)
	plaintext := []byte("hello, secure ephemeral world!")
	ad := []byte("additional-authenticated-data")

	t.Run("round-trip encryption and decryption with AD", func(t *testing.T) {
		ciphertext, err := crypto.Seal(key, nonce, plaintext, ad)
		if err != nil {
			t.Fatalf("Seal failed: %v", err)
		}

		// ChaCha20-Poly1305 ciphertext length is plaintext length + 16 (Poly1305 overhead)
		expectedLen := len(plaintext) + chacha20poly1305.Overhead
		if len(ciphertext) != expectedLen {
			t.Fatalf("expected ciphertext length %d, got %d", expectedLen, len(ciphertext))
		}

		decrypted, err := crypto.Open(key, nonce, ciphertext, ad)
		if err != nil {
			t.Fatalf("Open failed: %v", err)
		}

		if !bytes.Equal(decrypted, plaintext) {
			t.Fatalf("decrypted text mismatch:\ngot:  %s\nwant: %s", decrypted, plaintext)
		}
	})

	t.Run("round-trip encryption without AD", func(t *testing.T) {
		ciphertext, err := crypto.Seal(key, nonce, plaintext, nil)
		if err != nil {
			t.Fatalf("Seal failed: %v", err)
		}

		decrypted, err := crypto.Open(key, nonce, ciphertext, nil)
		if err != nil {
			t.Fatalf("Open failed: %v", err)
		}

		if !bytes.Equal(decrypted, plaintext) {
			t.Fatalf("decrypted text mismatch: got %s, want %s", decrypted, plaintext)
		}
	})

	t.Run("round-trip with empty plaintext", func(t *testing.T) {
		emptyPlaintext := []byte{}
		ciphertext, err := crypto.Seal(key, nonce, emptyPlaintext, ad)
		if err != nil {
			t.Fatalf("Seal failed: %v", err)
		}

		if len(ciphertext) != chacha20poly1305.Overhead {
			t.Fatalf("expected %d bytes for empty plaintext, got %d", chacha20poly1305.Overhead, len(ciphertext))
		}

		decrypted, err := crypto.Open(key, nonce, ciphertext, ad)
		if err != nil {
			t.Fatalf("Open failed: %v", err)
		}

		if len(decrypted) != 0 {
			t.Fatalf("expected empty decrypted plaintext, got %d bytes", len(decrypted))
		}
	})

	t.Run("rejects corrupted ciphertext", func(t *testing.T) {
		ciphertext, err := crypto.Seal(key, nonce, plaintext, ad)
		if err != nil {
			t.Fatalf("Seal failed: %v", err)
		}

		// Corrupt a byte
		corrupted := make([]byte, len(ciphertext))
		copy(corrupted, ciphertext)
		corrupted[0] ^= 0xFF

		if _, err := crypto.Open(key, nonce, corrupted, ad); err == nil {
			t.Fatal("expected Open to fail on corrupted ciphertext, but got nil error")
		}
	})

	t.Run("rejects tampered additional data", func(t *testing.T) {
		ciphertext, err := crypto.Seal(key, nonce, plaintext, ad)
		if err != nil {
			t.Fatalf("Seal failed: %v", err)
		}

		tamperedAD := []byte("tampered-additional-data")
		if _, err := crypto.Open(key, nonce, ciphertext, tamperedAD); err == nil {
			t.Fatal("expected Open to fail on tampered AD, but got nil error")
		}
	})

	t.Run("rejects incorrect key", func(t *testing.T) {
		ciphertext, err := crypto.Seal(key, nonce, plaintext, ad)
		if err != nil {
			t.Fatalf("Seal failed: %v", err)
		}

		wrongKey := make([]byte, chacha20poly1305.KeySize)
		copy(wrongKey, key)
		wrongKey[0] ^= 0xFF

		if _, err := crypto.Open(wrongKey, nonce, ciphertext, ad); err == nil {
			t.Fatal("expected Open to fail with incorrect key, but got nil error")
		}
	})

	t.Run("rejects incorrect nonce", func(t *testing.T) {
		ciphertext, err := crypto.Seal(key, nonce, plaintext, ad)
		if err != nil {
			t.Fatalf("Seal failed: %v", err)
		}

		wrongNonce := crypto.NonceFromCounter(9999)
		if _, err := crypto.Open(key, wrongNonce, ciphertext, ad); err == nil {
			t.Fatal("expected Open to fail with incorrect nonce, but got nil error")
		}
	})

	t.Run("rejects invalid key sizes", func(t *testing.T) {
		invalidKeys := [][]byte{
			nil,
			{},
			make([]byte, 16),
			make([]byte, 31),
			make([]byte, 33),
		}

		for _, k := range invalidKeys {
			if _, err := crypto.Seal(k, nonce, plaintext, ad); err == nil {
				t.Errorf("expected Seal to fail with key size %d", len(k))
			}
			if _, err := crypto.Open(k, nonce, []byte("fake-ciphertext"), ad); err == nil {
				t.Errorf("expected Open to fail with key size %d", len(k))
			}
		}
	})

	t.Run("rejects invalid nonce sizes", func(t *testing.T) {
		invalidNonces := [][]byte{
			nil,
			{},
			make([]byte, 8),
			make([]byte, 11),
			make([]byte, 13),
			make([]byte, 24),
		}

		for _, n := range invalidNonces {
			if _, err := crypto.Seal(key, n, plaintext, ad); err == nil {
				t.Errorf("expected Seal to fail with nonce size %d", len(n))
			}
			if _, err := crypto.Open(key, n, []byte("fake-ciphertext"), ad); err == nil {
				t.Errorf("expected Open to fail with nonce size %d", len(n))
			}
		}
	})
}
