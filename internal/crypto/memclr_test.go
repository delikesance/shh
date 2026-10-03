package crypto_test

import (
	"bytes"
	"testing"

	"git.delikesance.cloud/delikesance/shh/internal/crypto"
)

func TestMemclr(t *testing.T) {
	t.Run("zeros non-empty byte slice", func(t *testing.T) {
		buf := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
		crypto.Memclr(buf)
		expected := make([]byte, len(buf))
		if !bytes.Equal(buf, expected) {
			t.Errorf("Memclr failed: expected all zeros, got %v", buf)
		}
	})

	t.Run("zeros multi-byte buffers", func(t *testing.T) {
		sizes := []int{1, 16, 32, 64, 256, 1024}
		for _, size := range sizes {
			buf := make([]byte, size)
			for i := range buf {
				buf[i] = byte((i % 255) + 1)
			}
			crypto.Memclr(buf)
			for i, b := range buf {
				if b != 0 {
					t.Fatalf("Memclr failed at index %d for size %d: byte is %d", i, size, b)
				}
			}
		}
	})

	t.Run("handles nil slice gracefully", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Memclr panicked on nil slice: %v", r)
			}
		}()
		crypto.Memclr(nil)
	})

	t.Run("handles empty slice gracefully", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Memclr panicked on empty slice: %v", r)
			}
		}()
		crypto.Memclr([]byte{})
	})
}
