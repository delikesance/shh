package crypto_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/ssh"

	"git.delikesance.cloud/delikesance/shh/internal/crypto"
)

func TestFingerprint(t *testing.T) {
	t.Run("computes SHA256 of ssh.MarshalAuthorizedKey", func(t *testing.T) {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate ed25519 key: %v", err)
		}

		sshPubKey, err := ssh.NewPublicKey(pub)
		if err != nil {
			t.Fatalf("failed to convert to ssh.PublicKey: %v", err)
		}

		expectedHash := sha256.Sum256(ssh.MarshalAuthorizedKey(sshPubKey))
		expectedFingerprint := hex.EncodeToString(expectedHash[:])

		fp := crypto.Fingerprint(sshPubKey)
		if fp != expectedFingerprint {
			t.Errorf("Fingerprint mismatch:\nexpected: %s\ngot:      %s", expectedFingerprint, fp)
		}
	})

	t.Run("returns distinct fingerprints for distinct keys", func(t *testing.T) {
		pub1, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate key 1: %v", err)
		}
		pub2, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate key 2: %v", err)
		}

		sshPub1, err := ssh.NewPublicKey(pub1)
		if err != nil {
			t.Fatalf("failed to convert key 1: %v", err)
		}
		sshPub2, err := ssh.NewPublicKey(pub2)
		if err != nil {
			t.Fatalf("failed to convert key 2: %v", err)
		}

		fp1 := crypto.Fingerprint(sshPub1)
		fp2 := crypto.Fingerprint(sshPub2)

		if fp1 == fp2 {
			t.Fatalf("expected different fingerprints for different keys, got identical: %s", fp1)
		}
	})

	t.Run("returns empty string for nil public key", func(t *testing.T) {
		fp := crypto.Fingerprint(nil)
		if fp != "" {
			t.Errorf("expected empty string for nil public key, got: %s", fp)
		}
	})
}
