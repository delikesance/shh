package crypto

import (
	"crypto/sha256"
	"encoding/hex"

	"golang.org/x/crypto/ssh"
)

// Fingerprint computes the SHA-256 fingerprint hex string of an SSH public key
// by hashing the OpenSSH authorized key wire representation:
// SHA256(ssh.MarshalAuthorizedKey(pubKey)).
// Returns an empty string if pubKey is nil.
func Fingerprint(pubKey ssh.PublicKey) string {
	if pubKey == nil {
		return ""
	}
	sum := sha256.Sum256(ssh.MarshalAuthorizedKey(pubKey))
	return hex.EncodeToString(sum[:])
}
