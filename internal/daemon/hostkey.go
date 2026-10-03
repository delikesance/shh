package daemon

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"git.delikesance.cloud/delikesance/shh/internal/crypto"
	"golang.org/x/crypto/ssh"
)

var (
	// ErrEmptyHostKeyPath is returned when an empty path is provided to LoadOrGenerateHostKey.
	ErrEmptyHostKeyPath = errors.New("host key path cannot be empty")
)

// LoadOrGenerateHostKey loads an existing Ed25519 SSH host key from the specified path.
// If the file does not exist, it generates a new Ed25519 key pair, writes it to disk
// with strictly enforced 0600 permissions, and returns the ssh.Signer.
// Any sensitive private key material in memory during generation is wiped using crypto.Memclr.
func LoadOrGenerateHostKey(path string) (ssh.Signer, error) {
	if path == "" {
		return nil, ErrEmptyHostKeyPath
	}

	data, err := os.ReadFile(path)
	if err == nil {
		defer crypto.Memclr(data)
		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse host key at %q: %w", path, err)
		}
		return signer, nil
	}

	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to read host key at %q: %w", path, err)
	}

	// Key file does not exist; generate a new Ed25519 key pair
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ed25519 key: %w", err)
	}
	defer crypto.Memclr(priv)

	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	defer crypto.Memclr(block.Bytes)

	pemBytes := pem.EncodeToMemory(block)
	if pemBytes == nil {
		return nil, errors.New("failed to encode private key block to PEM")
	}
	defer crypto.Memclr(pemBytes)

	// Ensure parent directory exists
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("failed to create directory for host key %q: %w", dir, err)
		}
	}

	// Open file exclusively with 0600 permissions to avoid races
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open host key file %q: %w", path, err)
	}
	if _, err := f.Write(pemBytes); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("failed to write host key data to %q: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("failed to close host key file %q: %w", path, err)
	}

	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated host key: %w", err)
	}

	return signer, nil
}
