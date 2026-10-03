package daemon_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"git.delikesance.cloud/delikesance/shh/internal/daemon"
	"golang.org/x/crypto/ssh"
)

func TestLoadOrGenerateHostKey_GenerateNew(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test_ed25519_key")

	// Verify file does not exist initially
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatalf("expected key file to not exist initially")
	}

	signer, err := daemon.LoadOrGenerateHostKey(keyPath)
	if err != nil {
		t.Fatalf("LoadOrGenerateHostKey failed: %v", err)
	}
	if signer == nil {
		t.Fatalf("expected non-nil ssh.Signer")
	}

	// Verify key algorithm is ssh-ed25519
	if got := signer.PublicKey().Type(); got != ssh.KeyAlgoED25519 {
		t.Errorf("expected key type %q, got %q", ssh.KeyAlgoED25519, got)
	}

	// Verify file exists and has 0600 permissions
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("failed to stat generated key file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("expected file permissions 0600, got %#o", perm)
	}

	// Verify key is functionally valid for signing (ensures memclr did not destroy signer)
	sig, err := signer.Sign(nil, []byte("test-payload-generation"))
	if err != nil {
		t.Fatalf("failed to sign with generated host key: %v", err)
	}
	if err := signer.PublicKey().Verify([]byte("test-payload-generation"), sig); err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}
}

func TestLoadOrGenerateHostKey_NestedDirectoryCreation(t *testing.T) {
	tmpDir := t.TempDir()
	nestedKeyPath := filepath.Join(tmpDir, "nested", "keys", "host_ed25519")

	signer, err := daemon.LoadOrGenerateHostKey(nestedKeyPath)
	if err != nil {
		t.Fatalf("LoadOrGenerateHostKey with nested directory failed: %v", err)
	}
	if signer == nil {
		t.Fatalf("expected non-nil signer")
	}

	// Verify directory permissions
	dirInfo, err := os.Stat(filepath.Dir(nestedKeyPath))
	if err != nil {
		t.Fatalf("failed to stat parent dir: %v", err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0700 {
		t.Errorf("expected parent directory permissions 0700, got %#o", perm)
	}
}

func TestLoadOrGenerateHostKey_LoadExisting(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test_ed25519_key")

	// First call: generates new key
	signer1, err := daemon.LoadOrGenerateHostKey(keyPath)
	if err != nil {
		t.Fatalf("first LoadOrGenerateHostKey failed: %v", err)
	}

	// Second call: loads the existing key without regenerating
	signer2, err := daemon.LoadOrGenerateHostKey(keyPath)
	if err != nil {
		t.Fatalf("second LoadOrGenerateHostKey failed: %v", err)
	}

	// The public keys must be byte-for-byte identical
	pub1 := signer1.PublicKey().Marshal()
	pub2 := signer2.PublicKey().Marshal()
	if !bytes.Equal(pub1, pub2) {
		t.Fatalf("loaded key does not match originally generated key")
	}

	// Verify loaded key signs correctly
	sig, err := signer2.Sign(nil, []byte("test-payload-load"))
	if err != nil {
		t.Fatalf("failed to sign with loaded host key: %v", err)
	}
	if err := signer2.PublicKey().Verify([]byte("test-payload-load"), sig); err != nil {
		t.Fatalf("loaded key signature verification failed: %v", err)
	}
}

func TestLoadOrGenerateHostKey_InvalidUnwritablePath(t *testing.T) {
	// Test with unwritable / invalid paths
	unwritablePaths := []string{
		"",
		"/proc/nonexistent/key",
		"/dev/null/forbidden/key",
	}

	for _, path := range unwritablePaths {
		signer, err := daemon.LoadOrGenerateHostKey(path)
		if err == nil {
			t.Errorf("expected error for unwritable path %q, got nil", path)
		}
		if signer != nil {
			t.Errorf("expected nil signer for unwritable path %q, got non-nil", path)
		}
	}
}

func TestLoadOrGenerateHostKey_CorruptedFile(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "corrupted_key")

	// Write invalid/corrupted data
	if err := os.WriteFile(keyPath, []byte("NOT A VALID SSH PRIVATE KEY"), 0600); err != nil {
		t.Fatalf("failed to write corrupted file: %v", err)
	}

	signer, err := daemon.LoadOrGenerateHostKey(keyPath)
	if err == nil {
		t.Fatalf("expected error loading corrupted key, got nil")
	}
	if signer != nil {
		t.Fatalf("expected nil signer for corrupted key, got non-nil")
	}
}
