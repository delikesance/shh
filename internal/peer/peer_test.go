package peer_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
	"time"

	"git.delikesance.cloud/delikesance/shh/internal/peer"
	"golang.org/x/crypto/ssh"
)

func generateTestSSHKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("failed to create ssh public key: %v", err)
	}
	return sshPub
}

func computeExpectedFingerprint(pubKey ssh.PublicKey) string {
	h := sha256.Sum256(ssh.MarshalAuthorizedKey(pubKey))
	return hex.EncodeToString(h[:])
}

func TestNewPeer_Success(t *testing.T) {
	pubKey := generateTestSSHKey(t)
	handle := "alice_99"

	p, err := peer.NewPeer(pubKey, handle)
	if err != nil {
		t.Fatalf("expected NewPeer to succeed, got error: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil peer")
	}

	if p.Handle() != handle {
		t.Errorf("expected handle %q, got %q", handle, p.Handle())
	}

	if !bytes.Equal(p.PublicKey().Marshal(), pubKey.Marshal()) {
		t.Errorf("expected public key %v, got %v", pubKey, p.PublicKey())
	}

	expectedFP := computeExpectedFingerprint(pubKey)
	if p.Fingerprint() != expectedFP {
		t.Errorf("expected fingerprint %s, got %s", expectedFP, p.Fingerprint())
	}

	if p.Presence() != peer.PresenceOnline {
		t.Errorf("expected default presence %q, got %q", peer.PresenceOnline, p.Presence())
	}

	if time.Since(p.ConnectedAt()) > 2*time.Second {
		t.Errorf("expected recent ConnectedAt, got %v", p.ConnectedAt())
	}
}

func TestNewPeer_NilPublicKey(t *testing.T) {
	_, err := peer.NewPeer(nil, "alice")
	if err == nil {
		t.Fatal("expected error when pubKey is nil, got nil")
	}
	if !errors.Is(err, peer.ErrNilPublicKey) {
		t.Errorf("expected ErrNilPublicKey, got %v", err)
	}
}

func TestValidateHandle(t *testing.T) {
	tests := []struct {
		name    string
		handle  string
		wantErr bool
	}{
		// Valid handles: 3-20 chars, alphanumeric + underscore + dash
		{name: "min length (3 chars)", handle: "abc", wantErr: false},
		{name: "with underscore", handle: "user_name", wantErr: false},
		{name: "with dash", handle: "user-name", wantErr: false},
		{name: "with numbers", handle: "user123", wantErr: false},
		{name: "mixed case", handle: "AliceDev", wantErr: false},
		{name: "max length (20 chars)", handle: "abcdefghijklmnopqrst", wantErr: false},
		{name: "mixed separators", handle: "a_b-1_2-3", wantErr: false},

		// Invalid handles
		{name: "empty string", handle: "", wantErr: true},
		{name: "too short (1 char)", handle: "a", wantErr: true},
		{name: "too short (2 chars)", handle: "ab", wantErr: true},
		{name: "too long (21 chars)", handle: "abcdefghijklmnopqrstu", wantErr: true},
		{name: "contains space", handle: "alice dev", wantErr: true},
		{name: "contains special char !", handle: "alice!", wantErr: true},
		{name: "contains at sign @", handle: "alice@ssh", wantErr: true},
		{name: "contains hash #", handle: "alice#001", wantErr: true},
		{name: "contains dot .", handle: "alice.dev", wantErr: true},
		{name: "contains slash /", handle: "alice/dev", wantErr: true},
		{name: "contains non-ascii", handle: "alíce", wantErr: true},
	}

	pubKey := generateTestSSHKey(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := peer.ValidateHandle(tt.handle)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateHandle(%q) error = %v, wantErr = %v", tt.handle, err, tt.wantErr)
			}
			if tt.wantErr && !errors.Is(err, peer.ErrInvalidHandle) {
				t.Errorf("expected ErrInvalidHandle, got %v", err)
			}

			// Also verify NewPeer rejects invalid handles
			_, err = peer.NewPeer(pubKey, tt.handle)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewPeer(pubKey, %q) error = %v, wantErr = %v", tt.handle, err, tt.wantErr)
			}
		})
	}
}

func TestPeer_FingerprintImmutability(t *testing.T) {
	pubKey := generateTestSSHKey(t)
	p, err := peer.NewPeer(pubKey, "alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	initialFP := p.Fingerprint()
	expectedFP := computeExpectedFingerprint(pubKey)
	if initialFP != expectedFP {
		t.Fatalf("expected fingerprint %s, got %s", expectedFP, initialFP)
	}

	// Change handle
	if err := p.SetHandle("bob_new"); err != nil {
		t.Fatalf("failed to set handle: %v", err)
	}
	if p.Fingerprint() != initialFP {
		t.Errorf("fingerprint changed after SetHandle! got %s, want %s", p.Fingerprint(), initialFP)
	}

	// Change presence
	if err := p.SetPresence(peer.PresenceIdle); err != nil {
		t.Fatalf("failed to set presence: %v", err)
	}
	if p.Fingerprint() != initialFP {
		t.Errorf("fingerprint changed after SetPresence! got %s, want %s", p.Fingerprint(), initialFP)
	}

	// Update activity
	p.Touch()
	if p.Fingerprint() != initialFP {
		t.Errorf("fingerprint changed after Touch! got %s, want %s", p.Fingerprint(), initialFP)
	}
}

func TestPeer_PresenceStates(t *testing.T) {
	pubKey := generateTestSSHKey(t)
	p, err := peer.NewPeer(pubKey, "alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Initial state must be Online
	if p.Presence() != peer.PresenceOnline {
		t.Errorf("expected initial presence %q, got %q", peer.PresenceOnline, p.Presence())
	}

	// Valid presence transitions
	validStates := []peer.PresenceState{
		peer.PresenceActive,
		peer.PresenceIdle,
		peer.PresenceDisconnected,
		peer.PresenceOnline,
	}

	for _, state := range validStates {
		t.Run(string(state), func(t *testing.T) {
			if err := p.SetPresence(state); err != nil {
				t.Fatalf("SetPresence(%q) failed: %v", state, err)
			}
			if p.Presence() != state {
				t.Errorf("expected presence %q, got %q", state, p.Presence())
			}
		})
	}

	// Invalid presence state
	t.Run("invalid presence", func(t *testing.T) {
		err := p.SetPresence(peer.PresenceState("unknown_state"))
		if err == nil {
			t.Fatal("expected error for invalid presence state, got nil")
		}
		if !errors.Is(err, peer.ErrInvalidPresence) {
			t.Errorf("expected ErrInvalidPresence, got %v", err)
		}
	})
}

func TestPeer_TouchAndLastActive(t *testing.T) {
	pubKey := generateTestSSHKey(t)
	p, err := peer.NewPeer(pubKey, "alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	t1 := p.LastActive()
	time.Sleep(10 * time.Millisecond)
	p.Touch()
	t2 := p.LastActive()

	if !t2.After(t1) {
		t.Errorf("expected LastActive to advance after Touch(): t1=%v, t2=%v", t1, t2)
	}
}

func TestPeer_ConcurrentAccess(t *testing.T) {
	pubKey := generateTestSSHKey(t)
	p, err := peer.NewPeer(pubKey, "alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	const goroutines = 20
	const iterations = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_ = p.Handle()
				_ = p.Fingerprint()
				_ = p.PublicKey()
				_ = p.Presence()
				_ = p.ConnectedAt()
				_ = p.LastActive()
				p.Touch()

				if id%2 == 0 {
					_ = p.SetPresence(peer.PresenceActive)
				} else {
					_ = p.SetPresence(peer.PresenceIdle)
				}
			}
		}(i)
	}

	wg.Wait()
}

func TestFingerprintKey_Nil(t *testing.T) {
	if got := peer.FingerprintKey(nil); got != "" {
		t.Errorf("FingerprintKey(nil) = %q, want empty string", got)
	}
}

func TestPeer_SetHandle_Invalid(t *testing.T) {
	pubKey := generateTestSSHKey(t)
	p, err := peer.NewPeer(pubKey, "alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = p.SetHandle("a")
	if !errors.Is(err, peer.ErrInvalidHandle) {
		t.Errorf("expected ErrInvalidHandle, got %v", err)
	}
	if p.Handle() != "alice" {
		t.Errorf("expected handle to remain alice, got %q", p.Handle())
	}
}

func TestPeer_PresenceHelpers(t *testing.T) {
	pubKey := generateTestSSHKey(t)
	p, err := peer.NewPeer(pubKey, "alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !p.IsOnline() {
		t.Error("expected IsOnline to be true")
	}

	_ = p.SetPresence(peer.PresenceActive)
	if !p.IsActive() {
		t.Error("expected IsActive to be true")
	}

	_ = p.SetPresence(peer.PresenceIdle)
	if !p.IsIdle() {
		t.Error("expected IsIdle to be true")
	}

	_ = p.SetPresence(peer.PresenceDisconnected)
	if !p.IsDisconnected() {
		t.Error("expected IsDisconnected to be true")
	}
}

func TestPeer_String(t *testing.T) {
	pubKey := generateTestSSHKey(t)
	p, err := peer.NewPeer(pubKey, "alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	str := p.String()
	if str == "" {
		t.Error("expected non-empty string")
	}
	if p.Handle() != "alice" {
		t.Errorf("expected handle alice, got %s", p.Handle())
	}
}
