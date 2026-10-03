package peer_test

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"git.delikesance.cloud/delikesance/shh/internal/peer"
)

func TestNewRegistry(t *testing.T) {
	reg := peer.NewRegistry()
	if reg == nil {
		t.Fatal("expected NewRegistry to return non-nil")
	}
	if got := reg.Count(); got != 0 {
		t.Errorf("expected count 0, got %d", got)
	}
	if list := reg.List(); len(list) != 0 {
		t.Errorf("expected empty list, got len %d", len(list))
	}
}

func TestRegister_Success(t *testing.T) {
	reg := peer.NewRegistry()
	pubKey := generateTestSSHKey(t)
	p, err := peer.NewPeer(pubKey, "alice")
	if err != nil {
		t.Fatalf("unexpected error creating peer: %v", err)
	}

	if err := reg.Register(p); err != nil {
		t.Fatalf("expected Register to succeed, got %v", err)
	}

	if reg.Count() != 1 {
		t.Errorf("expected count 1, got %d", reg.Count())
	}

	// Verify lookup by fingerprint
	got, ok := reg.Get(p.Fingerprint())
	if !ok || got != p {
		t.Errorf("Get(fingerprint) = (%v, %v), want (%v, true)", got, ok, p)
	}

	// Verify lookup by handle
	gotByHandle, ok := reg.GetByHandle("alice")
	if !ok || gotByHandle != p {
		t.Errorf("GetByHandle(\"alice\") = (%v, %v), want (%v, true)", gotByHandle, ok, p)
	}
}

func TestRegister_NilPeer(t *testing.T) {
	reg := peer.NewRegistry()
	err := reg.Register(nil)
	if err == nil {
		t.Fatal("expected error registering nil peer, got nil")
	}
	if !errors.Is(err, peer.ErrNilPeer) {
		t.Errorf("expected ErrNilPeer, got %v", err)
	}
}

func TestRegister_DuplicateFingerprint(t *testing.T) {
	reg := peer.NewRegistry()
	pubKey := generateTestSSHKey(t)

	p1, err := peer.NewPeer(pubKey, "alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := reg.Register(p1); err != nil {
		t.Fatalf("unexpected error registering p1: %v", err)
	}

	// Create p2 with the same public key (same fingerprint) but different handle
	p2, err := peer.NewPeer(pubKey, "bob")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = reg.Register(p2)
	if err == nil {
		t.Fatal("expected error registering duplicate fingerprint, got nil")
	}
	if !errors.Is(err, peer.ErrDuplicateFingerprint) {
		t.Errorf("expected ErrDuplicateFingerprint, got %v", err)
	}

	// Registry count must remain 1
	if reg.Count() != 1 {
		t.Errorf("expected count 1, got %d", reg.Count())
	}
}

func TestRegister_DuplicateHandle(t *testing.T) {
	reg := peer.NewRegistry()
	pubKey1 := generateTestSSHKey(t)
	pubKey2 := generateTestSSHKey(t)

	p1, err := peer.NewPeer(pubKey1, "alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := reg.Register(p1); err != nil {
		t.Fatalf("unexpected error registering p1: %v", err)
	}

	// Create p2 with different key but exact same handle
	p2, err := peer.NewPeer(pubKey2, "alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = reg.Register(p2)
	if err == nil {
		t.Fatal("expected error registering duplicate handle, got nil")
	}
	if !errors.Is(err, peer.ErrDuplicateHandle) {
		t.Errorf("expected ErrDuplicateHandle, got %v", err)
	}

	// Create p3 with different key and case-variant handle (e.g. "Alice")
	pubKey3 := generateTestSSHKey(t)
	p3, err := peer.NewPeer(pubKey3, "Alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = reg.Register(p3)
	if err == nil {
		t.Fatal("expected error registering case-insensitive duplicate handle, got nil")
	}
	if !errors.Is(err, peer.ErrDuplicateHandle) {
		t.Errorf("expected ErrDuplicateHandle, got %v", err)
	}

	if reg.Count() != 1 {
		t.Errorf("expected count 1, got %d", reg.Count())
	}
}

func TestUnregister_Success(t *testing.T) {
	reg := peer.NewRegistry()
	pubKey := generateTestSSHKey(t)
	p, err := peer.NewPeer(pubKey, "alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := reg.Register(p); err != nil {
		t.Fatalf("unexpected error registering: %v", err)
	}

	// Unregister existing peer
	err = reg.Unregister(p.Fingerprint())
	if err != nil {
		t.Fatalf("expected Unregister to succeed, got %v", err)
	}

	if reg.Count() != 0 {
		t.Errorf("expected count 0, got %d", reg.Count())
	}

	// Peer should no longer be found by fingerprint
	if _, ok := reg.Get(p.Fingerprint()); ok {
		t.Error("peer still found by fingerprint after Unregister")
	}

	// Peer should no longer be found by handle
	if _, ok := reg.GetByHandle("alice"); ok {
		t.Error("peer still found by handle after Unregister")
	}

	// Handle should now be free to re-register with a different key
	pubKey2 := generateTestSSHKey(t)
	p2, err := peer.NewPeer(pubKey2, "alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := reg.Register(p2); err != nil {
		t.Fatalf("expected re-registering released handle to succeed, got: %v", err)
	}
	if reg.Count() != 1 {
		t.Errorf("expected count 1, got %d", reg.Count())
	}
}

func TestUnregister_NotFound(t *testing.T) {
	reg := peer.NewRegistry()
	err := reg.Unregister("nonexistent-fingerprint")
	if err == nil {
		t.Fatal("expected error unregistering nonexistent peer, got nil")
	}
	if !errors.Is(err, peer.ErrPeerNotFound) {
		t.Errorf("expected ErrPeerNotFound, got %v", err)
	}
}

func TestGet(t *testing.T) {
	reg := peer.NewRegistry()
	pubKey := generateTestSSHKey(t)
	p, _ := peer.NewPeer(pubKey, "alice")
	_ = reg.Register(p)

	// Existing peer
	got, ok := reg.Get(p.Fingerprint())
	if !ok || got != p {
		t.Errorf("Get(%q) = (%v, %v), want (%v, true)", p.Fingerprint(), got, ok, p)
	}

	// Non-existent peer
	got, ok = reg.Get("nonexistent")
	if ok || got != nil {
		t.Errorf("Get(\"nonexistent\") = (%v, %v), want (nil, false)", got, ok)
	}
}

func TestGetByHandle(t *testing.T) {
	reg := peer.NewRegistry()
	pubKey := generateTestSSHKey(t)
	p, _ := peer.NewPeer(pubKey, "Alice_Dev")
	_ = reg.Register(p)

	// Exact handle
	got, ok := reg.GetByHandle("Alice_Dev")
	if !ok || got != p {
		t.Errorf("GetByHandle(\"Alice_Dev\") = (%v, %v), want (%v, true)", got, ok, p)
	}

	// Case-insensitive match
	got, ok = reg.GetByHandle("alice_dev")
	if !ok || got != p {
		t.Errorf("GetByHandle(\"alice_dev\") = (%v, %v), want (%v, true)", got, ok, p)
	}

	// Non-existent handle
	got, ok = reg.GetByHandle("bob")
	if ok || got != nil {
		t.Errorf("GetByHandle(\"bob\") = (%v, %v), want (nil, false)", got, ok)
	}
}

func TestUpdateHandle(t *testing.T) {
	reg := peer.NewRegistry()
	pubKey1 := generateTestSSHKey(t)
	pubKey2 := generateTestSSHKey(t)

	p1, _ := peer.NewPeer(pubKey1, "alice")
	p2, _ := peer.NewPeer(pubKey2, "bob")
	_ = reg.Register(p1)
	_ = reg.Register(p2)

	// 1. Invalid handle format
	err := reg.UpdateHandle(p1.Fingerprint(), "a")
	if !errors.Is(err, peer.ErrInvalidHandle) {
		t.Errorf("expected ErrInvalidHandle, got %v", err)
	}
	if p1.Handle() != "alice" {
		t.Errorf("expected handle to remain alice, got %q", p1.Handle())
	}

	// 2. Peer not found
	err = reg.UpdateHandle("nonexistent", "charlie")
	if !errors.Is(err, peer.ErrPeerNotFound) {
		t.Errorf("expected ErrPeerNotFound, got %v", err)
	}

	// 3. Collision with another peer's handle
	err = reg.UpdateHandle(p1.Fingerprint(), "bob")
	if !errors.Is(err, peer.ErrDuplicateHandle) {
		t.Errorf("expected ErrDuplicateHandle, got %v", err)
	}
	// Case-insensitive collision with another peer
	err = reg.UpdateHandle(p1.Fingerprint(), "BOB")
	if !errors.Is(err, peer.ErrDuplicateHandle) {
		t.Errorf("expected ErrDuplicateHandle on case collision, got %v", err)
	}

	// 4. Keeping current handle (exact match)
	err = reg.UpdateHandle(p1.Fingerprint(), "alice")
	if err != nil {
		t.Errorf("expected keeping current handle to succeed, got %v", err)
	}
	if p1.Handle() != "alice" {
		t.Errorf("expected handle to be alice, got %q", p1.Handle())
	}

	// 5. Changing casing of current handle
	err = reg.UpdateHandle(p1.Fingerprint(), "Alice")
	if err != nil {
		t.Errorf("expected changing casing of own handle to succeed, got %v", err)
	}
	if p1.Handle() != "Alice" {
		t.Errorf("expected handle to be Alice, got %q", p1.Handle())
	}

	// 6. Valid new handle
	err = reg.UpdateHandle(p1.Fingerprint(), "alicia")
	if err != nil {
		t.Fatalf("expected valid handle update to succeed, got %v", err)
	}
	if p1.Handle() != "alicia" {
		t.Errorf("expected p1 handle to be alicia, got %q", p1.Handle())
	}

	// Old handle should no longer resolve
	if _, ok := reg.GetByHandle("alice"); ok {
		t.Error("old handle 'alice' still resolvable after update")
	}

	// New handle should resolve
	got, ok := reg.GetByHandle("alicia")
	if !ok || got != p1 {
		t.Errorf("new handle 'alicia' not found: (%v, %v)", got, ok)
	}

	// Old handle can now be taken by p2
	err = reg.UpdateHandle(p2.Fingerprint(), "alice")
	if err != nil {
		t.Errorf("expected p2 to take old released handle, got %v", err)
	}
}

func TestList_Snapshot(t *testing.T) {
	reg := peer.NewRegistry()
	pubKey1 := generateTestSSHKey(t)
	pubKey2 := generateTestSSHKey(t)
	pubKey3 := generateTestSSHKey(t)

	p1, _ := peer.NewPeer(pubKey1, "user1")
	p2, _ := peer.NewPeer(pubKey2, "user2")
	p3, _ := peer.NewPeer(pubKey3, "user3")

	_ = reg.Register(p1)
	_ = reg.Register(p2)
	_ = reg.Register(p3)

	list := reg.List()
	if len(list) != 3 {
		t.Fatalf("expected 3 peers in list, got %d", len(list))
	}

	// Verify modifying returned slice does not corrupt registry
	list[0] = nil
	list = append(list, nil)

	newList := reg.List()
	if len(newList) != 3 {
		t.Fatalf("internal registry modified after mutating List() slice: got len %d", len(newList))
	}
	for i, p := range newList {
		if p == nil {
			t.Errorf("peer at index %d is nil in snapshot", i)
		}
	}
}

func TestConcurrencySafety(t *testing.T) {
	reg := peer.NewRegistry()
	const numPeers = 20
	peers := make([]*peer.Peer, numPeers)

	for i := 0; i < numPeers; i++ {
		pubKey := generateTestSSHKey(t)
		p, err := peer.NewPeer(pubKey, fmt.Sprintf("user_%03d", i))
		if err != nil {
			t.Fatalf("failed to create peer %d: %v", i, err)
		}
		peers[i] = p
	}

	var wg sync.WaitGroup
	const workers = 16
	const iterations = 100

	var regCount atomic.Int64

	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func(workerID int) {
			defer wg.Done()
			for iter := 0; iter < iterations; iter++ {
				idx := (workerID*iterations + iter) % numPeers
				p := peers[idx]

				switch iter % 6 {
				case 0:
					// Register
					if err := reg.Register(p); err == nil {
						regCount.Add(1)
					}
				case 1:
					// Unregister
					if err := reg.Unregister(p.Fingerprint()); err == nil {
						regCount.Add(-1)
					}
				case 2:
					// Get by fingerprint
					_, _ = reg.Get(p.Fingerprint())
				case 3:
					// Get by handle
					_, _ = reg.GetByHandle(p.Handle())
				case 4:
					// Update handle
					newHandle := fmt.Sprintf("u%02d_%04d", idx, iter)
					_ = reg.UpdateHandle(p.Fingerprint(), newHandle)
				case 5:
					// List snapshot & Count
					_ = reg.List()
					_ = reg.Count()
				}
			}
		}(w)
	}

	wg.Wait()
}

func TestRegister_UninitializedPeer(t *testing.T) {
	reg := peer.NewRegistry()

	// Empty peer struct (no pubkey, empty fingerprint)
	p := &peer.Peer{}
	err := reg.Register(p)
	if err == nil {
		t.Fatal("expected error registering empty peer struct, got nil")
	}
	if !errors.Is(err, peer.ErrNilPublicKey) {
		t.Errorf("expected ErrNilPublicKey, got %v", err)
	}
}
