package channel

import (
	"bytes"
	"encoding/binary"
	"sync"
	"testing"
	"time"
)

func TestNewChannel(t *testing.T) {
	selfFP := "SHA256:alice1234567890abcdef"
	peerFP := "SHA256:bob1234567890abcdef"
	sharedKey := []byte("01234567890123456789012345678901") // 32 bytes

	ch := NewChannel(selfFP, peerFP, sharedKey)
	if ch == nil {
		t.Fatal("expected non-nil Channel")
	}

	if ch.SelfFP() != selfFP {
		t.Errorf("expected selfFP %s, got %s", selfFP, ch.SelfFP())
	}
	if ch.PeerFP() != peerFP {
		t.Errorf("expected peerFP %s, got %s", peerFP, ch.PeerFP())
	}
	if !bytes.Equal(ch.SharedKey(), sharedKey) {
		t.Errorf("expected sharedKey to match input key")
	}
	if ch.IsClosed() {
		t.Error("expected new channel to not be closed")
	}
	if ch.Buffer() == nil {
		t.Fatal("expected channel ring buffer to be initialized")
	}
	if ch.Buffer().Len() != 0 {
		t.Errorf("expected initial buffer len 0, got %d", ch.Buffer().Len())
	}
}

func TestMonotonicSequenceCounter(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	ch := NewChannel("alice", "bob", key)

	// Verify sequential nonces
	n1 := ch.NextNonce()
	n2 := ch.NextNonce()
	n3 := ch.NextNonce()

	for i, n := range [][]byte{n1, n2, n3} {
		if len(n) != 12 {
			t.Fatalf("nonce %d: expected length 12, got %d", i+1, len(n))
		}
	}

	// In 12-byte 96-bit big-endian representation:
	// First 4 bytes are 0x00, bytes 4..11 are the 64-bit sequence counter.
	for i, n := range [][]byte{n1, n2, n3} {
		for bIdx := 0; bIdx < 4; bIdx++ {
			if n[bIdx] != 0 {
				t.Errorf("nonce %d: expected high byte %d to be 0, got %d", i+1, bIdx, n[bIdx])
			}
		}
	}

	seq1 := binary.BigEndian.Uint64(n1[4:12])
	seq2 := binary.BigEndian.Uint64(n2[4:12])
	seq3 := binary.BigEndian.Uint64(n3[4:12])

	if seq1 != 1 {
		t.Errorf("expected first sequence 1, got %d", seq1)
	}
	if seq2 != 2 {
		t.Errorf("expected second sequence 2, got %d", seq2)
	}
	if seq3 != 3 {
		t.Errorf("expected third sequence 3, got %d", seq3)
	}

	// Concurrency test: ensure atomic monotonicity across goroutines
	const numGoroutines = 50
	const noncesPerGoroutine = 20
	var wg sync.WaitGroup
	var mu sync.Mutex
	seenSeqs := make(map[uint64]bool)

	wg.Add(numGoroutines)
	for g := 0; g < numGoroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < noncesPerGoroutine; i++ {
				nonce := ch.NextNonce()
				seq := binary.BigEndian.Uint64(nonce[4:12])

				mu.Lock()
				if seenSeqs[seq] {
					t.Errorf("duplicate sequence generated concurrently: %d", seq)
				}
				seenSeqs[seq] = true
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	expectedTotal := numGoroutines*noncesPerGoroutine + 3
	if uint64(len(seenSeqs)) != uint64(numGoroutines*noncesPerGoroutine) {
		t.Errorf("expected %d unique sequences, got %d", numGoroutines*noncesPerGoroutine, len(seenSeqs))
	}
	lastNonce := ch.NextNonce()
	lastSeq := binary.BigEndian.Uint64(lastNonce[4:12])
	if lastSeq != uint64(expectedTotal+1) {
		t.Errorf("expected final sequence %d, got %d", expectedTotal+1, lastSeq)
	}
}

func TestReplayProtection(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	ch := NewChannel("alice", "bob", key)

	makeNonce := func(seq uint64) []byte {
		n := make([]byte, 12)
		binary.BigEndian.PutUint64(n[4:12], seq)
		return n
	}

	n1 := makeNonce(1)
	n2 := makeNonce(2)
	n3 := makeNonce(3)
	n5 := makeNonce(5)

	// Valid initial frame sequence 1
	if !ch.VerifyNonce(n1) {
		t.Error("expected sequence 1 to be accepted")
	}

	// Duplicate of sequence 1 should be rejected
	if ch.VerifyNonce(n1) {
		t.Error("expected duplicate sequence 1 to be rejected")
	}

	// Forward jump to sequence 3 is accepted
	if !ch.VerifyNonce(n3) {
		t.Error("expected future sequence 3 to be accepted")
	}

	// Out-of-order sequence 2 (older than sequence 3) should be rejected
	if ch.VerifyNonce(n2) {
		t.Error("expected out-of-order sequence 2 to be rejected")
	}

	// Duplicate of sequence 3 should be rejected
	if ch.VerifyNonce(n3) {
		t.Error("expected duplicate sequence 3 to be rejected")
	}

	// Sequence 5 is accepted
	if !ch.VerifyNonce(n5) {
		t.Error("expected sequence 5 to be accepted")
	}

	// Sequence 0 is invalid/replayed
	n0 := makeNonce(0)
	if ch.VerifyNonce(n0) {
		t.Error("expected sequence 0 to be rejected")
	}

	// Malformed nonces
	if ch.VerifyNonce(nil) {
		t.Error("expected nil nonce to be rejected")
	}
	if ch.VerifyNonce([]byte{0, 1, 2}) {
		t.Error("expected short nonce to be rejected")
	}
	if ch.VerifyNonce(make([]byte, 16)) {
		t.Error("expected oversized nonce to be rejected")
	}
}

func TestClose(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	// Make a slice sharing the same backing array to test zeroization
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)

	ch := NewChannel("alice", "bob", key)

	// Add messages to ring buffer
	msgContent := []byte("confidential conversation")
	msg := &Message{
		ID:        "msg-secret",
		Seq:       1,
		Content:   msgContent,
		Timestamp: time.Now(),
	}
	ch.Push(msg)

	if len(ch.Messages()) != 1 {
		t.Fatalf("expected 1 message in channel buffer, got %d", len(ch.Messages()))
	}

	// Close channel
	ch.Close()

	if !ch.IsClosed() {
		t.Error("expected channel to be closed after Close()")
	}

	// Verify key slice was zeroed in memory
	for i, b := range key {
		if b != 0 {
			t.Errorf("key byte %d was not zeroed: %d", i, b)
		}
	}

	// Verify channel's own key is zeroed
	for i, b := range ch.SharedKey() {
		if b != 0 {
			t.Errorf("ch.SharedKey byte %d was not zeroed: %d", i, b)
		}
	}

	// Verify buffer is empty
	if len(ch.Messages()) != 0 {
		t.Errorf("expected 0 messages in buffer after Close(), got %d", len(ch.Messages()))
	}

	// Verify buffered message content was wiped
	for i, b := range msgContent {
		if b != 0 {
			t.Errorf("msgContent byte %d was not zeroed: %d", i, b)
		}
	}

	// Verify VerifyNonce rejects on closed channel
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[4:12], 100)
	if ch.VerifyNonce(n) {
		t.Error("expected VerifyNonce to reject on closed channel")
	}

	// Repeated Close should be safe (idempotent)
	ch.Close()
	if !ch.IsClosed() {
		t.Error("expected channel to remain closed after second Close()")
	}
}

func TestSealAndOpen(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	keyBob := make([]byte, len(key))
	copy(keyBob, key)

	alice := NewChannel("alice", "bob", key)
	bob := NewChannel("bob", "alice", keyBob)

	plaintext := []byte("hello from alice to bob over encrypted channel")

	// Alice seals message
	nonce, ciphertext, err := alice.Seal(plaintext)
	if err != nil {
		t.Fatalf("alice Seal failed: %v", err)
	}
	if len(nonce) != 12 {
		t.Fatalf("expected 12-byte nonce, got %d", len(nonce))
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("ciphertext must not match plaintext")
	}

	// Bob opens message
	decrypted, err := bob.Open(nonce, ciphertext)
	if err != nil {
		t.Fatalf("bob Open failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted payload %q does not match original %q", decrypted, plaintext)
	}

	// Replay attack: Bob tries to open the same nonce/ciphertext again
	_, err = bob.Open(nonce, ciphertext)
	if err == nil {
		t.Error("expected replay of identical nonce to fail")
	}

	// Tampered ciphertext attack
	nonce2, ciphertext2, err := alice.Seal([]byte("another secret message"))
	if err != nil {
		t.Fatalf("alice Seal failed: %v", err)
	}
	ciphertext2[0] ^= 0xff // tamper with ciphertext
	_, err = bob.Open(nonce2, ciphertext2)
	if err == nil {
		t.Error("expected tampered ciphertext to fail Open")
	}

	// Closed channel rejects operations
	alice.Close()
	_, _, err = alice.Seal([]byte("closed channel test"))
	if err != ErrClosedChannel {
		t.Errorf("expected ErrClosedChannel on Seal, got %v", err)
	}
	_, err = alice.Open(nonce, ciphertext)
	if err != ErrClosedChannel {
		t.Errorf("expected ErrClosedChannel on Open, got %v", err)
	}
}

func TestMemclr(t *testing.T) {
	buf := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x42, 0x13, 0x37}
	Memclr(buf)
	for i, b := range buf {
		if b != 0 {
			t.Errorf("byte at %d not zeroed: %d", i, b)
		}
	}

	// Should not panic on empty or nil
	Memclr(nil)
	Memclr([]byte{})
}

func TestChannel_SequencesAndEdgeCases(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	ch := NewChannel("alice", "bob", key)

	if ch.SendSeq() != 0 {
		t.Errorf("expected initial SendSeq 0, got %d", ch.SendSeq())
	}
	if ch.RecvSeq() != 0 {
		t.Errorf("expected initial RecvSeq 0, got %d", ch.RecvSeq())
	}

	ch.NextNonce()
	if ch.SendSeq() != 1 {
		t.Errorf("expected SendSeq 1, got %d", ch.SendSeq())
	}

	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:12], 42)
	if !ch.VerifyNonce(nonce) {
		t.Error("expected nonce 42 to be valid")
	}
	if ch.RecvSeq() != 42 {
		t.Errorf("expected RecvSeq 42, got %d", ch.RecvSeq())
	}

	// Nonce with non-zero high bytes
	badNonce := make([]byte, 12)
	badNonce[0] = 1
	binary.BigEndian.PutUint64(badNonce[4:12], 50)
	if ch.VerifyNonce(badNonce) {
		t.Error("expected nonce with non-zero upper bytes to be rejected")
	}

	// Nil buffer handling
	chNilBuffer := &Channel{}
	if chNilBuffer.Messages() != nil {
		t.Error("expected nil messages for nil buffer")
	}
	chNilBuffer.Push(&Message{ID: "msg"}) // should not panic
}

func TestChannel_InvalidKey(t *testing.T) {
	shortKey := []byte("short-key")
	ch := NewChannel("alice", "bob", shortKey)

	_, _, err := ch.Seal([]byte("test"))
	if err != ErrInvalidKey {
		t.Errorf("expected ErrInvalidKey, got %v", err)
	}

	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:12], 1)
	_, err = ch.Open(nonce, []byte("fake-ciphertext"))
	if err != ErrInvalidKey {
		t.Errorf("expected ErrInvalidKey, got %v", err)
	}
}

func TestOpen_InvalidNonce(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	ch := NewChannel("alice", "bob", key)

	// Short nonce
	_, err := ch.Open([]byte{1, 2, 3}, []byte("ciphertext"))
	if err != ErrInvalidNonce {
		t.Errorf("expected ErrInvalidNonce for short nonce, got %v", err)
	}

	// Bad upper 4 bytes
	badNonce := make([]byte, 12)
	badNonce[1] = 0xff
	binary.BigEndian.PutUint64(badNonce[4:12], 10)
	_, err = ch.Open(badNonce, []byte("ciphertext"))
	if err != ErrInvalidNonce {
		t.Errorf("expected ErrInvalidNonce for non-zero upper bytes, got %v", err)
	}
}

func TestOpen_TamperedDoesNotAdvanceSeq(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	alice := NewChannel("alice", "bob", key)
	bob := NewChannel("bob", "alice", key)

	// Alice produces message 1
	n1, c1, err := alice.Seal([]byte("valid message 1"))
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	// Tamper message 1
	tampered := make([]byte, len(c1))
	copy(tampered, c1)
	tampered[len(tampered)-1] ^= 0xff

	// Bob attempts to open tampered message 1
	_, err = bob.Open(n1, tampered)
	if err != ErrDecryptionFail {
		t.Fatalf("expected ErrDecryptionFail, got %v", err)
	}

	// Verify Bob's recvSeq did NOT advance
	if bob.RecvSeq() != 0 {
		t.Fatalf("bob RecvSeq advanced to %d despite decryption failure", bob.RecvSeq())
	}

	// Now Bob receives untampered message 1 - it must succeed
	decrypted, err := bob.Open(n1, c1)
	if err != nil {
		t.Fatalf("failed to open untampered message after tamper attempt: %v", err)
	}
	if string(decrypted) != "valid message 1" {
		t.Errorf("unexpected decrypted message: %s", string(decrypted))
	}
	if bob.RecvSeq() != 1 {
		t.Errorf("expected bob RecvSeq 1, got %d", bob.RecvSeq())
	}
}
