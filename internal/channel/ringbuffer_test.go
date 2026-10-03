package channel

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestNewRingBuffer(t *testing.T) {
	t.Run("positive capacity", func(t *testing.T) {
		capacity := 10
		rb := NewRingBuffer(capacity)
		if rb == nil {
			t.Fatal("expected non-nil RingBuffer")
		}
		if rb.Capacity() != capacity {
			t.Errorf("expected capacity %d, got %d", capacity, rb.Capacity())
		}
		if rb.Len() != 0 {
			t.Errorf("expected initial len 0, got %d", rb.Len())
		}
		msgs := rb.Messages()
		if len(msgs) != 0 {
			t.Errorf("expected empty messages, got %d", len(msgs))
		}
	})

	t.Run("zero or negative capacity defaults cleanly", func(t *testing.T) {
		rbZero := NewRingBuffer(0)
		if rbZero.Capacity() <= 0 {
			t.Errorf("expected positive default capacity, got %d", rbZero.Capacity())
		}

		rbNeg := NewRingBuffer(-5)
		if rbNeg.Capacity() <= 0 {
			t.Errorf("expected positive default capacity, got %d", rbNeg.Capacity())
		}
	})
}

func TestPush_FIFO(t *testing.T) {
	rb := NewRingBuffer(5)

	m1 := &Message{
		ID:        "msg-1",
		Seq:       1,
		SenderFP:  "fp-alice",
		Content:   []byte("first"),
		Timestamp: time.Now(),
	}
	m2 := &Message{
		ID:        "msg-2",
		Seq:       2,
		SenderFP:  "fp-bob",
		Content:   []byte("second"),
		Timestamp: time.Now(),
	}
	m3 := &Message{
		ID:        "msg-3",
		Seq:       3,
		SenderFP:  "fp-alice",
		Content:   []byte("third"),
		Timestamp: time.Now(),
	}

	rb.Push(m1)
	rb.Push(m2)
	rb.Push(m3)

	if rb.Len() != 3 {
		t.Fatalf("expected len 3, got %d", rb.Len())
	}

	msgs := rb.Messages()
	if len(msgs) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(msgs))
	}

	if msgs[0].ID != "msg-1" || msgs[1].ID != "msg-2" || msgs[2].ID != "msg-3" {
		t.Errorf("messages not in FIFO order: [%s, %s, %s]", msgs[0].ID, msgs[1].ID, msgs[2].ID)
	}

	// Nil message push should be safely ignored
	rb.Push(nil)
	if rb.Len() != 3 {
		t.Errorf("expected len to remain 3 after nil push, got %d", rb.Len())
	}
}

func TestRingOverflow(t *testing.T) {
	capacity := 3
	rb := NewRingBuffer(capacity)

	m1 := &Message{ID: "m1", Seq: 1, Content: []byte("payload 1")}
	m2 := &Message{ID: "m2", Seq: 2, Content: []byte("payload 2")}
	m3 := &Message{ID: "m3", Seq: 3, Content: []byte("payload 3")}

	rb.Push(m1)
	rb.Push(m2)
	rb.Push(m3)

	if rb.Len() != 3 {
		t.Fatalf("expected len 3, got %d", rb.Len())
	}

	// Buffer is at capacity. Pushing 4th message should drop oldest (m1) cleanly.
	m4 := &Message{ID: "m4", Seq: 4, Content: []byte("payload 4")}
	rb.Push(m4)

	if rb.Len() != capacity {
		t.Errorf("expected len to stay at capacity %d, got %d", capacity, rb.Len())
	}

	msgs := rb.Messages()
	if len(msgs) != 3 {
		t.Fatalf("expected 3 messages after overflow, got %d", len(msgs))
	}
	expectedIDs := []string{"m2", "m3", "m4"}
	for i, exp := range expectedIDs {
		if msgs[i].ID != exp {
			t.Errorf("at index %d: expected %s, got %s", i, exp, msgs[i].ID)
		}
	}

	// Push 5th message: should drop m2
	m5 := &Message{ID: "m5", Seq: 5, Content: []byte("payload 5")}
	rb.Push(m5)

	msgs = rb.Messages()
	expectedIDs = []string{"m3", "m4", "m5"}
	for i, exp := range expectedIDs {
		if msgs[i].ID != exp {
			t.Errorf("at index %d: expected %s, got %s", i, exp, msgs[i].ID)
		}
	}
}

func TestMessages_ChronologicalOrder(t *testing.T) {
	capacity := 4
	rb := NewRingBuffer(capacity)

	baseTime := time.Date(2026, 10, 2, 23, 0, 0, 0, time.UTC)
	for i := 1; i <= 8; i++ {
		rb.Push(&Message{
			ID:        fmt.Sprintf("msg-%d", i),
			Seq:       uint64(i),
			Timestamp: baseTime.Add(time.Duration(i) * time.Minute),
			Content:   []byte(fmt.Sprintf("content-%d", i)),
		})
	}

	msgs := rb.Messages()
	if len(msgs) != capacity {
		t.Fatalf("expected %d messages, got %d", capacity, len(msgs))
	}

	// Expected to hold the last 4: msg-5, msg-6, msg-7, msg-8
	for i, msg := range msgs {
		expectedSeq := uint64(5 + i)
		if msg.Seq != expectedSeq {
			t.Errorf("at index %d: expected seq %d, got %d", i, expectedSeq, msg.Seq)
		}
		if i > 0 && !msg.Timestamp.After(msgs[i-1].Timestamp) {
			t.Errorf("messages not in strict chronological order at index %d", i)
		}
	}

	// Defensive copy: mutating returned slice does not corrupt ring buffer
	msgs[0] = nil
	freshMsgs := rb.Messages()
	if freshMsgs[0] == nil || freshMsgs[0].Seq != 5 {
		t.Errorf("ring buffer was mutated by caller modification of Messages() result")
	}
}

func TestClear(t *testing.T) {
	rb := NewRingBuffer(5)

	content1 := []byte("super secret data 1")
	content2 := []byte("super secret data 2")

	m1 := &Message{ID: "m1", Content: content1}
	m2 := &Message{ID: "m2", Content: content2}

	rb.Push(m1)
	rb.Push(m2)

	if rb.Len() != 2 {
		t.Fatalf("expected len 2, got %d", rb.Len())
	}

	rb.Clear()

	if rb.Len() != 0 {
		t.Errorf("expected len 0 after Clear(), got %d", rb.Len())
	}
	if len(rb.Messages()) != 0 {
		t.Errorf("expected 0 messages after Clear(), got %d", len(rb.Messages()))
	}

	// Verify message contents were wiped (all bytes zeroed)
	for i, b := range m1.Content {
		if b != 0 {
			t.Errorf("m1 content byte %d not zeroed: got %d", i, b)
		}
	}
	for i, b := range m2.Content {
		if b != 0 {
			t.Errorf("m2 content byte %d not zeroed: got %d", i, b)
		}
	}
}

func TestConcurrentPushAndMessages(t *testing.T) {
	capacity := 50
	rb := NewRingBuffer(capacity)

	const numProducers = 10
	const msgsPerProducer = 100
	const numConsumers = 5

	var wg sync.WaitGroup
	wg.Add(numProducers + numConsumers)

	// Producers concurrently pushing messages
	for p := 0; p < numProducers; p++ {
		go func(producerID int) {
			defer wg.Done()
			for i := 0; i < msgsPerProducer; i++ {
				rb.Push(&Message{
					ID:        fmt.Sprintf("p%d-m%d", producerID, i),
					Seq:       uint64(i),
					Content:   bytes.Repeat([]byte{byte(producerID)}, 16),
					Timestamp: time.Now(),
				})
			}
		}(p)
	}

	// Consumers concurrently reading messages
	for c := 0; c < numConsumers; c++ {
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				msgs := rb.Messages()
				l := rb.Len()
				capVal := rb.Capacity()
				if l > capVal {
					t.Errorf("len %d exceeded capacity %d", l, capVal)
				}
				if len(msgs) > capVal {
					t.Errorf("retrieved msgs len %d exceeded capacity %d", len(msgs), capVal)
				}
				time.Sleep(100 * time.Microsecond)
			}
		}()
	}

	wg.Wait()

	if rb.Len() > capacity {
		t.Errorf("final len %d exceeded capacity %d", rb.Len(), capacity)
	}
	if rb.Len() != capacity {
		t.Logf("final len is %d (capped at capacity %d)", rb.Len(), capacity)
	}
}

func TestMessage_WipeNil(t *testing.T) {
	var m *Message
	m.Wipe() // must not panic
}

func TestRingOverflow_EvictedMessageWiped(t *testing.T) {
	rb := NewRingBuffer(2)
	payload1 := []byte("confidential-msg-1")
	payload2 := []byte("confidential-msg-2")
	payload3 := []byte("confidential-msg-3")

	m1 := &Message{ID: "m1", Seq: 1, Content: payload1}
	m2 := &Message{ID: "m2", Seq: 2, Content: payload2}
	m3 := &Message{ID: "m3", Seq: 3, Content: payload3}

	rb.Push(m1)
	rb.Push(m2)

	// Pushing m3 should evict m1 and wipe payload1
	rb.Push(m3)

	for i, b := range payload1 {
		if b != 0 {
			t.Fatalf("expected evicted payload byte %d to be wiped, got %d", i, b)
		}
	}
}
