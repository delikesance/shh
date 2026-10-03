package channel

import (
	"sync"
	"time"
)

// DefaultCapacity defines the default maximum number of messages in a RingBuffer.
const DefaultCapacity = 100

// Message represents an ephemeral in-memory message frame within a channel.
type Message struct {
	ID          string    `json:"id"`
	Seq         uint64    `json:"seq"`
	SenderFP    string    `json:"sender_fp"`
	RecipientFP string    `json:"recipient_fp,omitempty"`
	Content     []byte    `json:"content"`
	Timestamp   time.Time `json:"timestamp"`
}

// Wipe securely zeroizes the message payload in memory using Memclr.
func (m *Message) Wipe() {
	if m == nil {
		return
	}
	Memclr(m.Content)
}

// RingBuffer is a thread-safe circular in-memory buffer holding message frames.
// When capacity is exceeded, the oldest message is dropped cleanly to make room for new messages.
// It provides zero disk persistence and explicit memory zeroization on Clear.
type RingBuffer struct {
	mu       sync.RWMutex
	capacity int
	items    []*Message
	head     int // index of the oldest item
	tail     int // index where the next item will be inserted
	count    int // current number of items in buffer
}

// NewRingBuffer creates an in-memory RingBuffer with the given capacity.
// If capacity <= 0, DefaultCapacity is used.
func NewRingBuffer(capacity int) *RingBuffer {
	if capacity <= 0 {
		capacity = DefaultCapacity
	}
	return &RingBuffer{
		capacity: capacity,
		items:    make([]*Message, capacity),
	}
}

// Push adds a message to the ring buffer in FIFO order.
// If the buffer is full, the oldest message is dropped cleanly.
// Pushing nil is a safe no-op.
func (rb *RingBuffer) Push(msg *Message) {
	if msg == nil {
		return
	}

	rb.mu.Lock()
	defer rb.mu.Unlock()

	if rb.count < rb.capacity {
		rb.items[rb.tail] = msg
		rb.tail = (rb.tail + 1) % rb.capacity
		rb.count++
	} else {
		// Buffer is at capacity: wipe evicted message content and overwrite at head
		if rb.items[rb.head] != nil {
			rb.items[rb.head].Wipe()
		}
		rb.items[rb.head] = msg
		rb.head = (rb.head + 1) % rb.capacity
		rb.tail = rb.head
	}
}

// Messages returns all buffered messages in strict chronological (FIFO) order.
// It returns a newly allocated slice copy to prevent caller mutation from affecting internal state.
func (rb *RingBuffer) Messages() []*Message {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	result := make([]*Message, rb.count)
	for i := 0; i < rb.count; i++ {
		idx := (rb.head + i) % rb.capacity
		result[i] = rb.items[idx]
	}
	return result
}

// Clear empties the buffer and wipes the content of all messages currently stored.
func (rb *RingBuffer) Clear() {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	for i := 0; i < rb.count; i++ {
		idx := (rb.head + i) % rb.capacity
		if rb.items[idx] != nil {
			rb.items[idx].Wipe()
			rb.items[idx] = nil
		}
	}

	rb.head = 0
	rb.tail = 0
	rb.count = 0
}

// Len returns the current number of messages in the buffer.
func (rb *RingBuffer) Len() int {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return rb.count
}

// Capacity returns the maximum message capacity of the buffer.
func (rb *RingBuffer) Capacity() int {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return rb.capacity
}
