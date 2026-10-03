package ui

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

func TestNewModel(t *testing.T) {
	// Test creation with nick and fingerprint
	m := NewModel("alice", "SHA256:u1234567890abcdef")
	if m.SelfNick != "alice" {
		t.Errorf("expected SelfNick 'alice', got %q", m.SelfNick)
	}
	if m.SelfFingerprint != "SHA256:u1234567890abcdef" {
		t.Errorf("expected SelfFingerprint 'SHA256:u1234567890abcdef', got %q", m.SelfFingerprint)
	}
	if m.Focus != FocusInput {
		t.Errorf("expected default focus FocusInput, got %v", m.Focus)
	}
	if m.Init() == nil {
		t.Error("expected Init() to return non-nil cmd (e.g. textinput.Blink)")
	}

	// Test creation with default / no args
	mDefault := NewModel()
	if mDefault.SelfNick == "" {
		t.Error("expected non-empty default SelfNick")
	}
}

func TestWindowResize(t *testing.T) {
	m := NewModel("alice", "SHA256:test")

	// Trigger resize
	newModel, cmd := m.Update(tea.WindowSizeMsg{
		Width:  120,
		Height: 40,
	})
	if cmd != nil {
		t.Errorf("expected nil cmd from resize, got %v", cmd)
	}

	updated, ok := newModel.(Model)
	if !ok {
		t.Fatalf("expected updated model to be Model, got %T", newModel)
	}

	if updated.Width != 120 {
		t.Errorf("expected Width 120, got %d", updated.Width)
	}
	if updated.Height != 40 {
		t.Errorf("expected Height 40, got %d", updated.Height)
	}
	if updated.RosterWidth <= 0 || updated.RosterWidth >= updated.Width {
		t.Errorf("invalid RosterWidth: %d for total width %d", updated.RosterWidth, updated.Width)
	}
	if updated.ViewportWidth <= 0 {
		t.Errorf("invalid ViewportWidth: %d", updated.ViewportWidth)
	}
	if updated.ViewportHeight <= 0 {
		t.Errorf("invalid ViewportHeight: %d", updated.ViewportHeight)
	}

	// Check View renders without error / panic
	view := updated.View()
	if len(view) == 0 {
		t.Error("expected non-empty view output after resize")
	}
}

func TestNavigationKeys_FocusCycle(t *testing.T) {
	m := NewModel("alice", "SHA256:test")
	m.Width = 100
	m.Height = 30

	// Initial focus is FocusInput
	if m.Focus != FocusInput {
		t.Fatalf("expected initial FocusInput, got %v", m.Focus)
	}

	// Tab: Input -> Roster
	newM, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
	m = newM.(Model)
	if m.Focus != FocusRoster {
		t.Errorf("expected FocusRoster after Tab, got %v", m.Focus)
	}

	// Tab: Roster -> Messages
	newM, _ = m.Update(tea.KeyMsg{Type: tea.KeyTab})
	m = newM.(Model)
	if m.Focus != FocusMessages {
		t.Errorf("expected FocusMessages after second Tab, got %v", m.Focus)
	}

	// Tab: Messages -> Input
	newM, _ = m.Update(tea.KeyMsg{Type: tea.KeyTab})
	m = newM.(Model)
	if m.Focus != FocusInput {
		t.Errorf("expected FocusInput after third Tab, got %v", m.Focus)
	}

	// Shift-Tab: Input -> Messages
	newM, _ = m.Update(tea.KeyMsg{Type: tea.KeyShiftTab})
	m = newM.(Model)
	if m.Focus != FocusMessages {
		t.Errorf("expected FocusMessages after Shift-Tab, got %v", m.Focus)
	}

	// Shift-Tab: Messages -> Roster
	newM, _ = m.Update(tea.KeyMsg{Type: tea.KeyShiftTab})
	m = newM.(Model)
	if m.Focus != FocusRoster {
		t.Errorf("expected FocusRoster after second Shift-Tab, got %v", m.Focus)
	}

	// Shift-Tab: Roster -> Input
	newM, _ = m.Update(tea.KeyMsg{Type: tea.KeyShiftTab})
	m = newM.(Model)
	if m.Focus != FocusInput {
		t.Errorf("expected FocusInput after third Shift-Tab, got %v", m.Focus)
	}
}

func TestNavigationKeys_RosterSelection(t *testing.T) {
	m := NewModel("alice", "SHA256:test")
	m.Peers = []Peer{
		{Nick: "alice", Fingerprint: "SHA256:aaa", Status: "active", IsSelf: true},
		{Nick: "bob", Fingerprint: "SHA256:bbb", Status: "online"},
		{Nick: "charlie", Fingerprint: "SHA256:ccc", Status: "idle"},
	}
	m.Focus = FocusRoster
	m.SelectedPeerIdx = 0

	// Down arrow moves selection
	newM, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = newM.(Model)
	if m.SelectedPeerIdx != 1 {
		t.Errorf("expected SelectedPeerIdx 1 after Down, got %d", m.SelectedPeerIdx)
	}

	// 'j' moves selection down
	newM, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})
	m = newM.(Model)
	if m.SelectedPeerIdx != 2 {
		t.Errorf("expected SelectedPeerIdx 2 after 'j', got %d", m.SelectedPeerIdx)
	}

	// Down at bottom stays at bottom
	newM, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = newM.(Model)
	if m.SelectedPeerIdx != 2 {
		t.Errorf("expected SelectedPeerIdx clamped at 2, got %d", m.SelectedPeerIdx)
	}

	// Up arrow moves selection up
	newM, _ = m.Update(tea.KeyMsg{Type: tea.KeyUp})
	m = newM.(Model)
	if m.SelectedPeerIdx != 1 {
		t.Errorf("expected SelectedPeerIdx 1 after Up, got %d", m.SelectedPeerIdx)
	}

	// 'k' moves selection up
	newM, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'k'}})
	m = newM.(Model)
	if m.SelectedPeerIdx != 0 {
		t.Errorf("expected SelectedPeerIdx 0 after 'k', got %d", m.SelectedPeerIdx)
	}

	// Up at top stays at 0
	newM, _ = m.Update(tea.KeyMsg{Type: tea.KeyUp})
	m = newM.(Model)
	if m.SelectedPeerIdx != 0 {
		t.Errorf("expected SelectedPeerIdx clamped at 0, got %d", m.SelectedPeerIdx)
	}
}

func TestNavigationKeys_Esc(t *testing.T) {
	m := NewModel("alice", "SHA256:test")

	// When in Messages, Esc returns focus to Roster
	m.Focus = FocusMessages
	newM, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = newM.(Model)
	if m.Focus != FocusRoster {
		t.Errorf("expected Esc from Messages to focus Roster, got %v", m.Focus)
	}

	// When in Input with text, Esc clears text
	m.Focus = FocusInput
	m.Input.SetValue("some draft text")
	newM, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = newM.(Model)
	if m.Input.Value() != "" {
		t.Errorf("expected Esc in Input to clear value, got %q", m.Input.Value())
	}

	// When in Input without text, Esc switches focus to Roster
	newM, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = newM.(Model)
	if m.Focus != FocusRoster {
		t.Errorf("expected Esc in empty Input to focus Roster, got %v", m.Focus)
	}
}

func TestSlashCommand_Quit(t *testing.T) {
	m := NewModel("alice", "SHA256:test")
	m.Focus = FocusInput
	m.Messages = []Message{{Sender: "bob", Content: "secret message"}}
	m.Input.SetValue("/quit")

	newM, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("expected non-nil cmd for /quit")
	}

	// Verify memory wipe on quit
	quitModel := newM.(Model)
	if len(quitModel.Messages) != 0 {
		t.Errorf("expected messages wiped on /quit, got %d", len(quitModel.Messages))
	}

	// Execute command and verify it produces tea.QuitMsg
	msg := cmd()
	if _, ok := msg.(tea.QuitMsg); !ok {
		t.Errorf("expected tea.QuitMsg from /quit command, got %T", msg)
	}

	// Also test /q alias
	m.Messages = []Message{{Sender: "bob", Content: "secret message 2"}}
	m.Input.SetValue("/q")
	newM, cmd = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("expected non-nil cmd for /q")
	}
	quitModel = newM.(Model)
	if len(quitModel.Messages) != 0 {
		t.Errorf("expected messages wiped on /q, got %d", len(quitModel.Messages))
	}
	msg = cmd()
	if _, ok := msg.(tea.QuitMsg); !ok {
		t.Errorf("expected tea.QuitMsg from /q command, got %T", msg)
	}
}

func TestSlashCommand_Clear(t *testing.T) {
	m := NewModel("alice", "SHA256:test")
	m.Messages = []Message{
		{Sender: "bob", Content: "hello", Timestamp: time.Now()},
		{Sender: "alice", Content: "hi", Timestamp: time.Now()},
	}
	m.Focus = FocusInput
	m.Input.SetValue("/clear")

	newM, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = newM.(Model)

	if len(m.Messages) != 0 {
		t.Errorf("expected messages to be cleared, got %d messages", len(m.Messages))
	}
	if m.Input.Value() != "" {
		t.Errorf("expected input to be cleared, got %q", m.Input.Value())
	}
}

func TestSlashCommand_Nick(t *testing.T) {
	m := NewModel("alice", "SHA256:test")
	m.Focus = FocusInput

	// Missing argument
	m.Input.SetValue("/nick")
	newM, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = newM.(Model)
	if m.SelfNick != "alice" {
		t.Errorf("SelfNick should remain alice on missing arg, got %q", m.SelfNick)
	}
	// Backlog should show a usage / error message
	if len(m.Messages) == 0 || !strings.Contains(m.Messages[len(m.Messages)-1].Content, "Usage") {
		t.Error("expected usage message for /nick with missing argument")
	}

	// Valid argument
	m.Input.SetValue("/nick valkyrie")
	newM, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = newM.(Model)
	if m.SelfNick != "valkyrie" {
		t.Errorf("expected SelfNick 'valkyrie', got %q", m.SelfNick)
	}
	if m.Input.Value() != "" {
		t.Errorf("expected input cleared, got %q", m.Input.Value())
	}
}

func TestSlashCommand_Whois(t *testing.T) {
	m := NewModel("alice", "SHA256:test")
	m.Peers = []Peer{
		{Nick: "bob", Fingerprint: "SHA256:bobfingerprint12345", Status: "active"},
	}
	m.Focus = FocusInput

	// Missing argument
	m.Input.SetValue("/whois")
	newM, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = newM.(Model)
	if len(m.Messages) == 0 || !strings.Contains(m.Messages[len(m.Messages)-1].Content, "Usage") {
		t.Error("expected usage message for /whois without args")
	}

	// Valid peer
	m.Input.SetValue("/whois bob")
	newM, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = newM.(Model)
	lastMsg := m.Messages[len(m.Messages)-1].Content
	if !strings.Contains(lastMsg, "bob") || !strings.Contains(lastMsg, "SHA256:bobfingerprint12345") {
		t.Errorf("expected whois output containing peer info, got %q", lastMsg)
	}

	// Non-existent peer
	m.Input.SetValue("/whois nonesuch")
	newM, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = newM.(Model)
	lastMsg = m.Messages[len(m.Messages)-1].Content
	if !strings.Contains(strings.ToLower(lastMsg), "not found") {
		t.Errorf("expected 'not found' message for non-existent peer, got %q", lastMsg)
	}
}

func TestSlashCommand_Keys(t *testing.T) {
	m := NewModel("alice", "SHA256:test")
	m.ActivePeer = &Peer{Nick: "bob", Fingerprint: "SHA256:bobfingerprint"}
	m.Focus = FocusInput
	m.Input.SetValue("/keys")

	newM, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = newM.(Model)

	if len(m.Messages) == 0 {
		t.Fatal("expected keys info message in backlog")
	}
	lastMsg := m.Messages[len(m.Messages)-1].Content
	if !strings.Contains(lastMsg, "ChaCha20-Poly1305") || !strings.Contains(lastMsg, "X25519") {
		t.Errorf("expected cipher details in /keys output, got %q", lastMsg)
	}
}

func TestSlashCommand_Unrecognized(t *testing.T) {
	m := NewModel("alice", "SHA256:test")
	m.Focus = FocusInput
	m.Input.SetValue("/unknowncmd")

	newM, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = newM.(Model)

	if len(m.Messages) == 0 {
		t.Fatal("expected message for unknown command")
	}
	lastMsg := m.Messages[len(m.Messages)-1].Content
	if !strings.Contains(strings.ToLower(lastMsg), "unknown command") {
		t.Errorf("expected 'unknown command' notice, got %q", lastMsg)
	}
}

func TestCipherBadgeAndStatusIndicators(t *testing.T) {
	m := NewModel("alice", "SHA256:alicefp123")
	m.Width = 100
	m.Height = 30
	m.Peers = []Peer{
		{Nick: "alice", Fingerprint: "SHA256:alicefp123", Status: "active", IsSelf: true},
		{Nick: "bob", Fingerprint: "SHA256:bobfp456", Status: "idle"},
	}
	m.ActivePeer = &m.Peers[1]

	// Update to format panes
	newM, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	m = newM.(Model)

	view := m.View()

	// Check cipher badge is present in View output
	if !strings.Contains(view, "ChaCha20-Poly1305") {
		t.Errorf("expected view to contain ChaCha20-Poly1305 cipher badge, got:\n%s", view)
	}
	if !strings.Contains(view, "X25519") {
		t.Errorf("expected view to contain X25519 indicator, got:\n%s", view)
	}

	// Check peer presence indicator is rendered
	if !strings.Contains(view, "bob") {
		t.Errorf("expected view to contain peer 'bob', got:\n%s", view)
	}
}

func TestCtrlCAndCtrlD(t *testing.T) {
	m := NewModel("alice", "SHA256:test")
	m.Messages = []Message{{Sender: "bob", Content: "secret message"}}
	m.Input.SetValue("unsent draft")

	// Ctrl+C
	newM, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	if cmd == nil {
		t.Fatal("expected non-nil cmd for Ctrl+C")
	}
	quitModel := newM.(Model)
	if len(quitModel.Messages) != 0 {
		t.Errorf("expected messages wiped on Ctrl+C, got %d", len(quitModel.Messages))
	}
	if quitModel.Input.Value() != "" {
		t.Errorf("expected input wiped on Ctrl+C, got %q", quitModel.Input.Value())
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Errorf("expected tea.QuitMsg for Ctrl+C")
	}

	// Ctrl+D
	m.Messages = []Message{{Sender: "bob", Content: "secret message 2"}}
	m.Input.SetValue("unsent draft 2")
	newM, cmd = m.Update(tea.KeyMsg{Type: tea.KeyCtrlD})
	if cmd == nil {
		t.Fatal("expected non-nil cmd for Ctrl+D")
	}
	quitModel = newM.(Model)
	if len(quitModel.Messages) != 0 {
		t.Errorf("expected messages wiped on Ctrl+D, got %d", len(quitModel.Messages))
	}
	if quitModel.Input.Value() != "" {
		t.Errorf("expected input wiped on Ctrl+D, got %q", quitModel.Input.Value())
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Errorf("expected tea.QuitMsg for Ctrl+D")
	}
}

func TestPeerSelectionViaEnter(t *testing.T) {
	m := NewModel("alice", "SHA256:test")
	m.Peers = []Peer{
		{Nick: "alice", Fingerprint: "SHA256:aaa", Status: "active", IsSelf: true},
		{Nick: "bob", Fingerprint: "SHA256:bbb", Status: "online"},
	}
	m.Focus = FocusRoster
	m.SelectedPeerIdx = 1

	// Enter selects peer
	newM, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = newM.(Model)

	if m.ActivePeer == nil || m.ActivePeer.Nick != "bob" {
		t.Errorf("expected ActivePeer to be 'bob', got %v", m.ActivePeer)
	}
	if m.Focus != FocusInput {
		t.Errorf("expected Enter on peer to focus Input for chatting, got %v", m.Focus)
	}
}

func TestMessageSending(t *testing.T) {
	m := NewModel("alice", "SHA256:test")
	m.Peers = []Peer{
		{Nick: "bob", Fingerprint: "SHA256:bbb", Status: "online"},
	}
	m.ActivePeer = &m.Peers[0]
	m.Focus = FocusInput
	m.Input.SetValue("Secret message payload")

	newM, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = newM.(Model)

	if len(m.Messages) == 0 {
		t.Fatal("expected message to be added to backlog")
	}
	last := m.Messages[len(m.Messages)-1]
	if last.Sender != "alice" || last.Content != "Secret message payload" {
		t.Errorf("expected message from alice with content, got %v", last)
	}
	if m.Input.Value() != "" {
		t.Errorf("expected input to be cleared after sending, got %q", m.Input.Value())
	}
}

func TestMessageSending_InvokesCallback(t *testing.T) {
	var sentRecipient string
	var sentContent string

	m := NewModel("alice", "SHA256:test")
	m.Peers = []Peer{
		{Nick: "bob", Fingerprint: "SHA256:bbb", Status: "online"},
	}
	m.ActivePeer = &m.Peers[0]
	m.Focus = FocusInput
	m.Input.SetValue("Hello Bob via callback")
	m.SendMessage = func(recipientFP, content string) error {
		sentRecipient = recipientFP
		sentContent = content
		return nil
	}

	newM, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	_ = newM.(Model)

	if sentRecipient != "SHA256:bbb" {
		t.Errorf("expected recipient 'SHA256:bbb', got %q", sentRecipient)
	}
	if sentContent != "Hello Bob via callback" {
		t.Errorf("expected content 'Hello Bob via callback', got %q", sentContent)
	}
}

func TestSlashCommand_Nick_InvokesCallback(t *testing.T) {
	var reportedOld, reportedNew string

	m := NewModel("alice", "SHA256:test")
	m.Focus = FocusInput
	m.Input.SetValue("/nick alicia")
	m.ChangeNick = func(oldNick, newNick string) error {
		reportedOld = oldNick
		reportedNew = newNick
		return nil
	}

	newM, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	_ = newM.(Model)

	if reportedOld != "alice" || reportedNew != "alicia" {
		t.Errorf("expected old='alice', new='alicia', got old=%q, new=%q", reportedOld, reportedNew)
	}
}

func TestExternalMessages(t *testing.T) {
	m := NewModel("alice", "SHA256:alice")

	// Test PeerJoinedMsg
	newM, _ := m.Update(PeerJoinedMsg{Nick: "bob", Fingerprint: "SHA256:bob", Status: "online"})
	m = newM.(Model)
	if len(m.Peers) != 2 || m.Peers[1].Nick != "bob" {
		t.Errorf("expected bob to be joined, got %v", m.Peers)
	}

	// Test ReceiveMessageMsg
	now := time.Now()
	newM, _ = m.Update(ReceiveMessageMsg{Sender: "bob", Content: "hello alice", Timestamp: now})
	m = newM.(Model)
	if len(m.Messages) != 1 || m.Messages[0].Content != "hello alice" {
		t.Errorf("expected received message in backlog, got %v", m.Messages)
	}

	// Test NickChangedMsg
	newM, _ = m.Update(NickChangedMsg{OldNick: "bob", NewNick: "robert"})
	m = newM.(Model)
	if m.Peers[1].Nick != "robert" {
		t.Errorf("expected peer nick to update to robert, got %q", m.Peers[1].Nick)
	}

	// Test PeerLeftMsg
	newM, _ = m.Update(PeerLeftMsg("robert"))
	m = newM.(Model)
	if len(m.Peers) != 1 {
		t.Errorf("expected robert to be removed, got %d peers", len(m.Peers))
	}

	// Test PeerRosterMsg
	roster := []Peer{
		{Nick: "alice", Fingerprint: "SHA256:alice", Status: "online", IsSelf: true},
		{Nick: "charlie", Fingerprint: "SHA256:charlie", Status: "active"},
		{Nick: "dave", Fingerprint: "SHA256:dave", Status: "idle"},
	}
	newM, _ = m.Update(PeerRosterMsg(roster))
	m = newM.(Model)
	if len(m.Peers) != 3 {
		t.Errorf("expected 3 peers from roster update, got %d", len(m.Peers))
	}

	// Test SystemMessageMsg
	newM, _ = m.Update(SystemMessageMsg("Server maintenance in 5 minutes"))
	m = newM.(Model)
	last := m.Messages[len(m.Messages)-1]
	if !last.IsSystem || !strings.Contains(last.Content, "maintenance") {
		t.Errorf("expected system message, got %v", last)
	}
}

func TestSmallTerminalResize(t *testing.T) {
	m := NewModel("alice", "SHA256:alice")
	newM, _ := m.Update(tea.WindowSizeMsg{Width: 35, Height: 10})
	m = newM.(Model)

	if m.Width != 35 || m.Height != 10 {
		t.Errorf("expected width 35 height 10, got %dx%d", m.Width, m.Height)
	}
	view := m.View()
	if len(view) == 0 {
		t.Error("expected view to render in small terminal without panicking")
	}
}

func TestEmptyInputEnterIgnored(t *testing.T) {
	m := NewModel("alice", "SHA256:alice")
	m.Focus = FocusInput
	m.Input.SetValue("   ")

	newM, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = newM.(Model)

	if len(m.Messages) != 0 {
		t.Errorf("expected no messages added for whitespace input, got %d", len(m.Messages))
	}
}

func TestMemoryWipe(t *testing.T) {
	m := NewModel("alice", "SHA256:alice")
	m.Messages = []Message{
		{Sender: "alice", Content: "secret message 1", Timestamp: time.Now()},
		{Sender: "bob", Content: "secret response 2", Timestamp: time.Now()},
	}
	m.Input.SetValue("unsent sensitive draft")

	m.Wipe()

	if len(m.Messages) != 0 {
		t.Errorf("expected messages wiped, got %d", len(m.Messages))
	}
	if m.Input.Value() != "" {
		t.Errorf("expected input wiped, got %q", m.Input.Value())
	}
}
