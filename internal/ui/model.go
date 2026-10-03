package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// FocusArea denotes the currently focused pane in the UI.
type FocusArea int

const (
	FocusRoster FocusArea = iota
	FocusMessages
	FocusInput
)

// Peer represents a connected peer in the in-memory roster.
type Peer struct {
	Nick        string
	Fingerprint string
	Status      string // "online", "active", "idle", etc.
	IsSelf      bool
}

// Message represents a direct message frame or system notification.
type Message struct {
	Sender    string
	Content   string
	Timestamp time.Time
	IsSystem  bool
}

// Custom tea.Msg types for external event communication
type ReceiveMessageMsg Message
type PeerRosterMsg []Peer
type PeerJoinedMsg Peer
type PeerLeftMsg string
type SystemMessageMsg string
type NickChangedMsg struct {
	OldNick string
	NewNick string
}

// Model is the main Bubble Tea model implementing the dual-pane UI.
type Model struct {
	SelfNick        string
	SelfFingerprint string

	Peers           []Peer
	ActivePeer      *Peer
	SelectedPeerIdx int
	Messages        []Message

	Focus FocusArea

	Viewport viewport.Model
	Input    textinput.Model

	Width          int
	Height         int
	RosterWidth    int
	ViewportWidth  int
	ViewportHeight int

	SendMessage func(recipientFP string, content string) error
	ChangeNick  func(oldNick string, newNick string) error
}

// NewModel constructs and initializes a new UI model with defaults.
func NewModel(params ...string) Model {
	selfNick := "anonymous"
	selfFingerprint := ""
	if len(params) > 0 && params[0] != "" {
		selfNick = params[0]
	}
	if len(params) > 1 {
		selfFingerprint = params[1]
	}

	ti := textinput.New()
	ti.Placeholder = "Type a message or /command (/nick, /whois, /keys, /clear, /quit)..."
	ti.Focus()
	ti.Prompt = "💬 "
	ti.CharLimit = 1024

	vp := viewport.New(60, 20)

	m := Model{
		SelfNick:        selfNick,
		SelfFingerprint: selfFingerprint,
		Peers: []Peer{
			{Nick: selfNick, Fingerprint: selfFingerprint, Status: "online", IsSelf: true},
		},
		SelectedPeerIdx: 0,
		Focus:           FocusInput,
		Input:           ti,
		Viewport:        vp,
		Width:           80,
		Height:          24,
	}

	m.updateDimensions()
	m.refreshViewportContent()
	return m
}

// Init implements tea.Model.
func (m Model) Init() tea.Cmd {
	return textinput.Blink
}

// updateDimensions recalculates pane widths and heights on resize.
func (m *Model) updateDimensions() {
	if m.Width <= 0 || m.Height <= 0 {
		return
	}

	// Dual-pane: left roster is ~28% width (min 22, max Width - 30)
	rosterW := m.Width * 28 / 100
	if rosterW < 22 {
		rosterW = 22
	}
	if rosterW > m.Width-30 {
		rosterW = m.Width - 30
	}
	if rosterW <= 0 {
		rosterW = m.Width / 3
	}

	m.RosterWidth = rosterW
	m.ViewportWidth = m.Width - rosterW

	// Vertical: input bar takes 3 lines at bottom
	inputBoxHeight := 3
	paneH := m.Height - inputBoxHeight
	if paneH < 4 {
		paneH = 4
	}
	m.ViewportHeight = paneH

	// Inner content dimensions
	innerViewportW := m.ViewportWidth - 4
	if innerViewportW < 10 {
		innerViewportW = 10
	}
	innerViewportH := m.ViewportHeight - 6
	if innerViewportH < 2 {
		innerViewportH = 2
	}

	m.Viewport.Width = innerViewportW
	m.Viewport.Height = innerViewportH

	m.Input.Width = m.Width - 8
	m.refreshViewportContent()
}

// setFocus updates focus and controls cursor blinking in the textinput.
func (m *Model) setFocus(f FocusArea) {
	m.Focus = f
	if f == FocusInput {
		m.Input.Focus()
	} else {
		m.Input.Blur()
	}
}

// addSystemMessage appends a system notification to the message backlog.
func (m *Model) addSystemMessage(text string) {
	m.Messages = append(m.Messages, Message{
		Sender:    "system",
		Content:   text,
		Timestamp: time.Now(),
		IsSystem:  true,
	})
	m.refreshViewportContent()
	m.Viewport.GotoBottom()
}

// refreshViewportContent refreshes the formatted message log inside the viewport.
func (m *Model) refreshViewportContent() {
	var sb strings.Builder

	// Top cipher badge
	sb.WriteString(CipherBadgeStyle.Render(CipherBadgeText) + "\n")
	if m.ActivePeer != nil {
		sb.WriteString(FingerprintStyle.Render(fmt.Sprintf("Direct Message Channel with @%s [%s]", m.ActivePeer.Nick, m.ActivePeer.Fingerprint)) + "\n")
	} else {
		sb.WriteString(HelpStyle.Render("No active channel. Select a peer from the roster to begin direct messaging.") + "\n")
	}
	sb.WriteString(strings.Repeat("─", 40) + "\n\n")

	for _, msg := range m.Messages {
		timeStr := TimestampStyle.Render(fmt.Sprintf("[%s] ", msg.Timestamp.Format("15:04:05")))
		if msg.IsSystem {
			sb.WriteString(timeStr + SystemMessageStyle.Render("* "+msg.Content) + "\n")
		} else if msg.Sender == m.SelfNick {
			sb.WriteString(timeStr + SenderSelfStyle.Render("<"+msg.Sender+"> ") + msg.Content + "\n")
		} else {
			sb.WriteString(timeStr + SenderPeerStyle.Render("<"+msg.Sender+"> ") + msg.Content + "\n")
		}
	}

	m.Viewport.SetContent(sb.String())
}

// Wipe securely clears all message backlogs and sensitive input buffers from memory.
func (m *Model) Wipe() {
	for i := range m.Messages {
		m.Messages[i].Content = ""
		m.Messages[i].Sender = ""
	}
	m.Messages = nil
	m.Input.Reset()
	m.refreshViewportContent()
}

// Update implements tea.Model.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.Width = msg.Width
		m.Height = msg.Height
		m.updateDimensions()
		return m, nil

	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC, tea.KeyCtrlD:
			m.Wipe()
			return m, tea.Quit

		case tea.KeyCtrlL:
			return m, tea.ClearScreen

		case tea.KeyTab:
			switch m.Focus {
			case FocusInput:
				m.setFocus(FocusRoster)
			case FocusRoster:
				m.setFocus(FocusMessages)
			case FocusMessages:
				m.setFocus(FocusInput)
			}
			return m, nil

		case tea.KeyShiftTab:
			switch m.Focus {
			case FocusInput:
				m.setFocus(FocusMessages)
			case FocusMessages:
				m.setFocus(FocusRoster)
			case FocusRoster:
				m.setFocus(FocusInput)
			}
			return m, nil

		case tea.KeyEsc:
			switch m.Focus {
			case FocusMessages:
				m.setFocus(FocusRoster)
			case FocusInput:
				if m.Input.Value() != "" {
					m.Input.SetValue("")
				} else {
					m.setFocus(FocusRoster)
				}
			case FocusRoster:
				// remain in roster or switch to input if needed
			}
			return m, nil

		case tea.KeyEnter:
			if m.Focus == FocusRoster {
				if len(m.Peers) > 0 && m.SelectedPeerIdx >= 0 && m.SelectedPeerIdx < len(m.Peers) {
					peer := m.Peers[m.SelectedPeerIdx]
					m.ActivePeer = &peer
					m.setFocus(FocusInput)
					m.refreshViewportContent()
				}
				return m, nil
			}

			if m.Focus == FocusInput {
				text := strings.TrimSpace(m.Input.Value())
				if text == "" {
					m.Input.SetValue("")
					return m, nil
				}

				cmd, args, isCmd := ParseCommand(text)
				if isCmd {
					m.Input.SetValue("")
					return m.handleCommand(cmd, args, text)
				}

				// Regular message
				m.Input.SetValue("")
				if m.ActivePeer == nil {
					m.addSystemMessage("No peer selected. Select a peer from the roster to start an encrypted DM.")
					return m, nil
				}

				m.Messages = append(m.Messages, Message{
					Sender:    m.SelfNick,
					Content:   text,
					Timestamp: time.Now(),
					IsSystem:  false,
				})
				m.refreshViewportContent()
				m.Viewport.GotoBottom()
				if m.SendMessage != nil {
					_ = m.SendMessage(m.ActivePeer.Fingerprint, text)
				}
				return m, nil
			}
		}

		// Pane-specific keyboard navigation
		switch m.Focus {
		case FocusRoster:
			switch {
			case msg.Type == tea.KeyUp || (msg.Type == tea.KeyRunes && len(msg.Runes) == 1 && msg.Runes[0] == 'k') || msg.String() == "k":
				if m.SelectedPeerIdx > 0 {
					m.SelectedPeerIdx--
				}
				return m, nil
			case msg.Type == tea.KeyDown || (msg.Type == tea.KeyRunes && len(msg.Runes) == 1 && msg.Runes[0] == 'j') || msg.String() == "j":
				if m.SelectedPeerIdx < len(m.Peers)-1 {
					m.SelectedPeerIdx++
				}
				return m, nil
			}

		case FocusMessages:
			var vpCmd tea.Cmd
			m.Viewport, vpCmd = m.Viewport.Update(msg)
			if vpCmd != nil {
				cmds = append(cmds, vpCmd)
			}
			return m, tea.Batch(cmds...)

		case FocusInput:
			var tiCmd tea.Cmd
			m.Input, tiCmd = m.Input.Update(msg)
			if tiCmd != nil {
				cmds = append(cmds, tiCmd)
			}
			return m, tea.Batch(cmds...)
		}

	case ReceiveMessageMsg:
		m.Messages = append(m.Messages, Message(msg))
		m.refreshViewportContent()
		m.Viewport.GotoBottom()
		return m, nil

	case PeerRosterMsg:
		m.Peers = []Peer(msg)
		if m.SelectedPeerIdx >= len(m.Peers) && len(m.Peers) > 0 {
			m.SelectedPeerIdx = len(m.Peers) - 1
		}
		m.refreshViewportContent()
		return m, nil

	case PeerJoinedMsg:
		m.Peers = append(m.Peers, Peer(msg))
		m.refreshViewportContent()
		return m, nil

	case PeerLeftMsg:
		target := string(msg)
		for i, p := range m.Peers {
			if p.Nick == target || p.Fingerprint == target {
				m.Peers = append(m.Peers[:i], m.Peers[i+1:]...)
				break
			}
		}
		if m.SelectedPeerIdx >= len(m.Peers) && len(m.Peers) > 0 {
			m.SelectedPeerIdx = len(m.Peers) - 1
		}
		m.refreshViewportContent()
		return m, nil

	case SystemMessageMsg:
		m.addSystemMessage(string(msg))
		return m, nil

	case NickChangedMsg:
		for i := range m.Peers {
			if m.Peers[i].Nick == msg.OldNick {
				m.Peers[i].Nick = msg.NewNick
				break
			}
		}
		if m.ActivePeer != nil && m.ActivePeer.Nick == msg.OldNick {
			m.ActivePeer.Nick = msg.NewNick
		}
		m.refreshViewportContent()
		return m, nil
	}

	return m, tea.Batch(cmds...)
}

// handleCommand executes parsed slash commands.
func (m Model) handleCommand(cmd Command, args []string, rawInput string) (tea.Model, tea.Cmd) {
	switch cmd {
	case CmdQuit:
		m.Wipe()
		return m, tea.Quit

	case CmdClear:
		for i := range m.Messages {
			m.Messages[i].Content = ""
			m.Messages[i].Sender = ""
		}
		m.Messages = nil
		m.refreshViewportContent()
		return m, nil

	case CmdNick:
		if len(args) == 0 {
			m.addSystemMessage("Usage: /nick <handle>")
			return m, nil
		}
		newNick := args[0]
		oldNick := m.SelfNick
		m.SelfNick = newNick
		for i := range m.Peers {
			if m.Peers[i].IsSelf {
				m.Peers[i].Nick = newNick
				break
			}
		}
		if m.ChangeNick != nil {
			_ = m.ChangeNick(oldNick, newNick)
		}
		m.addSystemMessage(fmt.Sprintf("Nickname changed from %s to %s", oldNick, newNick))
		return m, nil

	case CmdWhois:
		if len(args) == 0 {
			m.addSystemMessage("Usage: /whois <handle>")
			return m, nil
		}
		target := args[0]
		var found *Peer
		for i := range m.Peers {
			if strings.EqualFold(m.Peers[i].Nick, target) {
				found = &m.Peers[i]
				break
			}
		}
		if found == nil {
			m.addSystemMessage(fmt.Sprintf("Peer @%s not found", target))
		} else {
			m.addSystemMessage(fmt.Sprintf("[whois] Peer: @%s | Fingerprint: %s | Status: %s | Cipher: ChaCha20-Poly1305 (X25519)", found.Nick, found.Fingerprint, found.Status))
		}
		return m, nil

	case CmdKeys:
		if m.ActivePeer == nil {
			m.addSystemMessage("[keys] No active channel. Select a peer to view channel keys.")
		} else {
			m.addSystemMessage(fmt.Sprintf("[keys] Active Channel: @%s\n  Cipher: ChaCha20-Poly1305 (RFC 8439)\n  Key Exchange: X25519 (Montgomery ECDH)\n  KDF: HKDF-SHA256 (RFC 5869)\n  Peer Fingerprint: %s\n  Replay Protection: 96-bit monotonic sequence counter", m.ActivePeer.Nick, m.ActivePeer.Fingerprint))
		}
		return m, nil

	case CmdUnknown:
		m.addSystemMessage(fmt.Sprintf("Unknown command: %s", rawInput))
		return m, nil

	default:
		return m, nil
	}
}

// renderRoster renders the left peer roster pane.
func (m Model) renderRoster() string {
	var sb strings.Builder
	title := PaneTitleStyle.Render(fmt.Sprintf("── PEERS (%d) ──", len(m.Peers)))
	sb.WriteString(title + "\n\n")

	if len(m.Peers) == 0 {
		sb.WriteString(HelpStyle.Render("No peers online"))
	} else {
		for i, p := range m.Peers {
			statusIcon := "·"
			statusStyle := lipgloss.NewStyle().Foreground(ColorMuted)
			switch p.Status {
			case "active", "online":
				statusIcon = "●"
				statusStyle = PeerItemActive
			case "idle":
				statusIcon = "○"
				statusStyle = PeerItemIdle
			}

			icon := statusStyle.Render(statusIcon)
			nickText := p.Nick
			if p.IsSelf {
				nickText += " " + PeerItemSelf.Render("(you)")
			}

			prefix := "  "
			lineStyle := PeerItemNormal
			if i == m.SelectedPeerIdx && m.Focus == FocusRoster {
				prefix = "> "
				lineStyle = PeerItemSelected
			}

			sb.WriteString(prefix + icon + " " + lineStyle.Render(nickText) + "\n")
		}
	}

	style := PaneStyle
	if m.Focus == FocusRoster {
		style = ActivePaneStyle
	}

	contentWidth := m.RosterWidth - 4
	if contentWidth < 10 {
		contentWidth = 10
	}
	contentHeight := m.ViewportHeight - 2
	if contentHeight < 3 {
		contentHeight = 3
	}

	return style.
		Width(contentWidth).
		Height(contentHeight).
		Render(sb.String())
}

// renderMessages renders the right DM viewport pane with the cipher badge header.
func (m Model) renderMessages() string {
	var header strings.Builder
	if m.ActivePeer != nil {
		header.WriteString(HeaderStyle.Render(fmt.Sprintf("DIRECT MESSAGE: @%s", m.ActivePeer.Nick)) + "\n")
		header.WriteString(FingerprintStyle.Render("Fingerprint: "+m.ActivePeer.Fingerprint) + "\n")
	} else {
		header.WriteString(HeaderStyle.Render("CONVERSATION") + "\n")
	}
	header.WriteString(CipherBadgeStyle.Render(CipherBadgeText) + "\n\n")

	content := lipgloss.JoinVertical(lipgloss.Left, header.String(), m.Viewport.View())

	style := PaneStyle
	if m.Focus == FocusMessages {
		style = ActivePaneStyle
	}

	contentWidth := m.ViewportWidth - 4
	if contentWidth < 10 {
		contentWidth = 10
	}
	contentHeight := m.ViewportHeight - 2
	if contentHeight < 3 {
		contentHeight = 3
	}

	return style.
		Width(contentWidth).
		Height(contentHeight).
		Render(content)
}

// renderInput renders the bottom input bar.
func (m Model) renderInput() string {
	style := InputBarStyle
	if m.Focus == FocusInput {
		style = ActiveInputBarStyle
	}

	contentWidth := m.Width - 4
	if contentWidth < 10 {
		contentWidth = 10
	}

	return style.
		Width(contentWidth).
		Render(m.Input.View())
}

// View implements tea.Model.
func (m Model) View() string {
	if m.Width == 0 || m.Height == 0 {
		return "Initializing shh...\n"
	}

	roster := m.renderRoster()
	messages := m.renderMessages()
	panes := lipgloss.JoinHorizontal(lipgloss.Top, roster, messages)
	input := m.renderInput()

	return lipgloss.JoinVertical(lipgloss.Left, panes, input)
}
