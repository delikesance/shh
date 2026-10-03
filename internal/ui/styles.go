package ui

import "github.com/charmbracelet/lipgloss"

const (
	// CipherBadgeText is the standard cryptographic badge displayed in the active DM viewport.
	CipherBadgeText = "🔒 Cipher: ChaCha20-Poly1305 (Ephemeral X25519)"
)

// Palette definitions for terminal UI
var (
	ColorPrimary   = lipgloss.Color("63")  // Charm Purple
	ColorSecondary = lipgloss.Color("39")  // Cyan
	ColorSuccess   = lipgloss.Color("42")  // Bright Green
	ColorWarning   = lipgloss.Color("214") // Amber / Orange
	ColorDanger    = lipgloss.Color("196") // Red
	ColorMuted     = lipgloss.Color("241") // Mid Gray
	ColorDim       = lipgloss.Color("238") // Dark Gray
	ColorHighlight = lipgloss.Color("212") // Soft Pink
	ColorSelf      = lipgloss.Color("99")  // Light Violet
)

// Roster and pane styles
var (
	// Inactive pane border
	PaneStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorDim).
			Padding(0, 1)

	// Active (focused) pane border
	ActivePaneStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorPrimary).
			Padding(0, 1)

	// Pane title style
	PaneTitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorPrimary).
			Padding(0, 1)

	ActivePaneTitleStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(ColorSecondary).
				Padding(0, 1)

	// Input bar container style
	InputBarStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorDim).
			Padding(0, 1)

	ActiveInputBarStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(ColorPrimary).
				Padding(0, 1)

	// Peer item styles
	PeerItemNormal = lipgloss.NewStyle().
			Foreground(lipgloss.Color("252"))

	PeerItemSelected = lipgloss.NewStyle().
				Bold(true).
				Foreground(ColorSecondary).
				Background(lipgloss.Color("236"))

	PeerItemActive = lipgloss.NewStyle().
			Foreground(ColorSuccess)

	PeerItemIdle = lipgloss.NewStyle().
			Foreground(ColorWarning)

	PeerItemSelf = lipgloss.NewStyle().
			Foreground(ColorSelf).
			Italic(true)

	// Cipher badge style
	CipherBadgeStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(ColorSuccess)

	// Fingerprint and header styles
	HeaderStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorSecondary).
			Border(lipgloss.NormalBorder(), false, false, true, false).
			BorderForeground(ColorDim)

	FingerprintStyle = lipgloss.NewStyle().
				Foreground(ColorMuted)

	// Message backlog styles
	TimestampStyle = lipgloss.NewStyle().
			Foreground(ColorMuted)

	SenderSelfStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorSecondary)

	SenderPeerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorHighlight)

	SystemMessageStyle = lipgloss.NewStyle().
				Italic(true).
				Foreground(ColorMuted)

	ErrorMessageStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(ColorDanger)

	HelpStyle = lipgloss.NewStyle().
			Foreground(ColorMuted)
)
