package ui

import "strings"

// Command represents a recognized slash command enum.
type Command int

const (
	CmdNone Command = iota
	CmdNick
	CmdWhois
	CmdKeys
	CmdClear
	CmdQuit
	CmdUnknown
)

// String returns the string representation of the Command.
func (c Command) String() string {
	switch c {
	case CmdNick:
		return "/nick"
	case CmdWhois:
		return "/whois"
	case CmdKeys:
		return "/keys"
	case CmdClear:
		return "/clear"
	case CmdQuit:
		return "/quit"
	case CmdUnknown:
		return "unknown"
	default:
		return "none"
	}
}

// ParseCommand parses a user input string into a Command, arguments slice, and a boolean
// indicating whether the input was a slash command (i.e. starting with '/').
func ParseCommand(input string) (Command, []string, bool) {
	trimmed := strings.TrimSpace(input)
	if !strings.HasPrefix(trimmed, "/") {
		return CmdNone, nil, false
	}

	parts := strings.Fields(trimmed)
	if len(parts) == 0 {
		return CmdUnknown, []string{}, true
	}

	cmdStr := parts[0]
	cmdName := strings.ToLower(strings.TrimPrefix(cmdStr, "/"))
	args := parts[1:]
	if args == nil {
		args = []string{}
	}

	switch cmdName {
	case "nick":
		return CmdNick, args, true
	case "whois":
		return CmdWhois, args, true
	case "keys":
		return CmdKeys, args, true
	case "clear":
		return CmdClear, args, true
	case "quit", "q":
		return CmdQuit, args, true
	default:
		return CmdUnknown, args, true
	}
}
