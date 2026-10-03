package ui

import (
	"reflect"
	"testing"
)

func TestParseCommand_PlainText(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty string", ""},
		{"spaces only", "   "},
		{"regular message", "hello world"},
		{"message with leading spaces", "  hey there  "},
		{"message with slash inside", "check out http://example.com"},
		{"message with slash after word", "look/at/this"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd, args, isCmd := ParseCommand(tc.input)
			if isCmd {
				t.Errorf("expected isCmd=false for %q, got true", tc.input)
			}
			if cmd != CmdNone {
				t.Errorf("expected CmdNone for %q, got %v", tc.input, cmd)
			}
			if len(args) != 0 {
				t.Errorf("expected empty args for %q, got %v", tc.input, args)
			}
		})
	}
}

func TestParseCommand_Nick(t *testing.T) {
	// Valid argument
	cmd, args, isCmd := ParseCommand("/nick alice")
	if !isCmd {
		t.Fatal("expected isCmd=true")
	}
	if cmd != CmdNick {
		t.Errorf("expected CmdNick, got %v", cmd)
	}
	expectedArgs := []string{"alice"}
	if !reflect.DeepEqual(args, expectedArgs) {
		t.Errorf("expected args %v, got %v", expectedArgs, args)
	}

	// Valid with multiple spaces
	cmd, args, isCmd = ParseCommand("  /nick   bob_99  ")
	if !isCmd || cmd != CmdNick {
		t.Fatalf("expected CmdNick, got cmd=%v, isCmd=%v", cmd, isCmd)
	}
	if !reflect.DeepEqual(args, []string{"bob_99"}) {
		t.Errorf("expected args ['bob_99'], got %v", args)
	}

	// Missing argument
	cmd, args, isCmd = ParseCommand("/nick")
	if !isCmd {
		t.Fatal("expected isCmd=true for /nick without args")
	}
	if cmd != CmdNick {
		t.Errorf("expected CmdNick, got %v", cmd)
	}
	if len(args) != 0 {
		t.Errorf("expected 0 args for /nick, got %v", args)
	}

	// Missing argument with trailing spaces
	cmd, args, isCmd = ParseCommand("/nick   ")
	if !isCmd || cmd != CmdNick || len(args) != 0 {
		t.Errorf("expected CmdNick with 0 args, got cmd=%v, args=%v, isCmd=%v", cmd, args, isCmd)
	}
}

func TestParseCommand_Whois(t *testing.T) {
	// Valid argument
	cmd, args, isCmd := ParseCommand("/whois charlie")
	if !isCmd {
		t.Fatal("expected isCmd=true")
	}
	if cmd != CmdWhois {
		t.Errorf("expected CmdWhois, got %v", cmd)
	}
	if !reflect.DeepEqual(args, []string{"charlie"}) {
		t.Errorf("expected args ['charlie'], got %v", args)
	}

	// Missing argument
	cmd, args, isCmd = ParseCommand("/whois")
	if !isCmd {
		t.Fatal("expected isCmd=true")
	}
	if cmd != CmdWhois {
		t.Errorf("expected CmdWhois, got %v", cmd)
	}
	if len(args) != 0 {
		t.Errorf("expected 0 args for /whois, got %v", args)
	}
}

func TestParseCommand_Keys(t *testing.T) {
	cmd, args, isCmd := ParseCommand("/keys")
	if !isCmd {
		t.Fatal("expected isCmd=true")
	}
	if cmd != CmdKeys {
		t.Errorf("expected CmdKeys, got %v", cmd)
	}
	if len(args) != 0 {
		t.Errorf("expected 0 args for /keys, got %v", args)
	}
}

func TestParseCommand_Clear(t *testing.T) {
	cmd, args, isCmd := ParseCommand("/clear")
	if !isCmd {
		t.Fatal("expected isCmd=true")
	}
	if cmd != CmdClear {
		t.Errorf("expected CmdClear, got %v", cmd)
	}
	if len(args) != 0 {
		t.Errorf("expected 0 args for /clear, got %v", args)
	}
}

func TestParseCommand_Quit(t *testing.T) {
	// Full command
	cmd, args, isCmd := ParseCommand("/quit")
	if !isCmd {
		t.Fatal("expected isCmd=true")
	}
	if cmd != CmdQuit {
		t.Errorf("expected CmdQuit, got %v", cmd)
	}
	if len(args) != 0 {
		t.Errorf("expected 0 args for /quit, got %v", args)
	}

	// Short alias /q
	cmd, args, isCmd = ParseCommand("/q")
	if !isCmd {
		t.Fatal("expected isCmd=true for /q")
	}
	if cmd != CmdQuit {
		t.Errorf("expected CmdQuit for /q, got %v", cmd)
	}
	if len(args) != 0 {
		t.Errorf("expected 0 args for /q, got %v", args)
	}
}

func TestParseCommand_Unrecognized(t *testing.T) {
	// Unknown command /foo
	cmd, args, isCmd := ParseCommand("/foo")
	if !isCmd {
		t.Fatal("expected isCmd=true for unrecognized command /foo")
	}
	if cmd != CmdUnknown {
		t.Errorf("expected CmdUnknown, got %v", cmd)
	}

	// Unknown command with args
	cmd, args, isCmd = ParseCommand("/bar baz qux")
	if !isCmd {
		t.Fatal("expected isCmd=true for unrecognized command /bar")
	}
	if cmd != CmdUnknown {
		t.Errorf("expected CmdUnknown, got %v", cmd)
	}
	if !reflect.DeepEqual(args, []string{"baz", "qux"}) {
		t.Errorf("expected args ['baz', 'qux'], got %v", args)
	}

	// Standalone slash
	cmd, _, isCmd = ParseCommand("/")
	if !isCmd {
		t.Fatal("expected isCmd=true for standalone slash")
	}
	if cmd != CmdUnknown {
		t.Errorf("expected CmdUnknown for standalone slash, got %v", cmd)
	}
}

func TestCommand_String(t *testing.T) {
	tests := []struct {
		cmd      Command
		expected string
	}{
		{CmdNone, "none"},
		{CmdNick, "/nick"},
		{CmdWhois, "/whois"},
		{CmdKeys, "/keys"},
		{CmdClear, "/clear"},
		{CmdQuit, "/quit"},
		{CmdUnknown, "unknown"},
	}

	for _, tc := range tests {
		if tc.cmd.String() != tc.expected {
			t.Errorf("expected %s.String() == %q, got %q", tc.expected, tc.expected, tc.cmd.String())
		}
	}
}
