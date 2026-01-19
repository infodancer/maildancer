package smtp

import (
	"context"
	"regexp"
	"strings"
	"testing"
)

// Helper function to create a test session with default config
func newTestSession() *SMTPSession {
	return NewSMTPSession(
		ConnectionInfo{ClientIP: "192.168.1.100"},
		DefaultSessionConfig(),
	)
}

// Helper function to create a session already in greeted state
func newGreetedSession() *SMTPSession {
	session := newTestSession()
	session.SetState(StateGreeted)
	session.SetHelo("test.example.com")
	return session
}

// Helper function to create a session with MAIL FROM set
func newMailFromSession() *SMTPSession {
	session := newGreetedSession()
	session.SetSender("sender@example.com")
	session.SetState(StateMailFrom)
	return session
}

// Helper function to create a session with at least one recipient
func newRcptToSession() *SMTPSession {
	session := newMailFromSession()
	session.AddRecipient("recipient@example.com")
	session.SetState(StateRcptTo)
	return session
}

// TestSessionState tests the SessionState String method
func TestSessionState_String(t *testing.T) {
	tests := []struct {
		state    SessionState
		expected string
	}{
		{StateInit, "INIT"},
		{StateGreeted, "GREETED"},
		{StateMailFrom, "MAIL_FROM"},
		{StateRcptTo, "RCPT_TO"},
		{StateData, "DATA"},
		{SessionState(99), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.state.String(); got != tt.expected {
				t.Errorf("SessionState.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestDefaultSessionConfig tests the default configuration values
func TestDefaultSessionConfig(t *testing.T) {
	config := DefaultSessionConfig()

	if config.MaxRecipients != 100 {
		t.Errorf("MaxRecipients = %d, want 100", config.MaxRecipients)
	}
	if config.MaxMessageSize != 0 {
		t.Errorf("MaxMessageSize = %d, want 0", config.MaxMessageSize)
	}
	if config.MaxHeloDomainLen != 255 {
		t.Errorf("MaxHeloDomainLen = %d, want 255", config.MaxHeloDomainLen)
	}
	if config.MaxEmailLen != 320 {
		t.Errorf("MaxEmailLen = %d, want 320", config.MaxEmailLen)
	}
}

// TestNewSMTPSession tests session initialization
func TestNewSMTPSession(t *testing.T) {
	connInfo := ConnectionInfo{
		ClientIP:   "10.0.0.1",
		ReverseDNS: "client.example.com",
	}
	config := DefaultSessionConfig()
	session := NewSMTPSession(connInfo, config)

	if session.State() != StateInit {
		t.Errorf("initial state = %v, want StateInit", session.State())
	}
	if session.ConnInfo().ClientIP != "10.0.0.1" {
		t.Errorf("ClientIP = %v, want 10.0.0.1", session.ConnInfo().ClientIP)
	}
	if session.GetHelo() != "" {
		t.Errorf("GetHelo() = %v, want empty", session.GetHelo())
	}
	if session.GetSender() != "" {
		t.Errorf("GetSender() = %v, want empty", session.GetSender())
	}
	if len(session.GetRecipients()) != 0 {
		t.Errorf("GetRecipients() length = %d, want 0", len(session.GetRecipients()))
	}
}

// TestGetRecipients_DefensiveCopy tests that GetRecipients returns a copy
func TestGetRecipients_DefensiveCopy(t *testing.T) {
	session := newTestSession()
	session.AddRecipient("user1@example.com")
	session.AddRecipient("user2@example.com")

	recipients := session.GetRecipients()
	recipients[0] = "modified@example.com"

	// Original should be unchanged
	original := session.GetRecipients()
	if original[0] == "modified@example.com" {
		t.Error("GetRecipients did not return a defensive copy")
	}
}

// TestSessionReset tests the session reset functionality
func TestSessionReset(t *testing.T) {
	session := newRcptToSession()

	session.Reset()

	if session.State() != StateGreeted {
		t.Errorf("state after reset = %v, want StateGreeted", session.State())
	}
	if session.GetSender() != "" {
		t.Errorf("sender after reset = %v, want empty", session.GetSender())
	}
	if len(session.GetRecipients()) != 0 {
		t.Errorf("recipients after reset = %d, want 0", len(session.GetRecipients()))
	}
	// HELO should be preserved
	if session.GetHelo() == "" {
		t.Error("HELO should be preserved after reset")
	}
}

// TestSessionReset_FromInit tests reset from initial state
func TestSessionReset_FromInit(t *testing.T) {
	session := newTestSession()
	session.Reset()

	if session.State() != StateInit {
		t.Errorf("state after reset from init = %v, want StateInit", session.State())
	}
}

// TestCommandRegistry_Match tests the command registry matching
func TestCommandRegistry_Match(t *testing.T) {
	registry := NewCommandRegistry("test.example.com", nil, nil)

	tests := []struct {
		name        string
		input       string
		wantErr     error
		wantCommand string
	}{
		{"EHLO valid", "EHLO example.com", nil, "*smtp.EHLOCommand"},
		{"EHLO lowercase", "ehlo example.com", nil, "*smtp.EHLOCommand"},
		{"EHLO mixed case", "Ehlo example.com", nil, "*smtp.EHLOCommand"},
		{"HELO valid", "HELO example.com", nil, "*smtp.HELOCommand"},
		{"MAIL FROM valid", "MAIL FROM:<user@example.com>", nil, "*smtp.MAILCommand"},
		{"MAIL FROM with space", "MAIL FROM: <user@example.com>", nil, "*smtp.MAILCommand"},
		{"MAIL FROM empty", "MAIL FROM:<>", nil, "*smtp.MAILCommand"},
		{"RCPT TO valid", "RCPT TO:<user@example.com>", nil, "*smtp.RCPTCommand"},
		{"DATA valid", "DATA", nil, "*smtp.DATACommand"},
		{"DATA lowercase", "data", nil, "*smtp.DATACommand"},
		{"RSET valid", "RSET", nil, "*smtp.RSETCommand"},
		{"NOOP valid", "NOOP", nil, "*smtp.NOOPCommand"},
		{"NOOP with arg", "NOOP hello", nil, "*smtp.NOOPCommand"},
		{"QUIT valid", "QUIT", nil, "*smtp.QUITCommand"},
		{"unknown command", "INVALID", ErrUnknownCommand, ""},
		{"EHLO missing domain", "EHLO", ErrUnknownCommand, ""},
		{"HELO missing domain", "HELO", ErrUnknownCommand, ""},
		{"MAIL wrong format", "MAIL user@example.com", ErrUnknownCommand, ""},
		{"DATA with args", "DATA something", ErrUnknownCommand, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, _, err := registry.Match(tt.input)
			if err != tt.wantErr {
				t.Errorf("Match() error = %v, want %v", err, tt.wantErr)
				return
			}
			if tt.wantErr == nil {
				cmdType := cmdTypeString(cmd)
				if cmdType != tt.wantCommand {
					t.Errorf("Match() command type = %v, want %v", cmdType, tt.wantCommand)
				}
			}
		})
	}
}

func cmdTypeString(cmd SMTPCommand) string {
	if cmd == nil {
		return ""
	}
	switch cmd.(type) {
	case *EHLOCommand:
		return "*smtp.EHLOCommand"
	case *HELOCommand:
		return "*smtp.HELOCommand"
	case *MAILCommand:
		return "*smtp.MAILCommand"
	case *RCPTCommand:
		return "*smtp.RCPTCommand"
	case *DATACommand:
		return "*smtp.DATACommand"
	case *RSETCommand:
		return "*smtp.RSETCommand"
	case *NOOPCommand:
		return "*smtp.NOOPCommand"
	case *QUITCommand:
		return "*smtp.QUITCommand"
	default:
		return "unknown"
	}
}

// TestEHLOCommand tests the EHLO command execution
func TestEHLOCommand(t *testing.T) {
	ctx := context.Background()
	cmd := &EHLOCommand{}

	t.Run("valid EHLO", func(t *testing.T) {
		session := newTestSession()
		matches := ehloPattern.FindStringSubmatch("EHLO mail.example.com")

		result, err := cmd.Execute(ctx, session, matches)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result.Code != 250 {
			t.Errorf("Code = %d, want 250", result.Code)
		}
		if session.State() != StateGreeted {
			t.Errorf("state = %v, want StateGreeted", session.State())
		}
		if session.GetHelo() != "mail.example.com" {
			t.Errorf("helo = %v, want mail.example.com", session.GetHelo())
		}
		// EHLO returns multi-line response, check Lines instead of Message
		if len(result.Lines) == 0 {
			t.Errorf("expected multi-line response, got empty Lines")
		}
		allLines := strings.Join(result.Lines, " ")
		if !strings.Contains(allLines, "192.168.1.100") {
			t.Errorf("response should contain client IP, got: %v", result.Lines)
		}
	})

	t.Run("domain too long", func(t *testing.T) {
		session := newTestSession()
		longDomain := strings.Repeat("a", 300)
		matches := []string{"EHLO " + longDomain, longDomain}

		result, err := cmd.Execute(ctx, session, matches)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result.Code != 501 {
			t.Errorf("Code = %d, want 501", result.Code)
		}
	})

	t.Run("empty client IP shows unknown", func(t *testing.T) {
		session := NewSMTPSession(ConnectionInfo{}, DefaultSessionConfig())
		matches := ehloPattern.FindStringSubmatch("EHLO test.com")

		result, _ := cmd.Execute(ctx, session, matches)

		// EHLO returns multi-line response, check Lines
		allLines := strings.Join(result.Lines, " ")
		if !strings.Contains(allLines, "[unknown]") {
			t.Errorf("response should contain [unknown], got: %v", result.Lines)
		}
	})
}

// TestHELOCommand tests the HELO command execution
func TestHELOCommand(t *testing.T) {
	ctx := context.Background()
	cmd := &HELOCommand{}

	t.Run("valid HELO", func(t *testing.T) {
		session := newTestSession()
		matches := heloPattern.FindStringSubmatch("HELO mail.example.com")

		result, err := cmd.Execute(ctx, session, matches)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result.Code != 250 {
			t.Errorf("Code = %d, want 250", result.Code)
		}
		if session.State() != StateGreeted {
			t.Errorf("state = %v, want StateGreeted", session.State())
		}
	})
}

// TestMAILCommand tests the MAIL command execution
func TestMAILCommand(t *testing.T) {
	ctx := context.Background()
	cmd := &MAILCommand{}

	t.Run("valid MAIL FROM", func(t *testing.T) {
		session := newGreetedSession()
		matches := mailPattern.FindStringSubmatch("MAIL FROM:<sender@example.com>")

		result, err := cmd.Execute(ctx, session, matches)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result.Code != 250 {
			t.Errorf("Code = %d, want 250", result.Code)
		}
		if session.State() != StateMailFrom {
			t.Errorf("state = %v, want StateMailFrom", session.State())
		}
		if session.GetSender() != "sender@example.com" {
			t.Errorf("sender = %v, want sender@example.com", session.GetSender())
		}
	})

	t.Run("MAIL FROM with empty sender (bounce)", func(t *testing.T) {
		session := newGreetedSession()
		matches := mailPattern.FindStringSubmatch("MAIL FROM:<>")

		result, _ := cmd.Execute(ctx, session, matches)

		if result.Code != 250 {
			t.Errorf("Code = %d, want 250", result.Code)
		}
		if session.GetSender() != "" {
			t.Errorf("sender = %v, want empty (bounce address)", session.GetSender())
		}
	})

	t.Run("MAIL FROM before HELO", func(t *testing.T) {
		session := newTestSession() // StateInit
		matches := mailPattern.FindStringSubmatch("MAIL FROM:<sender@example.com>")

		result, _ := cmd.Execute(ctx, session, matches)

		if result.Code != 503 {
			t.Errorf("Code = %d, want 503 (bad sequence)", result.Code)
		}
	})

	t.Run("MAIL FROM email too long", func(t *testing.T) {
		session := newGreetedSession()
		longEmail := strings.Repeat("a", 400) + "@example.com"
		matches := []string{"MAIL FROM:<" + longEmail + ">", longEmail, ""}

		result, _ := cmd.Execute(ctx, session, matches)

		if result.Code != 501 {
			t.Errorf("Code = %d, want 501 (email too long)", result.Code)
		}
	})

	t.Run("MAIL FROM with SIZE parameter", func(t *testing.T) {
		session := newGreetedSession()
		matches := mailPattern.FindStringSubmatch("MAIL FROM:<sender@example.com> SIZE=1024")

		result, _ := cmd.Execute(ctx, session, matches)

		if result.Code != 250 {
			t.Errorf("Code = %d, want 250", result.Code)
		}
		// Parameters are captured but ignored for now
		if matches[2] != " SIZE=1024" {
			t.Errorf("params = %v, want ' SIZE=1024'", matches[2])
		}
	})
}

// TestRCPTCommand tests the RCPT command execution
func TestRCPTCommand(t *testing.T) {
	ctx := context.Background()
	cmd := &RCPTCommand{}

	t.Run("valid RCPT TO", func(t *testing.T) {
		session := newMailFromSession()
		matches := rcptPattern.FindStringSubmatch("RCPT TO:<recipient@example.com>")

		result, err := cmd.Execute(ctx, session, matches)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result.Code != 250 {
			t.Errorf("Code = %d, want 250", result.Code)
		}
		if session.State() != StateRcptTo {
			t.Errorf("state = %v, want StateRcptTo", session.State())
		}
		recipients := session.GetRecipients()
		if len(recipients) != 1 || recipients[0] != "recipient@example.com" {
			t.Errorf("recipients = %v, want [recipient@example.com]", recipients)
		}
	})

	t.Run("multiple RCPT TO", func(t *testing.T) {
		session := newMailFromSession()
		matches1 := rcptPattern.FindStringSubmatch("RCPT TO:<user1@example.com>")
		matches2 := rcptPattern.FindStringSubmatch("RCPT TO:<user2@example.com>")

		_, _ = cmd.Execute(ctx, session, matches1)
		result, _ := cmd.Execute(ctx, session, matches2)

		if result.Code != 250 {
			t.Errorf("Code = %d, want 250", result.Code)
		}
		if session.RecipientCount() != 2 {
			t.Errorf("recipient count = %d, want 2", session.RecipientCount())
		}
	})

	t.Run("RCPT TO before MAIL FROM", func(t *testing.T) {
		session := newGreetedSession() // StateGreeted, no MAIL FROM
		matches := rcptPattern.FindStringSubmatch("RCPT TO:<recipient@example.com>")

		result, _ := cmd.Execute(ctx, session, matches)

		if result.Code != 503 {
			t.Errorf("Code = %d, want 503 (bad sequence)", result.Code)
		}
	})

	t.Run("RCPT TO too many recipients", func(t *testing.T) {
		connInfo := ConnectionInfo{ClientIP: "192.168.1.100"}
		config := SessionConfig{
			MaxRecipients:    2,
			MaxHeloDomainLen: 255,
			MaxEmailLen:      320,
		}
		session := NewSMTPSession(connInfo, config)
		session.SetState(StateMailFrom)
		session.AddRecipient("user1@example.com")
		session.AddRecipient("user2@example.com")

		matches := rcptPattern.FindStringSubmatch("RCPT TO:<user3@example.com>")
		result, _ := cmd.Execute(ctx, session, matches)

		if result.Code != 452 {
			t.Errorf("Code = %d, want 452 (too many recipients)", result.Code)
		}
	})

	t.Run("RCPT TO email too long", func(t *testing.T) {
		session := newMailFromSession()
		longEmail := strings.Repeat("a", 400) + "@example.com"
		matches := []string{"RCPT TO:<" + longEmail + ">", longEmail, ""}

		result, _ := cmd.Execute(ctx, session, matches)

		if result.Code != 501 {
			t.Errorf("Code = %d, want 501 (email too long)", result.Code)
		}
	})
}

// TestDATACommand tests the DATA command execution
func TestDATACommand(t *testing.T) {
	ctx := context.Background()
	cmd := &DATACommand{}

	t.Run("valid DATA", func(t *testing.T) {
		session := newRcptToSession()
		matches := dataPattern.FindStringSubmatch("DATA")

		result, err := cmd.Execute(ctx, session, matches)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result.Code != 354 {
			t.Errorf("Code = %d, want 354", result.Code)
		}
		if session.State() != StateData {
			t.Errorf("state = %v, want StateData", session.State())
		}
		if !session.InData() {
			t.Error("InData() should return true")
		}
	})

	t.Run("DATA before RCPT TO", func(t *testing.T) {
		session := newMailFromSession() // No recipients
		matches := dataPattern.FindStringSubmatch("DATA")

		result, _ := cmd.Execute(ctx, session, matches)

		if result.Code != 503 {
			t.Errorf("Code = %d, want 503 (bad sequence)", result.Code)
		}
	})
}

// TestRSETCommand tests the RSET command execution
func TestRSETCommand(t *testing.T) {
	ctx := context.Background()
	cmd := &RSETCommand{}

	t.Run("RSET after MAIL FROM", func(t *testing.T) {
		session := newRcptToSession()
		matches := rsetPattern.FindStringSubmatch("RSET")

		result, err := cmd.Execute(ctx, session, matches)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result.Code != 250 {
			t.Errorf("Code = %d, want 250", result.Code)
		}
		if session.State() != StateGreeted {
			t.Errorf("state = %v, want StateGreeted", session.State())
		}
		if session.GetSender() != "" {
			t.Errorf("sender should be reset")
		}
		if len(session.GetRecipients()) != 0 {
			t.Errorf("recipients should be reset")
		}
	})
}

// TestNOOPCommand tests the NOOP command execution
func TestNOOPCommand(t *testing.T) {
	ctx := context.Background()
	cmd := &NOOPCommand{}

	t.Run("NOOP", func(t *testing.T) {
		session := newTestSession()
		matches := noopPattern.FindStringSubmatch("NOOP")

		result, err := cmd.Execute(ctx, session, matches)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result.Code != 250 {
			t.Errorf("Code = %d, want 250", result.Code)
		}
	})

	t.Run("NOOP with argument", func(t *testing.T) {
		session := newTestSession()
		matches := noopPattern.FindStringSubmatch("NOOP hello world")

		result, _ := cmd.Execute(ctx, session, matches)

		if result.Code != 250 {
			t.Errorf("Code = %d, want 250", result.Code)
		}
	})
}

// TestQUITCommand tests the QUIT command execution
func TestQUITCommand(t *testing.T) {
	ctx := context.Background()
	cmd := &QUITCommand{}

	t.Run("QUIT", func(t *testing.T) {
		session := newTestSession()
		matches := quitPattern.FindStringSubmatch("QUIT")

		result, err := cmd.Execute(ctx, session, matches)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result.Code != 221 {
			t.Errorf("Code = %d, want 221", result.Code)
		}
		if !strings.Contains(result.Message, "Goodbye") {
			t.Errorf("message should contain 'Goodbye', got: %s", result.Message)
		}
	})
}

// TestPatternMatching tests the regexp patterns directly
func TestPatternMatching(t *testing.T) {
	tests := []struct {
		name    string
		pattern *regexp.Regexp
		input   string
		match   bool
		groups  []string // expected capture groups (excluding full match)
	}{
		// EHLO patterns
		{"EHLO valid", ehloPattern, "EHLO example.com", true, []string{"example.com"}},
		{"EHLO with IP", ehloPattern, "EHLO [192.168.1.1]", true, []string{"[192.168.1.1]"}},
		{"EHLO lowercase", ehloPattern, "ehlo example.com", true, []string{"example.com"}},
		{"EHLO missing domain", ehloPattern, "EHLO", false, nil},
		{"EHLO trailing space", ehloPattern, "EHLO example.com ", true, []string{"example.com"}},
		{"EHLO extra args", ehloPattern, "EHLO example.com extra", false, nil},

		// HELO patterns
		{"HELO valid", heloPattern, "HELO example.com", true, []string{"example.com"}},
		{"HELO missing domain", heloPattern, "HELO", false, nil},

		// MAIL patterns
		{"MAIL FROM valid", mailPattern, "MAIL FROM:<user@example.com>", true, []string{"user@example.com", ""}},
		{"MAIL FROM empty", mailPattern, "MAIL FROM:<>", true, []string{"", ""}},
		{"MAIL FROM with space", mailPattern, "MAIL FROM: <user@example.com>", true, []string{"user@example.com", ""}},
		{"MAIL FROM with SIZE", mailPattern, "MAIL FROM:<user@example.com> SIZE=1024", true, []string{"user@example.com", " SIZE=1024"}},
		{"MAIL FROM lowercase", mailPattern, "mail from:<user@example.com>", true, []string{"user@example.com", ""}},
		{"MAIL wrong format", mailPattern, "MAIL user@example.com", false, nil},
		{"MAIL no angle brackets", mailPattern, "MAIL FROM:user@example.com", false, nil},

		// RCPT patterns
		{"RCPT TO valid", rcptPattern, "RCPT TO:<user@example.com>", true, []string{"user@example.com", ""}},
		{"RCPT TO with space", rcptPattern, "RCPT TO: <user@example.com>", true, []string{"user@example.com", ""}},
		{"RCPT wrong format", rcptPattern, "RCPT user@example.com", false, nil},

		// DATA patterns
		{"DATA valid", dataPattern, "DATA", true, nil},
		{"DATA lowercase", dataPattern, "data", true, nil},
		{"DATA with args", dataPattern, "DATA extra", false, nil},
		{"DATA with space", dataPattern, "DATA ", true, nil}, // trailing whitespace is allowed per RFC 5321

		// RSET patterns
		{"RSET valid", rsetPattern, "RSET", true, nil},
		{"RSET with args", rsetPattern, "RSET extra", false, nil},

		// NOOP patterns
		{"NOOP valid", noopPattern, "NOOP", true, nil},
		{"NOOP with arg", noopPattern, "NOOP hello", true, nil},
		{"NOOP lowercase", noopPattern, "noop", true, nil},

		// QUIT patterns
		{"QUIT valid", quitPattern, "QUIT", true, nil},
		{"QUIT with args", quitPattern, "QUIT extra", false, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := tt.pattern.FindStringSubmatch(tt.input)
			matched := matches != nil

			if matched != tt.match {
				t.Errorf("pattern match = %v, want %v", matched, tt.match)
				return
			}

			if tt.match && tt.groups != nil {
				// Check capture groups (skip full match at index 0)
				for i, expected := range tt.groups {
					if i+1 >= len(matches) {
						t.Errorf("missing capture group %d, want %q", i+1, expected)
						continue
					}
					if matches[i+1] != expected {
						t.Errorf("capture group %d = %q, want %q", i+1, matches[i+1], expected)
					}
				}
			}
		})
	}
}

// TestFullSMTPConversation tests a complete SMTP conversation flow
func TestFullSMTPConversation(t *testing.T) {
	ctx := context.Background()
	registry := NewCommandRegistry("test.example.com", nil, nil)
	session := newTestSession()

	// Simulate a full SMTP conversation
	commands := []struct {
		input        string
		expectedCode int
		expectedMsg  string
	}{
		{"EHLO mail.example.com", 250, "Hello"},
		{"MAIL FROM:<sender@example.com>", 250, "OK"},
		{"RCPT TO:<recipient@example.com>", 250, "OK"},
		{"RCPT TO:<another@example.com>", 250, "OK"},
		{"DATA", 354, "Start mail input"},
		// After DATA, the server would read message body until <CRLF>.<CRLF>
	}

	for _, c := range commands {
		t.Run(c.input, func(t *testing.T) {
			cmd, matches, err := registry.Match(c.input)
			if err != nil {
				t.Fatalf("failed to match command: %v", err)
			}

			result, err := cmd.Execute(ctx, session, matches)
			if err != nil {
				t.Fatalf("execution error: %v", err)
			}

			if result.Code != c.expectedCode {
				t.Errorf("Code = %d, want %d", result.Code, c.expectedCode)
			}
			// For multi-line responses (EHLO), check Lines; for single-line, check Message
			responseText := result.Message
			if len(result.Lines) > 0 {
				responseText = strings.Join(result.Lines, " ")
			}
			if !strings.Contains(responseText, c.expectedMsg) {
				t.Errorf("Response = %q, want to contain %q", responseText, c.expectedMsg)
			}
		})
	}

	// Verify final state
	if session.State() != StateData {
		t.Errorf("final state = %v, want StateData", session.State())
	}
	if session.RecipientCount() != 2 {
		t.Errorf("recipient count = %d, want 2", session.RecipientCount())
	}
}

// TestRSETMidConversation tests RSET in the middle of a conversation
func TestRSETMidConversation(t *testing.T) {
	ctx := context.Background()
	registry := NewCommandRegistry("test.example.com", nil, nil)
	session := newTestSession()

	// Start a conversation
	executeCommand(t, ctx, registry, session, "EHLO mail.example.com")
	executeCommand(t, ctx, registry, session, "MAIL FROM:<sender@example.com>")
	executeCommand(t, ctx, registry, session, "RCPT TO:<recipient@example.com>")

	// RSET should clear the transaction but keep HELO
	executeCommand(t, ctx, registry, session, "RSET")

	if session.State() != StateGreeted {
		t.Errorf("state after RSET = %v, want StateGreeted", session.State())
	}
	if session.GetHelo() != "mail.example.com" {
		t.Errorf("HELO should be preserved after RSET")
	}
	if session.GetSender() != "" {
		t.Errorf("sender should be cleared after RSET")
	}
	if len(session.GetRecipients()) != 0 {
		t.Errorf("recipients should be cleared after RSET")
	}

	// Should be able to start a new transaction
	result := executeCommand(t, ctx, registry, session, "MAIL FROM:<newsender@example.com>")
	if result.Code != 250 {
		t.Errorf("MAIL FROM after RSET: Code = %d, want 250", result.Code)
	}
}

func executeCommand(t *testing.T, ctx context.Context, registry *CommandRegistry, session *SMTPSession, input string) SMTPResult {
	t.Helper()
	cmd, matches, err := registry.Match(input)
	if err != nil {
		t.Fatalf("failed to match %q: %v", input, err)
	}
	result, err := cmd.Execute(ctx, session, matches)
	if err != nil {
		t.Fatalf("failed to execute %q: %v", input, err)
	}
	return result
}
