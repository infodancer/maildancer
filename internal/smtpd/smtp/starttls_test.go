package smtp

import (
	"context"
	"crypto/tls"
	"testing"
)

func TestSTARTTLSCommand_Pattern(t *testing.T) {
	cmd := &STARTTLSCommand{}
	pattern := cmd.Pattern()

	tests := []struct {
		name    string
		input   string
		matches bool
	}{
		{"uppercase", "STARTTLS", true},
		{"lowercase", "starttls", true},
		{"mixed case", "StartTLS", true},
		{"with trailing space", "STARTTLS ", true},
		{"with extra text", "STARTTLS extra", false},
		{"partial match", "START", false},
		{"similar command", "STARTTL", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matched := pattern.MatchString(tc.input)
			if matched != tc.matches {
				t.Errorf("pattern.MatchString(%q) = %v, want %v", tc.input, matched, tc.matches)
			}
		})
	}
}

func TestSTARTTLSCommand_Execute_Success(t *testing.T) {
	tlsConfig := &tls.Config{}
	cmd := &STARTTLSCommand{tlsConfig: tlsConfig}

	session := NewSMTPSession(ConnectionInfo{ClientIP: "192.168.1.1"}, DefaultSessionConfig())
	session.SetTLSActive(false)

	result, err := cmd.Execute(context.Background(), session, []string{"STARTTLS"})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if result.Code != 220 {
		t.Errorf("result.Code = %d, want 220", result.Code)
	}
}

func TestSTARTTLSCommand_Execute_AlreadyTLS(t *testing.T) {
	tlsConfig := &tls.Config{}
	cmd := &STARTTLSCommand{tlsConfig: tlsConfig}

	session := NewSMTPSession(ConnectionInfo{ClientIP: "192.168.1.1"}, DefaultSessionConfig())
	session.SetTLSActive(true)

	result, err := cmd.Execute(context.Background(), session, []string{"STARTTLS"})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if result.Code != 503 {
		t.Errorf("result.Code = %d, want 503 (TLS already active)", result.Code)
	}
}

func TestSTARTTLSCommand_Execute_NoTLSConfig(t *testing.T) {
	cmd := &STARTTLSCommand{tlsConfig: nil}

	session := NewSMTPSession(ConnectionInfo{ClientIP: "192.168.1.1"}, DefaultSessionConfig())
	session.SetTLSActive(false)

	result, err := cmd.Execute(context.Background(), session, []string{"STARTTLS"})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if result.Code != 454 {
		t.Errorf("result.Code = %d, want 454 (TLS not available)", result.Code)
	}
}

func TestSTARTTLSCommand_TLSConfig(t *testing.T) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	cmd := &STARTTLSCommand{tlsConfig: tlsConfig}

	if cmd.TLSConfig() != tlsConfig {
		t.Error("TLSConfig() did not return the expected config")
	}
}

func TestCommandRegistry_WithSTARTTLS(t *testing.T) {
	tlsConfig := &tls.Config{}
	registry := NewCommandRegistry("test.example.com", nil, tlsConfig)

	cmd, matches, err := registry.Match("STARTTLS")
	if err != nil {
		t.Fatalf("Match returned error: %v", err)
	}

	if _, ok := cmd.(*STARTTLSCommand); !ok {
		t.Errorf("expected *STARTTLSCommand, got %T", cmd)
	}

	if len(matches) == 0 {
		t.Error("expected non-empty matches")
	}
}

func TestCommandRegistry_WithoutSTARTTLS(t *testing.T) {
	registry := NewCommandRegistry("test.example.com", nil, nil)

	_, _, err := registry.Match("STARTTLS")
	if err != ErrUnknownCommand {
		t.Errorf("expected ErrUnknownCommand, got %v", err)
	}
}

func TestEHLOCommand_AdvertisesSTARTTLS(t *testing.T) {
	tlsConfig := &tls.Config{}
	cmd := &EHLOCommand{
		hostname:  "mail.example.com",
		tlsConfig: tlsConfig,
	}

	session := NewSMTPSession(ConnectionInfo{ClientIP: "192.168.1.1"}, DefaultSessionConfig())
	session.SetTLSActive(false)

	result, err := cmd.Execute(context.Background(), session, []string{"EHLO client.example.com", "client.example.com"})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if result.Code != 250 {
		t.Errorf("result.Code = %d, want 250", result.Code)
	}

	// Check that STARTTLS is advertised
	found := false
	for _, line := range result.Lines {
		if line == "STARTTLS" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("STARTTLS not advertised in EHLO response: %v", result.Lines)
	}
}

func TestEHLOCommand_NoSTARTTLSWhenTLSActive(t *testing.T) {
	tlsConfig := &tls.Config{}
	cmd := &EHLOCommand{
		hostname:  "mail.example.com",
		tlsConfig: tlsConfig,
	}

	session := NewSMTPSession(ConnectionInfo{ClientIP: "192.168.1.1"}, DefaultSessionConfig())
	session.SetTLSActive(true)

	result, err := cmd.Execute(context.Background(), session, []string{"EHLO client.example.com", "client.example.com"})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	// Check that STARTTLS is NOT advertised when TLS is already active
	for _, line := range result.Lines {
		if line == "STARTTLS" {
			t.Error("STARTTLS should not be advertised when TLS is already active")
		}
	}
}

func TestEHLOCommand_NoSTARTTLSWithoutConfig(t *testing.T) {
	cmd := &EHLOCommand{
		hostname:  "mail.example.com",
		tlsConfig: nil,
	}

	session := NewSMTPSession(ConnectionInfo{ClientIP: "192.168.1.1"}, DefaultSessionConfig())
	session.SetTLSActive(false)

	result, err := cmd.Execute(context.Background(), session, []string{"EHLO client.example.com", "client.example.com"})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	// Check that STARTTLS is NOT advertised when no TLS config
	for _, line := range result.Lines {
		if line == "STARTTLS" {
			t.Error("STARTTLS should not be advertised without TLS config")
		}
	}
}
