package smtp

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	gosmtp "github.com/emersion/go-smtp"
	"github.com/infodancer/maildancer/auth"
	"github.com/infodancer/maildancer/auth/domain"
)

func TestSessionHelperFunctions(t *testing.T) {
	t.Run("sessionExtractRecipientDomain", func(t *testing.T) {
		tests := []struct {
			recipients []string
			expected   string
		}{
			{nil, "unknown"},
			{[]string{}, "unknown"},
			{[]string{"user@example.com"}, "example.com"},
			{[]string{"user@mail.example.org", "other@other.com"}, "mail.example.org"},
			{[]string{"nodomain"}, "unknown"},
		}

		for _, tt := range tests {
			got := sessionExtractRecipientDomain(tt.recipients)
			if got != tt.expected {
				t.Errorf("sessionExtractRecipientDomain(%v) = %q, want %q", tt.recipients, got, tt.expected)
			}
		}
	})

	t.Run("sessionExtractSenderDomain", func(t *testing.T) {
		tests := []struct {
			sender   string
			expected string
		}{
			{"", "unknown"},
			{"user@example.com", "example.com"},
			{"admin@mail.example.org", "mail.example.org"},
			{"nodomain", "unknown"},
		}

		for _, tt := range tests {
			got := sessionExtractSenderDomain(tt.sender)
			if got != tt.expected {
				t.Errorf("sessionExtractSenderDomain(%q) = %q, want %q", tt.sender, got, tt.expected)
			}
		}
	})

	t.Run("sessionExtractAuthDomain", func(t *testing.T) {
		tests := []struct {
			username string
			expected string
		}{
			{"", "unknown"},
			{"user@example.com", "example.com"},
			{"localuser", "local"},
		}

		for _, tt := range tests {
			got := sessionExtractAuthDomain(tt.username)
			if got != tt.expected {
				t.Errorf("sessionExtractAuthDomain(%q) = %q, want %q", tt.username, got, tt.expected)
			}
		}
	})

	t.Run("sessionIsLocalhost", func(t *testing.T) {
		tests := []struct {
			ip       string
			expected bool
		}{
			{"127.0.0.1", true},
			{"::1", true},
			{"127.0.0.2", true},
			{"localhost", true},
			{"192.168.1.1", false},
			{"10.0.0.1", false},
			{"8.8.8.8", false},
		}

		for _, tt := range tests {
			got := sessionIsLocalhost(tt.ip)
			if got != tt.expected {
				t.Errorf("sessionIsLocalhost(%q) = %v, want %v", tt.ip, got, tt.expected)
			}
		}
	})
}

// mockAuthAgent implements auth.AuthenticationAgent for testing.
type mockAuthAgent struct {
	users      map[string]bool
	lookupErr  error
	closeCalls int
}

func (m *mockAuthAgent) Authenticate(_ context.Context, _, _ string) (*auth.AuthSession, error) {
	return nil, errors.New("not implemented")
}

func (m *mockAuthAgent) UserExists(_ context.Context, username string) (bool, error) {
	if m.lookupErr != nil {
		return false, m.lookupErr
	}
	return m.users[username], nil
}

func (m *mockAuthAgent) Close() error {
	m.closeCalls++
	return nil
}

// mockDomainProvider implements domain.DomainProvider for testing.
type mockDomainProvider struct {
	domains map[string]*domain.Domain
}

func (m *mockDomainProvider) GetDomain(name string) *domain.Domain {
	return m.domains[name]
}

func (m *mockDomainProvider) Domains() []string {
	var names []string
	for name := range m.domains {
		names = append(names, name)
	}
	return names
}

func (m *mockDomainProvider) Close() error {
	return nil
}

func TestSession_Rcpt_DomainValidation(t *testing.T) {
	logger := slog.Default()

	t.Run("unknown domain rejected with 550", func(t *testing.T) {
		provider := &mockDomainProvider{
			domains: map[string]*domain.Domain{
				"example.com": {
					Name:      "example.com",
					AuthAgent: &mockAuthAgent{users: map[string]bool{"user@example.com": true}},
				},
			},
		}

		backend := NewBackend(BackendConfig{
			DomainProvider: provider,
			Logger:         logger,
		})

		session := &Session{
			backend: backend,
			logger:  logger,
		}

		err := session.Rcpt("user@unknown.com", nil)
		if err == nil {
			t.Fatal("expected error for unknown domain")
		}

		smtpErr, ok := err.(*gosmtp.SMTPError)
		if !ok {
			t.Fatalf("expected SMTPError, got %T", err)
		}
		if smtpErr.Code != 550 {
			t.Errorf("expected code 550, got %d", smtpErr.Code)
		}
	})

	t.Run("unknown user rejected with 550", func(t *testing.T) {
		provider := &mockDomainProvider{
			domains: map[string]*domain.Domain{
				"example.com": {
					Name:      "example.com",
					AuthAgent: &mockAuthAgent{users: map[string]bool{"validuser@example.com": true}},
				},
			},
		}

		backend := NewBackend(BackendConfig{
			DomainProvider: provider,
			Logger:         logger,
		})

		session := &Session{
			backend: backend,
			logger:  logger,
		}

		err := session.Rcpt("unknownuser@example.com", nil)
		if err == nil {
			t.Fatal("expected error for unknown user")
		}

		smtpErr, ok := err.(*gosmtp.SMTPError)
		if !ok {
			t.Fatalf("expected SMTPError, got %T", err)
		}
		if smtpErr.Code != 550 {
			t.Errorf("expected code 550, got %d", smtpErr.Code)
		}
		if smtpErr.EnhancedCode != (gosmtp.EnhancedCode{5, 1, 1}) {
			t.Errorf("expected enhanced code 5.1.1, got %v", smtpErr.EnhancedCode)
		}
	})

	t.Run("valid user accepted", func(t *testing.T) {
		provider := &mockDomainProvider{
			domains: map[string]*domain.Domain{
				"example.com": {
					Name:      "example.com",
					AuthAgent: &mockAuthAgent{users: map[string]bool{"validuser@example.com": true}},
				},
			},
		}

		backend := NewBackend(BackendConfig{
			DomainProvider: provider,
			Logger:         logger,
		})

		session := &Session{
			backend: backend,
			logger:  logger,
		}

		err := session.Rcpt("validuser@example.com", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(session.recipients) != 1 {
			t.Errorf("expected 1 recipient, got %d", len(session.recipients))
		}
		if session.domain == nil {
			t.Error("expected domain to be set on session")
		}
	})

	t.Run("multiple RCPT TO rejected with 452", func(t *testing.T) {
		provider := &mockDomainProvider{
			domains: map[string]*domain.Domain{
				"example.com": {
					Name:      "example.com",
					AuthAgent: &mockAuthAgent{users: map[string]bool{"user1@example.com": true, "user2@example.com": true}},
				},
			},
		}

		backend := NewBackend(BackendConfig{
			DomainProvider: provider,
			Logger:         logger,
		})

		session := &Session{
			backend: backend,
			logger:  logger,
		}

		// First RCPT TO should succeed
		err := session.Rcpt("user1@example.com", nil)
		if err != nil {
			t.Fatalf("first RCPT TO failed: %v", err)
		}

		// Second RCPT TO should be rejected
		err = session.Rcpt("user2@example.com", nil)
		if err == nil {
			t.Fatal("expected error for second RCPT TO")
		}

		smtpErr, ok := err.(*gosmtp.SMTPError)
		if !ok {
			t.Fatalf("expected SMTPError, got %T", err)
		}
		if smtpErr.Code != 452 {
			t.Errorf("expected code 452, got %d", smtpErr.Code)
		}
	})

	t.Run("lookup failure returns 451", func(t *testing.T) {
		provider := &mockDomainProvider{
			domains: map[string]*domain.Domain{
				"example.com": {
					Name:      "example.com",
					AuthAgent: &mockAuthAgent{lookupErr: errors.New("database error")},
				},
			},
		}

		backend := NewBackend(BackendConfig{
			DomainProvider: provider,
			Logger:         logger,
		})

		session := &Session{
			backend: backend,
			logger:  logger,
		}

		err := session.Rcpt("user@example.com", nil)
		if err == nil {
			t.Fatal("expected error for lookup failure")
		}

		smtpErr, ok := err.(*gosmtp.SMTPError)
		if !ok {
			t.Fatalf("expected SMTPError, got %T", err)
		}
		if smtpErr.Code != 451 {
			t.Errorf("expected code 451, got %d", smtpErr.Code)
		}
	})
}

func TestExtractDomain(t *testing.T) {
	tests := []struct {
		email    string
		expected string
	}{
		{"user@example.com", "example.com"},
		{"<user@example.com>", "example.com"},
		{"User@EXAMPLE.COM", "example.com"},
		{"user@sub.domain.org", "sub.domain.org"},
		{"nodomain", ""},
		{"user@", ""},
		{"@domain.com", "domain.com"},
	}

	for _, tt := range tests {
		got := extractDomain(tt.email)
		if got != tt.expected {
			t.Errorf("extractDomain(%q) = %q, want %q", tt.email, got, tt.expected)
		}
	}
}
