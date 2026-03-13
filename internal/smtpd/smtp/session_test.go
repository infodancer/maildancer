package smtp

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	gosmtp "github.com/emersion/go-smtp"
	"github.com/infodancer/maildancer/auth"
	"github.com/infodancer/maildancer/auth/domain"
	"github.com/infodancer/maildancer/msgstore"
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

func (m *mockAuthAgent) ResolveForward(_ context.Context, _ string) ([]string, bool) {
	return nil, false
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

// mockDeliveryAgent implements msgstore.DeliveryAgent for testing.
type mockDeliveryAgent struct{}

func (m *mockDeliveryAgent) Deliver(_ context.Context, _ msgstore.Envelope, _ io.Reader) error {
	return nil
}

// newTestBackend creates a Backend with a DomainProvider and matching AuthRouter for tests.
func newTestBackend(provider *mockDomainProvider, logger *slog.Logger) *Backend {
	return NewBackend(BackendConfig{
		DomainProvider: provider,
		AuthRouter:     domain.NewAuthRouter(provider, nil),
		Logger:         logger,
	})
}

func TestSession_Rcpt_DomainValidation(t *testing.T) {
	logger := slog.Default()

	t.Run("unknown domain rejected with 550", func(t *testing.T) {
		provider := &mockDomainProvider{
			domains: map[string]*domain.Domain{
				"example.com": {
					Name:      "example.com",
					AuthAgent: &mockAuthAgent{users: map[string]bool{"user": true}},
				},
			},
		}

		session := &Session{
			backend: newTestBackend(provider, logger),
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
					AuthAgent: &mockAuthAgent{users: map[string]bool{"validuser": true}},
				},
			},
		}

		session := &Session{
			backend: newTestBackend(provider, logger),
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
					Name:          "example.com",
					AuthAgent:     &mockAuthAgent{users: map[string]bool{"validuser": true}},
					DeliveryAgent: &mockDeliveryAgent{},
				},
			},
		}

		session := &Session{
			backend: newTestBackend(provider, logger),
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
					Name:          "example.com",
					AuthAgent:     &mockAuthAgent{users: map[string]bool{"user1": true, "user2": true}},
					DeliveryAgent: &mockDeliveryAgent{},
				},
			},
		}

		session := &Session{
			backend: newTestBackend(provider, logger),
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

		session := &Session{
			backend: newTestBackend(provider, logger),
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

func TestSession_Mail_SenderVerification(t *testing.T) {
	logger := slog.Default()

	t.Run("unauthenticated allows any sender", func(t *testing.T) {
		session := &Session{
			backend: &Backend{},
			logger:  logger,
		}
		err := session.Mail("anyone@anywhere.com", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("authenticated allows exact match", func(t *testing.T) {
		session := &Session{
			backend:  &Backend{},
			authUser: "matthew@example.com",
			logger:   logger,
		}
		err := session.Mail("matthew@example.com", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("authenticated rejects different local part same domain", func(t *testing.T) {
		session := &Session{
			backend:  &Backend{},
			authUser: "matthew@example.com",
			logger:   logger,
		}
		err := session.Mail("noreply@example.com", nil)
		if err == nil {
			t.Fatal("expected error for different local part")
		}
		smtpErr, ok := err.(*gosmtp.SMTPError)
		if !ok {
			t.Fatalf("expected SMTPError, got %T", err)
		}
		if smtpErr.Code != 553 {
			t.Errorf("expected code 553, got %d", smtpErr.Code)
		}
	})

	t.Run("authenticated rejects different domain", func(t *testing.T) {
		session := &Session{
			backend:  &Backend{},
			authUser: "matthew@example.com",
			logger:   logger,
		}
		err := session.Mail("matthew@otherdomain.com", nil)
		if err == nil {
			t.Fatal("expected error for mismatched domain")
		}
		smtpErr, ok := err.(*gosmtp.SMTPError)
		if !ok {
			t.Fatalf("expected SMTPError, got %T", err)
		}
		if smtpErr.Code != 553 {
			t.Errorf("expected code 553, got %d", smtpErr.Code)
		}
	})

	t.Run("authenticated allows bounce (empty sender)", func(t *testing.T) {
		session := &Session{
			backend:  &Backend{},
			authUser: "matthew@example.com",
			logger:   logger,
		}
		err := session.Mail("", nil)
		if err != nil {
			t.Fatalf("unexpected error for bounce: %v", err)
		}
	})

	t.Run("case insensitive match", func(t *testing.T) {
		session := &Session{
			backend:  &Backend{},
			authUser: "Matthew@Example.COM",
			logger:   logger,
		}
		err := session.Mail("matthew@example.com", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("angle brackets stripped for comparison", func(t *testing.T) {
		session := &Session{
			backend:  &Backend{},
			authUser: "matthew@example.com",
			logger:   logger,
		}
		err := session.Mail("<matthew@example.com>", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestSession_Mail_SenderRateLimit(t *testing.T) {
	logger := slog.Default()

	t.Run("rate limit enforced for authenticated sender", func(t *testing.T) {
		limiter := newMemRateLimiter()
		backend := &Backend{senderRateLimiter: limiter, maxSendsPerHour: 3}
		session := &Session{
			backend:  backend,
			authUser: "alice@example.com",
			logger:   logger,
		}

		// First 3 should succeed
		for i := 0; i < 3; i++ {
			err := session.Mail("alice@example.com", nil)
			if err != nil {
				t.Fatalf("message %d: unexpected error: %v", i+1, err)
			}
			session.Reset()
		}

		// 4th should be rate limited
		err := session.Mail("alice@example.com", nil)
		if err == nil {
			t.Fatal("expected rate limit error")
		}
		smtpErr, ok := err.(*gosmtp.SMTPError)
		if !ok {
			t.Fatalf("expected SMTPError, got %T", err)
		}
		if smtpErr.Code != 452 {
			t.Errorf("expected code 452, got %d", smtpErr.Code)
		}
	})

	t.Run("no rate limit for unauthenticated", func(t *testing.T) {
		limiter := newMemRateLimiter()
		backend := &Backend{senderRateLimiter: limiter, maxSendsPerHour: 1}
		session := &Session{
			backend: backend,
			logger:  logger,
		}

		// Should succeed without limit since not authenticated
		for i := 0; i < 5; i++ {
			err := session.Mail("anyone@anywhere.com", nil)
			if err != nil {
				t.Fatalf("message %d: unexpected error: %v", i+1, err)
			}
			session.Reset()
		}
	})

	t.Run("no rate limit when limiter not configured", func(t *testing.T) {
		backend := &Backend{}
		session := &Session{
			backend:  backend,
			authUser: "alice@example.com",
			logger:   logger,
		}

		for i := 0; i < 5; i++ {
			err := session.Mail("alice@example.com", nil)
			if err != nil {
				t.Fatalf("message %d: unexpected error: %v", i+1, err)
			}
			session.Reset()
		}
	})

	t.Run("separate limits per sender", func(t *testing.T) {
		limiter := newMemRateLimiter()
		backend := &Backend{senderRateLimiter: limiter, maxSendsPerHour: 2}

		alice := &Session{backend: backend, authUser: "alice@example.com", logger: logger}
		bob := &Session{backend: backend, authUser: "bob@example.com", logger: logger}

		// Alice sends 2
		for i := 0; i < 2; i++ {
			if err := alice.Mail("alice@example.com", nil); err != nil {
				t.Fatalf("alice message %d: %v", i+1, err)
			}
			alice.Reset()
		}

		// Alice is now limited
		if err := alice.Mail("alice@example.com", nil); err == nil {
			t.Fatal("expected alice to be rate limited")
		}

		// Bob should still be fine
		if err := bob.Mail("bob@example.com", nil); err != nil {
			t.Fatalf("bob should not be rate limited: %v", err)
		}
	})

	t.Run("per-domain limit overrides global", func(t *testing.T) {
		limiter := newMemRateLimiter()
		provider := &mockDomainProvider{
			domains: map[string]*domain.Domain{
				"example.com": {
					Name:   "example.com",
					Limits: domain.LimitsConfig{MaxSendsPerHour: 2},
				},
			},
		}
		backend := &Backend{
			senderRateLimiter: limiter,
			maxSendsPerHour:   100, // global allows 100
			domainProvider:    provider,
		}
		session := &Session{
			backend:  backend,
			authUser: "alice@example.com",
			logger:   logger,
		}

		// Per-domain limit is 2, so first 2 succeed
		for i := 0; i < 2; i++ {
			err := session.Mail("alice@example.com", nil)
			if err != nil {
				t.Fatalf("message %d: unexpected error: %v", i+1, err)
			}
			session.Reset()
		}

		// 3rd should be rate limited (per-domain limit of 2)
		err := session.Mail("alice@example.com", nil)
		if err == nil {
			t.Fatal("expected rate limit error from per-domain limit")
		}
		smtpErr, ok := err.(*gosmtp.SMTPError)
		if !ok {
			t.Fatalf("expected SMTPError, got %T", err)
		}
		if smtpErr.Code != 452 {
			t.Errorf("expected code 452, got %d", smtpErr.Code)
		}
	})

	t.Run("no limit when maxSendsPerHour is zero", func(t *testing.T) {
		limiter := newMemRateLimiter()
		backend := &Backend{senderRateLimiter: limiter, maxSendsPerHour: 0}
		session := &Session{
			backend:  backend,
			authUser: "alice@example.com",
			logger:   logger,
		}

		// Should succeed without limit since maxSendsPerHour is 0
		for i := 0; i < 10; i++ {
			err := session.Mail("alice@example.com", nil)
			if err != nil {
				t.Fatalf("message %d: unexpected error: %v", i+1, err)
			}
			session.Reset()
		}
	})
}

func TestSession_CheckFromAlignment(t *testing.T) {
	logger := slog.Default()

	makeMsg := func(from string) string {
		return "From: " + from + "\r\nTo: bob@remote.com\r\nSubject: test\r\n\r\nBody\r\n"
	}

	t.Run("aligned domains pass", func(t *testing.T) {
		session := &Session{
			backend:  &Backend{},
			authUser: "alice@example.com",
			from:     "alice@example.com",
			logger:   logger,
		}
		err := session.checkFromAlignment(strings.NewReader(makeMsg("alice@example.com")))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("different local part same domain rejected", func(t *testing.T) {
		session := &Session{
			backend:  &Backend{},
			authUser: "alice@example.com",
			from:     "alice@example.com",
			logger:   logger,
		}
		err := session.checkFromAlignment(strings.NewReader(makeMsg("noreply@example.com")))
		if err == nil {
			t.Fatal("expected error for different local part")
		}
		smtpErr, ok := err.(*gosmtp.SMTPError)
		if !ok {
			t.Fatalf("expected SMTPError, got %T", err)
		}
		if smtpErr.Code != 550 {
			t.Errorf("expected code 550, got %d", smtpErr.Code)
		}
	})

	t.Run("mismatched domain rejected", func(t *testing.T) {
		session := &Session{
			backend:  &Backend{},
			authUser: "alice@example.com",
			from:     "alice@example.com",
			logger:   logger,
		}
		err := session.checkFromAlignment(strings.NewReader(makeMsg("alice@evil.com")))
		if err == nil {
			t.Fatal("expected error for mismatched domain")
		}
		smtpErr, ok := err.(*gosmtp.SMTPError)
		if !ok {
			t.Fatalf("expected SMTPError, got %T", err)
		}
		if smtpErr.Code != 550 {
			t.Errorf("expected code 550, got %d", smtpErr.Code)
		}
	})

	t.Run("missing From header rejected", func(t *testing.T) {
		session := &Session{
			backend:  &Backend{},
			authUser: "alice@example.com",
			from:     "alice@example.com",
			logger:   logger,
		}
		msg := "To: bob@remote.com\r\nSubject: test\r\n\r\nBody\r\n"
		err := session.checkFromAlignment(strings.NewReader(msg))
		if err == nil {
			t.Fatal("expected error for missing From header")
		}
		smtpErr, ok := err.(*gosmtp.SMTPError)
		if !ok {
			t.Fatalf("expected SMTPError, got %T", err)
		}
		if smtpErr.Code != 550 {
			t.Errorf("expected code 550, got %d", smtpErr.Code)
		}
	})

	t.Run("multiple From addresses rejected", func(t *testing.T) {
		session := &Session{
			backend:  &Backend{},
			authUser: "alice@example.com",
			from:     "alice@example.com",
			logger:   logger,
		}
		msg := "From: alice@example.com, bob@example.com\r\nTo: ext@remote.com\r\nSubject: test\r\n\r\nBody\r\n"
		err := session.checkFromAlignment(strings.NewReader(msg))
		if err == nil {
			t.Fatal("expected error for multiple From addresses")
		}
		smtpErr, ok := err.(*gosmtp.SMTPError)
		if !ok {
			t.Fatalf("expected SMTPError, got %T", err)
		}
		if smtpErr.Code != 550 {
			t.Errorf("expected code 550, got %d", smtpErr.Code)
		}
	})

	t.Run("case insensitive domain match", func(t *testing.T) {
		session := &Session{
			backend:  &Backend{},
			authUser: "alice@Example.COM",
			from:     "alice@Example.COM",
			logger:   logger,
		}
		err := session.checkFromAlignment(strings.NewReader(makeMsg("alice@example.com")))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("display name in From header handled", func(t *testing.T) {
		session := &Session{
			backend:  &Backend{},
			authUser: "alice@example.com",
			from:     "alice@example.com",
			logger:   logger,
		}
		msg := "From: Alice Smith <alice@example.com>\r\nTo: bob@remote.com\r\nSubject: test\r\n\r\nBody\r\n"
		err := session.checkFromAlignment(strings.NewReader(msg))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
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
