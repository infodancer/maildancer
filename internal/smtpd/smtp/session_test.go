package smtp

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"testing"

	gosmtp "github.com/emersion/go-smtp"
	smpb "github.com/infodancer/maildancer/internal/session-manager/proto/sessionmanager/v1"
	"github.com/infodancer/maildancer/internal/smtpd/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

// mockSessionService implements the session-manager SessionService for tests.
type mockSessionService struct {
	smpb.UnimplementedSessionServiceServer

	loginResult    *smpb.LoginResponse
	loginErr       error
	validateResult *smpb.ValidateRecipientResponse
	validateErr    error
}

func (m *mockSessionService) Login(_ context.Context, req *smpb.LoginRequest) (*smpb.LoginResponse, error) {
	if m.loginErr != nil {
		return nil, m.loginErr
	}
	return m.loginResult, nil
}

func (m *mockSessionService) ValidateRecipient(_ context.Context, req *smpb.ValidateRecipientRequest) (*smpb.ValidateRecipientResponse, error) {
	if m.validateErr != nil {
		return nil, m.validateErr
	}
	return m.validateResult, nil
}

// startMockSessionServer starts a gRPC server with a mock SessionService on a
// temp unix socket and returns a SessionManagerDeliveryAgent connected to it.
func startMockSessionServer(t *testing.T, mock *mockSessionService) *SessionManagerDeliveryAgent {
	t.Helper()

	socketPath := t.TempDir() + "/session.sock"
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	gsrv := grpc.NewServer()
	smpb.RegisterSessionServiceServer(gsrv, mock)
	go func() { _ = gsrv.Serve(ln) }()
	t.Cleanup(func() { gsrv.Stop() })

	agent, err := NewSessionManagerDeliveryAgent(config.SessionManagerConfig{
		Socket: socketPath,
	}, nil)
	if err != nil {
		t.Fatalf("new agent: %v", err)
	}
	t.Cleanup(func() { _ = agent.Close() })

	return agent
}

func TestSession_Rcpt_DomainValidation(t *testing.T) {
	logger := slog.Default()

	t.Run("unknown domain rejected with 550 for unauthenticated", func(t *testing.T) {
		agent := startMockSessionServer(t, &mockSessionService{
			validateResult: &smpb.ValidateRecipientResponse{
				DomainIsLocal: false,
				UserExists:    false,
			},
		})
		backend := &Backend{smDelivery: agent, logger: logger}

		session := &Session{backend: backend, logger: logger}
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
		agent := startMockSessionServer(t, &mockSessionService{
			validateResult: &smpb.ValidateRecipientResponse{
				DomainIsLocal:  true,
				UserExists:     false,
				DeferRejection: false,
			},
		})
		backend := &Backend{smDelivery: agent, logger: logger}

		session := &Session{backend: backend, logger: logger}
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
		agent := startMockSessionServer(t, &mockSessionService{
			validateResult: &smpb.ValidateRecipientResponse{
				DomainIsLocal: true,
				UserExists:    true,
			},
		})
		backend := &Backend{smDelivery: agent, logger: logger}

		session := &Session{backend: backend, logger: logger}
		err := session.Rcpt("validuser@example.com", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(session.recipients) != 1 {
			t.Errorf("expected 1 recipient, got %d", len(session.recipients))
		}
	})

	t.Run("multiple RCPT TO rejected with 452", func(t *testing.T) {
		agent := startMockSessionServer(t, &mockSessionService{
			validateResult: &smpb.ValidateRecipientResponse{
				DomainIsLocal: true,
				UserExists:    true,
			},
		})
		backend := &Backend{smDelivery: agent, logger: logger}

		session := &Session{backend: backend, logger: logger}

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

	t.Run("validate failure returns 451", func(t *testing.T) {
		agent := startMockSessionServer(t, &mockSessionService{
			validateErr: status.Error(codes.Internal, "database error"),
		})
		backend := &Backend{smDelivery: agent, logger: logger}

		session := &Session{backend: backend, logger: logger}
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
		session := &Session{backend: &Backend{}, logger: logger}
		err := session.Mail("anyone@anywhere.com", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("authenticated allows exact match", func(t *testing.T) {
		session := &Session{backend: &Backend{}, authUser: "matthew@example.com", logger: logger}
		err := session.Mail("matthew@example.com", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("authenticated rejects different local part same domain", func(t *testing.T) {
		session := &Session{backend: &Backend{}, authUser: "matthew@example.com", logger: logger}
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
		session := &Session{backend: &Backend{}, authUser: "matthew@example.com", logger: logger}
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
		session := &Session{backend: &Backend{}, authUser: "matthew@example.com", logger: logger}
		err := session.Mail("", nil)
		if err != nil {
			t.Fatalf("unexpected error for bounce: %v", err)
		}
	})

	t.Run("case insensitive match", func(t *testing.T) {
		session := &Session{backend: &Backend{}, authUser: "Matthew@Example.COM", logger: logger}
		err := session.Mail("matthew@example.com", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("angle brackets stripped for comparison", func(t *testing.T) {
		session := &Session{backend: &Backend{}, authUser: "matthew@example.com", logger: logger}
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
		session := &Session{backend: backend, authUser: "alice@example.com", logger: logger}

		for i := 0; i < 3; i++ {
			if err := session.Mail("alice@example.com", nil); err != nil {
				t.Fatalf("message %d: unexpected error: %v", i+1, err)
			}
			session.Reset()
		}

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
		session := &Session{backend: backend, logger: logger}

		for i := 0; i < 5; i++ {
			if err := session.Mail("anyone@anywhere.com", nil); err != nil {
				t.Fatalf("message %d: unexpected error: %v", i+1, err)
			}
			session.Reset()
		}
	})

	t.Run("no rate limit when limiter not configured", func(t *testing.T) {
		backend := &Backend{}
		session := &Session{backend: backend, authUser: "alice@example.com", logger: logger}

		for i := 0; i < 5; i++ {
			if err := session.Mail("alice@example.com", nil); err != nil {
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

		for i := 0; i < 2; i++ {
			if err := alice.Mail("alice@example.com", nil); err != nil {
				t.Fatalf("alice message %d: %v", i+1, err)
			}
			alice.Reset()
		}

		if err := alice.Mail("alice@example.com", nil); err == nil {
			t.Fatal("expected alice to be rate limited")
		}

		if err := bob.Mail("bob@example.com", nil); err != nil {
			t.Fatalf("bob should not be rate limited: %v", err)
		}
	})

	t.Run("per-session limit overrides global", func(t *testing.T) {
		limiter := newMemRateLimiter()
		backend := &Backend{senderRateLimiter: limiter, maxSendsPerHour: 100}
		session := &Session{
			backend:  backend,
			authUser: "alice@example.com",
			loginResult: &LoginResult{
				Mailbox:         "alice@example.com",
				MaxSendsPerHour: 2,
			},
			logger: logger,
		}

		for i := 0; i < 2; i++ {
			if err := session.Mail("alice@example.com", nil); err != nil {
				t.Fatalf("message %d: unexpected error: %v", i+1, err)
			}
			session.Reset()
		}

		err := session.Mail("alice@example.com", nil)
		if err == nil {
			t.Fatal("expected rate limit error from per-session limit")
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
		session := &Session{backend: backend, authUser: "alice@example.com", logger: logger}

		for i := 0; i < 10; i++ {
			if err := session.Mail("alice@example.com", nil); err != nil {
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
		session := &Session{backend: &Backend{}, authUser: "alice@example.com", from: "alice@example.com", logger: logger}
		err := session.checkFromAlignment(strings.NewReader(makeMsg("alice@example.com")))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("different local part same domain rejected", func(t *testing.T) {
		session := &Session{backend: &Backend{}, authUser: "alice@example.com", from: "alice@example.com", logger: logger}
		err := session.checkFromAlignment(strings.NewReader(makeMsg("noreply@example.com")))
		if err == nil {
			t.Fatal("expected error for different local part")
		}
		smtpErr := err.(*gosmtp.SMTPError)
		if smtpErr.Code != 550 {
			t.Errorf("expected code 550, got %d", smtpErr.Code)
		}
	})

	t.Run("mismatched domain rejected", func(t *testing.T) {
		session := &Session{backend: &Backend{}, authUser: "alice@example.com", from: "alice@example.com", logger: logger}
		err := session.checkFromAlignment(strings.NewReader(makeMsg("alice@evil.com")))
		if err == nil {
			t.Fatal("expected error for mismatched domain")
		}
		smtpErr := err.(*gosmtp.SMTPError)
		if smtpErr.Code != 550 {
			t.Errorf("expected code 550, got %d", smtpErr.Code)
		}
	})

	t.Run("missing From header rejected", func(t *testing.T) {
		session := &Session{backend: &Backend{}, authUser: "alice@example.com", from: "alice@example.com", logger: logger}
		msg := "To: bob@remote.com\r\nSubject: test\r\n\r\nBody\r\n"
		err := session.checkFromAlignment(strings.NewReader(msg))
		if err == nil {
			t.Fatal("expected error for missing From header")
		}
		smtpErr := err.(*gosmtp.SMTPError)
		if smtpErr.Code != 550 {
			t.Errorf("expected code 550, got %d", smtpErr.Code)
		}
	})

	t.Run("multiple From addresses rejected", func(t *testing.T) {
		session := &Session{backend: &Backend{}, authUser: "alice@example.com", from: "alice@example.com", logger: logger}
		msg := "From: alice@example.com, bob@example.com\r\nTo: ext@remote.com\r\nSubject: test\r\n\r\nBody\r\n"
		err := session.checkFromAlignment(strings.NewReader(msg))
		if err == nil {
			t.Fatal("expected error for multiple From addresses")
		}
		smtpErr := err.(*gosmtp.SMTPError)
		if smtpErr.Code != 550 {
			t.Errorf("expected code 550, got %d", smtpErr.Code)
		}
	})

	t.Run("case insensitive domain match", func(t *testing.T) {
		session := &Session{backend: &Backend{}, authUser: "alice@Example.COM", from: "alice@Example.COM", logger: logger}
		err := session.checkFromAlignment(strings.NewReader(makeMsg("alice@example.com")))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("display name in From header handled", func(t *testing.T) {
		session := &Session{backend: &Backend{}, authUser: "alice@example.com", from: "alice@example.com", logger: logger}
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
