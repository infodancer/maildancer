package pop3

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"testing"

	"github.com/infodancer/maildancer/auth"
	"github.com/infodancer/maildancer/auth/domain"
	"github.com/infodancer/maildancer/internal/pop3d/config"
)

// mockDomainAuth implements DomainAuthenticator for testing.
type mockDomainAuth struct {
	authenticateFn func(ctx context.Context, username, password string) (*domain.AuthResult, error)
}

func (m *mockDomainAuth) AuthenticateWithDomain(ctx context.Context, username, password string) (*domain.AuthResult, error) {
	if m.authenticateFn != nil {
		return m.authenticateFn(ctx, username, password)
	}
	return nil, errors.New("not implemented")
}

// newSimpleAuth creates a mockDomainAuth that authenticates without domain routing.
// This is the common case for tests that don't care about domain-specific behavior.
func newSimpleAuth(fn func(ctx context.Context, username, password string) (*auth.AuthSession, error)) *mockDomainAuth {
	return &mockDomainAuth{
		authenticateFn: func(ctx context.Context, username, password string) (*domain.AuthResult, error) {
			if fn == nil {
				return nil, errors.New("not implemented")
			}
			session, err := fn(ctx, username, password)
			if err != nil {
				return nil, err
			}
			return &domain.AuthResult{Session: session}, nil
		},
	}
}

// mockConnection is a minimal mock for testing commands that need a logger.
type mockConnection struct {
	logger *slog.Logger
}

func (m *mockConnection) Logger() *slog.Logger {
	if m.logger == nil {
		// Return a no-op logger for tests
		return slog.New(slog.NewTextHandler(nil, &slog.HandlerOptions{Level: slog.LevelError + 1}))
	}
	return m.logger
}

func newMockConnection() *mockConnection {
	return &mockConnection{}
}

// Test helper to create a session for testing.
// A non-nil sentinel TLS config is used so that insecureAuth stays false —
// the tests verify that missing TLS *activity* rejects auth, not that TLS
// is unconfigured.
func newTestSession(mode config.ListenerMode, isTLS bool) *Session {
	return NewSession("test.example.com", mode, &tls.Config{}, isTLS) //nolint:gosec
}

func TestCapaCommand(t *testing.T) {
	tests := []struct {
		name         string
		sess         *Session
		args         []string
		wantOK       bool
		wantMessage  string
		wantCapCount int
	}{
		{
			name:         "CAPA with no TLS shows limited capabilities",
			sess:         NewSession("test.example.com", config.ModePop3, nil, false), // nil TLS = no STLS/USER
			args:         []string{},
			wantOK:       true,
			wantMessage:  "Capability list follows",
			wantCapCount: 3, // TOP, UIDL, RESP-CODES (no USER, no STLS without TLS config)
		},
		{
			name:         "CAPA with TLS shows USER and SASL",
			sess:         newTestSession(config.ModePop3s, true),
			args:         []string{},
			wantOK:       true,
			wantMessage:  "Capability list follows",
			wantCapCount: 5, // USER, TOP, UIDL, RESP-CODES, SASL PLAIN
		},
		{
			name:        "CAPA with arguments fails",
			sess:        newTestSession(config.ModePop3, false),
			args:        []string{"invalid"},
			wantOK:      false,
			wantMessage: "CAPA command takes no arguments",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &capaCommand{}
			resp, err := cmd.Execute(context.Background(), tt.sess, nil, tt.args)

			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}

			if resp.OK != tt.wantOK {
				t.Errorf("Execute() OK = %v, want %v", resp.OK, tt.wantOK)
			}

			if resp.Message != tt.wantMessage {
				t.Errorf("Execute() Message = %v, want %v", resp.Message, tt.wantMessage)
			}

			if tt.wantOK && len(resp.Lines) != tt.wantCapCount {
				t.Errorf("Execute() capability count = %v, want %v (caps: %v)", len(resp.Lines), tt.wantCapCount, resp.Lines)
			}
		})
	}
}

func TestStlsCommand(t *testing.T) {
	tests := []struct {
		name        string
		sess        *Session
		args        []string
		wantOK      bool
		wantMessage string
	}{
		{
			name:        "STLS before TLS succeeds",
			sess:        NewSession("test.example.com", config.ModePop3, nil, false), // nil TLS = STLS not available
			args:        []string{},
			wantOK:      false,
			wantMessage: "TLS not available",
		},
		{
			name:        "STLS with TLS already active fails",
			sess:        newTestSession(config.ModePop3s, true),
			args:        []string{},
			wantOK:      false,
			wantMessage: "Already using TLS",
		},
		{
			name:        "STLS with arguments fails",
			sess:        newTestSession(config.ModePop3, false),
			args:        []string{"invalid"},
			wantOK:      false,
			wantMessage: "STLS command takes no arguments",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &stlsCommand{}
			resp, err := cmd.Execute(context.Background(), tt.sess, nil, tt.args)

			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}

			if resp.OK != tt.wantOK {
				t.Errorf("Execute() OK = %v, want %v", resp.OK, tt.wantOK)
			}

			if resp.Message != tt.wantMessage {
				t.Errorf("Execute() Message = %v, want %v", resp.Message, tt.wantMessage)
			}
		})
	}
}

func TestUserCommand(t *testing.T) {
	tests := []struct {
		name        string
		sess        *Session
		args        []string
		wantOK      bool
		wantMessage string
	}{
		{
			name:        "USER without TLS fails",
			sess:        newTestSession(config.ModePop3, false),
			args:        []string{"testuser"},
			wantOK:      false,
			wantMessage: "TLS required for authentication",
		},
		{
			name:        "USER with TLS succeeds",
			sess:        newTestSession(config.ModePop3s, true),
			args:        []string{"testuser"},
			wantOK:      true,
			wantMessage: "User testuser accepted",
		},
		{
			name:        "USER without arguments fails",
			sess:        newTestSession(config.ModePop3s, true),
			args:        []string{},
			wantOK:      false,
			wantMessage: "USER command requires username argument",
		},
		{
			name:        "USER with too many arguments fails",
			sess:        newTestSession(config.ModePop3s, true),
			args:        []string{"user1", "user2"},
			wantOK:      false,
			wantMessage: "USER command requires username argument",
		},
		{
			name:        "USER with empty username fails",
			sess:        newTestSession(config.ModePop3s, true),
			args:        []string{""},
			wantOK:      false,
			wantMessage: "Username cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &userCommand{}
			resp, err := cmd.Execute(context.Background(), tt.sess, nil, tt.args)

			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}

			if resp.OK != tt.wantOK {
				t.Errorf("Execute() OK = %v, want %v", resp.OK, tt.wantOK)
			}

			if resp.Message != tt.wantMessage {
				t.Errorf("Execute() Message = %v, want %v", resp.Message, tt.wantMessage)
			}

			if tt.wantOK && tt.sess.Username() != tt.args[0] {
				t.Errorf("Session username = %v, want %v", tt.sess.Username(), tt.args[0])
			}
		})
	}
}

func TestPassCommand(t *testing.T) {
	tests := []struct {
		name         string
		sess         *Session
		setupSession func(*Session)
		args         []string
		authFn       func(ctx context.Context, username, password string) (*auth.AuthSession, error)
		wantOK       bool
		wantMessage  string
		wantState    State
	}{
		{
			name: "PASS without TLS fails",
			sess: newTestSession(config.ModePop3, false),
			setupSession: func(s *Session) {
				s.SetUsername("testuser")
			},
			args:        []string{"password"},
			wantOK:      false,
			wantMessage: "TLS required for authentication",
			wantState:   StateAuthorization,
		},
		{
			name:        "PASS without prior USER fails",
			sess:        newTestSession(config.ModePop3s, true),
			args:        []string{"password"},
			wantOK:      false,
			wantMessage: "No username specified",
			wantState:   StateAuthorization,
		},
		{
			name: "PASS with successful auth",
			sess: newTestSession(config.ModePop3s, true),
			setupSession: func(s *Session) {
				s.SetUsername("testuser")
			},
			args: []string{"correctpassword"},
			authFn: func(_ context.Context, username, password string) (*auth.AuthSession, error) {
				return &auth.AuthSession{
					User: &auth.User{
						Username: username,
						Mailbox:  "/var/mail/" + username,
					},
				}, nil
			},
			wantOK:      true,
			wantMessage: "Logged in as testuser",
			wantState:   StateTransaction,
		},
		{
			name: "PASS with failed auth",
			sess: newTestSession(config.ModePop3s, true),
			setupSession: func(s *Session) {
				s.SetUsername("testuser")
			},
			args: []string{"wrongpassword"},
			authFn: func(_ context.Context, username, password string) (*auth.AuthSession, error) {
				return nil, errors.New("invalid credentials")
			},
			wantOK:      false,
			wantMessage: "Authentication failed",
			wantState:   StateAuthorization,
		},
		{
			name: "PASS without arguments fails",
			sess: newTestSession(config.ModePop3s, true),
			setupSession: func(s *Session) {
				s.SetUsername("testuser")
			},
			args:        []string{},
			wantOK:      false,
			wantMessage: "PASS command requires password argument",
			wantState:   StateAuthorization,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupSession != nil {
				tt.setupSession(tt.sess)
			}

			cmd := &passCommand{auth: newSimpleAuth(tt.authFn)}

			conn := newMockConnection()
			resp, err := cmd.Execute(context.Background(), tt.sess, conn, tt.args)

			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}

			if resp.OK != tt.wantOK {
				t.Errorf("Execute() OK = %v, want %v", resp.OK, tt.wantOK)
			}

			if resp.Message != tt.wantMessage {
				t.Errorf("Execute() Message = %v, want %v", resp.Message, tt.wantMessage)
			}

			if tt.sess.State() != tt.wantState {
				t.Errorf("Session state = %v, want %v", tt.sess.State(), tt.wantState)
			}
		})
	}
}

func TestQuitCommand(t *testing.T) {
	tests := []struct {
		name         string
		sess         *Session
		setupSession func(*Session)
		args         []string
		wantOK       bool
		wantMessage  string
		wantState    State
	}{
		{
			name:        "QUIT in AUTHORIZATION",
			sess:        newTestSession(config.ModePop3s, true),
			args:        []string{},
			wantOK:      true,
			wantMessage: "Goodbye",
			wantState:   StateAuthorization,
		},
		{
			name: "QUIT in TRANSACTION",
			sess: newTestSession(config.ModePop3s, true),
			setupSession: func(s *Session) {
				s.SetAuthenticated(&auth.AuthSession{
					User: &auth.User{Username: "test"},
				})
			},
			args:        []string{},
			wantOK:      true,
			wantMessage: "Logging out",
			wantState:   StateUpdate,
		},
		{
			name:        "QUIT with arguments fails",
			sess:        newTestSession(config.ModePop3s, true),
			args:        []string{"invalid"},
			wantOK:      false,
			wantMessage: "QUIT command takes no arguments",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupSession != nil {
				tt.setupSession(tt.sess)
			}

			cmd := &quitCommand{}
			resp, err := cmd.Execute(context.Background(), tt.sess, nil, tt.args)

			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}

			if resp.OK != tt.wantOK {
				t.Errorf("Execute() OK = %v, want %v", resp.OK, tt.wantOK)
			}

			if resp.Message != tt.wantMessage {
				t.Errorf("Execute() Message = %v, want %v", resp.Message, tt.wantMessage)
			}

			if tt.wantOK && len(tt.args) == 0 {
				if tt.sess.State() != tt.wantState {
					t.Errorf("Session state = %v, want %v", tt.sess.State(), tt.wantState)
				}
			}
		})
	}
}

func TestCommandRegistry(t *testing.T) {
	// Clear the registry first
	commandRegistry = make(map[string]Command)

	// Register test commands
	mockAuth := newSimpleAuth(nil)
	RegisterAuthCommands(mockAuth, nil, nil)

	tests := []struct {
		name      string
		cmdName   string
		wantFound bool
	}{
		{"CAPA exists", "CAPA", true},
		{"capa exists (case insensitive)", "capa", true},
		{"USER exists", "USER", true},
		{"PASS exists", "PASS", true},
		{"AUTH exists", "AUTH", true},
		{"auth exists (case insensitive)", "auth", true},
		{"QUIT exists", "QUIT", true},
		{"STLS exists", "STLS", true},
		{"INVALID does not exist", "INVALID", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, found := GetCommand(tt.cmdName)

			if found != tt.wantFound {
				t.Errorf("GetCommand(%q) found = %v, want %v", tt.cmdName, found, tt.wantFound)
			}

			if tt.wantFound && cmd == nil {
				t.Errorf("GetCommand(%q) returned nil command", tt.cmdName)
			}
		})
	}
}

func TestAuthCommand(t *testing.T) {
	tests := []struct {
		name             string
		sess             *Session
		args             []string
		authFn           func(ctx context.Context, username, password string) (*auth.AuthSession, error)
		wantOK           bool
		wantContinuation bool
		wantMessage      string
		wantState        State
	}{
		{
			name:        "AUTH without TLS fails",
			sess:        newTestSession(config.ModePop3, false),
			args:        []string{"PLAIN"},
			wantOK:      false,
			wantMessage: "TLS required for authentication",
			wantState:   StateAuthorization,
		},
		{
			name:        "AUTH without mechanism fails",
			sess:        newTestSession(config.ModePop3s, true),
			args:        []string{},
			wantOK:      false,
			wantMessage: "AUTH command requires mechanism argument",
			wantState:   StateAuthorization,
		},
		{
			name:        "AUTH with unsupported mechanism fails",
			sess:        newTestSession(config.ModePop3s, true),
			args:        []string{"CRAM-MD5"},
			wantOK:      false,
			wantMessage: "Unsupported mechanism: CRAM-MD5",
			wantState:   StateAuthorization,
		},
		{
			name:             "AUTH PLAIN without initial response sends challenge",
			sess:             newTestSession(config.ModePop3s, true),
			args:             []string{"PLAIN"},
			wantContinuation: true,
			wantState:        StateAuthorization,
		},
		{
			name: "AUTH PLAIN with valid initial response succeeds",
			sess: newTestSession(config.ModePop3s, true),
			// Base64 of "\x00alice\x00secret"
			args: []string{"PLAIN", "AGFsaWNlAHNlY3JldA=="},
			authFn: func(_ context.Context, username, password string) (*auth.AuthSession, error) {
				if username == "alice" && password == "secret" {
					return &auth.AuthSession{
						User: &auth.User{
							Username: username,
							Mailbox:  "/var/mail/" + username,
						},
					}, nil
				}
				return nil, errors.New("invalid credentials")
			},
			wantOK:      true,
			wantMessage: "Logged in as alice",
			wantState:   StateTransaction,
		},
		{
			name: "AUTH PLAIN with invalid credentials fails",
			sess: newTestSession(config.ModePop3s, true),
			// Base64 of "\x00alice\x00wrongpassword"
			args: []string{"PLAIN", "AGFsaWNlAHdyb25ncGFzc3dvcmQ="},
			authFn: func(_ context.Context, username, password string) (*auth.AuthSession, error) {
				return nil, errors.New("invalid credentials")
			},
			wantOK:      false,
			wantMessage: "Authentication failed",
			wantState:   StateAuthorization,
		},
		{
			name:        "AUTH PLAIN with invalid base64 fails",
			sess:        newTestSession(config.ModePop3s, true),
			args:        []string{"PLAIN", "not-valid-base64!!!"},
			wantOK:      false,
			wantMessage: "Invalid base64 encoding",
			wantState:   StateAuthorization,
		},
		{
			name: "AUTH PLAIN with empty initial response (=) sends challenge",
			sess: newTestSession(config.ModePop3s, true),
			args: []string{"PLAIN", "="},
			authFn: func(_ context.Context, username, password string) (*auth.AuthSession, error) {
				// Empty response is not valid PLAIN credentials
				return nil, errors.New("invalid credentials")
			},
			wantOK:      false,
			wantMessage: "Authentication failed",
			wantState:   StateAuthorization,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &authCommand{auth: newSimpleAuth(tt.authFn)}

			conn := newMockConnection()
			resp, err := cmd.Execute(context.Background(), tt.sess, conn, tt.args)

			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}

			if resp.OK != tt.wantOK {
				t.Errorf("Execute() OK = %v, want %v", resp.OK, tt.wantOK)
			}

			if resp.Continuation != tt.wantContinuation {
				t.Errorf("Execute() Continuation = %v, want %v", resp.Continuation, tt.wantContinuation)
			}

			if !tt.wantContinuation && resp.Message != tt.wantMessage {
				t.Errorf("Execute() Message = %v, want %v", resp.Message, tt.wantMessage)
			}

			if tt.sess.State() != tt.wantState {
				t.Errorf("Session state = %v, want %v", tt.sess.State(), tt.wantState)
			}
		})
	}
}

func TestAuthCommandInTransaction(t *testing.T) {
	sess := newTestSession(config.ModePop3s, true)
	sess.SetAuthenticated(&auth.AuthSession{
		User: &auth.User{Username: "test"},
	})

	cmd := &authCommand{auth: newSimpleAuth(nil)}
	conn := newMockConnection()

	resp, err := cmd.Execute(context.Background(), sess, conn, []string{"PLAIN"})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	if resp.OK {
		t.Error("Execute() should fail in TRANSACTION state")
	}

	if resp.Message != "Command not valid in this state" {
		t.Errorf("Execute() Message = %v, want %v", resp.Message, "Command not valid in this state")
	}
}

func TestAuthSASLCancellation(t *testing.T) {
	sess := newTestSession(config.ModePop3s, true)

	cmd := &authCommand{auth: newSimpleAuth(nil)}
	conn := newMockConnection()

	// First, start AUTH to create SASL state
	resp, err := cmd.Execute(context.Background(), sess, conn, []string{"PLAIN"})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	if !resp.Continuation {
		t.Fatal("Expected continuation response")
	}

	if !sess.IsSASLInProgress() {
		t.Fatal("Expected SASL to be in progress")
	}

	// Now send cancellation
	resp, err = cmd.ProcessSASLResponse(context.Background(), sess, conn, "*")
	if err != nil {
		t.Fatalf("ProcessSASLResponse() error = %v", err)
	}

	if resp.OK {
		t.Error("Cancellation should return -ERR")
	}

	if resp.Message != "Authentication cancelled" {
		t.Errorf("Message = %v, want %v", resp.Message, "Authentication cancelled")
	}

	if sess.IsSASLInProgress() {
		t.Error("SASL should be cleared after cancellation")
	}
}

func TestAuthSASLMultiStep(t *testing.T) {
	sess := newTestSession(config.ModePop3s, true)
	mockAuth := newSimpleAuth(func(_ context.Context, username, password string) (*auth.AuthSession, error) {
		if username == "alice" && password == "secret" {
			return &auth.AuthSession{
				User: &auth.User{
					Username: username,
					Mailbox:  "/var/mail/" + username,
				},
			}, nil
		}
		return nil, errors.New("invalid credentials")
	})

	cmd := &authCommand{auth: mockAuth}
	conn := newMockConnection()

	// Start AUTH without initial response
	resp, err := cmd.Execute(context.Background(), sess, conn, []string{"PLAIN"})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	if !resp.Continuation {
		t.Fatal("Expected continuation response")
	}

	// Send credentials in second step
	// Base64 of "\x00alice\x00secret"
	resp, err = cmd.ProcessSASLResponse(context.Background(), sess, conn, "AGFsaWNlAHNlY3JldA==")
	if err != nil {
		t.Fatalf("ProcessSASLResponse() error = %v", err)
	}

	if !resp.OK {
		t.Errorf("Expected +OK, got -ERR: %s", resp.Message)
	}

	if sess.State() != StateTransaction {
		t.Errorf("Session state = %v, want TRANSACTION", sess.State())
	}

	if sess.Username() != "alice" {
		t.Errorf("Username = %v, want alice", sess.Username())
	}
}

func TestCapabilitiesIncludeSASL(t *testing.T) {
	// With TLS active, SASL should be advertised
	sess := newTestSession(config.ModePop3s, true)
	caps := sess.Capabilities()

	found := false
	for _, cap := range caps {
		if cap == "SASL PLAIN" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Capabilities() should include 'SASL PLAIN' when TLS is active, got: %v", caps)
	}
}

func TestCapabilitiesHideSASLWithoutTLS(t *testing.T) {
	// Without TLS, SASL should not be advertised
	sess := newTestSession(config.ModePop3, false)
	caps := sess.Capabilities()

	for _, cap := range caps {
		if cap == "SASL PLAIN" {
			t.Errorf("Capabilities() should not include 'SASL PLAIN' without TLS, got: %v", caps)
		}
	}
}

func TestResponseFormatting(t *testing.T) {
	tests := []struct {
		name     string
		resp     Response
		wantText string
	}{
		{
			name: "Simple OK response",
			resp: Response{
				OK:      true,
				Message: "Success",
			},
			wantText: "+OK Success\r\n",
		},
		{
			name: "Simple ERR response",
			resp: Response{
				OK:      false,
				Message: "Failed",
			},
			wantText: "-ERR Failed\r\n",
		},
		{
			name: "Multi-line response",
			resp: Response{
				OK:      true,
				Message: "Capabilities",
				Lines:   []string{"USER", "TOP", "UIDL"},
			},
			wantText: "+OK Capabilities\r\nUSER\r\nTOP\r\nUIDL\r\n.\r\n",
		},
		{
			name: "Response with dot-stuffing",
			resp: Response{
				OK:      true,
				Message: "Data",
				Lines:   []string{".hidden", "normal", "..double"},
			},
			wantText: "+OK Data\r\n..hidden\r\nnormal\r\n...double\r\n.\r\n",
		},
		{
			name: "SASL continuation response with challenge",
			resp: Response{
				Continuation: true,
				Challenge:    "SGVsbG8=",
			},
			wantText: "+ SGVsbG8=\r\n",
		},
		{
			name: "SASL continuation response with empty challenge",
			resp: Response{
				Continuation: true,
				Challenge:    "",
			},
			wantText: "+ \r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.resp.String()
			if got != tt.wantText {
				t.Errorf("Response.String() = %q, want %q", got, tt.wantText)
			}
		})
	}
}

func TestPassCommandDomainAuth(t *testing.T) {
	// Create a mock that routes domain auth via AuthResult.Domain
	domainAuth := &mockDomainAuth{
		authenticateFn: func(_ context.Context, username, password string) (*domain.AuthResult, error) {
			local, domainName := domain.SplitUsername(username)

			if domainName == "example.com" {
				if local == "alice" && password == "domainpass" {
					return &domain.AuthResult{
						Session: &auth.AuthSession{
							User: &auth.User{Username: local, Mailbox: local},
						},
						Domain: &domain.Domain{Name: "example.com"},
					}, nil
				}
				return nil, errors.New("invalid credentials")
			}

			// Simulate unknown domain falling through to global auth
			if username == "globaluser" && password == "globalpass" {
				return &domain.AuthResult{
					Session: &auth.AuthSession{
						User: &auth.User{Username: username, Mailbox: username},
					},
				}, nil
			}

			return nil, errors.New("invalid credentials")
		},
	}

	tests := []struct {
		name        string
		username    string
		password    string
		wantOK      bool
		wantMessage string
		wantState   State
	}{
		{
			name:        "domain user authenticates with local part",
			username:    "alice@example.com",
			password:    "domainpass",
			wantOK:      true,
			wantMessage: "Logged in as alice@example.com",
			wantState:   StateTransaction,
		},
		{
			name:        "domain user wrong password fails",
			username:    "alice@example.com",
			password:    "wrongpass",
			wantOK:      false,
			wantMessage: "Authentication failed",
			wantState:   StateAuthorization,
		},
		{
			name:        "unknown domain fails",
			username:    "alice@unknown.org",
			password:    "domainpass",
			wantOK:      false,
			wantMessage: "Authentication failed",
			wantState:   StateAuthorization,
		},
		{
			name:        "plain user falls back to global auth",
			username:    "globaluser",
			password:    "globalpass",
			wantOK:      true,
			wantMessage: "Logged in as globaluser",
			wantState:   StateTransaction,
		},
		{
			name:        "plain user wrong password fails via global auth",
			username:    "globaluser",
			password:    "wrongpass",
			wantOK:      false,
			wantMessage: "Authentication failed",
			wantState:   StateAuthorization,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sess := newTestSession(config.ModePop3s, true)
			sess.SetUsername(tt.username)

			cmd := &passCommand{auth: domainAuth}

			conn := newMockConnection()
			resp, err := cmd.Execute(context.Background(), sess, conn, []string{tt.password})

			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}

			if resp.OK != tt.wantOK {
				t.Errorf("Execute() OK = %v, want %v", resp.OK, tt.wantOK)
			}

			if resp.Message != tt.wantMessage {
				t.Errorf("Execute() Message = %v, want %v", resp.Message, tt.wantMessage)
			}

			if sess.State() != tt.wantState {
				t.Errorf("Session state = %v, want %v", sess.State(), tt.wantState)
			}
		})
	}
}

func TestPassCommandNoDomainAuthFallsThrough(t *testing.T) {
	// With no domain routing, user@domain goes to global auth as-is
	mockAuth := newSimpleAuth(func(_ context.Context, username, password string) (*auth.AuthSession, error) {
		if username == "alice@example.com" && password == "pass" {
			return &auth.AuthSession{
				User: &auth.User{Username: username, Mailbox: "alice"},
			}, nil
		}
		return nil, errors.New("invalid credentials")
	})

	sess := newTestSession(config.ModePop3s, true)
	sess.SetUsername("alice@example.com")

	cmd := &passCommand{auth: mockAuth}
	conn := newMockConnection()

	resp, err := cmd.Execute(context.Background(), sess, conn, []string{"pass"})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	if !resp.OK {
		t.Errorf("Execute() OK = false, want true (no domain routing should fall through to global auth)")
	}
}

func TestAuthCommandDomainAuth(t *testing.T) {
	domainAuth := &mockDomainAuth{
		authenticateFn: func(_ context.Context, username, password string) (*domain.AuthResult, error) {
			local, domainName := domain.SplitUsername(username)

			if domainName == "example.com" {
				if local == "alice" && password == "secret" {
					return &domain.AuthResult{
						Session: &auth.AuthSession{
							User: &auth.User{Username: local, Mailbox: local},
						},
						Domain: &domain.Domain{Name: "example.com"},
					}, nil
				}
				return nil, errors.New("invalid credentials")
			}

			return nil, errors.New("invalid credentials")
		},
	}

	tests := []struct {
		name        string
		args        []string
		wantOK      bool
		wantMessage string
		wantState   State
	}{
		{
			name: "AUTH PLAIN with domain user succeeds",
			// Base64 of "\x00alice@example.com\x00secret"
			args:        []string{"PLAIN", "AGFsaWNlQGV4YW1wbGUuY29tAHNlY3JldA=="},
			wantOK:      true,
			wantMessage: "Logged in as alice@example.com",
			wantState:   StateTransaction,
		},
		{
			name: "AUTH PLAIN with unknown domain fails",
			// Base64 of "\x00alice@unknown.org\x00secret"
			args:        []string{"PLAIN", "AGFsaWNlQHVua25vd24ub3JnAHNlY3JldA=="},
			wantOK:      false,
			wantMessage: "Authentication failed",
			wantState:   StateAuthorization,
		},
		{
			name: "AUTH PLAIN with domain user wrong password fails",
			// Base64 of "\x00alice@example.com\x00wrong"
			args:        []string{"PLAIN", "AGFsaWNlQGV4YW1wbGUuY29tAHdyb25n"},
			wantOK:      false,
			wantMessage: "Authentication failed",
			wantState:   StateAuthorization,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sess := newTestSession(config.ModePop3s, true)

			cmd := &authCommand{auth: domainAuth}

			conn := newMockConnection()
			resp, err := cmd.Execute(context.Background(), sess, conn, tt.args)

			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}

			if resp.OK != tt.wantOK {
				t.Errorf("Execute() OK = %v, want %v", resp.OK, tt.wantOK)
			}

			if !resp.Continuation && resp.Message != tt.wantMessage {
				t.Errorf("Execute() Message = %v, want %v", resp.Message, tt.wantMessage)
			}

			if sess.State() != tt.wantState {
				t.Errorf("Session state = %v, want %v", sess.State(), tt.wantState)
			}
		})
	}
}
