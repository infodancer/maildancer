package pop3

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/infodancer/maildancer/msgstore"
	"github.com/infodancer/maildancer/internal/pop3d/config"
)

// mockAuthProvider is a test double for AuthProvider.
type mockAuthProvider struct {
	authenticateFn func(ctx context.Context, username, password string) (*msgstore.AuthSession, error)
}

func (m *mockAuthProvider) Authenticate(ctx context.Context, username, password string) (*msgstore.AuthSession, error) {
	if m.authenticateFn != nil {
		return m.authenticateFn(ctx, username, password)
	}
	return nil, errors.New("not implemented")
}

func (m *mockAuthProvider) Close() error {
	return nil
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

// Test helper to create a session for testing
func newTestSession(mode config.ListenerMode, isTLS bool) *Session {
	return NewSession("test.example.com", mode, nil, isTLS)
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
			sess:         newTestSession(config.ModePop3, false),
			args:         []string{},
			wantOK:       true,
			wantMessage:  "Capability list follows",
			wantCapCount: 3, // TOP, UIDL, RESP-CODES (no USER, no STLS without TLS config)
		},
		{
			name:         "CAPA with TLS shows USER",
			sess:         newTestSession(config.ModePop3s, true),
			args:         []string{},
			wantOK:       true,
			wantMessage:  "Capability list follows",
			wantCapCount: 4, // USER, TOP, UIDL, RESP-CODES
		},
		{
			name:    "CAPA with arguments fails",
			sess:    newTestSession(config.ModePop3, false),
			args:    []string{"invalid"},
			wantOK:  false,
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
			sess:        newTestSession(config.ModePop3, false),
			args:        []string{},
			wantOK:      false, // Fails because no TLS config
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
		name          string
		sess          *Session
		setupSession  func(*Session)
		args          []string
		authFn        func(ctx context.Context, username, password string) (*msgstore.AuthSession, error)
		wantOK        bool
		wantMessage   string
		wantState     State
	}{
		{
			name:        "PASS without TLS fails",
			sess:        newTestSession(config.ModePop3, false),
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
			name:        "PASS with successful auth",
			sess:        newTestSession(config.ModePop3s, true),
			setupSession: func(s *Session) {
				s.SetUsername("testuser")
			},
			args: []string{"correctpassword"},
			authFn: func(ctx context.Context, username, password string) (*msgstore.AuthSession, error) {
				return &msgstore.AuthSession{
					User: &msgstore.User{
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
			name:        "PASS with failed auth",
			sess:        newTestSession(config.ModePop3s, true),
			setupSession: func(s *Session) {
				s.SetUsername("testuser")
			},
			args: []string{"wrongpassword"},
			authFn: func(ctx context.Context, username, password string) (*msgstore.AuthSession, error) {
				return nil, errors.New("invalid credentials")
			},
			wantOK:      false,
			wantMessage: "Authentication failed",
			wantState:   StateAuthorization,
		},
		{
			name:        "PASS without arguments fails",
			sess:        newTestSession(config.ModePop3s, true),
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

			mockAuth := &mockAuthProvider{
				authenticateFn: tt.authFn,
			}

			cmd := &passCommand{authProvider: mockAuth}

			// Create a minimal mock connection for logging
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
		name        string
		sess        *Session
		setupSession func(*Session)
		args        []string
		wantOK      bool
		wantMessage string
		wantState   State
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
			name:        "QUIT in TRANSACTION",
			sess:        newTestSession(config.ModePop3s, true),
			setupSession: func(s *Session) {
				s.SetAuthenticated(&msgstore.AuthSession{
					User: &msgstore.User{Username: "test"},
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
	mockAuth := &mockAuthProvider{}
	RegisterAuthCommands(mockAuth)

	tests := []struct {
		name      string
		cmdName   string
		wantFound bool
	}{
		{"CAPA exists", "CAPA", true},
		{"capa exists (case insensitive)", "capa", true},
		{"USER exists", "USER", true},
		{"PASS exists", "PASS", true},
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
