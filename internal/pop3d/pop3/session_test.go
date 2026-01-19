package pop3

import (
	"crypto/tls"
	"testing"

	"github.com/infodancer/maildancer/auth"
	"github.com/infodancer/maildancer/internal/pop3d/config"
)

func TestNewSession(t *testing.T) {
	tests := []struct {
		name         string
		hostname     string
		mode         config.ListenerMode
		isTLS        bool
		wantState    State
		wantTLSState TLSState
	}{
		{
			name:         "ModePop3 without TLS",
			hostname:     "test.example.com",
			mode:         config.ModePop3,
			isTLS:        false,
			wantState:    StateAuthorization,
			wantTLSState: TLSStateNone,
		},
		{
			name:         "ModePop3s with implicit TLS",
			hostname:     "test.example.com",
			mode:         config.ModePop3s,
			isTLS:        true,
			wantState:    StateAuthorization,
			wantTLSState: TLSStateActive,
		},
		{
			name:         "ModePop3 with explicit TLS",
			hostname:     "test.example.com",
			mode:         config.ModePop3,
			isTLS:        true,
			wantState:    StateAuthorization,
			wantTLSState: TLSStateActive,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sess := NewSession(tt.hostname, tt.mode, nil, tt.isTLS)

			if sess.State() != tt.wantState {
				t.Errorf("NewSession() state = %v, want %v", sess.State(), tt.wantState)
			}

			if sess.TLSState() != tt.wantTLSState {
				t.Errorf("NewSession() tlsState = %v, want %v", sess.TLSState(), tt.wantTLSState)
			}
		})
	}
}

func TestSessionTLSManagement(t *testing.T) {
	sess := NewSession("test.example.com", config.ModePop3, nil, false)

	// Initial state should be no TLS
	if sess.IsTLSActive() {
		t.Error("Expected TLS to be inactive initially")
	}

	// Activate TLS
	sess.SetTLSActive()

	if !sess.IsTLSActive() {
		t.Error("Expected TLS to be active after SetTLSActive()")
	}

	if sess.TLSState() != TLSStateActive {
		t.Errorf("TLSState = %v, want %v", sess.TLSState(), TLSStateActive)
	}
}

func TestCanSTLS(t *testing.T) {
	tlsConfig := &tls.Config{}

	tests := []struct {
		name      string
		mode      config.ListenerMode
		isTLS     bool
		tlsConfig *tls.Config
		want      bool
	}{
		{
			name:      "ModePop3 without TLS config",
			mode:      config.ModePop3,
			isTLS:     false,
			tlsConfig: nil,
			want:      false,
		},
		{
			name:      "ModePop3 with TLS config before upgrade",
			mode:      config.ModePop3,
			isTLS:     false,
			tlsConfig: tlsConfig,
			want:      true,
		},
		{
			name:      "ModePop3 after TLS upgrade",
			mode:      config.ModePop3,
			isTLS:     true,
			tlsConfig: tlsConfig,
			want:      false,
		},
		{
			name:      "ModePop3s (implicit TLS)",
			mode:      config.ModePop3s,
			isTLS:     true,
			tlsConfig: tlsConfig,
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sess := NewSession("test.example.com", tt.mode, tt.tlsConfig, tt.isTLS)

			if got := sess.CanSTLS(); got != tt.want {
				t.Errorf("CanSTLS() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSessionAuthentication(t *testing.T) {
	sess := NewSession("test.example.com", config.ModePop3s, nil, true)

	// Initially not authenticated
	if sess.IsAuthenticated() {
		t.Error("Session should not be authenticated initially")
	}

	if sess.AuthSession() != nil {
		t.Error("AuthSession() should return nil when not authenticated")
	}

	// Set username
	sess.SetUsername("testuser")
	if sess.Username() != "testuser" {
		t.Errorf("Username() = %v, want testuser", sess.Username())
	}

	// Authenticate
	authSession := &auth.AuthSession{
		User: &auth.User{
			Username: "testuser",
			Mailbox:  "/var/mail/testuser",
		},
	}
	sess.SetAuthenticated(authSession)

	// Should now be authenticated
	if !sess.IsAuthenticated() {
		t.Error("Session should be authenticated after SetAuthenticated()")
	}

	if sess.State() != StateTransaction {
		t.Errorf("State = %v, want %v", sess.State(), StateTransaction)
	}

	if sess.AuthSession() != authSession {
		t.Error("AuthSession() should return the authenticated session")
	}
}

func TestSessionStateTransitions(t *testing.T) {
	sess := NewSession("test.example.com", config.ModePop3s, nil, true)

	// Start in AUTHORIZATION
	if sess.State() != StateAuthorization {
		t.Errorf("Initial state = %v, want %v", sess.State(), StateAuthorization)
	}

	// Authenticate -> TRANSACTION
	authSession := &auth.AuthSession{
		User: &auth.User{Username: "test"},
	}
	sess.SetAuthenticated(authSession)

	if sess.State() != StateTransaction {
		t.Errorf("After SetAuthenticated state = %v, want %v", sess.State(), StateTransaction)
	}

	// QUIT -> UPDATE
	sess.EnterUpdate()

	if sess.State() != StateUpdate {
		t.Errorf("After EnterUpdate state = %v, want %v", sess.State(), StateUpdate)
	}

	// Should still be authenticated in UPDATE state
	if !sess.IsAuthenticated() {
		t.Error("Session should still be authenticated in UPDATE state")
	}
}

func TestCapabilities(t *testing.T) {
	tests := []struct {
		name          string
		mode          config.ListenerMode
		isTLS         bool
		tlsConfig     *tls.Config
		wantCapCount  int
		wantHasUser   bool
		wantHasSTLS   bool
	}{
		{
			name:          "ModePop3 without TLS config",
			mode:          config.ModePop3,
			isTLS:         false,
			tlsConfig:     nil,
			wantCapCount:  3, // TOP, UIDL, RESP-CODES
			wantHasUser:   false,
			wantHasSTLS:   false,
		},
		{
			name:          "ModePop3 with TLS config before upgrade",
			mode:          config.ModePop3,
			isTLS:         false,
			tlsConfig:     &tls.Config{},
			wantCapCount:  4, // TOP, UIDL, RESP-CODES, STLS
			wantHasUser:   false,
			wantHasSTLS:   true,
		},
		{
			name:          "ModePop3s with implicit TLS",
			mode:          config.ModePop3s,
			isTLS:         true,
			tlsConfig:     &tls.Config{},
			wantCapCount:  4, // USER, TOP, UIDL, RESP-CODES
			wantHasUser:   true,
			wantHasSTLS:   false,
		},
		{
			name:          "ModePop3 after STARTTLS",
			mode:          config.ModePop3,
			isTLS:         true,
			tlsConfig:     &tls.Config{},
			wantCapCount:  4, // USER, TOP, UIDL, RESP-CODES
			wantHasUser:   true,
			wantHasSTLS:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sess := NewSession("test.example.com", tt.mode, tt.tlsConfig, tt.isTLS)
			caps := sess.Capabilities()

			if len(caps) != tt.wantCapCount {
				t.Errorf("Capabilities() count = %v, want %v (caps: %v)", len(caps), tt.wantCapCount, caps)
			}

			hasUser := false
			hasSTLS := false
			for _, cap := range caps {
				if cap == "USER" {
					hasUser = true
				}
				if cap == "STLS" {
					hasSTLS = true
				}
			}

			if hasUser != tt.wantHasUser {
				t.Errorf("Capabilities() hasUser = %v, want %v", hasUser, tt.wantHasUser)
			}

			if hasSTLS != tt.wantHasSTLS {
				t.Errorf("Capabilities() hasSTLS = %v, want %v", hasSTLS, tt.wantHasSTLS)
			}
		})
	}
}

func TestSessionCleanup(t *testing.T) {
	sess := NewSession("test.example.com", config.ModePop3s, nil, true)

	// Authenticate with a session
	authSession := &auth.AuthSession{
		User: &auth.User{Username: "test"},
	}
	sess.SetAuthenticated(authSession)

	// Cleanup should zero the auth session
	sess.Cleanup()

	if sess.AuthSession() != nil {
		t.Error("AuthSession should be nil after Cleanup()")
	}
}

func TestStateString(t *testing.T) {
	tests := []struct {
		state State
		want  string
	}{
		{StateAuthorization, "AUTHORIZATION"},
		{StateTransaction, "TRANSACTION"},
		{StateUpdate, "UPDATE"},
		{State(999), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.state.String(); got != tt.want {
				t.Errorf("State.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTLSStateString(t *testing.T) {
	tests := []struct {
		state TLSState
		want  string
	}{
		{TLSStateNone, "NONE"},
		{TLSStateActive, "ACTIVE"},
		{TLSState(999), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.state.String(); got != tt.want {
				t.Errorf("TLSState.String() = %v, want %v", got, tt.want)
			}
		})
	}
}
