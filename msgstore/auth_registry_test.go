package msgstore

import (
	"context"
	"testing"

	"github.com/infodancer/maildancer/msgstore/errors"
)

// mockAuthAgent is a test implementation of AuthenticationAgent.
type mockAuthAgent struct {
	closed bool
}

func (m *mockAuthAgent) Authenticate(ctx context.Context, username, password string) (*AuthSession, error) {
	if username == "testuser" && password == "secret" {
		return &AuthSession{
			User: &User{
				Username: "testuser",
				Mailbox:  "/var/mail/testuser",
			},
		}, nil
	}
	return nil, errors.ErrAuthFailed
}

func (m *mockAuthAgent) Close() error {
	m.closed = true
	return nil
}

func TestRegisterAuthAgent(t *testing.T) {
	// Save original registry and restore after test
	authRegistryMu.Lock()
	origRegistry := authRegistry
	authRegistry = make(map[string]AuthAgentFactory)
	authRegistryMu.Unlock()
	defer func() {
		authRegistryMu.Lock()
		authRegistry = origRegistry
		authRegistryMu.Unlock()
	}()

	t.Run("register and open", func(t *testing.T) {
		RegisterAuthAgent("mock", func(config AuthAgentConfig) (AuthenticationAgent, error) {
			return &mockAuthAgent{}, nil
		})

		agent, err := OpenAuthAgent(AuthAgentConfig{Type: "mock"})
		if err != nil {
			t.Fatalf("open auth agent: %v", err)
		}

		session, err := agent.Authenticate(context.Background(), "testuser", "secret")
		if err != nil {
			t.Fatalf("authenticate: %v", err)
		}
		if session.User.Username != "testuser" {
			t.Errorf("username = %q, want %q", session.User.Username, "testuser")
		}

		if err := agent.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})

	t.Run("unregistered type", func(t *testing.T) {
		_, err := OpenAuthAgent(AuthAgentConfig{Type: "nonexistent"})
		if err != errors.ErrAuthAgentNotRegistered {
			t.Errorf("err = %v, want ErrAuthAgentNotRegistered", err)
		}
	})
}

func TestRegisterAuthAgent_Panics(t *testing.T) {
	// Save original registry and restore after test
	authRegistryMu.Lock()
	origRegistry := authRegistry
	authRegistry = make(map[string]AuthAgentFactory)
	authRegistryMu.Unlock()
	defer func() {
		authRegistryMu.Lock()
		authRegistry = origRegistry
		authRegistryMu.Unlock()
	}()

	t.Run("empty name", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic for empty name")
			}
		}()
		RegisterAuthAgent("", func(config AuthAgentConfig) (AuthenticationAgent, error) {
			return &mockAuthAgent{}, nil
		})
	})

	t.Run("nil factory", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic for nil factory")
			}
		}()
		RegisterAuthAgent("test", nil)
	})

	t.Run("duplicate registration", func(t *testing.T) {
		RegisterAuthAgent("duplicate", func(config AuthAgentConfig) (AuthenticationAgent, error) {
			return &mockAuthAgent{}, nil
		})
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic for duplicate registration")
			}
		}()
		RegisterAuthAgent("duplicate", func(config AuthAgentConfig) (AuthenticationAgent, error) {
			return &mockAuthAgent{}, nil
		})
	})
}

func TestRegisteredAuthAgents(t *testing.T) {
	// Save original registry and restore after test
	authRegistryMu.Lock()
	origRegistry := authRegistry
	authRegistry = make(map[string]AuthAgentFactory)
	authRegistryMu.Unlock()
	defer func() {
		authRegistryMu.Lock()
		authRegistry = origRegistry
		authRegistryMu.Unlock()
	}()

	factory := func(config AuthAgentConfig) (AuthenticationAgent, error) {
		return &mockAuthAgent{}, nil
	}

	RegisterAuthAgent("charlie", factory)
	RegisterAuthAgent("alpha", factory)
	RegisterAuthAgent("bravo", factory)

	types := RegisteredAuthAgents()

	if len(types) != 3 {
		t.Fatalf("len(types) = %d, want 3", len(types))
	}

	// Should be sorted
	expected := []string{"alpha", "bravo", "charlie"}
	for i, name := range expected {
		if types[i] != name {
			t.Errorf("types[%d] = %q, want %q", i, types[i], name)
		}
	}
}

func TestAuthSession_Clear(t *testing.T) {
	session := &AuthSession{
		User: &User{
			Username: "testuser",
			Mailbox:  "/var/mail/testuser",
		},
		PrivateKey:        []byte("secret-key-material"),
		PublicKey:         []byte("public-key"),
		EncryptionEnabled: true,
	}

	// Verify private key has content
	if len(session.PrivateKey) == 0 {
		t.Fatal("private key should have content before clear")
	}

	session.Clear()

	// Private key should be nil
	if session.PrivateKey != nil {
		t.Error("private key should be nil after clear")
	}

	// User and public key should still be accessible (not zeroed)
	if session.User == nil {
		t.Error("user should still be set")
	}
	if session.PublicKey == nil {
		t.Error("public key should still be set")
	}
}
