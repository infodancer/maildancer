package domain

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/infodancer/maildancer/auth"
	autherrors "github.com/infodancer/maildancer/auth/errors"
	"github.com/infodancer/maildancer/auth/forwards"
	"github.com/infodancer/maildancer/msgstore"
)

// --- stubs ---

type stubAuthAgent struct {
	users map[string]bool
}

func (s *stubAuthAgent) Authenticate(_ context.Context, username, _ string) (*auth.AuthSession, error) {
	if !s.users[username] {
		return nil, autherrors.ErrUserNotFound
	}
	return &auth.AuthSession{User: &auth.User{Username: username}}, nil
}

func (s *stubAuthAgent) UserExists(_ context.Context, username string) (bool, error) {
	return s.users[username], nil
}

func (s *stubAuthAgent) Close() error { return nil }

func (s *stubAuthAgent) ResolveForward(_ context.Context, _ string) ([]string, bool) {
	return nil, false
}

type stubDeliveryAgent struct {
	delivered []msgstore.Envelope
}

func (s *stubDeliveryAgent) Deliver(_ context.Context, env msgstore.Envelope, _ io.Reader) error {
	s.delivered = append(s.delivered, env)
	return nil
}

// --- forwardingAuthAgent tests ---

func TestForwardingAuthAgent_UserExists_LocalUser(t *testing.T) {
	inner := &stubAuthAgent{users: map[string]bool{"alice": true}}
	chain := &forwardChain{
		domainForwards:  &forwards.ForwardMap{},
		defaultForwards: &forwards.ForwardMap{},
	}
	agent := &mailAuthAgent{inner: inner, chain: chain}

	exists, err := agent.UserExists(context.Background(), "alice")
	if err != nil || !exists {
		t.Errorf("expected alice to exist: err=%v exists=%v", err, exists)
	}
}

func TestForwardingAuthAgent_UserExists_ForwardOnly(t *testing.T) {
	dir := t.TempDir()
	fwdPath := filepath.Join(dir, "forwards")
	if err := os.WriteFile(fwdPath, []byte("*:catchall@other.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	fwdMap, err := forwards.Load(fwdPath)
	if err != nil {
		t.Fatal(err)
	}

	inner := &stubAuthAgent{users: map[string]bool{}}
	chain := &forwardChain{
		domainForwards:  fwdMap,
		defaultForwards: &forwards.ForwardMap{},
	}
	agent := &mailAuthAgent{inner: inner, chain: chain}

	// User doesn't exist locally, but catchall forward covers all addresses.
	exists, err := agent.UserExists(context.Background(), "anyone")
	if err != nil || !exists {
		t.Errorf("expected forward-only address to exist: err=%v exists=%v", err, exists)
	}
}

func TestForwardingAuthAgent_UserExists_Unknown(t *testing.T) {
	inner := &stubAuthAgent{users: map[string]bool{}}
	chain := &forwardChain{
		domainForwards:  &forwards.ForwardMap{},
		defaultForwards: &forwards.ForwardMap{},
	}
	agent := &mailAuthAgent{inner: inner, chain: chain}

	exists, err := agent.UserExists(context.Background(), "ghost")
	if err != nil || exists {
		t.Errorf("expected ghost to not exist: err=%v exists=%v", err, exists)
	}
}

func TestForwardingAuthAgent_Authenticate_DelegatesInner(t *testing.T) {
	inner := &stubAuthAgent{users: map[string]bool{"alice": true}}
	chain := &forwardChain{
		domainForwards:  &forwards.ForwardMap{},
		defaultForwards: &forwards.ForwardMap{},
	}
	agent := &mailAuthAgent{inner: inner, chain: chain}

	session, err := agent.Authenticate(context.Background(), "alice", "pass")
	if err != nil || session == nil {
		t.Errorf("expected successful auth for alice: err=%v", err)
	}

	_, err = agent.Authenticate(context.Background(), "ghost", "pass")
	if err == nil {
		t.Error("expected error for unknown user")
	}
}

func TestForwardingAuthAgent_UserLevel(t *testing.T) {
	dir := t.TempDir()
	userFwdDir := filepath.Join(dir, "user_forwards")
	if err := os.MkdirAll(userFwdDir, 0755); err != nil {
		t.Fatal(err)
	}
	// Write per-user forward for "bob"
	if err := os.WriteFile(filepath.Join(userFwdDir, "bob"), []byte("bob@canonical.com\n"), 0644); err != nil {
		t.Fatal(err)
	}

	inner := &stubAuthAgent{users: map[string]bool{}}
	chain := &forwardChain{
		userForwardsDir: userFwdDir,
		domainForwards:  &forwards.ForwardMap{},
		defaultForwards: &forwards.ForwardMap{},
	}
	agent := &mailAuthAgent{inner: inner, chain: chain}

	exists, err := agent.UserExists(context.Background(), "bob")
	if err != nil || !exists {
		t.Errorf("expected bob to exist via user-level forward: err=%v exists=%v", err, exists)
	}
	exists, err = agent.UserExists(context.Background(), "alice")
	if err != nil || exists {
		t.Errorf("expected alice to not exist: err=%v exists=%v", err, exists)
	}
}

// --- MailDeliveryAgent tests ---

// MailDeliveryAgent is now a thin pass-through; forwarding is resolved upstream
// in session-manager, before the privilege drop (the 1-hop ceiling is covered
// by TestFollowRedirect_OneHopCeiling in internal/smtpd/smtp). The only behavior
// left to verify here is that Deliver hands the message straight to the inner
// agent.
func TestMailDeliveryAgent_PassesThroughToInner(t *testing.T) {
	inner := &stubDeliveryAgent{}
	agent := &MailDeliveryAgent{inner: inner}

	env := msgstore.Envelope{Recipients: []string{"alice@example.com"}}
	if err := agent.Deliver(context.Background(), env, bytes.NewReader([]byte("test"))); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(inner.delivered) != 1 {
		t.Errorf("expected 1 local delivery, got %d", len(inner.delivered))
	}
}

func TestForwardChain_ResolutionOrder(t *testing.T) {
	// Precedence is admin -> domain -> user -> system default (admins/domains
	// win over users). See the forwardChain doc.
	dir := t.TempDir()
	userFwdDir := filepath.Join(dir, "user_forwards")
	if err := os.MkdirAll(userFwdDir, 0755); err != nil {
		t.Fatal(err)
	}
	// User-level forwards for alice, bob, carol.
	for name, target := range map[string]string{
		"alice": "alice@user-level.com",
		"bob":   "bob@user-level.com",
		"carol": "carol@user-level.com",
	} {
		if err := os.WriteFile(filepath.Join(userFwdDir, name), []byte(target+"\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	// Admin tier (config.toml [forwards]) covers alice only.
	adminFwd := forwards.FromMap(map[string]string{"alice": "alice@admin.com"})

	// Domain tier (forwards file) covers bob only.
	domainFwdPath := filepath.Join(dir, "domain_forwards")
	if err := os.WriteFile(domainFwdPath, []byte("bob:bob@domain-level.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	domainFwd, _ := forwards.Load(domainFwdPath)

	// System default is a catchall.
	defaultFwdPath := filepath.Join(dir, "default_forwards")
	if err := os.WriteFile(defaultFwdPath, []byte("*:anyone@default-level.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	defaultFwd, _ := forwards.Load(defaultFwdPath)

	chain := &forwardChain{
		adminForwards:   adminFwd,
		domainForwards:  domainFwd,
		userForwardsDir: userFwdDir,
		defaultForwards: defaultFwd,
	}

	cases := []struct {
		name, localpart, want string
	}{
		{"admin beats user", "alice", "alice@admin.com"},
		{"domain beats user", "bob", "bob@domain-level.com"},
		{"user beats default", "carol", "carol@user-level.com"},
		{"default catchall fallback", "dave", "anyone@default-level.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			targets, ok := chain.resolve(tc.localpart)
			if !ok || len(targets) != 1 || targets[0] != tc.want {
				t.Errorf("%s: want %q, got %v ok=%v", tc.localpart, tc.want, targets, ok)
			}
		})
	}
}

// TestForwardChain_DomainCatchallShadowsUser pins the deliberate shadowing: a
// domain (or admin) catchall funnels mail that a user-level forward would
// otherwise catch -- admins/domains win over users, by design.
func TestForwardChain_DomainCatchallShadowsUser(t *testing.T) {
	dir := t.TempDir()
	userFwdDir := filepath.Join(dir, "user_forwards")
	if err := os.MkdirAll(userFwdDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(userFwdDir, "alice"), []byte("alice@user-level.com\n"), 0644); err != nil {
		t.Fatal(err)
	}

	domainFwdPath := filepath.Join(dir, "domain_forwards")
	if err := os.WriteFile(domainFwdPath, []byte("*:catchall@domain-level.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	domainFwd, _ := forwards.Load(domainFwdPath)

	chain := &forwardChain{
		domainForwards:  domainFwd,
		userForwardsDir: userFwdDir,
	}

	targets, ok := chain.resolve("alice")
	if !ok || len(targets) != 1 || targets[0] != "catchall@domain-level.com" {
		t.Errorf("alice: domain catchall should shadow the user forward, got %v ok=%v", targets, ok)
	}
}
