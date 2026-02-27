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

// stubDomainProvider implements DomainProvider with a fixed map of domains.
type stubDomainProvider struct {
	domains map[string]*Domain
}

func (s *stubDomainProvider) GetDomain(name string) *Domain {
	return s.domains[name]
}

func (s *stubDomainProvider) Domains() []string {
	keys := make([]string, 0, len(s.domains))
	for k := range s.domains {
		keys = append(keys, k)
	}
	return keys
}

func (s *stubDomainProvider) Close() error { return nil }

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

// --- forwardingDeliveryAgent tests ---

func TestForwardingDeliveryAgent_NoForward_DeliversLocally(t *testing.T) {
	inner := &stubDeliveryAgent{}
	chain := &forwardChain{
		domainForwards:  &forwards.ForwardMap{},
		defaultForwards: &forwards.ForwardMap{},
	}
	provider := &stubDomainProvider{domains: map[string]*Domain{}}
	agent := &SmartDeliveryAgent{inner: inner, chain: chain, provider: provider}

	env := msgstore.Envelope{Recipients: []string{"alice@example.com"}}
	if err := agent.Deliver(context.Background(), env, bytes.NewReader([]byte("test"))); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(inner.delivered) != 1 {
		t.Errorf("expected 1 local delivery, got %d", len(inner.delivered))
	}
}

func TestForwardingDeliveryAgent_DomainForward_RoutesToTarget(t *testing.T) {
	dir := t.TempDir()
	fwdPath := filepath.Join(dir, "forwards")
	if err := os.WriteFile(fwdPath, []byte("*:matthew@canonical.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	fwdMap, err := forwards.Load(fwdPath)
	if err != nil {
		t.Fatal(err)
	}

	canonicalInner := &stubDeliveryAgent{}
	canonicalDomain := &Domain{
		Name:          "canonical.com",
		DeliveryAgent: canonicalInner,
	}
	provider := &stubDomainProvider{
		domains: map[string]*Domain{"canonical.com": canonicalDomain},
	}

	inner := &stubDeliveryAgent{}
	chain := &forwardChain{
		domainForwards:  fwdMap,
		defaultForwards: &forwards.ForwardMap{},
	}
	agent := &SmartDeliveryAgent{inner: inner, chain: chain, provider: provider}

	env := msgstore.Envelope{Recipients: []string{"anyone@this.com"}}
	if err := agent.Deliver(context.Background(), env, bytes.NewReader([]byte("test"))); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should not deliver locally
	if len(inner.delivered) != 0 {
		t.Errorf("expected 0 local deliveries, got %d", len(inner.delivered))
	}
	// Should deliver to canonical.com
	if len(canonicalInner.delivered) != 1 {
		t.Fatalf("expected 1 forwarded delivery, got %d", len(canonicalInner.delivered))
	}
	if canonicalInner.delivered[0].Recipients[0] != "matthew@canonical.com" {
		t.Errorf("unexpected forward recipient: %v", canonicalInner.delivered[0].Recipients)
	}
}

func TestForwardingDeliveryAgent_ExternalTarget_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	fwdPath := filepath.Join(dir, "forwards")
	if err := os.WriteFile(fwdPath, []byte("*:me@gmail.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	fwdMap, err := forwards.Load(fwdPath)
	if err != nil {
		t.Fatal(err)
	}

	// Provider has no domain for gmail.com
	provider := &stubDomainProvider{domains: map[string]*Domain{}}

	inner := &stubDeliveryAgent{}
	chain := &forwardChain{
		domainForwards:  fwdMap,
		defaultForwards: &forwards.ForwardMap{},
	}
	agent := &SmartDeliveryAgent{inner: inner, chain: chain, provider: provider}

	env := msgstore.Envelope{Recipients: []string{"anyone@this.com"}}
	err = agent.Deliver(context.Background(), env, bytes.NewReader([]byte("test")))
	if err == nil {
		t.Error("expected error for unroutable external forward target")
	}
}

func TestForwardingDeliveryAgent_UserLevelForward(t *testing.T) {
	dir := t.TempDir()
	userFwdDir := filepath.Join(dir, "user_forwards")
	if err := os.MkdirAll(userFwdDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(userFwdDir, "alice"), []byte("alice@other.com\n"), 0644); err != nil {
		t.Fatal(err)
	}

	targetInner := &stubDeliveryAgent{}
	provider := &stubDomainProvider{
		domains: map[string]*Domain{
			"other.com": {Name: "other.com", DeliveryAgent: targetInner},
		},
	}

	inner := &stubDeliveryAgent{}
	chain := &forwardChain{
		userForwardsDir: userFwdDir,
		domainForwards:  &forwards.ForwardMap{},
		defaultForwards: &forwards.ForwardMap{},
	}
	agent := &SmartDeliveryAgent{inner: inner, chain: chain, provider: provider}

	env := msgstore.Envelope{Recipients: []string{"alice@this.com"}}
	if err := agent.Deliver(context.Background(), env, bytes.NewReader([]byte("test"))); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(inner.delivered) != 0 {
		t.Errorf("expected no local delivery, got %d", len(inner.delivered))
	}
	if len(targetInner.delivered) != 1 {
		t.Errorf("expected 1 forwarded delivery, got %d", len(targetInner.delivered))
	}
}

func TestForwardChain_ResolutionOrder(t *testing.T) {
	// User-level should win over domain-level, domain over default
	dir := t.TempDir()
	userFwdDir := filepath.Join(dir, "user_forwards")
	if err := os.MkdirAll(userFwdDir, 0755); err != nil {
		t.Fatal(err)
	}
	// User-level for alice only
	if err := os.WriteFile(filepath.Join(userFwdDir, "alice"), []byte("alice@user-level.com\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Domain-level covers alice and bob
	domainFwdPath := filepath.Join(dir, "domain_forwards")
	if err := os.WriteFile(domainFwdPath, []byte("alice:alice@domain-level.com\nbob:bob@domain-level.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	domainFwd, _ := forwards.Load(domainFwdPath)

	// Default-level is catchall
	defaultFwdPath := filepath.Join(dir, "default_forwards")
	if err := os.WriteFile(defaultFwdPath, []byte("*:anyone@default-level.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	defaultFwd, _ := forwards.Load(defaultFwdPath)

	chain := &forwardChain{
		userForwardsDir: userFwdDir,
		domainForwards:  domainFwd,
		defaultForwards: defaultFwd,
	}

	// alice: user-level wins
	targets, ok := chain.resolve("alice")
	if !ok || len(targets) != 1 || targets[0] != "alice@user-level.com" {
		t.Errorf("alice: expected user-level target, got %v ok=%v", targets, ok)
	}

	// bob: domain-level wins (no user file)
	targets, ok = chain.resolve("bob")
	if !ok || len(targets) != 1 || targets[0] != "bob@domain-level.com" {
		t.Errorf("bob: expected domain-level target, got %v ok=%v", targets, ok)
	}

	// charlie: default catchall
	targets, ok = chain.resolve("charlie")
	if !ok || len(targets) != 1 || targets[0] != "anyone@default-level.com" {
		t.Errorf("charlie: expected default-level catchall, got %v ok=%v", targets, ok)
	}
}
