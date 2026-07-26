package domain

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/infodancer/maildancer/auth"
	autherrors "github.com/infodancer/maildancer/auth/errors"
)

// mockAuthAgent implements auth.AuthenticationAgent for testing.
type mockAuthAgent struct {
	authenticateFn func(ctx context.Context, username, password string) (*auth.AuthSession, error)
	userExistsFn   func(ctx context.Context, username string) (bool, error)
	closed         bool
}

func (m *mockAuthAgent) Authenticate(ctx context.Context, username, password string) (*auth.AuthSession, error) {
	if m.authenticateFn != nil {
		return m.authenticateFn(ctx, username, password)
	}
	return nil, autherrors.ErrAuthFailed
}

func (m *mockAuthAgent) UserExists(ctx context.Context, username string) (bool, error) {
	if m.userExistsFn != nil {
		return m.userExistsFn(ctx, username)
	}
	return false, nil
}

func (m *mockAuthAgent) Close() error {
	m.closed = true
	return nil
}

func (m *mockAuthAgent) ResolveForward(_ context.Context, _ string) ([]string, bool) {
	return nil, false
}

// mockDomainProvider implements DomainProvider for testing.
type mockDomainProvider struct {
	domains map[string]*Domain
}

func (m *mockDomainProvider) GetDomain(name string) *Domain {
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

func TestSplitUsername(t *testing.T) {
	tests := []struct {
		input      string
		wantLocal  string
		wantDomain string
	}{
		{"user@example.com", "user", "example.com"},
		{"alice@sub.domain.org", "alice", "sub.domain.org"},
		{"plainuser", "plainuser", ""},
		{"", "", ""},
		{"user@", "user", ""},
		{"@domain.com", "", "domain.com"},
		{"user@first@second", "user@first", "second"},
	}

	for _, tt := range tests {
		local, domain := SplitUsername(tt.input)
		if local != tt.wantLocal || domain != tt.wantDomain {
			t.Errorf("SplitUsername(%q) = (%q, %q), want (%q, %q)",
				tt.input, local, domain, tt.wantLocal, tt.wantDomain)
		}
	}
}

func TestParseLocalPart(t *testing.T) {
	tests := []struct {
		input    string
		wantBase string
		wantExt  string
	}{
		{"user+folder", "user", "folder"},
		{"user", "user", ""},
		{"user+", "user", ""},
		{"user+a+b", "user", "a+b"},
		{"+folder", "", "folder"},
		{"", "", ""},
		{"plain", "plain", ""},
		{"+", "", ""},
	}

	for _, tt := range tests {
		base, ext := ParseLocalPart(tt.input)
		if base != tt.wantBase || ext != tt.wantExt {
			t.Errorf("ParseLocalPart(%q) = (%q, %q), want (%q, %q)",
				tt.input, base, ext, tt.wantBase, tt.wantExt)
		}
	}
}

func TestAuthRouterAuthenticateDomain(t *testing.T) {
	domainAgent := &mockAuthAgent{
		authenticateFn: func(_ context.Context, username, password string) (*auth.AuthSession, error) {
			if username == "alice" && password == "secret" {
				return &auth.AuthSession{User: &auth.User{Username: "alice"}}, nil
			}
			return nil, autherrors.ErrAuthFailed
		},
	}

	fallback := &mockAuthAgent{
		authenticateFn: func(_ context.Context, username, password string) (*auth.AuthSession, error) {
			return nil, fmt.Errorf("fallback should not be called")
		},
	}

	provider := &mockDomainProvider{
		domains: map[string]*Domain{
			"example.com": {
				Name:      "example.com",
				AuthAgent: domainAgent,
			},
		},
	}

	router := NewAuthRouter(provider, fallback)
	ctx := context.Background()

	// Successful domain auth
	result, err := router.AuthenticateWithDomain(ctx, "alice@example.com", "secret")
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if result.Session.User.Username != "alice" {
		t.Errorf("expected username 'alice', got %q", result.Session.User.Username)
	}
	if result.Domain == nil {
		t.Fatal("expected domain to be set")
	}
	if result.Domain.Name != "example.com" {
		t.Errorf("expected domain 'example.com', got %q", result.Domain.Name)
	}
	if result.Extension != "" {
		t.Errorf("expected empty extension, got %q", result.Extension)
	}

	// Failed domain auth (wrong password)
	_, err = router.AuthenticateWithDomain(ctx, "alice@example.com", "wrong")
	if err == nil {
		t.Fatal("expected auth failure")
	}
}

func TestAuthRouterAuthenticateFallback(t *testing.T) {
	fallback := &mockAuthAgent{
		authenticateFn: func(_ context.Context, username, password string) (*auth.AuthSession, error) {
			if username == "bob" && password == "pass" {
				return &auth.AuthSession{User: &auth.User{Username: "bob"}}, nil
			}
			return nil, autherrors.ErrAuthFailed
		},
	}

	router := NewAuthRouter(nil, fallback)
	ctx := context.Background()

	// Plain username goes to fallback
	result, err := router.AuthenticateWithDomain(ctx, "bob", "pass")
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if result.Session.User.Username != "bob" {
		t.Errorf("expected username 'bob', got %q", result.Session.User.Username)
	}
	if result.Domain != nil {
		t.Error("expected domain to be nil for fallback auth")
	}
	if result.Extension != "" {
		t.Errorf("expected empty extension, got %q", result.Extension)
	}
}

func TestAuthRouterAuthenticateUnknownDomainFallback(t *testing.T) {
	fallback := &mockAuthAgent{
		authenticateFn: func(_ context.Context, username, password string) (*auth.AuthSession, error) {
			// Fallback receives the full username
			if username == "carol@unknown.com" && password == "pass" {
				return &auth.AuthSession{User: &auth.User{Username: "carol@unknown.com"}}, nil
			}
			return nil, autherrors.ErrAuthFailed
		},
	}

	provider := &mockDomainProvider{
		domains: map[string]*Domain{}, // no domains
	}

	router := NewAuthRouter(provider, fallback)
	ctx := context.Background()

	// Unknown domain falls back to global auth with full username
	result, err := router.AuthenticateWithDomain(ctx, "carol@unknown.com", "pass")
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if result.Session.User.Username != "carol@unknown.com" {
		t.Errorf("expected username 'carol@unknown.com', got %q", result.Session.User.Username)
	}
	if result.Domain != nil {
		t.Error("expected domain to be nil for fallback auth")
	}
	if result.Extension != "" {
		t.Errorf("expected empty extension, got %q", result.Extension)
	}
}

func TestAuthRouterAuthenticateNoProviderNoFallback(t *testing.T) {
	router := NewAuthRouter(nil, nil)
	ctx := context.Background()

	_, err := router.AuthenticateWithDomain(ctx, "user@example.com", "pass")
	if err != autherrors.ErrAuthFailed {
		t.Errorf("expected ErrAuthFailed, got %v", err)
	}
}

func TestAuthRouterAuthenticate(t *testing.T) {
	// Test that Authenticate() (the AuthenticationAgent interface method)
	// delegates to AuthenticateWithDomain and returns just the session.
	fallback := &mockAuthAgent{
		authenticateFn: func(_ context.Context, username, password string) (*auth.AuthSession, error) {
			return &auth.AuthSession{User: &auth.User{Username: username}}, nil
		},
	}

	router := NewAuthRouter(nil, fallback)
	ctx := context.Background()

	session, err := router.Authenticate(ctx, "user", "pass")
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if session.User.Username != "user" {
		t.Errorf("expected username 'user', got %q", session.User.Username)
	}
}

func TestAuthRouterUserExistsDomain(t *testing.T) {
	domainAgent := &mockAuthAgent{
		userExistsFn: func(_ context.Context, username string) (bool, error) {
			// Domain agent receives the local part only
			return username == "dave", nil
		},
	}

	provider := &mockDomainProvider{
		domains: map[string]*Domain{
			"example.com": {
				Name:      "example.com",
				AuthAgent: domainAgent,
			},
		},
	}

	router := NewAuthRouter(provider, nil)
	ctx := context.Background()

	// User exists in domain
	exists, err := router.UserExists(ctx, "dave@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !exists {
		t.Error("expected user to exist")
	}

	// User does not exist in domain
	exists, err = router.UserExists(ctx, "nobody@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exists {
		t.Error("expected user to not exist")
	}
}

func TestAuthRouterUserExistsFallback(t *testing.T) {
	fallback := &mockAuthAgent{
		userExistsFn: func(_ context.Context, username string) (bool, error) {
			// Fallback receives the full username
			return username == "eve", nil
		},
	}

	router := NewAuthRouter(nil, fallback)
	ctx := context.Background()

	exists, err := router.UserExists(ctx, "eve")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !exists {
		t.Error("expected user to exist")
	}
}

func TestAuthRouterUserExistsUnknownDomain(t *testing.T) {
	fallback := &mockAuthAgent{
		userExistsFn: func(_ context.Context, username string) (bool, error) {
			return username == "frank@unknown.com", nil
		},
	}

	provider := &mockDomainProvider{
		domains: map[string]*Domain{},
	}

	router := NewAuthRouter(provider, fallback)
	ctx := context.Background()

	exists, err := router.UserExists(ctx, "frank@unknown.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !exists {
		t.Error("expected user to exist via fallback")
	}
}

func TestAuthRouterUserExistsNoProviderNoFallback(t *testing.T) {
	router := NewAuthRouter(nil, nil)
	ctx := context.Background()

	exists, err := router.UserExists(ctx, "nobody@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exists {
		t.Error("expected user to not exist")
	}
}

func TestAuthRouterClose(t *testing.T) {
	fallback := &mockAuthAgent{}
	router := NewAuthRouter(nil, fallback)

	err := router.Close()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify fallback was NOT closed (lifecycle managed by caller)
	if fallback.closed {
		t.Error("AuthRouter should not close the fallback agent")
	}
}

func TestAuthRouterAuthenticateSubaddress(t *testing.T) {
	domainAgent := &mockAuthAgent{
		authenticateFn: func(_ context.Context, username, password string) (*auth.AuthSession, error) {
			// Domain agent should receive "alice" (base only, no extension)
			if username == "alice" && password == "secret" {
				return &auth.AuthSession{User: &auth.User{Username: "alice"}}, nil
			}
			return nil, autherrors.ErrAuthFailed
		},
	}

	provider := &mockDomainProvider{
		domains: map[string]*Domain{
			"example.com": {
				Name:      "example.com",
				AuthAgent: domainAgent,
			},
		},
	}

	router := NewAuthRouter(provider, nil)
	ctx := context.Background()

	result, err := router.AuthenticateWithDomain(ctx, "alice+folder@example.com", "secret")
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if result.Session.User.Username != "alice" {
		t.Errorf("expected username 'alice', got %q", result.Session.User.Username)
	}
	if result.Extension != "folder" {
		t.Errorf("expected extension 'folder', got %q", result.Extension)
	}
	if result.Domain == nil || result.Domain.Name != "example.com" {
		t.Error("expected domain to be set to example.com")
	}
}

func TestAuthRouterUserExistsSubaddress(t *testing.T) {
	domainAgent := &mockAuthAgent{
		userExistsFn: func(_ context.Context, username string) (bool, error) {
			// Domain agent should receive "dave" (base only)
			return username == "dave", nil
		},
	}

	provider := &mockDomainProvider{
		domains: map[string]*Domain{
			"example.com": {
				Name:      "example.com",
				AuthAgent: domainAgent,
			},
		},
	}

	router := NewAuthRouter(provider, nil)
	ctx := context.Background()

	exists, err := router.UserExists(ctx, "dave+inbox@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !exists {
		t.Error("expected user to exist when using subaddress")
	}

	// Non-existent base user with subaddress
	exists, err = router.UserExists(ctx, "nobody+tag@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exists {
		t.Error("expected user to not exist")
	}
}

func TestAuthRouterAuthenticateSubaddressFallback(t *testing.T) {
	fallback := &mockAuthAgent{
		authenticateFn: func(_ context.Context, username, password string) (*auth.AuthSession, error) {
			// Fallback should receive "bob@unknown.com" (extension stripped)
			if username == "bob@unknown.com" && password == "pass" {
				return &auth.AuthSession{User: &auth.User{Username: "bob@unknown.com"}}, nil
			}
			return nil, fmt.Errorf("unexpected fallback call with username %q", username)
		},
	}

	provider := &mockDomainProvider{
		domains: map[string]*Domain{}, // no domains configured
	}

	router := NewAuthRouter(provider, fallback)
	ctx := context.Background()

	result, err := router.AuthenticateWithDomain(ctx, "bob+tag@unknown.com", "pass")
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if result.Session.User.Username != "bob@unknown.com" {
		t.Errorf("expected username 'bob@unknown.com', got %q", result.Session.User.Username)
	}
	if result.Extension != "tag" {
		t.Errorf("expected extension 'tag', got %q", result.Extension)
	}
	if result.Domain != nil {
		t.Error("expected domain to be nil for fallback auth")
	}
}

func TestAuthRouterUserExistsSubaddressFallback(t *testing.T) {
	fallback := &mockAuthAgent{
		userExistsFn: func(_ context.Context, username string) (bool, error) {
			// Fallback should receive "eve" (extension stripped, no domain)
			return username == "eve", nil
		},
	}

	router := NewAuthRouter(nil, fallback)
	ctx := context.Background()

	exists, err := router.UserExists(ctx, "eve+lists")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !exists {
		t.Error("expected user to exist via fallback with subaddress stripped")
	}
}

// TestAuthRouterMailbox_AddressContract verifies that AuthRouter normalises
// User.Mailbox to a fully-qualified "localpart@domain" address after domain
// authentication. The store is responsible for stripping the domain; no daemon
// (smtpd, pop3d, imapd) should have to perform this normalisation itself.
func TestAuthRouterMailbox_AddressContract(t *testing.T) {
	domainAgent := &mockAuthAgent{
		authenticateFn: func(_ context.Context, username, password string) (*auth.AuthSession, error) {
			// Domain agent receives only the base localpart (no extension, no domain)
			if username == "alice" && password == "secret" {
				return &auth.AuthSession{User: &auth.User{Username: "alice"}}, nil
			}
			return nil, autherrors.ErrAuthFailed
		},
	}

	provider := &mockDomainProvider{
		domains: map[string]*Domain{
			"example.com": {
				Name:      "example.com",
				AuthAgent: domainAgent,
			},
		},
	}

	router := NewAuthRouter(provider, nil)
	ctx := context.Background()

	t.Run("plain address", func(t *testing.T) {
		result, err := router.AuthenticateWithDomain(ctx, "alice@example.com", "secret")
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}
		want := "alice@example.com"
		if got := result.Session.User.Mailbox; got != want {
			t.Errorf("User.Mailbox = %q, want %q (must be fully-qualified, not bare localpart)", got, want)
		}
	})

	t.Run("subaddress stripped", func(t *testing.T) {
		result, err := router.AuthenticateWithDomain(ctx, "alice+folder@example.com", "secret")
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}
		// Extension must be stripped from Mailbox; store gets base@domain
		want := "alice@example.com"
		if got := result.Session.User.Mailbox; got != want {
			t.Errorf("User.Mailbox = %q, want %q (subaddress must not appear in Mailbox)", got, want)
		}
		if result.Extension != "folder" {
			t.Errorf("Extension = %q, want %q", result.Extension, "folder")
		}
	})
}

// Verify AuthRouter implements auth.AuthenticationAgent at compile time.
var _ auth.AuthenticationAgent = (*AuthRouter)(nil)

// TestAuthRouterAuthenticate_UnhostedDomain covers the case where the username
// names a domain this server does not host.
//
// Before #221 there was no way to tell that apart from any other failure, and
// what happened depended on deployment accident: with a fallback agent
// configured (which production has) the attempt reached the fallback, missed,
// and came back ErrUserNotFound -- so session-manager's rule 1 banned the
// address on the first attempt. With no fallback it came back ErrAuthFailed and
// nothing happened at all. Production and every test fixture disagreed about
// what this case even was.
//
// The live cost of that: a domain migrated off this server gets its former
// users' addresses banned on attempt one, because their stale clients keep
// authenticating here.
//
// The discriminator is whether any domains are configured at all. A server with
// domains configured is not the legacy unqualified-address host that fallback
// authentication exists for, so an unhosted domain there is a real signal. A
// server with no domains is exactly that host, and its behaviour is unchanged.
func TestAuthRouterAuthenticate_UnhostedDomain(t *testing.T) {
	// knowsCarol authenticates one fully-qualified legacy user and nothing else,
	// which is a supported passwd-file configuration: auth/passwd keys its user
	// map on the exact string from the file, including any domain part.
	knowsCarol := func() *mockAuthAgent {
		return &mockAuthAgent{
			authenticateFn: func(_ context.Context, username, password string) (*auth.AuthSession, error) {
				if username == "carol@unknown.com" && password == "pass" {
					return &auth.AuthSession{User: &auth.User{Username: username}}, nil
				}
				if username == "carol@unknown.com" {
					return nil, autherrors.ErrAuthFailed // real user, wrong password
				}
				return nil, autherrors.ErrUserNotFound
			},
		}
	}

	hosted := map[string]*Domain{
		"example.com": {Name: "example.com", AuthAgent: &mockAuthAgent{
			authenticateFn: func(_ context.Context, username, _ string) (*auth.AuthSession, error) {
				if username == "alice" {
					return &auth.AuthSession{User: &auth.User{Username: username}}, nil
				}
				return nil, autherrors.ErrUserNotFound
			},
		}},
	}

	tests := []struct {
		name     string
		domains  map[string]*Domain
		fallback auth.AuthenticationAgent
		username string
		password string
		wantErr  error
		wantOK   bool
	}{
		{
			name:     "domains configured, unhosted domain, no fallback",
			domains:  hosted,
			username: "dave@notours.test",
			password: "pass",
			wantErr:  autherrors.ErrDomainNotHosted,
		},
		{
			name:     "domains configured, unhosted domain, fallback present",
			domains:  hosted,
			fallback: knowsCarol(),
			username: "dave@notours.test",
			password: "pass",
			// The fallback is never consulted: a configured server is not the
			// legacy host that fallback authentication is for.
			wantErr: autherrors.ErrDomainNotHosted,
		},
		{
			name:     "no domains configured, unhosted domain, fallback knows the user",
			domains:  map[string]*Domain{},
			fallback: knowsCarol(),
			username: "carol@unknown.com",
			password: "pass",
			// The legacy drop-in case: user@host where the host is implied.
			// Unchanged, and TestAuthRouterAuthenticateUnknownDomainFallback
			// pins the same behaviour.
			wantOK: true,
		},
		{
			name:     "no domains configured, unhosted domain, fallback misses",
			domains:  map[string]*Domain{},
			fallback: knowsCarol(),
			username: "nobody@unknown.com",
			password: "pass",
			// Still ErrUserNotFound, not the new sentinel: with no domains
			// configured this server cannot claim a domain is "not hosted".
			wantErr: autherrors.ErrUserNotFound,
		},
		{
			name:     "bare username with no domain part",
			domains:  hosted,
			fallback: knowsCarol(),
			username: "carol",
			password: "pass",
			// No domain was named, so there is no domain to call unhosted. The
			// fallback decides, exactly as before.
			wantErr: autherrors.ErrUserNotFound,
		},
		{
			name:     "hosted domain, missing user, still rule 1",
			domains:  hosted,
			username: "nosuchuser@example.com",
			password: "pass",
			wantErr:  autherrors.ErrUserNotFound,
		},
		{
			name:     "hosted domain, real user",
			domains:  hosted,
			username: "alice@example.com",
			password: "pass",
			wantOK:   true,
		},
		{
			name:     "nil provider cannot claim anything about domains",
			domains:  nil,
			username: "dave@notours.test",
			password: "pass",
			wantErr:  autherrors.ErrAuthFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var provider DomainProvider
			if tt.domains != nil {
				provider = &mockDomainProvider{domains: tt.domains}
			}
			router := NewAuthRouter(provider, tt.fallback)
			t.Cleanup(func() { _ = router.Close() })

			_, err := router.AuthenticateWithDomain(context.Background(), tt.username, tt.password)
			if tt.wantOK {
				if err != nil {
					t.Fatalf("expected success, got %v", err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("got error %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestAuthRouterAuthenticate_UnhostedDomainWrongPassword is carved out because
// getting it wrong turns a real user into a counted abuse signal. A fallback
// user who exists and typed the wrong password must stay ErrAuthFailed: that is
// somebody with a stale saved password, not somebody probing for domains.
func TestAuthRouterAuthenticate_UnhostedDomainWrongPassword(t *testing.T) {
	fallback := &mockAuthAgent{
		authenticateFn: func(_ context.Context, username, password string) (*auth.AuthSession, error) {
			switch {
			case username == "carol@unknown.com" && password == "right":
				return &auth.AuthSession{User: &auth.User{Username: username}}, nil
			case username == "carol@unknown.com":
				return nil, autherrors.ErrAuthFailed
			default:
				return nil, autherrors.ErrUserNotFound
			}
		},
	}

	router := NewAuthRouter(&mockDomainProvider{domains: map[string]*Domain{}}, fallback)
	t.Cleanup(func() { _ = router.Close() })

	_, err := router.AuthenticateWithDomain(context.Background(), "carol@unknown.com", "wrong")
	if !errors.Is(err, autherrors.ErrAuthFailed) {
		t.Errorf("got %v, want ErrAuthFailed: a real user with a stale password "+
			"must not be reclassified as a domain probe", err)
	}
}
