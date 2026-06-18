package manager

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/infodancer/maildancer/auth/domain"
	"github.com/infodancer/maildancer/internal/session-manager/config"
	"github.com/infodancer/maildancer/internal/session-manager/metrics"
)

// newResolveForwardManager builds a Manager backed by a real
// FilesystemDomainProvider over a temp config tree. The domain has an admin-tier
// forward (config.toml [forwards]) for "alias" and a domain-tier forward
// (forwards file) for "team", but no passwd entries -- these are forward-only
// addresses with no uid, the case that used to fail credential lookup.
func newResolveForwardManager(t *testing.T) *Manager {
	t.Helper()
	base := t.TempDir()
	domainDir := filepath.Join(base, "example.com")
	if err := os.MkdirAll(domainDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := `[auth]
type = "passwd"
credential_backend = "passwd"
key_backend = "keys"

[msgstore]
type = "maildir"
base_path = "users"

[forwards]
alias = "real@elsewhere.example.com"
`
	if err := os.WriteFile(filepath.Join(domainDir, "config.toml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	// Empty passwd: no local mailboxes, so every match below is forward-only.
	if err := os.WriteFile(filepath.Join(domainDir, "passwd"), []byte("# none\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(domainDir, "forwards"), []byte("team:lead@elsewhere.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	provider := domain.NewFilesystemDomainProvider(base, nil)
	t.Cleanup(func() { _ = provider.Close() })

	return &Manager{
		cfg:            &config.Config{DomainsPath: base},
		domainProvider: provider,
		metrics:        &metrics.NoopCollector{},
		byToken:        make(map[string]*sessionEntry),
		byUser:         make(map[string]*sessionEntry),
	}
}

func TestResolveForward(t *testing.T) {
	m := newResolveForwardManager(t)
	ctx := context.Background()

	cases := []struct {
		name      string
		recipient string
		wantOK    bool
		wantFirst string
	}{
		{"admin tier, forward-only (no uid)", "alias@example.com", true, "real@elsewhere.example.com"},
		{"domain tier forwards file", "team@example.com", true, "lead@elsewhere.example.com"},
		{"no forward rule", "nobody@example.com", false, ""},
		{"unknown domain", "x@absent.example.com", false, ""},
		{"malformed address", "noatsign", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			targets, ok := m.ResolveForward(ctx, tc.recipient)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (targets %v)", ok, tc.wantOK, targets)
			}
			if tc.wantOK && (len(targets) != 1 || targets[0] != tc.wantFirst) {
				t.Errorf("targets = %v, want [%s]", targets, tc.wantFirst)
			}
		})
	}
}

// TestResolveForward_NoProvider: a manager with no domain provider never
// resolves a forward (returns false), rather than panicking.
func TestResolveForward_NoProvider(t *testing.T) {
	m := &Manager{}
	if _, ok := m.ResolveForward(context.Background(), "anyone@example.com"); ok {
		t.Error("expected no forward without a domain provider")
	}
}
