package domain

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestValidateForwardTarget(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr error
	}{
		{"single", "Bob@Example.COM", "bob@example.com", nil},
		{"trims", "  bob@example.com  ", "bob@example.com", nil},
		{"comma multi", "a@x.com,b@y.com", "", ErrMultiTargetForward},
		{"space multi", "a@x.com b@y.com", "", ErrMultiTargetForward},
		{"empty", "", "", ErrInvalidForwardTarget},
		{"no at", "bob", "", ErrInvalidForwardTarget},
		{"leading at", "@example.com", "", ErrInvalidForwardTarget},
		{"trailing at", "bob@", "", ErrInvalidForwardTarget},
		{"two ats", "bob@@example.com", "", ErrInvalidForwardTarget},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateForwardTarget(tt.in)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// setupDomain creates a domains-path tree with a domain directory and optional
// initial config.toml content, returning the domains path.
func setupDomain(t *testing.T, domain, initialConfig string) string {
	t.Helper()
	domainsPath := t.TempDir()
	dir := filepath.Join(domainsPath, domain)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if initialConfig != "" {
		if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(initialConfig), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	return domainsPath
}

func TestSetDomainForward_CreatesAndResolves(t *testing.T) {
	domainsPath := setupDomain(t, "example.com", "")

	if err := SetDomainForward(domainsPath, "example.com", "alice", "bob@gmail.com"); err != nil {
		t.Fatalf("SetDomainForward: %v", err)
	}

	// It must be readable back...
	fwds, err := ListDomainForwards(domainsPath, "example.com")
	if err != nil {
		t.Fatalf("ListDomainForwards: %v", err)
	}
	if fwds["alice"] != "bob@gmail.com" {
		t.Errorf("forwards[alice] = %q, want bob@gmail.com", fwds["alice"])
	}

	// ...and the written config.toml must actually be loadable by the domain
	// config loader (the file the forwarding chain reads).
	cfg, err := LoadDomainConfig(filepath.Join(domainsPath, "example.com", "config.toml"))
	if err != nil {
		t.Fatalf("LoadDomainConfig: %v", err)
	}
	if cfg.Forwards["alice"] != "bob@gmail.com" {
		t.Errorf("loaded cfg.Forwards[alice] = %q, want bob@gmail.com", cfg.Forwards["alice"])
	}
}

func TestSetDomainForward_Catchall(t *testing.T) {
	domainsPath := setupDomain(t, "example.com", "")
	if err := SetDomainForward(domainsPath, "example.com", "*", "owner@example.com"); err != nil {
		t.Fatalf("SetDomainForward catchall: %v", err)
	}
	fwds, _ := ListDomainForwards(domainsPath, "example.com")
	if fwds["*"] != "owner@example.com" {
		t.Errorf("catchall = %q, want owner@example.com", fwds["*"])
	}
}

func TestSetDomainForward_RejectsMultiTarget(t *testing.T) {
	domainsPath := setupDomain(t, "example.com", "")

	err := SetDomainForward(domainsPath, "example.com", "alice", "a@x.com,b@y.com")
	if !errors.Is(err, ErrMultiTargetForward) {
		t.Fatalf("err = %v, want ErrMultiTargetForward", err)
	}
	// No file may have been written.
	if _, err := os.Stat(filepath.Join(domainsPath, "example.com", "config.toml")); !os.IsNotExist(err) {
		t.Errorf("config.toml should not exist after a rejected multi-target set, stat err = %v", err)
	}
}

func TestSetDomainForward_PreservesOtherFields(t *testing.T) {
	// A config.toml with unrelated settings must survive a forward edit.
	initial := `
gid = 5000
recipient_rejection = "data"

[auth]
type = "passwd"
credential_backend = "passwd"

[msgstore]
type = "maildir"
base_path = "mail"
`
	domainsPath := setupDomain(t, "example.com", initial)

	if err := SetDomainForward(domainsPath, "example.com", "alice", "bob@gmail.com"); err != nil {
		t.Fatalf("SetDomainForward: %v", err)
	}

	cfg, err := LoadDomainConfig(filepath.Join(domainsPath, "example.com", "config.toml"))
	if err != nil {
		t.Fatalf("LoadDomainConfig: %v", err)
	}
	if cfg.Gid != 5000 {
		t.Errorf("Gid = %d, want 5000 (other fields must survive)", cfg.Gid)
	}
	if cfg.RecipientRejection != "data" {
		t.Errorf("RecipientRejection = %q, want data", cfg.RecipientRejection)
	}
	if cfg.Auth.Type != "passwd" {
		t.Errorf("Auth.Type = %q, want passwd", cfg.Auth.Type)
	}
	if cfg.MsgStore.BasePath != "mail" {
		t.Errorf("MsgStore.BasePath = %q, want mail", cfg.MsgStore.BasePath)
	}
	if cfg.Forwards["alice"] != "bob@gmail.com" {
		t.Errorf("Forwards[alice] = %q, want bob@gmail.com", cfg.Forwards["alice"])
	}
}

func TestSetDomainForward_UpsertOverwrites(t *testing.T) {
	domainsPath := setupDomain(t, "example.com", "")
	_ = SetDomainForward(domainsPath, "example.com", "alice", "old@gmail.com")
	if err := SetDomainForward(domainsPath, "example.com", "alice", "new@gmail.com"); err != nil {
		t.Fatalf("SetDomainForward upsert: %v", err)
	}
	fwds, _ := ListDomainForwards(domainsPath, "example.com")
	if fwds["alice"] != "new@gmail.com" {
		t.Errorf("forwards[alice] = %q, want new@gmail.com", fwds["alice"])
	}
	if len(fwds) != 1 {
		t.Errorf("want exactly 1 forward after upsert, got %d", len(fwds))
	}
}

func TestDeleteDomainForward(t *testing.T) {
	domainsPath := setupDomain(t, "example.com", "")
	_ = SetDomainForward(domainsPath, "example.com", "alice", "bob@gmail.com")

	removed, err := DeleteDomainForward(domainsPath, "example.com", "alice")
	if err != nil {
		t.Fatalf("DeleteDomainForward: %v", err)
	}
	if !removed {
		t.Error("removed = false, want true for an existing forward")
	}
	fwds, _ := ListDomainForwards(domainsPath, "example.com")
	if _, ok := fwds["alice"]; ok {
		t.Error("alice forward still present after delete")
	}

	// Deleting a non-existent forward is a no-op, not an error.
	removed, err = DeleteDomainForward(domainsPath, "example.com", "nobody")
	if err != nil {
		t.Fatalf("DeleteDomainForward (absent): %v", err)
	}
	if removed {
		t.Error("removed = true for an absent forward, want false")
	}
}

func TestSetDomainForward_UnknownDomain(t *testing.T) {
	domainsPath := t.TempDir() // no domain directory created
	err := SetDomainForward(domainsPath, "example.com", "alice", "bob@gmail.com")
	if !errors.Is(err, ErrDomainNotFound) {
		t.Fatalf("err = %v, want ErrDomainNotFound", err)
	}
}
