package admin

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/infodancer/maildancer/auth/domain"
)

func TestCreateDKIMKey(t *testing.T) {
	p := newTestPaths(t)
	if _, err := p.CreateDomain("example.com"); err != nil {
		t.Fatal(err)
	}

	rec, err := p.CreateDKIMKey("example.com", "sel1", false)
	if err != nil {
		t.Fatalf("CreateDKIMKey: %v", err)
	}
	if rec.Selector != "sel1" {
		t.Errorf("selector = %q, want sel1", rec.Selector)
	}

	// Private key file exists with owner-only permissions.
	keyPath := filepath.Join(p.Config, "example.com", "dkim", "sel1.key")
	if rec.KeyPath != keyPath {
		t.Errorf("KeyPath = %q, want %q", rec.KeyPath, keyPath)
	}
	fi, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file mode = %04o, want 0600", perm)
	}

	// The key loads through the same loader the signing path uses, and the
	// DNS record's p= value is the base64 of the matching public key.
	signer, err := domain.LoadDKIMKey(keyPath)
	if err != nil {
		t.Fatalf("LoadDKIMKey: %v", err)
	}
	pub := signer.Public().(ed25519.PublicKey)
	wantValue := "v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(pub)
	if rec.DNSValue != wantValue {
		t.Errorf("DNSValue = %q, want %q", rec.DNSValue, wantValue)
	}
	if rec.DNSName != "sel1._domainkey.example.com" {
		t.Errorf("DNSName = %q", rec.DNSName)
	}

	// Config points at the new key with a path relative to the domain dir.
	cfg, err := domain.LoadDomainConfig(filepath.Join(p.Config, "example.com", "config.toml"))
	if err != nil {
		t.Fatalf("LoadDomainConfig: %v", err)
	}
	if cfg.DKIM.Selector != "sel1" {
		t.Errorf("config dkim.selector = %q", cfg.DKIM.Selector)
	}
	if cfg.DKIM.PrivateKeyPath != "dkim/sel1.key" {
		t.Errorf("config dkim.private_key = %q", cfg.DKIM.PrivateKeyPath)
	}
	// Creation-time defaults survive the config patch.
	if cfg.Auth.Type != "passwd" || cfg.MsgStore.Type != "maildir" {
		t.Errorf("creation defaults lost: auth=%+v msgstore=%+v", cfg.Auth, cfg.MsgStore)
	}
}

func TestCreateDKIMKey_DefaultSelector(t *testing.T) {
	p := newTestPaths(t)
	if _, err := p.CreateDomain("example.com"); err != nil {
		t.Fatal(err)
	}

	rec, err := p.CreateDKIMKey("example.com", "", false)
	if err != nil {
		t.Fatalf("CreateDKIMKey: %v", err)
	}
	want := DefaultDKIMSelector(time.Now())
	if rec.Selector != want {
		t.Errorf("selector = %q, want %q", rec.Selector, want)
	}
	if !regexp.MustCompile(`^d\d{6}$`).MatchString(rec.Selector) {
		t.Errorf("default selector %q is not date-stamped", rec.Selector)
	}
}

func TestCreateDKIMKey_RefusesOverwrite(t *testing.T) {
	p := newTestPaths(t)
	if _, err := p.CreateDomain("example.com"); err != nil {
		t.Fatal(err)
	}

	first, err := p.CreateDKIMKey("example.com", "sel1", false)
	if err != nil {
		t.Fatalf("first create: %v", err)
	}

	if _, err := p.CreateDKIMKey("example.com", "sel1", false); !errors.Is(err, ErrDKIMKeyExists) {
		t.Errorf("second create: err = %v, want ErrDKIMKeyExists", err)
	}

	// --force replaces the key material.
	second, err := p.CreateDKIMKey("example.com", "sel1", true)
	if err != nil {
		t.Fatalf("forced create: %v", err)
	}
	if second.DNSValue == first.DNSValue {
		t.Error("forced create did not generate a new key")
	}
}

func TestCreateDKIMKey_Rotation(t *testing.T) {
	p := newTestPaths(t)
	if _, err := p.CreateDomain("example.com"); err != nil {
		t.Fatal(err)
	}

	if _, err := p.CreateDKIMKey("example.com", "old", false); err != nil {
		t.Fatalf("create old: %v", err)
	}
	if _, err := p.CreateDKIMKey("example.com", "new", false); err != nil {
		t.Fatalf("create new: %v", err)
	}

	// Config points at the new selector; the old key file is retained so
	// mail signed before the rotation still verifies.
	cfg, err := domain.LoadDomainConfig(filepath.Join(p.Config, "example.com", "config.toml"))
	if err != nil {
		t.Fatalf("LoadDomainConfig: %v", err)
	}
	if cfg.DKIM.Selector != "new" || cfg.DKIM.PrivateKeyPath != "dkim/new.key" {
		t.Errorf("config = selector %q key %q, want new", cfg.DKIM.Selector, cfg.DKIM.PrivateKeyPath)
	}
	if _, err := os.Stat(filepath.Join(p.Config, "example.com", "dkim", "old.key")); err != nil {
		t.Errorf("old key file removed: %v", err)
	}
}

func TestCreateDKIMKey_InvalidInput(t *testing.T) {
	p := newTestPaths(t)
	if _, err := p.CreateDomain("example.com"); err != nil {
		t.Fatal(err)
	}

	if _, err := p.CreateDKIMKey("missing.example", "sel1", false); !errors.Is(err, ErrDomainNotFound) {
		t.Errorf("missing domain: err = %v, want ErrDomainNotFound", err)
	}
	if _, err := p.CreateDKIMKey("../escape", "sel1", false); !errors.Is(err, ErrInvalidDomainName) {
		t.Errorf("bad domain: err = %v, want ErrInvalidDomainName", err)
	}

	for _, sel := range []string{"../x", "UPPER", "has_underscore", "has space", "-start", "end-", strings.Repeat("a", 64)} {
		if _, err := p.CreateDKIMKey("example.com", sel, false); !errors.Is(err, ErrInvalidSelector) {
			t.Errorf("selector %q: err = %v, want ErrInvalidSelector", sel, err)
		}
	}
}

func TestDKIMStatus(t *testing.T) {
	p := newTestPaths(t)
	if _, err := p.CreateDomain("example.com"); err != nil {
		t.Fatal(err)
	}

	if _, err := p.DKIMStatus("example.com"); !errors.Is(err, ErrDKIMNotConfigured) {
		t.Errorf("unconfigured: err = %v, want ErrDKIMNotConfigured", err)
	}

	created, err := p.CreateDKIMKey("example.com", "sel1", false)
	if err != nil {
		t.Fatalf("CreateDKIMKey: %v", err)
	}

	status, err := p.DKIMStatus("example.com")
	if err != nil {
		t.Fatalf("DKIMStatus: %v", err)
	}
	if status.Selector != created.Selector ||
		status.DNSName != created.DNSName ||
		status.DNSValue != created.DNSValue ||
		status.KeyPath != created.KeyPath {
		t.Errorf("status %+v does not match create result %+v", status, created)
	}
}

func TestDKIMStatus_MissingDomain(t *testing.T) {
	p := newTestPaths(t)
	if _, err := p.DKIMStatus("missing.example"); !errors.Is(err, ErrDomainNotFound) {
		t.Errorf("err = %v, want ErrDomainNotFound", err)
	}
}

func TestDefaultDKIMSelector(t *testing.T) {
	at := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
	if got := DefaultDKIMSelector(at); got != "d202606" {
		t.Errorf("DefaultDKIMSelector = %q, want d202606", got)
	}
}

// TestCreateDKIMKey_SignerRoundTrip proves the generated key signs through
// the same crypto.Signer interface the outbound queue uses.
func TestCreateDKIMKey_SignerRoundTrip(t *testing.T) {
	p := newTestPaths(t)
	if _, err := p.CreateDomain("example.com"); err != nil {
		t.Fatal(err)
	}
	rec, err := p.CreateDKIMKey("example.com", "sel1", false)
	if err != nil {
		t.Fatalf("CreateDKIMKey: %v", err)
	}

	signer, err := domain.LoadDKIMKey(rec.KeyPath)
	if err != nil {
		t.Fatalf("LoadDKIMKey: %v", err)
	}
	msg := []byte("test message")
	sig, err := signer.Sign(nil, msg, &ed25519.Options{})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	pub := signer.Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, msg, sig) {
		t.Error("signature did not verify against the published public key")
	}
}
