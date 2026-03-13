package dkim

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDKIMKey(t *testing.T) {
	dir := t.TempDir()
	domainDir := filepath.Join(dir, "example.com")
	if err := os.MkdirAll(domainDir, 0700); err != nil {
		t.Fatal(err)
	}

	// Generate an Ed25519 key and write it as PEM.
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	if err := os.WriteFile(filepath.Join(domainDir, "dkim.key"), keyPEM, 0600); err != nil {
		t.Fatal(err)
	}

	// Write domain config.toml with DKIM settings.
	config := `[dkim]
selector = "default"
private_key = "dkim.key"
`
	if err := os.WriteFile(filepath.Join(domainDir, "config.toml"), []byte(config), 0644); err != nil {
		t.Fatal(err)
	}

	selector, key, err := LoadDKIMKey(dir, "example.com")
	if err != nil {
		t.Fatalf("LoadDKIMKey: %v", err)
	}
	if selector != "default" {
		t.Errorf("selector: got %q, want %q", selector, "default")
	}
	if key == nil {
		t.Fatal("key is nil")
	}
}

func TestLoadDKIMKey_NoDKIMConfig(t *testing.T) {
	dir := t.TempDir()
	domainDir := filepath.Join(dir, "example.com")
	if err := os.MkdirAll(domainDir, 0700); err != nil {
		t.Fatal(err)
	}

	// config.toml with no DKIM section.
	config := `[auth]
type = "passwd"
`
	if err := os.WriteFile(filepath.Join(domainDir, "config.toml"), []byte(config), 0644); err != nil {
		t.Fatal(err)
	}

	selector, key, err := LoadDKIMKey(dir, "example.com")
	if err != nil {
		t.Fatalf("LoadDKIMKey: %v", err)
	}
	if selector != "" || key != nil {
		t.Errorf("expected empty selector and nil key, got %q, %v", selector, key)
	}
}

func TestLoadDKIMKey_NoDomainDir(t *testing.T) {
	dir := t.TempDir()

	selector, key, err := LoadDKIMKey(dir, "nonexistent.com")
	if err != nil {
		t.Fatalf("LoadDKIMKey: %v", err)
	}
	if selector != "" || key != nil {
		t.Errorf("expected empty selector and nil key, got %q, %v", selector, key)
	}
}
