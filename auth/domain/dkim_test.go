package domain

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func writeTestKey(t *testing.T) (string, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8,
	})

	path := filepath.Join(t.TempDir(), "dkim.pem")
	if err := os.WriteFile(path, pemBlock, 0600); err != nil {
		t.Fatal(err)
	}
	return path, pub
}

func TestLoadDKIMKey(t *testing.T) {
	path, wantPub := writeTestKey(t)

	signer, err := LoadDKIMKey(path)
	if err != nil {
		t.Fatalf("LoadDKIMKey: %v", err)
	}

	gotPub, ok := signer.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatalf("public key is %T, want ed25519.PublicKey", signer.Public())
	}
	if !gotPub.Equal(wantPub) {
		t.Error("loaded public key does not match generated key")
	}
}

func TestLoadDKIMKey_MissingFile(t *testing.T) {
	_, err := LoadDKIMKey("/nonexistent/path")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadDKIMKey_InvalidPEM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(path, []byte("not a pem file"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadDKIMKey(path)
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}
