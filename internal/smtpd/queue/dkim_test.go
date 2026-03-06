package queue

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-msgauth/dkim"
)

func TestWriteWithDKIM(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	keys := map[string]DKIMKey{
		"example.com": {Selector: "default", Key: priv},
	}

	cfg := Config{
		Dir:        t.TempDir(),
		MessageTTL: 7 * 24 * time.Hour,
		Hostname:   "mail.example.com",
		DKIMSign:   NewDKIMSigner(keys),
	}

	body := strings.NewReader("From: alice@example.com\r\nTo: bob@gmail.com\r\nSubject: test\r\n\r\nHello\r\n")
	if err := Write(cfg, "alice@example.com", []string{"bob@gmail.com"}, body); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Read the body file and check for DKIM-Signature header.
	msgDir := filepath.Join(cfg.Dir, "msg", "com", "example")
	bodies := readDir(t, msgDir)
	if len(bodies) != 1 {
		t.Fatalf("expected 1 body, got %d", len(bodies))
	}

	content, err := os.ReadFile(filepath.Join(msgDir, bodies[0]))
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(content), "DKIM-Signature:") {
		t.Errorf("body missing DKIM-Signature header; got:\n%s", content)
	}
	if !strings.Contains(string(content), "Message-ID:") {
		t.Errorf("body missing Message-ID header; got:\n%s", content)
	}
	// The DKIM-Signature should appear before Message-ID.
	dkimIdx := strings.Index(string(content), "DKIM-Signature:")
	msgidIdx := strings.Index(string(content), "Message-ID:")
	if dkimIdx > msgidIdx {
		t.Errorf("DKIM-Signature should come before Message-ID")
	}
}

func TestWriteWithoutDKIM(t *testing.T) {
	cfg := Config{
		Dir:        t.TempDir(),
		MessageTTL: 7 * 24 * time.Hour,
		Hostname:   "mail.example.com",
		// DKIMSign is nil — no signing
	}

	body := strings.NewReader("From: alice@example.com\r\nTo: bob@gmail.com\r\n\r\nHello\r\n")
	if err := Write(cfg, "alice@example.com", []string{"bob@gmail.com"}, body); err != nil {
		t.Fatalf("Write: %v", err)
	}

	msgDir := filepath.Join(cfg.Dir, "msg", "com", "example")
	bodies := readDir(t, msgDir)
	if len(bodies) != 1 {
		t.Fatalf("expected 1 body, got %d", len(bodies))
	}

	content, err := os.ReadFile(filepath.Join(msgDir, bodies[0]))
	if err != nil {
		t.Fatal(err)
	}

	// Should have Message-ID but no DKIM-Signature.
	if strings.Contains(string(content), "DKIM-Signature:") {
		t.Error("body should not contain DKIM-Signature when signing is disabled")
	}
	if !strings.Contains(string(content), "Message-ID:") {
		t.Error("body missing Message-ID header")
	}
}

func TestWriteDKIM_UnknownDomain(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	// Key configured for example.com but sender is other.com.
	keys := map[string]DKIMKey{
		"example.com": {Selector: "default", Key: priv},
	}

	cfg := Config{
		Dir:        t.TempDir(),
		MessageTTL: 7 * 24 * time.Hour,
		Hostname:   "mail.other.com",
		DKIMSign:   NewDKIMSigner(keys),
	}

	body := strings.NewReader("From: alice@other.com\r\nTo: bob@gmail.com\r\n\r\nHello\r\n")
	if err := Write(cfg, "alice@other.com", []string{"bob@gmail.com"}, body); err != nil {
		t.Fatalf("Write: %v", err)
	}

	msgDir := filepath.Join(cfg.Dir, "msg", "com", "other")
	bodies := readDir(t, msgDir)
	if len(bodies) != 1 {
		t.Fatalf("expected 1 body, got %d", len(bodies))
	}

	content, err := os.ReadFile(filepath.Join(msgDir, bodies[0]))
	if err != nil {
		t.Fatal(err)
	}

	// No key for other.com — should not be signed.
	if strings.Contains(string(content), "DKIM-Signature:") {
		t.Error("body should not contain DKIM-Signature for unconfigured domain")
	}
}

func TestSignDKIM_Verifiable(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	msg := "From: alice@example.com\r\nTo: bob@gmail.com\r\nSubject: test\r\n\r\nHello\r\n"
	signed, err := SignDKIM("example.com", "sel1", priv, strings.NewReader(msg))
	if err != nil {
		t.Fatalf("SignDKIM: %v", err)
	}

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(signed); err != nil {
		t.Fatal(err)
	}

	// Verify the signature using the public key via a fake DNS lookup.
	b64pub := base64.StdEncoding.EncodeToString(pub)
	txtRecord := "v=DKIM1; k=ed25519; p=" + b64pub

	verifications, err := dkim.VerifyWithOptions(&buf, &dkim.VerifyOptions{
		LookupTXT: func(domain string) ([]string, error) {
			return []string{txtRecord}, nil
		},
	})
	if err != nil {
		t.Fatalf("dkim.Verify: %v", err)
	}
	if len(verifications) == 0 {
		t.Fatal("no DKIM verifications returned")
	}
	for _, v := range verifications {
		if v.Err != nil {
			t.Errorf("DKIM verification failed: %v", v.Err)
		}
	}
}

func TestNewDKIMSigner_NilForEmptyKeys(t *testing.T) {
	signer := NewDKIMSigner(nil)
	if signer != nil {
		t.Error("expected nil signer for empty keys")
	}

	signer = NewDKIMSigner(map[string]DKIMKey{})
	if signer != nil {
		t.Error("expected nil signer for empty map")
	}
}
