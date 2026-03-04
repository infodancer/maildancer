package envelope_test

import (
	"os"
	"testing"
	"time"

	"github.com/infodancer/maildancer/internal/mail-remote/envelope"
)

func writeEnvFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "env.*")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return f.Name()
}

func TestParse_Valid(t *testing.T) {
	path := writeEnvFile(t, `TTL 2099-01-01T00:00:00Z
SENDER bounces+alice=gmail.com@example.com
RECIPIENT alice@gmail.com
MSGID abc123
`)
	env, err := envelope.Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if env.Sender != "bounces+alice=gmail.com@example.com" {
		t.Errorf("Sender = %q", env.Sender)
	}
	if env.Recipient != "alice@gmail.com" {
		t.Errorf("Recipient = %q", env.Recipient)
	}
	if env.MsgID != "abc123" {
		t.Errorf("MsgID = %q", env.MsgID)
	}
	if env.Expired() {
		t.Error("should not be expired")
	}
}

func TestParse_Expired(t *testing.T) {
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	path := writeEnvFile(t, "TTL "+past+"\nSENDER a@b.com\nRECIPIENT c@d.com\nMSGID x\n")
	env, err := envelope.Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !env.Expired() {
		t.Error("should be expired")
	}
}

func TestParse_MissingField(t *testing.T) {
	path := writeEnvFile(t, "TTL 2099-01-01T00:00:00Z\nSENDER a@b.com\n")
	if _, err := envelope.Parse(path); err == nil {
		t.Error("expected error for missing fields")
	}
}

func TestRecipientDomain(t *testing.T) {
	path := writeEnvFile(t, "TTL 2099-01-01T00:00:00Z\nSENDER a@b.com\nRECIPIENT alice@gmail.com\nMSGID x\n")
	env, err := envelope.Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	domain, err := env.RecipientDomain()
	if err != nil {
		t.Fatal(err)
	}
	if domain != "gmail.com" {
		t.Errorf("domain = %q, want gmail.com", domain)
	}
}
