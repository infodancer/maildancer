package envelope_test

import (
	"encoding/json"
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
	_ = f.Close()
	return f.Name()
}

func writeJSONEnv(t *testing.T, env map[string]interface{}) string {
	t.Helper()
	data, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return writeEnvFile(t, string(data))
}

func TestParse_Valid(t *testing.T) {
	path := writeJSONEnv(t, map[string]interface{}{
		"ttl":       "2099-01-01T00:00:00Z",
		"created":   "2026-01-01T00:00:00Z",
		"sender":    "bounces+alice=gmail.com@example.com",
		"recipient": "alice@gmail.com",
		"msgid":     "abc123",
		"origin":    "user@example.com",
	})
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
	if env.Origin != "user@example.com" {
		t.Errorf("Origin = %q", env.Origin)
	}
	if env.Created.IsZero() {
		t.Error("Created should not be zero")
	}
	if env.Expired() {
		t.Error("should not be expired")
	}
}

func TestParse_Expired(t *testing.T) {
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	path := writeJSONEnv(t, map[string]interface{}{
		"ttl":       past,
		"sender":    "a@b.com",
		"recipient": "c@d.com",
		"msgid":     "x",
	})
	env, err := envelope.Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !env.Expired() {
		t.Error("should be expired")
	}
}

func TestParse_MissingField(t *testing.T) {
	path := writeJSONEnv(t, map[string]interface{}{
		"ttl":    "2099-01-01T00:00:00Z",
		"sender": "a@b.com",
	})
	if _, err := envelope.Parse(path); err == nil {
		t.Error("expected error for missing fields")
	}
}

func TestParse_InvalidJSON(t *testing.T) {
	path := writeEnvFile(t, "not valid json")
	if _, err := envelope.Parse(path); err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestRecipientDomain(t *testing.T) {
	path := writeJSONEnv(t, map[string]interface{}{
		"ttl":       "2099-01-01T00:00:00Z",
		"sender":    "a@b.com",
		"recipient": "alice@gmail.com",
		"msgid":     "x",
	})
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
