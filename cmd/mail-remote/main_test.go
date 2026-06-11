package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"
)

// errWriter is an io.Writer that always returns an error, used to simulate a
// broken stdout pipe.
type errWriter struct{ err error }

func (e errWriter) Write(_ []byte) (int, error) { return 0, e.err }

func TestWriteResultsAndCleanup_SuccessDeletesFiles(t *testing.T) {
	// Create two temporary "envelope" files.
	dir := t.TempDir()
	f1 := createTempFile(t, dir, "env1")
	f2 := createTempFile(t, dir, "env2")

	output := []recipientResult{
		{Envelope: f1, Status: "delivered", SMTPCode: 250},
		{Envelope: f2, Status: "perm_fail", SMTPCode: 550},
	}

	var buf bytes.Buffer
	if err := writeResultsAndCleanup(&buf, output, []string{f1, f2}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// JSON must be present in the buffer.
	var got []recipientResult
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("could not parse written JSON: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 results, got %d", len(got))
	}

	// Files must be deleted after a successful write.
	for _, p := range []string{f1, f2} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("envelope %s still exists after successful write", p)
		}
	}
}

func TestWriteResultsAndCleanup_EncodeFailureLeavesFiles(t *testing.T) {
	dir := t.TempDir()
	f1 := createTempFile(t, dir, "env1")
	f2 := createTempFile(t, dir, "env2")

	output := []recipientResult{
		{Envelope: f1, Status: "delivered", SMTPCode: 250},
		{Envelope: f2, Status: "perm_fail", SMTPCode: 550},
	}

	w := errWriter{err: io.ErrClosedPipe}
	err := writeResultsAndCleanup(w, output, []string{f1, f2})
	if err == nil {
		t.Fatal("expected error from encode failure, got nil")
	}

	// Files must NOT be deleted when the encode failed.
	for _, p := range []string{f1, f2} {
		if _, statErr := os.Stat(p); statErr != nil {
			t.Errorf("envelope %s was removed despite encode failure: %v", p, statErr)
		}
	}
}

func createTempFile(t *testing.T, dir, name string) string {
	t.Helper()
	p := dir + "/" + name
	if err := os.WriteFile(p, []byte("envelope data"), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReadStdinConfig(t *testing.T) {
	t.Run("valid JSON pipe", func(t *testing.T) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		input := `{"strategy":"smarthost","hostname":"mail.example.com","smarthost":"relay.example.com:587","smarthost_user":"alice","password":"s3cret"}`
		if _, err := w.WriteString(input); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}

		origStdin := os.Stdin
		os.Stdin = r
		defer func() { os.Stdin = origStdin }()

		cfg := readStdinConfig()
		if cfg == nil {
			t.Fatal("expected config, got nil")
		}
		if cfg.Strategy != "smarthost" {
			t.Errorf("Strategy = %q, want %q", cfg.Strategy, "smarthost")
		}
		if cfg.Smarthost != "relay.example.com:587" {
			t.Errorf("Smarthost = %q, want %q", cfg.Smarthost, "relay.example.com:587")
		}
		if cfg.Username != "alice" {
			t.Errorf("Username = %q, want %q", cfg.Username, "alice")
		}
		if cfg.Password != "s3cret" {
			t.Errorf("Password = %q, want %q", cfg.Password, "s3cret")
		}
		if cfg.Hostname != "mail.example.com" {
			t.Errorf("Hostname = %q, want %q", cfg.Hostname, "mail.example.com")
		}
	})

	t.Run("empty pipe returns nil", func(t *testing.T) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}

		origStdin := os.Stdin
		os.Stdin = r
		defer func() { os.Stdin = origStdin }()

		if cfg := readStdinConfig(); cfg != nil {
			t.Errorf("expected nil for empty pipe, got %+v", cfg)
		}
	})

	t.Run("invalid JSON returns nil", func(t *testing.T) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.WriteString("not json"); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}

		origStdin := os.Stdin
		os.Stdin = r
		defer func() { os.Stdin = origStdin }()

		if cfg := readStdinConfig(); cfg != nil {
			t.Errorf("expected nil for invalid JSON, got %+v", cfg)
		}
	})

	t.Run("direct strategy", func(t *testing.T) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		input := `{"strategy":"direct","hostname":"mx.example.com"}`
		if _, err := w.WriteString(input); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}

		origStdin := os.Stdin
		os.Stdin = r
		defer func() { os.Stdin = origStdin }()

		cfg := readStdinConfig()
		if cfg == nil {
			t.Fatal("expected config, got nil")
		}
		if cfg.Strategy != "direct" {
			t.Errorf("Strategy = %q, want %q", cfg.Strategy, "direct")
		}
		if cfg.Password != "" {
			t.Errorf("Password = %q, want empty", cfg.Password)
		}
		if cfg.Hostname != "mx.example.com" {
			t.Errorf("Hostname = %q, want %q", cfg.Hostname, "mx.example.com")
		}
	})
}
