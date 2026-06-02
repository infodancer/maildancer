package main

import (
	"os"
	"testing"
)

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
