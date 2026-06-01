package msgstore

import (
	"net"
	"testing"
	"time"
)

func TestParseRecipient(t *testing.T) {
	tests := []struct {
		name     string
		email    string
		wantAddr string
		wantExt  string
	}{
		{
			name:     "standard with extension",
			email:    "user+folder@example.com",
			wantAddr: "user@example.com",
			wantExt:  "folder",
		},
		{
			name:     "no extension",
			email:    "user@example.com",
			wantAddr: "user@example.com",
			wantExt:  "",
		},
		{
			name:     "empty extension",
			email:    "user+@example.com",
			wantAddr: "user@example.com",
			wantExt:  "",
		},
		{
			name:     "multiple plus signs",
			email:    "user+a+b@example.com",
			wantAddr: "user@example.com",
			wantExt:  "a+b",
		},
		{
			name:     "local user no domain",
			email:    "localuser",
			wantAddr: "localuser",
			wantExt:  "",
		},
		{
			name:     "extension only",
			email:    "+ext@example.com",
			wantAddr: "@example.com",
			wantExt:  "ext",
		},
		{
			name:     "extension no domain",
			email:    "user+ext",
			wantAddr: "user",
			wantExt:  "ext",
		},
		{
			name:     "empty string",
			email:    "",
			wantAddr: "",
			wantExt:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseRecipient(tt.email)
			if got.Address != tt.wantAddr {
				t.Errorf("ParseRecipient(%q).Address = %q, want %q", tt.email, got.Address, tt.wantAddr)
			}
			if got.Extension != tt.wantExt {
				t.Errorf("ParseRecipient(%q).Extension = %q, want %q", tt.email, got.Extension, tt.wantExt)
			}
		})
	}
}

func TestEnvelope_SpamResult(t *testing.T) {
	env := Envelope{
		From:           "sender@example.com",
		Recipients:     []string{"user@example.com"},
		ReceivedTime:   time.Now(),
		ClientIP:       net.ParseIP("192.0.2.1"),
		ClientHostname: "mail.example.com",
		SpamResult: &SpamResult{
			Score:   7.5,
			Action:  "flag",
			Checker: "rspamd",
		},
	}

	if env.SpamResult == nil {
		t.Fatal("SpamResult should not be nil")
	}
	if env.SpamResult.Score != 7.5 {
		t.Errorf("Score = %f, want 7.5", env.SpamResult.Score)
	}
	if env.SpamResult.Action != "flag" {
		t.Errorf("Action = %q, want %q", env.SpamResult.Action, "flag")
	}
	if env.SpamResult.Checker != "rspamd" {
		t.Errorf("Checker = %q, want %q", env.SpamResult.Checker, "rspamd")
	}
}

func TestEnvelope_SpamResultNil(t *testing.T) {
	env := Envelope{
		From:       "sender@example.com",
		Recipients: []string{"user@example.com"},
	}

	if env.SpamResult != nil {
		t.Error("SpamResult should be nil when no spam check performed")
	}
}
