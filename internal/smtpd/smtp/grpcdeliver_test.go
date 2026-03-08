package smtp

import (
	"testing"
)

func TestRedirectError_Error(t *testing.T) {
	tests := []struct {
		name     string
		addrs    []string
		wantPart string
	}{
		{
			name:     "single address",
			addrs:    []string{"user@example.com"},
			wantPart: "1 address(es)",
		},
		{
			name:     "multiple addresses",
			addrs:    []string{"a@example.com", "b@example.com"},
			wantPart: "2 address(es)",
		},
		{
			name:     "no addresses",
			addrs:    nil,
			wantPart: "0 address(es)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &RedirectError{Addresses: tt.addrs}
			msg := err.Error()
			if msg == "" {
				t.Error("expected non-empty error message")
			}
			if !contains(msg, tt.wantPart) {
				t.Errorf("error %q does not contain %q", msg, tt.wantPart)
			}
		})
	}
}

func TestJoinAddresses(t *testing.T) {
	tests := []struct {
		name  string
		addrs []string
		want  string
	}{
		{"empty", nil, "(none)"},
		{"single", []string{"a@b.com"}, "a@b.com"},
		{"multiple", []string{"a@b.com", "c@d.com"}, "a@b.com, c@d.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := joinAddresses(tt.addrs)
			if got != tt.want {
				t.Errorf("joinAddresses(%v) = %q, want %q", tt.addrs, got, tt.want)
			}
		})
	}
}

func TestNewGrpcDeliveryAgent_Defaults(t *testing.T) {
	agent := NewGrpcDeliveryAgent(GrpcDeliveryConfig{
		MailSessionCmd: "/usr/local/bin/mail-session",
		BasePath:       "/var/mail/store",
	})
	if agent.cfg.StoreType != "maildir" {
		t.Errorf("expected default StoreType 'maildir', got %q", agent.cfg.StoreType)
	}
	if agent.cfg.Logger == nil {
		t.Error("expected non-nil default logger")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr))
}

func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
