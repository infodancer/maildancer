package smtp

import (
	"testing"
)

func TestSessionHelperFunctions(t *testing.T) {
	t.Run("sessionExtractRecipientDomain", func(t *testing.T) {
		tests := []struct {
			recipients []string
			expected   string
		}{
			{nil, "unknown"},
			{[]string{}, "unknown"},
			{[]string{"user@example.com"}, "example.com"},
			{[]string{"user@mail.example.org", "other@other.com"}, "mail.example.org"},
			{[]string{"nodomain"}, "unknown"},
		}

		for _, tt := range tests {
			got := sessionExtractRecipientDomain(tt.recipients)
			if got != tt.expected {
				t.Errorf("sessionExtractRecipientDomain(%v) = %q, want %q", tt.recipients, got, tt.expected)
			}
		}
	})

	t.Run("sessionExtractSenderDomain", func(t *testing.T) {
		tests := []struct {
			sender   string
			expected string
		}{
			{"", "unknown"},
			{"user@example.com", "example.com"},
			{"admin@mail.example.org", "mail.example.org"},
			{"nodomain", "unknown"},
		}

		for _, tt := range tests {
			got := sessionExtractSenderDomain(tt.sender)
			if got != tt.expected {
				t.Errorf("sessionExtractSenderDomain(%q) = %q, want %q", tt.sender, got, tt.expected)
			}
		}
	})

	t.Run("sessionExtractAuthDomain", func(t *testing.T) {
		tests := []struct {
			username string
			expected string
		}{
			{"", "unknown"},
			{"user@example.com", "example.com"},
			{"localuser", "local"},
		}

		for _, tt := range tests {
			got := sessionExtractAuthDomain(tt.username)
			if got != tt.expected {
				t.Errorf("sessionExtractAuthDomain(%q) = %q, want %q", tt.username, got, tt.expected)
			}
		}
	})

	t.Run("sessionIsLocalhost", func(t *testing.T) {
		tests := []struct {
			ip       string
			expected bool
		}{
			{"127.0.0.1", true},
			{"::1", true},
			{"127.0.0.2", true},
			{"localhost", true},
			{"192.168.1.1", false},
			{"10.0.0.1", false},
			{"8.8.8.8", false},
		}

		for _, tt := range tests {
			got := sessionIsLocalhost(tt.ip)
			if got != tt.expected {
				t.Errorf("sessionIsLocalhost(%q) = %v, want %v", tt.ip, got, tt.expected)
			}
		}
	})
}
