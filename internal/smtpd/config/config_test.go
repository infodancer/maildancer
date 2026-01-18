package config

import (
	"crypto/tls"
	"testing"
	"time"
)

func TestDefault(t *testing.T) {
	cfg := Default()

	if cfg.Hostname != "localhost" {
		t.Errorf("expected hostname 'localhost', got %q", cfg.Hostname)
	}

	if cfg.LogLevel != "info" {
		t.Errorf("expected log_level 'info', got %q", cfg.LogLevel)
	}

	if len(cfg.Listeners) != 1 {
		t.Fatalf("expected 1 listener, got %d", len(cfg.Listeners))
	}

	if cfg.Listeners[0].Address != ":25" {
		t.Errorf("expected listener address ':25', got %q", cfg.Listeners[0].Address)
	}

	if cfg.Listeners[0].Mode != ModeSmtp {
		t.Errorf("expected listener mode 'smtp', got %q", cfg.Listeners[0].Mode)
	}

	if cfg.TLS.MinVersion != "1.2" {
		t.Errorf("expected TLS min_version '1.2', got %q", cfg.TLS.MinVersion)
	}

	if cfg.Limits.MaxMessageSize != 26214400 {
		t.Errorf("expected max_message_size 26214400, got %d", cfg.Limits.MaxMessageSize)
	}

	if cfg.Limits.MaxRecipients != 100 {
		t.Errorf("expected max_recipients 100, got %d", cfg.Limits.MaxRecipients)
	}

	if cfg.Timeouts.Connection != "5m" {
		t.Errorf("expected connection timeout '5m', got %q", cfg.Timeouts.Connection)
	}

	if cfg.Timeouts.Command != "1m" {
		t.Errorf("expected command timeout '1m', got %q", cfg.Timeouts.Command)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*Config)
		wantErr bool
	}{
		{
			name:    "valid default config",
			modify:  func(c *Config) {},
			wantErr: false,
		},
		{
			name:    "empty hostname",
			modify:  func(c *Config) { c.Hostname = "" },
			wantErr: true,
		},
		{
			name:    "no listeners",
			modify:  func(c *Config) { c.Listeners = nil },
			wantErr: true,
		},
		{
			name: "listener with empty address",
			modify: func(c *Config) {
				c.Listeners = []ListenerConfig{{Address: "", Mode: ModeSmtp}}
			},
			wantErr: true,
		},
		{
			name: "listener with invalid mode",
			modify: func(c *Config) {
				c.Listeners = []ListenerConfig{{Address: ":25", Mode: "invalid"}}
			},
			wantErr: true,
		},
		{
			name:    "zero max_message_size",
			modify:  func(c *Config) { c.Limits.MaxMessageSize = 0 },
			wantErr: true,
		},
		{
			name:    "negative max_message_size",
			modify:  func(c *Config) { c.Limits.MaxMessageSize = -1 },
			wantErr: true,
		},
		{
			name:    "zero max_recipients",
			modify:  func(c *Config) { c.Limits.MaxRecipients = 0 },
			wantErr: true,
		},
		{
			name:    "invalid connection timeout",
			modify:  func(c *Config) { c.Timeouts.Connection = "invalid" },
			wantErr: true,
		},
		{
			name:    "invalid command timeout",
			modify:  func(c *Config) { c.Timeouts.Command = "invalid" },
			wantErr: true,
		},
		{
			name:    "invalid TLS min_version",
			modify:  func(c *Config) { c.TLS.MinVersion = "1.4" },
			wantErr: true,
		},
		{
			name: "valid submission mode",
			modify: func(c *Config) {
				c.Listeners = []ListenerConfig{{Address: ":587", Mode: ModeSubmission}}
			},
			wantErr: false,
		},
		{
			name: "valid smtps mode",
			modify: func(c *Config) {
				c.Listeners = []ListenerConfig{{Address: ":465", Mode: ModeSmtps}}
			},
			wantErr: false,
		},
		{
			name: "valid alt mode",
			modify: func(c *Config) {
				c.Listeners = []ListenerConfig{{Address: ":2525", Mode: ModeAlt}}
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Default()
			tt.modify(&cfg)
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMinTLSVersion(t *testing.T) {
	tests := []struct {
		version  string
		expected uint16
	}{
		{"1.0", tls.VersionTLS10},
		{"1.1", tls.VersionTLS11},
		{"1.2", tls.VersionTLS12},
		{"1.3", tls.VersionTLS13},
		{"", tls.VersionTLS12},      // default
		{"invalid", tls.VersionTLS12}, // invalid falls back to default
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			cfg := TLSConfig{MinVersion: tt.version}
			if got := cfg.MinTLSVersion(); got != tt.expected {
				t.Errorf("MinTLSVersion() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestConnectionTimeout(t *testing.T) {
	tests := []struct {
		value    string
		expected time.Duration
	}{
		{"5m", 5 * time.Minute},
		{"1h", 1 * time.Hour},
		{"30s", 30 * time.Second},
		{"", 5 * time.Minute},       // default
		{"invalid", 5 * time.Minute}, // invalid falls back to default
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			cfg := TimeoutsConfig{Connection: tt.value}
			if got := cfg.ConnectionTimeout(); got != tt.expected {
				t.Errorf("ConnectionTimeout() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestCommandTimeout(t *testing.T) {
	tests := []struct {
		value    string
		expected time.Duration
	}{
		{"1m", 1 * time.Minute},
		{"30s", 30 * time.Second},
		{"2m", 2 * time.Minute},
		{"", 1 * time.Minute},       // default
		{"invalid", 1 * time.Minute}, // invalid falls back to default
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			cfg := TimeoutsConfig{Command: tt.value}
			if got := cfg.CommandTimeout(); got != tt.expected {
				t.Errorf("CommandTimeout() = %v, want %v", got, tt.expected)
			}
		})
	}
}
