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

	if cfg.Listeners[0].Address != ":110" {
		t.Errorf("expected listener address ':110', got %q", cfg.Listeners[0].Address)
	}

	if cfg.Listeners[0].Mode != ModePop3 {
		t.Errorf("expected listener mode 'pop3', got %q", cfg.Listeners[0].Mode)
	}

	if cfg.TLS.MinVersion != "1.2" {
		t.Errorf("expected TLS min_version '1.2', got %q", cfg.TLS.MinVersion)
	}

	if cfg.Limits.MaxConnections != 100 {
		t.Errorf("expected max_connections 100, got %d", cfg.Limits.MaxConnections)
	}

	if cfg.Timeouts.Connection != "10m" {
		t.Errorf("expected connection timeout '10m', got %q", cfg.Timeouts.Connection)
	}

	if cfg.Timeouts.Idle != "5m" {
		t.Errorf("expected idle timeout '5m', got %q", cfg.Timeouts.Idle)
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
				c.Listeners = []ListenerConfig{{Address: "", Mode: ModePop3}}
			},
			wantErr: true,
		},
		{
			name: "listener with invalid mode",
			modify: func(c *Config) {
				c.Listeners = []ListenerConfig{{Address: ":110", Mode: "invalid"}}
			},
			wantErr: true,
		},
		{
			name:    "zero max_connections",
			modify:  func(c *Config) { c.Limits.MaxConnections = 0 },
			wantErr: true,
		},
		{
			name:    "negative max_connections",
			modify:  func(c *Config) { c.Limits.MaxConnections = -1 },
			wantErr: true,
		},
		{
			name:    "invalid connection timeout",
			modify:  func(c *Config) { c.Timeouts.Connection = "invalid" },
			wantErr: true,
		},
		{
			name:    "invalid idle timeout",
			modify:  func(c *Config) { c.Timeouts.Idle = "invalid" },
			wantErr: true,
		},
		{
			name:    "invalid TLS min_version",
			modify:  func(c *Config) { c.TLS.MinVersion = "1.4" },
			wantErr: true,
		},
		{
			name: "valid pop3 mode",
			modify: func(c *Config) {
				c.Listeners = []ListenerConfig{{Address: ":110", Mode: ModePop3}}
			},
			wantErr: false,
		},
		{
			name: "valid pop3s mode",
			modify: func(c *Config) {
				c.Listeners = []ListenerConfig{{Address: ":995", Mode: ModePop3s}}
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
		{"", tls.VersionTLS12},        // default
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
		{"10m", 10 * time.Minute},
		{"1h", 1 * time.Hour},
		{"30s", 30 * time.Second},
		{"", 10 * time.Minute},        // default
		{"invalid", 10 * time.Minute}, // invalid falls back to default
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

func TestIdleTimeout(t *testing.T) {
	tests := []struct {
		value    string
		expected time.Duration
	}{
		{"5m", 5 * time.Minute},
		{"30s", 30 * time.Second},
		{"2m", 2 * time.Minute},
		{"", 5 * time.Minute},        // default
		{"invalid", 5 * time.Minute}, // invalid falls back to default
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			cfg := TimeoutsConfig{Idle: tt.value}
			if got := cfg.IdleTimeout(); got != tt.expected {
				t.Errorf("IdleTimeout() = %v, want %v", got, tt.expected)
			}
		})
	}
}
