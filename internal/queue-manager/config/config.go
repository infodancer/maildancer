// Package config handles TOML configuration for queue-manager.
// It reads the [queue-manager] section from the shared config file used by all
// infodancer mail daemons.
package config

import (
	"fmt"
	"os"

	toml "github.com/pelletier/go-toml/v2"
)

// RateLimitConfig controls per-domain delivery rate limiting.
type RateLimitConfig struct {
	MessagesPerHour int                        // default limit; 0 = unlimited
	Burst           int                        // max envelopes per scan cycle per domain
	Domains         map[string]DomainRateLimit // per-domain overrides
}

// DomainRateLimit holds rate limit settings for a specific domain.
type DomainRateLimit struct {
	MessagesPerHour int // 0 = unlimited
	Burst           int // 0 = inherit default
}

// DSNConfig controls DSN bounce message generation.
type DSNConfig struct {
	Enabled        bool   // whether to generate DSNs on permanent failure (default: true)
	BounceTemplate string // path to custom template; empty = embedded default
}

// SessionManagerConfig holds connection details for the session-manager gRPC endpoint.
type SessionManagerConfig struct {
	Socket string // Unix domain socket path
}

// MetricsConfig controls the Prometheus metrics HTTP server.
type MetricsConfig struct {
	Enabled bool   `toml:"enabled"`
	Address string `toml:"address"`
	Path    string `toml:"path"`
}

// QueueManagerConfig holds all queue-manager configuration from the TOML file.
type QueueManagerConfig struct {
	Hostname         string
	DomainConfigPath string // base directory for per-domain config files
	RateLimit        RateLimitConfig
	DSN              DSNConfig
	SessionManager   SessionManagerConfig
	Metrics          MetricsConfig
}

// DefaultRateLimit returns sensible default rate limit settings.
func DefaultRateLimit() RateLimitConfig {
	return RateLimitConfig{
		MessagesPerHour: 20,
		Burst:           10,
	}
}

// TOML structs use pointer fields to distinguish "not set" from "set to 0".

type fileConfig struct {
	QueueManager tomlQueueManager `toml:"queue-manager"`
}

type tomlQueueManager struct {
	Hostname         string             `toml:"hostname"`
	DomainConfigPath string             `toml:"domain_config_path"`
	RateLimit        tomlRateLimit      `toml:"rate-limit"`
	DSN              tomlDSN            `toml:"dsn"`
	SessionManager   tomlSessionManager `toml:"session-manager"`
	Metrics          MetricsConfig      `toml:"metrics"`
}

type tomlSessionManager struct {
	Socket string `toml:"socket"`
}

type tomlDSN struct {
	Enabled        *bool  `toml:"enabled"`
	BounceTemplate string `toml:"bounce_template"`
}

type tomlRateLimit struct {
	MessagesPerHour *int                       `toml:"messages_per_hour"`
	Burst           *int                       `toml:"burst"`
	Domains         map[string]tomlDomainLimit `toml:"domains"`
}

type tomlDomainLimit struct {
	MessagesPerHour *int `toml:"messages_per_hour"`
	Burst           *int `toml:"burst"`
}

// Load reads the full queue-manager configuration from a shared TOML config
// file. Returns defaults if the file does not exist or contains no
// [queue-manager] section.
func Load(path string) (QueueManagerConfig, error) {
	cfg := QueueManagerConfig{
		RateLimit: DefaultRateLimit(),
		DSN:       DSNConfig{Enabled: true},
	}
	if path == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("reading config: %w", err)
	}

	var fc fileConfig
	if err := toml.Unmarshal(data, &fc); err != nil {
		return cfg, fmt.Errorf("parsing config: %w", err)
	}

	cfg.Hostname = fc.QueueManager.Hostname
	cfg.DomainConfigPath = fc.QueueManager.DomainConfigPath

	// Rate limit.
	rl := fc.QueueManager.RateLimit
	if rl.MessagesPerHour != nil {
		cfg.RateLimit.MessagesPerHour = *rl.MessagesPerHour
	}
	if rl.Burst != nil {
		cfg.RateLimit.Burst = *rl.Burst
	}
	if len(rl.Domains) > 0 {
		cfg.RateLimit.Domains = make(map[string]DomainRateLimit, len(rl.Domains))
		for domain, dl := range rl.Domains {
			d := DomainRateLimit{}
			if dl.MessagesPerHour != nil {
				d.MessagesPerHour = *dl.MessagesPerHour
			}
			if dl.Burst != nil {
				d.Burst = *dl.Burst
			}
			cfg.RateLimit.Domains[domain] = d
		}
	}

	// DSN.
	dsn := fc.QueueManager.DSN
	if dsn.Enabled != nil {
		cfg.DSN.Enabled = *dsn.Enabled
	}
	cfg.DSN.BounceTemplate = dsn.BounceTemplate

	// Session-manager.
	cfg.SessionManager.Socket = fc.QueueManager.SessionManager.Socket

	// Metrics.
	cfg.Metrics = fc.QueueManager.Metrics
	if cfg.Metrics.Address == "" {
		cfg.Metrics.Address = ":9100"
	}
	if cfg.Metrics.Path == "" {
		cfg.Metrics.Path = "/metrics"
	}

	return cfg, nil
}

// LoadRateLimit reads rate limit configuration from a shared TOML config file.
// Returns defaults if the file does not exist or contains no
// [queue-manager.rate-limit] section.
func LoadRateLimit(path string) (RateLimitConfig, error) {
	cfg, err := Load(path)
	return cfg.RateLimit, err
}
