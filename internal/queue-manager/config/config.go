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
	RateLimit tomlRateLimit `toml:"rate-limit"`
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

// LoadRateLimit reads rate limit configuration from a shared TOML config file.
// Returns defaults if the file does not exist or contains no
// [queue-manager.rate-limit] section.
func LoadRateLimit(path string) (RateLimitConfig, error) {
	cfg := DefaultRateLimit()
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

	rl := fc.QueueManager.RateLimit
	if rl.MessagesPerHour != nil {
		cfg.MessagesPerHour = *rl.MessagesPerHour
	}
	if rl.Burst != nil {
		cfg.Burst = *rl.Burst
	}
	if len(rl.Domains) > 0 {
		cfg.Domains = make(map[string]DomainRateLimit, len(rl.Domains))
		for domain, dl := range rl.Domains {
			d := DomainRateLimit{}
			if dl.MessagesPerHour != nil {
				d.MessagesPerHour = *dl.MessagesPerHour
			}
			if dl.Burst != nil {
				d.Burst = *dl.Burst
			}
			cfg.Domains[domain] = d
		}
	}

	return cfg, nil
}
