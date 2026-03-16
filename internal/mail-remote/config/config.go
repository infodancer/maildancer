// Package config provides configuration for mail-remote.
// Settings can come from a shared TOML config file ([mail-remote] section),
// environment variables, or CLI flags. Precedence: flags > env > TOML > defaults.
package config

import (
	"fmt"
	"os"

	toml "github.com/pelletier/go-toml/v2"
)

// Config holds mail-remote runtime configuration.
type Config struct {
	// Hostname is the EHLO hostname (used for both smarthost and MX delivery).
	// Inherited from [server].hostname if not set in [mail-remote].
	Hostname string `toml:"hostname"`

	// Smarthost is the relay address in host:port form (e.g. "relay.example.com:587").
	// When set, outbound mail is relayed via this host instead of direct MX delivery.
	Smarthost string `toml:"smarthost"`

	// User is the SMTP AUTH username for smarthost relay.
	// Password comes from stdin JSON config or MAIL_REMOTE_PASSWORD env var.
	User string `toml:"user"`

	// SmarthostMaxTransactionsPerConn limits MAIL FROM transactions per smarthost connection.
	// Envelopes beyond the limit are deferred for retry on the next queue scan.
	// Default: 100 (smarthosts are trusted relays).
	SmarthostMaxTransactionsPerConn int `toml:"smarthost_max_transactions_per_conn"`

	// RemoteMX holds settings for direct MX delivery.
	RemoteMX RemoteMXConfig `toml:"remote-mx"`
}

// RemoteMXConfig holds settings specific to direct MX delivery.
type RemoteMXConfig struct {
	// MaxTransactionsPerConn limits MAIL FROM transactions per connection.
	// Envelopes beyond the limit are deferred for retry on the next queue scan.
	// Default: 25 (conservative for foreign servers).
	MaxTransactionsPerConn int `toml:"max_transactions_per_conn"`
}

// fileConfig is the top-level TOML structure for the shared config file.
type fileConfig struct {
	Server     serverConfig `toml:"server"`
	MailRemote Config       `toml:"mail-remote"`
}

// serverConfig holds shared settings from the [server] section.
type serverConfig struct {
	Hostname string `toml:"hostname"`
}

// Default returns a Config with sensible defaults.
func Default() Config {
	return Config{
		SmarthostMaxTransactionsPerConn: 100,
		RemoteMX: RemoteMXConfig{
			MaxTransactionsPerConn: 25,
		},
	}
}

// Load reads a TOML config file and returns the merged Config.
// Reads from [server] for shared settings and [mail-remote] for specific settings,
// with [mail-remote] taking precedence.
func Load(path string) (Config, error) {
	cfg := Default()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("reading config file: %w", err)
	}

	var fc fileConfig
	if err := toml.Unmarshal(data, &fc); err != nil {
		return cfg, fmt.Errorf("parsing config file: %w", err)
	}

	// Shared server hostname as baseline.
	if fc.Server.Hostname != "" {
		cfg.Hostname = fc.Server.Hostname
	}

	// [mail-remote] section overrides.
	if fc.MailRemote.Hostname != "" {
		cfg.Hostname = fc.MailRemote.Hostname
	}
	if fc.MailRemote.Smarthost != "" {
		cfg.Smarthost = fc.MailRemote.Smarthost
	}
	if fc.MailRemote.User != "" {
		cfg.User = fc.MailRemote.User
	}
	if fc.MailRemote.SmarthostMaxTransactionsPerConn > 0 {
		cfg.SmarthostMaxTransactionsPerConn = fc.MailRemote.SmarthostMaxTransactionsPerConn
	}
	if fc.MailRemote.RemoteMX.MaxTransactionsPerConn > 0 {
		cfg.RemoteMX.MaxTransactionsPerConn = fc.MailRemote.RemoteMX.MaxTransactionsPerConn
	}

	return cfg, nil
}

// ApplyEnv applies environment variable overrides.
func ApplyEnv(cfg Config) Config {
	if v := os.Getenv("MAIL_REMOTE_HOSTNAME"); v != "" {
		cfg.Hostname = v
	}
	if v := os.Getenv("MAIL_REMOTE_SMARTHOST"); v != "" {
		cfg.Smarthost = v
	}
	if v := os.Getenv("MAIL_REMOTE_SMARTHOST_USER"); v != "" {
		cfg.User = v
	}
	return cfg
}
