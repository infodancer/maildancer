package config

import (
	"flag"
	"fmt"
	"os"

	toml "github.com/pelletier/go-toml/v2"
)

// Flags holds command-line flag values.
type Flags struct {
	ConfigPath     string
	Hostname       string
	LogLevel       string
	Listen         string
	TLSCert        string
	TLSKey         string
	MaxConnections int
	Maildir        string
	DomainsPath    string
}

// ParseFlags parses command-line flags and returns a Flags struct.
func ParseFlags() *Flags {
	f := &Flags{}

	flag.StringVar(&f.ConfigPath, "config", "./pop3d.toml", "Path to configuration file")
	flag.StringVar(&f.Hostname, "hostname", "", "Server hostname")
	flag.StringVar(&f.LogLevel, "log-level", "", "Log level (debug, info, warn, error)")
	flag.StringVar(&f.Listen, "listen", "", "Listen address (replaces all config listeners)")
	flag.StringVar(&f.TLSCert, "tls-cert", "", "TLS certificate file path")
	flag.StringVar(&f.TLSKey, "tls-key", "", "TLS key file path")
	flag.IntVar(&f.MaxConnections, "max-connections", 0, "Maximum concurrent connections")
	flag.StringVar(&f.Maildir, "maildir", "", "Maildir path for message storage")
	flag.StringVar(&f.DomainsPath, "domains", "", "Path to per-domain configuration directory")

	flag.Parse()
	return f
}

// Load parses a TOML configuration file and returns the Config.
// If the file does not exist, returns the default configuration.
// The loader reads from both [server] (shared settings) and [pop3d] (specific settings),
// with [pop3d] values taking precedence over [server] values.
func Load(path string) (Config, error) {
	cfg := Default()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("reading config file: %w", err)
	}

	var fileConfig FileConfig
	if err := toml.Unmarshal(data, &fileConfig); err != nil {
		return cfg, fmt.Errorf("parsing config file: %w", err)
	}

	// First merge shared server config into defaults
	cfg = mergeServerConfig(cfg, fileConfig.Server)

	// Then merge pop3d-specific config (takes precedence)
	cfg = mergeConfig(cfg, fileConfig.Pop3d)

	return cfg, nil
}

// ApplyFlags merges command-line flag values into the config.
// Non-zero/non-empty flag values override config file values.
func ApplyFlags(cfg Config, f *Flags) Config {
	if f.Hostname != "" {
		cfg.Hostname = f.Hostname
	}

	if f.LogLevel != "" {
		cfg.LogLevel = f.LogLevel
	}

	if f.Listen != "" {
		// -listen flag replaces ALL listeners with a single listener
		cfg.Listeners = []ListenerConfig{
			{Address: f.Listen, Mode: ModePop3},
		}
	}

	if f.TLSCert != "" {
		cfg.TLS.CertFile = f.TLSCert
	}

	if f.TLSKey != "" {
		cfg.TLS.KeyFile = f.TLSKey
	}

	if f.MaxConnections > 0 {
		cfg.Limits.MaxConnections = f.MaxConnections
	}

	if f.Maildir != "" {
		cfg.Maildir = f.Maildir
	}

	if f.DomainsPath != "" {
		cfg.DomainsPath = f.DomainsPath
	}

	return cfg
}

// LoadWithFlags loads configuration from the path specified in flags,
// then applies flag overrides.
func LoadWithFlags(f *Flags) (Config, error) {
	cfg, err := Load(f.ConfigPath)
	if err != nil {
		return cfg, err
	}
	return ApplyFlags(cfg, f), nil
}

// mergeServerConfig merges shared server settings into the config.
func mergeServerConfig(dst Config, src ServerConfig) Config {
	if src.Hostname != "" {
		dst.Hostname = src.Hostname
	}

	if src.Maildir != "" {
		dst.Maildir = src.Maildir
	}

	if src.DomainsPath != "" {
		dst.DomainsPath = src.DomainsPath
	}

	if src.TLS.CertFile != "" {
		dst.TLS.CertFile = src.TLS.CertFile
	}

	if src.TLS.KeyFile != "" {
		dst.TLS.KeyFile = src.TLS.KeyFile
	}

	if src.TLS.MinVersion != "" {
		dst.TLS.MinVersion = src.TLS.MinVersion
	}

	return dst
}

// mergeConfig merges non-zero values from src into dst.
func mergeConfig(dst, src Config) Config {
	if src.Hostname != "" {
		dst.Hostname = src.Hostname
	}

	if src.LogLevel != "" {
		dst.LogLevel = src.LogLevel
	}

	if len(src.Listeners) > 0 {
		dst.Listeners = src.Listeners
	}

	if src.TLS.CertFile != "" {
		dst.TLS.CertFile = src.TLS.CertFile
	}

	if src.TLS.KeyFile != "" {
		dst.TLS.KeyFile = src.TLS.KeyFile
	}

	if src.TLS.MinVersion != "" {
		dst.TLS.MinVersion = src.TLS.MinVersion
	}

	if src.Timeouts.Connection != "" {
		dst.Timeouts.Connection = src.Timeouts.Connection
	}

	if src.Timeouts.Command != "" {
		dst.Timeouts.Command = src.Timeouts.Command
	}

	if src.Timeouts.Idle != "" {
		dst.Timeouts.Idle = src.Timeouts.Idle
	}

	if src.Limits.MaxConnections > 0 {
		dst.Limits.MaxConnections = src.Limits.MaxConnections
	}

	// Metrics: enabled is explicitly set (boolean), so we merge if source has any non-zero value
	if src.Metrics.Enabled {
		dst.Metrics.Enabled = src.Metrics.Enabled
	}

	if src.Metrics.Address != "" {
		dst.Metrics.Address = src.Metrics.Address
	}

	if src.Metrics.Path != "" {
		dst.Metrics.Path = src.Metrics.Path
	}

	if src.Maildir != "" {
		dst.Maildir = src.Maildir
	}

	if src.DomainsPath != "" {
		dst.DomainsPath = src.DomainsPath
	}

	if src.DomainsDataPath != "" {
		dst.DomainsDataPath = src.DomainsDataPath
	}

	// Merge auth config
	if src.Auth.Type != "" {
		dst.Auth.Type = src.Auth.Type
	}
	if src.Auth.CredentialBackend != "" {
		dst.Auth.CredentialBackend = src.Auth.CredentialBackend
	}
	if src.Auth.KeyBackend != "" {
		dst.Auth.KeyBackend = src.Auth.KeyBackend
	}
	if src.Auth.Options != nil {
		if dst.Auth.Options == nil {
			dst.Auth.Options = make(map[string]string)
		}
		for k, v := range src.Auth.Options {
			dst.Auth.Options[k] = v
		}
	}

	return dst
}
