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
	MaxMessageSize int
	MaxRecipients  int
	Maildir        string
}

// ParseFlags parses command-line flags and returns a Flags struct.
func ParseFlags() *Flags {
	f := &Flags{}

	flag.StringVar(&f.ConfigPath, "config", "./smtpd.toml", "Path to configuration file")
	flag.StringVar(&f.Hostname, "hostname", "", "Server hostname")
	flag.StringVar(&f.LogLevel, "log-level", "", "Log level (debug, info, warn, error)")
	flag.StringVar(&f.Listen, "listen", "", "Listen address (replaces all config listeners)")
	flag.StringVar(&f.TLSCert, "tls-cert", "", "TLS certificate file path")
	flag.StringVar(&f.TLSKey, "tls-key", "", "TLS key file path")
	flag.IntVar(&f.MaxMessageSize, "max-message-size", 0, "Maximum message size in bytes")
	flag.IntVar(&f.MaxRecipients, "max-recipients", 0, "Maximum recipients per message")
	flag.StringVar(&f.Maildir, "maildir", "", "Maildir path for message delivery")

	flag.Parse()
	return f
}

// Load parses a TOML configuration file and returns the Config.
// If the file does not exist, returns the default configuration.
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

	// Merge file config into defaults
	cfg = mergeConfig(cfg, fileConfig.Smtpd)

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
			{Address: f.Listen, Mode: ModeSmtp},
		}
	}

	if f.TLSCert != "" {
		cfg.TLS.CertFile = f.TLSCert
	}

	if f.TLSKey != "" {
		cfg.TLS.KeyFile = f.TLSKey
	}

	if f.MaxMessageSize > 0 {
		cfg.Limits.MaxMessageSize = f.MaxMessageSize
	}

	if f.MaxRecipients > 0 {
		cfg.Limits.MaxRecipients = f.MaxRecipients
	}

	if f.Maildir != "" {
		cfg.Delivery.Maildir = f.Maildir
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

	if src.Limits.MaxMessageSize > 0 {
		dst.Limits.MaxMessageSize = src.Limits.MaxMessageSize
	}

	if src.Limits.MaxRecipients > 0 {
		dst.Limits.MaxRecipients = src.Limits.MaxRecipients
	}

	if src.Timeouts.Connection != "" {
		dst.Timeouts.Connection = src.Timeouts.Connection
	}

	if src.Timeouts.Command != "" {
		dst.Timeouts.Command = src.Timeouts.Command
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

	if src.Delivery.Maildir != "" {
		dst.Delivery.Maildir = src.Delivery.Maildir
	}

	return dst
}
