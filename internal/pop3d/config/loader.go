package config

import (
	"flag"
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
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
	if _, err := toml.Decode(string(data), &fileConfig); err != nil {
		return cfg, fmt.Errorf("parsing config file: %w", err)
	}

	// Merge file config into defaults
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

	if src.Limits.MaxConnections > 0 {
		dst.Limits.MaxConnections = src.Limits.MaxConnections
	}

	if src.Timeouts.Connection != "" {
		dst.Timeouts.Connection = src.Timeouts.Connection
	}

	if src.Timeouts.Idle != "" {
		dst.Timeouts.Idle = src.Timeouts.Idle
	}

	return dst
}
