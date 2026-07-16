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
}

// ParseFlags parses command-line flags and returns a Flags struct.
func ParseFlags() *Flags {
	f := &Flags{}

	flag.StringVar(&f.ConfigPath, "config", "./imapd.toml", "Path to configuration file")
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
// The loader reads from [server] for global settings (hostname, paths, TLS) and
// [imapd] for protocol-specific settings (log_level, listeners, timeouts, limits).
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

	// Merge top-level [redis] section (shared across services)
	if fileConfig.Redis.URL != "" {
		cfg.Redis.URL = fileConfig.Redis.URL
	}
	if fileConfig.Redis.Password != "" {
		cfg.Redis.Password = fileConfig.Redis.Password
	}

	// Then merge imapd-specific config (takes precedence)
	cfg = mergeConfig(cfg, fileConfig.Imapd)

	// Merge top-level session-manager config
	cfg = mergeSessionManagerConfig(cfg, fileConfig.SessionManager)

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
			{Address: f.Listen, Mode: ModeImap},
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
	cfg = ApplyFlags(cfg, f)
	return cfg, nil
}

// mergeServerConfig merges shared server settings into the config.
func mergeServerConfig(dst Config, src ServerConfig) Config {
	if src.Hostname != "" {
		dst.Hostname = src.Hostname
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

// mergeSessionManagerConfig merges the top-level [session-manager] section into the config.
func mergeSessionManagerConfig(dst Config, src SessionManagerConfig) Config {
	if src.Socket != "" {
		dst.SessionManager.Socket = src.Socket
	}
	if src.Address != "" {
		dst.SessionManager.Address = src.Address
	}
	if src.CACert != "" {
		dst.SessionManager.CACert = src.CACert
	}
	if src.ClientCert != "" {
		dst.SessionManager.ClientCert = src.ClientCert
	}
	if src.ClientKey != "" {
		dst.SessionManager.ClientKey = src.ClientKey
	}
	return dst
}

// mergeConfig merges imapd-specific values from [imapd] into dst. It runs
// after mergeServerConfig, so an [imapd.tls] block overrides [server.tls] --
// section beats shared, the same order every other setting follows. The
// hostname and domain paths stay [server]-only.
func mergeConfig(dst, src Config) Config {
	if src.LogLevel != "" {
		dst.LogLevel = src.LogLevel
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

	if len(src.Listeners) > 0 {
		dst.Listeners = src.Listeners
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

	if src.Timeouts.SessionKeepalive != "" {
		dst.Timeouts.SessionKeepalive = src.Timeouts.SessionKeepalive
	}

	if src.Timeouts.UpstreamSessionIdle != "" {
		dst.Timeouts.UpstreamSessionIdle = src.Timeouts.UpstreamSessionIdle
	}

	if src.Limits.MaxConnections > 0 {
		dst.Limits.MaxConnections = src.Limits.MaxConnections
	}

	if src.Limits.MaxMessageSize > 0 {
		dst.Limits.MaxMessageSize = src.Limits.MaxMessageSize
	}

	// Metrics: enabled is a boolean so merge if source has any non-zero value
	if src.Metrics.Enabled {
		dst.Metrics.Enabled = src.Metrics.Enabled
	}

	if src.Metrics.Address != "" {
		dst.Metrics.Address = src.Metrics.Address
	}

	if src.Metrics.Path != "" {
		dst.Metrics.Path = src.Metrics.Path
	}

	if src.Rspamd.Controller != "" {
		dst.Rspamd.Controller = src.Rspamd.Controller
	}

	if src.Rspamd.JunkFolder != "" {
		dst.Rspamd.JunkFolder = src.Rspamd.JunkFolder
	}

	if src.Redis.URL != "" {
		dst.Redis.URL = src.Redis.URL
	}
	if src.Redis.Password != "" {
		dst.Redis.Password = src.Redis.Password
	}

	return dst
}
