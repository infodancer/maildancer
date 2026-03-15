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
	flag.Parse()
	return f
}

// Load parses a TOML configuration file and returns the Config.
// If the file does not exist, returns the default configuration.
// The loader reads from both [server] (shared settings) and [smtpd] (specific settings),
// with [smtpd] values taking precedence over [server] values.
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

	// Then merge smtpd-specific config (takes precedence)
	cfg = mergeConfig(cfg, fileConfig.Smtpd)

	// Merge top-level spamcheck config (shared across services)
	cfg = mergeSpamCheckConfig(cfg, fileConfig.SpamCheck)

	// Merge shared Redis config
	cfg = mergeRedisConfig(cfg, fileConfig.Redis)

	// Merge shared session-manager config
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

	return cfg
}

// LoadWithFlags loads configuration from the path specified in flags,
// then applies environment variable overrides and flag overrides.
// Precedence (highest to lowest): flags > environment variables > TOML config > defaults.
func LoadWithFlags(f *Flags) (Config, error) {
	cfg, err := Load(f.ConfigPath)
	if err != nil {
		return cfg, err
	}
	cfg = ApplyEnv(cfg)
	return ApplyFlags(cfg, f), nil
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

// mergeConfig merges smtpd-specific values from [smtpd] into dst.
// Global settings (hostname, domains_path, domains_data_path, TLS) come from
// [server] via mergeServerConfig and are not read from [smtpd].
func mergeConfig(dst, src Config) Config {
	if src.LogLevel != "" {
		dst.LogLevel = src.LogLevel
	}

	if len(src.Listeners) > 0 {
		dst.Listeners = src.Listeners
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

	// Merge spamcheck config (if defined in [smtpd.spamcheck])
	dst = mergeSpamCheckConfig(dst, src.SpamCheck)

	return dst
}

// mergeRedisConfig merges shared Redis settings into the config.
func mergeRedisConfig(dst Config, src RedisConfig) Config {
	if src.URL != "" {
		dst.Redis.URL = src.URL
	}
	if src.Password != "" {
		dst.Redis.Password = src.Password
	}
	return dst
}

// mergeSessionManagerConfig merges shared session-manager settings into the config.
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

// mergeSpamCheckConfig merges spamcheck settings into the config.
func mergeSpamCheckConfig(dst Config, src SpamCheckConfig) Config {
	if src.Enabled {
		dst.SpamCheck.Enabled = src.Enabled
	}
	if len(src.Checkers) > 0 {
		dst.SpamCheck.Checkers = src.Checkers
	}
	if src.Mode != "" {
		dst.SpamCheck.Mode = src.Mode
	}
	if src.FailMode != "" {
		dst.SpamCheck.FailMode = src.FailMode
	}
	if src.RejectThreshold != 0 {
		dst.SpamCheck.RejectThreshold = src.RejectThreshold
	}
	if src.TempFailThreshold != 0 {
		dst.SpamCheck.TempFailThreshold = src.TempFailThreshold
	}
	if src.AddHeaders {
		dst.SpamCheck.AddHeaders = src.AddHeaders
	}
	return dst
}
