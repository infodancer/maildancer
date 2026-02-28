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
	DeliveryType   string
	DeliveryPath   string
	DomainsPath    string
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
	flag.StringVar(&f.DeliveryType, "delivery-type", "", "Delivery storage type (e.g., maildir)")
	flag.StringVar(&f.DeliveryPath, "delivery-path", "", "Delivery storage base path")
	flag.StringVar(&f.DomainsPath, "domains-path", "", "Path to per-domain configuration directories")

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

	if f.DeliveryType != "" {
		cfg.Delivery.Type = f.DeliveryType
	}

	if f.DeliveryPath != "" {
		cfg.Delivery.BasePath = f.DeliveryPath
	}

	if f.DomainsPath != "" {
		cfg.DomainsPath = f.DomainsPath
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

	if src.Delivery.Type != "" {
		dst.Delivery.Type = src.Delivery.Type
	}

	if src.Delivery.BasePath != "" {
		dst.Delivery.BasePath = src.Delivery.BasePath
	}

	if len(src.Delivery.Options) > 0 {
		if dst.Delivery.Options == nil {
			dst.Delivery.Options = make(map[string]string)
		}
		for k, v := range src.Delivery.Options {
			dst.Delivery.Options[k] = v
		}
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

	if src.DomainsPath != "" {
		dst.DomainsPath = src.DomainsPath
	}

	if src.DomainsDataPath != "" {
		dst.DomainsDataPath = src.DomainsDataPath
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

	if src.Delivery.Type != "" {
		dst.Delivery.Type = src.Delivery.Type
	}

	if src.Delivery.BasePath != "" {
		dst.Delivery.BasePath = src.Delivery.BasePath
	}

	if len(src.Delivery.Options) > 0 {
		if dst.Delivery.Options == nil {
			dst.Delivery.Options = make(map[string]string)
		}
		for k, v := range src.Delivery.Options {
			dst.Delivery.Options[k] = v
		}
	}

	// Merge encryption config
	if src.Encryption.Enabled {
		dst.Encryption.Enabled = src.Encryption.Enabled
	}
	if src.Encryption.KeyBackendType != "" {
		dst.Encryption.KeyBackendType = src.Encryption.KeyBackendType
	}
	if src.Encryption.KeyBackend != "" {
		dst.Encryption.KeyBackend = src.Encryption.KeyBackend
	}
	if src.Encryption.CredentialBackend != "" {
		dst.Encryption.CredentialBackend = src.Encryption.CredentialBackend
	}
	if src.Encryption.Options != nil {
		if dst.Encryption.Options == nil {
			dst.Encryption.Options = make(map[string]string)
		}
		for k, v := range src.Encryption.Options {
			dst.Encryption.Options[k] = v
		}
	}

	// Merge spamcheck config (if defined in [smtpd.spamcheck])
	dst = mergeSpamCheckConfig(dst, src.SpamCheck)

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
