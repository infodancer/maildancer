package config

import "os"

// ApplyEnv applies environment variable overrides to the configuration.
// Environment variables take precedence over TOML config but are overridden by command-line flags.
func ApplyEnv(cfg Config) Config {
	if v := os.Getenv("SMTPD_HOSTNAME"); v != "" {
		cfg.Hostname = v
	}
	if v := os.Getenv("SMTPD_LOG_LEVEL"); v != "" {
		cfg.LogLevel = v
	}
	if v := os.Getenv("SMTPD_TLS_CERT_FILE"); v != "" {
		cfg.TLS.CertFile = v
	}
	if v := os.Getenv("SMTPD_TLS_KEY_FILE"); v != "" {
		cfg.TLS.KeyFile = v
	}
	// Apply shared Redis overrides
	if v := os.Getenv("REDIS_URL"); v != "" {
		cfg.Redis.URL = v
	}
	if v := os.Getenv("REDIS_PASSWORD"); v != "" {
		cfg.Redis.Password = v
	}

	// Apply rspamd overrides to the first rspamd checker found
	if v := os.Getenv("SMTPD_RSPAMD_URL"); v != "" {
		applyRspamdURL(&cfg, v)
	}
	if v := os.Getenv("SMTPD_RSPAMD_PASSWORD"); v != "" {
		applyRspamdPassword(&cfg, v)
	}

	return cfg
}

// applyRspamdURL sets the URL for the first rspamd checker, creating one if none exists.
func applyRspamdURL(cfg *Config, url string) {
	for i := range cfg.SpamCheck.Checkers {
		if cfg.SpamCheck.Checkers[i].Type == "rspamd" {
			cfg.SpamCheck.Checkers[i].URL = url
			return
		}
	}
	// No rspamd checker found; create one
	enabled := true
	cfg.SpamCheck.Checkers = append(cfg.SpamCheck.Checkers, SpamCheckerConfig{
		Type:    "rspamd",
		Enabled: &enabled,
		URL:     url,
	})
	cfg.SpamCheck.Enabled = true
}

// applyRspamdPassword sets the password for the first rspamd checker, creating one if none exists.
func applyRspamdPassword(cfg *Config, password string) {
	for i := range cfg.SpamCheck.Checkers {
		if cfg.SpamCheck.Checkers[i].Type == "rspamd" {
			cfg.SpamCheck.Checkers[i].Password = password
			return
		}
	}
	// No rspamd checker found; create one
	enabled := true
	cfg.SpamCheck.Checkers = append(cfg.SpamCheck.Checkers, SpamCheckerConfig{
		Type:     "rspamd",
		Enabled:  &enabled,
		Password: password,
	})
	cfg.SpamCheck.Enabled = true
}
