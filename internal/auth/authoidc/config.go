package authoidc

import (
	"fmt"
	"os"

	"github.com/pelletier/go-toml/v2"
)

// Config is the top-level auth-oidc configuration.
type Config struct {
	Server  ServerConfig   `toml:"server"`
	Clients []ClientConfig `toml:"client"`
}

// ServerConfig holds server-level settings.
type ServerConfig struct {
	Listen         string `toml:"listen"`
	DataDir        string `toml:"data_dir"`
	DomainDataPath string `toml:"domain_data_path"`
	JWTTTLSec      int64  `toml:"jwt_ttl_sec"`
	SessionTTLSec  int64  `toml:"session_ttl_sec"`
}

// ClientConfig describes a registered OIDC relying party.
// Secret is empty for public clients (PKCE only).
type ClientConfig struct {
	Domain       string   `toml:"domain"`
	ID           string   `toml:"id"`
	Secret       string   `toml:"secret"`
	RedirectURIs []string `toml:"redirect_uris"`
}

// Load reads and parses a TOML config file, applying defaults for omitted fields.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if cfg.Server.Listen == "" {
		cfg.Server.Listen = ":8080"
	}
	if cfg.Server.JWTTTLSec == 0 {
		cfg.Server.JWTTTLSec = 3600 // 1 hour
	}
	if cfg.Server.SessionTTLSec == 0 {
		cfg.Server.SessionTTLSec = 604800 // 7 days
	}

	return &cfg, nil
}
