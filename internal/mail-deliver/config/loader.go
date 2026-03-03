package config

import (
	"fmt"
	"os"

	"github.com/pelletier/go-toml/v2"
)

// Load reads the shared TOML config file and returns the [maildeliver] section.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %q: %w", path, err)
	}

	var fc FileConfig
	if err := toml.Unmarshal(data, &fc); err != nil {
		return Config{}, fmt.Errorf("parse config %q: %w", path, err)
	}

	return fc.MailDeliver, nil
}

// LoadSpamConfig reads a spam.toml file from path.
// Returns a zero-value SpamConfig and no error if the file does not exist.
func LoadSpamConfig(path string) (SpamConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return SpamConfig{}, nil
		}
		return SpamConfig{}, fmt.Errorf("read spam config %q: %w", path, err)
	}

	var sc SpamConfig
	if err := toml.Unmarshal(data, &sc); err != nil {
		return SpamConfig{}, fmt.Errorf("parse spam config %q: %w", path, err)
	}

	return sc, nil
}
