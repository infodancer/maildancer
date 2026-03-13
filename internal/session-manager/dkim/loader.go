// Package dkim loads DKIM signing keys from per-domain configuration.
package dkim

import (
	"crypto"
	"path/filepath"

	"github.com/infodancer/maildancer/auth/domain"
)

// LoadDKIMKey reads the DKIM private key for a domain from its config dir.
// Returns ("", nil, nil) if no DKIM config exists for the domain.
func LoadDKIMKey(domainsPath, domainName string) (selector string, key crypto.Signer, err error) {
	domainDir := filepath.Join(domainsPath, domainName)
	cfg, err := domain.LoadDomainConfig(filepath.Join(domainDir, "config.toml"))
	if err != nil {
		// Missing config is not an error — domain may not have DKIM.
		return "", nil, nil
	}

	if cfg.DKIM.Selector == "" || cfg.DKIM.PrivateKeyPath == "" {
		return "", nil, nil
	}

	keyPath := cfg.DKIM.PrivateKeyPath
	if !filepath.IsAbs(keyPath) {
		keyPath = filepath.Join(domainDir, keyPath)
	}

	key, err = domain.LoadDKIMKey(keyPath)
	if err != nil {
		return "", nil, err
	}

	return cfg.DKIM.Selector, key, nil
}
