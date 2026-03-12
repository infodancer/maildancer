package domain

import (
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
)

// warnInsecurePerms logs a warning if a sensitive file is group-writable or
// world-readable. Best-effort: errors from Stat are silently ignored.
func warnInsecurePerms(path string) {
	fi, err := os.Stat(path)
	if err != nil {
		return
	}
	perm := fi.Mode().Perm()
	if perm&0o027 != 0 {
		slog.Warn("sensitive file has overly permissive permissions",
			"path", path,
			"mode", fmt.Sprintf("%04o", perm),
			"recommended", "0600 or 0640")
	}
}

// LoadDKIMKey reads an Ed25519 private key from a PEM file (PKCS8 format).
func LoadDKIMKey(path string) (crypto.Signer, error) {
	warnInsecurePerms(path)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read DKIM key %s: %w", path, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse DKIM key %s: %w", path, err)
	}

	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("DKIM key %s is not Ed25519 (got %T)", path, key)
	}

	return edKey, nil
}
