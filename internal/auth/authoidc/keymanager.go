package authoidc

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// KeyManager is the offline operator API for signing keys: it opens the
// same SQLite database the auth-oidc server uses and exposes list /
// rotate / revoke operations without needing a running Server.
//
// Operations are safe to run while the server is up: rotations and
// revocations are atomic SQL transactions, and the server picks up the
// new state on its next request (per the design doc's option (a) —
// the server queries the DB on every signing request, so no SIGHUP or
// inotify coordination is needed).
//
// Files (generation on rotate, unlink on sweep) live under the same
// {data_dir}/{domain}/keys/ layout the server uses.
type KeyManager struct {
	dataDir   string
	store     Store
	retention time.Duration
}

// OpenKeyManager opens the OIDC state DB at the canonical path
// ({dataDir}/oidc-state.db) and returns a KeyManager ready for CLI use.
// Closing the manager releases the underlying database handle.
//
// retentionAfterRetire is the window applied to the outgoing key during
// a rotate operation. Pass zero to use the package default (24h).
func OpenKeyManager(dataDir string, retentionAfterRetire time.Duration) (*KeyManager, error) {
	if dataDir == "" {
		return nil, fmt.Errorf("data dir is required")
	}
	store, err := newSQLiteStore(filepath.Join(dataDir, "oidc-state.db"), nil)
	if err != nil {
		return nil, err
	}
	if retentionAfterRetire <= 0 {
		retentionAfterRetire = defaultKeyRetentionAfterRetire
	}
	return &KeyManager{
		dataDir:   dataDir,
		store:     store,
		retention: retentionAfterRetire,
	}, nil
}

// Close releases the underlying database handle.
func (km *KeyManager) Close() error { return km.store.Close() }

// KeyInfo is the exported view of one signing-key row. Mirrors
// signingKeyRecord but uses only exported types.
type KeyInfo struct {
	Domain    string
	KID       string
	Algorithm string
	State     string
	CreatedAt time.Time
	RetiredAt time.Time
	ExpiresAt time.Time
}

// List returns all signing-key rows for domain.
func (km *KeyManager) List(domain string) ([]KeyInfo, error) {
	rows, err := km.store.ListSigningKeys(domain)
	if err != nil {
		return nil, err
	}
	out := make([]KeyInfo, 0, len(rows))
	for _, r := range rows {
		out = append(out, KeyInfo(r))
	}
	return out, nil
}

// Rotate generates a new keypair for algorithm (or ES256 if empty),
// writes the PEM file, and atomically swaps the current key. Returns the
// new kid.
func (km *KeyManager) Rotate(domain, algorithm string) (string, error) {
	if algorithm == "" {
		algorithm = AlgES256
	}
	if _, ok := supportedSigningAlgorithms[algorithm]; !ok {
		return "", fmt.Errorf("unsupported algorithm: %s (supported: RS256, ES256, EdDSA)", algorithm)
	}
	now := time.Now()
	newKID := fmt.Sprintf("%s-%d", domain, now.UnixNano())
	if _, err := generateAndWriteKey(km.dataDir, domain, newKID, algorithm); err != nil {
		return "", err
	}
	rec := signingKeyRecord{
		Domain:    domain,
		KID:       newKID,
		Algorithm: algorithm,
		State:     keyStateCurrent,
		CreatedAt: now,
	}
	if err := km.store.RotateSigningKey(domain, rec, km.retention); err != nil {
		// Best effort: clean up the orphan key file. If this fails too,
		// the next sweep will not find it (no DB row) but the operator
		// can remove it manually.
		_ = os.Remove(keyFilePath(km.dataDir, domain, newKID))
		return "", fmt.Errorf("rotate signing key: %w", err)
	}
	slog.Info("authoidc: rotated signing key",
		"event", "key_rotation",
		"source", "userctl",
		"domain", domain,
		"kid", newKID,
		"algorithm", algorithm,
	)
	return newKID, nil
}

// Revoke marks kid as immediately expired. The next sweep (server-side or
// via a separate userctl call) removes the row and unlinks the file.
func (km *KeyManager) Revoke(domain, kid string) error {
	if err := km.store.RevokeSigningKey(domain, kid); err != nil {
		return err
	}
	slog.Warn("authoidc: revoked signing key",
		"event", "key_revoked",
		"source", "userctl",
		"domain", domain,
		"kid", kid,
	)
	return nil
}
