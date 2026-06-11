package authoidc

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// TestGenerateAndLoad_AllAlgorithms confirms that every supported algorithm
// can generate a key, write the PEM, read it back, and produce a valid JWS
// signature that verifies against the public JWK. Catches mismatches
// between generator, PEM encoder, PEM decoder, and signing-alg mapping.
func TestGenerateAndLoad_AllAlgorithms(t *testing.T) {
	cases := []struct {
		alg string
	}{
		{AlgRS256},
		{AlgES256},
		{AlgEdDSA},
	}

	for _, tc := range cases {
		t.Run(tc.alg, func(t *testing.T) {
			dataDir := t.TempDir()
			domain := "k.example"
			kid := domain + "-" + tc.alg

			generated, err := generateAndWriteKey(dataDir, domain, kid, tc.alg)
			if err != nil {
				t.Fatalf("generateAndWriteKey: %v", err)
			}
			if generated.kid != kid || generated.algorithm != tc.alg {
				t.Errorf("loaded: kid=%s alg=%s, want kid=%s alg=%s",
					generated.kid, generated.algorithm, kid, tc.alg)
			}

			// File exists with 0600 perms.
			info, err := os.Stat(keyFilePath(dataDir, domain, kid))
			if err != nil {
				t.Fatalf("stat key file: %v", err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Errorf("perm = %v, want 0600", info.Mode().Perm())
			}

			// Round-trip: load the file back, confirm declared alg matches.
			loaded, err := loadKeyFile(dataDir, domain, kid, tc.alg)
			if err != nil {
				t.Fatalf("loadKeyFile: %v", err)
			}
			if loaded.algorithm != tc.alg {
				t.Errorf("loaded alg = %s, want %s", loaded.algorithm, tc.alg)
			}

			// The internal key type is the one we expected for this alg.
			var rawPriv any
			if err := loaded.privJWK.Raw(&rawPriv); err != nil {
				t.Fatalf("Raw: %v", err)
			}
			switch tc.alg {
			case AlgRS256:
				if _, ok := rawPriv.(*rsa.PrivateKey); !ok {
					t.Errorf("RS256 key type = %T, want *rsa.PrivateKey", rawPriv)
				}
			case AlgES256:
				if _, ok := rawPriv.(*ecdsa.PrivateKey); !ok {
					t.Errorf("ES256 key type = %T, want *ecdsa.PrivateKey", rawPriv)
				}
			case AlgEdDSA:
				if _, ok := rawPriv.(ed25519.PrivateKey); !ok {
					t.Errorf("EdDSA key type = %T, want ed25519.PrivateKey", rawPriv)
				}
			}

			// End-to-end JWS: build, sign with the loaded key, verify
			// against the public JWK.
			tok, err := jwt.NewBuilder().Issuer("test").Build()
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			jwaAlg, err := jwaAlgorithm(tc.alg)
			if err != nil {
				t.Fatalf("jwaAlgorithm: %v", err)
			}
			signed, err := jwt.Sign(tok, jwt.WithKey(jwaAlg, loaded.privJWK))
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			set := jwk.NewSet()
			if err := set.AddKey(loaded.pubJWK); err != nil {
				t.Fatalf("AddKey: %v", err)
			}
			if _, err := jwt.Parse(signed, jwt.WithKeySet(set), jwt.WithValidate(true)); err != nil {
				t.Errorf("Parse(verify): %v", err)
			}
		})
	}
}

// TestLoadKeyFile_AlgorithmMismatch verifies the loader rejects a key file
// whose PEM type doesn't match the algorithm the DB row claims. This is
// the corruption check named in the design doc.
func TestLoadKeyFile_AlgorithmMismatch(t *testing.T) {
	dataDir := t.TempDir()
	domain := "k.example"
	kid := domain + "-mismatch"

	// Write a real ES256 key to disk.
	if _, err := generateAndWriteKey(dataDir, domain, kid, AlgES256); err != nil {
		t.Fatalf("generate: %v", err)
	}
	// Try to load it as if the DB said it was RS256 -- must fail.
	if _, err := loadKeyFile(dataDir, domain, kid, AlgRS256); err == nil {
		t.Error("expected mismatch error, got nil")
	}
}

// TestLegacyPKCS1Decode confirms decodePrivateKeyPEM still understands the
// "RSA PRIVATE KEY" PKCS#1 format the old single-key layout wrote. This is
// the migration on-ramp: the legacy file moves into keys/{domain}-1.key
// unchanged and must still parse.
func TestLegacyPKCS1Decode(t *testing.T) {
	dataDir := t.TempDir()
	domain := "old.example"
	kid := domain + "-1"

	// Write an RSA key in legacy PKCS#1 format directly. We bypass
	// encodePrivateKeyPEM because it intentionally only emits PKCS#8.
	rsaKey, err := generatePrivateKey(AlgRS256)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	rsaPriv := rsaKey.(*rsa.PrivateKey)
	if err := os.MkdirAll(keyDir(dataDir, domain), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	pemBytes := legacyPKCS1PEM(t, rsaPriv)
	if err := os.WriteFile(keyFilePath(dataDir, domain, kid), pemBytes, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	loaded, err := loadKeyFile(dataDir, domain, kid, AlgRS256)
	if err != nil {
		t.Fatalf("loadKeyFile: %v", err)
	}
	if loaded.algorithm != AlgRS256 {
		t.Errorf("alg = %s, want RS256", loaded.algorithm)
	}
}

// TestServer_MigrateLegacySigningKey writes a legacy single-key layout to
// disk, starts a Server, and confirms the file moves to the new location
// AND a signing_keys row is recorded with the preserved kid {domain}-1 and
// algorithm=RS256. Mirrors the migration plan in docs/signing-key-rotation.md.
func TestServer_MigrateLegacySigningKey(t *testing.T) {
	tmp := t.TempDir()
	domain := "test.example"
	dataDir := filepath.Join(tmp, "data")

	// Pre-create the legacy layout: {data_dir}/{domain}/signing.key holding
	// an RSA key in PKCS#1 PEM (matching what the old keys.go used to write).
	if err := os.MkdirAll(filepath.Join(dataDir, domain), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	rsaKey, err := generatePrivateKey(AlgRS256)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	rsaPriv := rsaKey.(*rsa.PrivateKey)
	legacyPath := filepath.Join(dataDir, domain, "signing.key")
	if err := os.WriteFile(legacyPath, legacyPKCS1PEM(t, rsaPriv), 0o600); err != nil {
		t.Fatalf("write legacy: %v", err)
	}

	// Open a Store + run ensureSigningKeys directly. Avoids the larger
	// Server fixture which would also need domain configs and a passwd
	// file -- neither is relevant to the migration check.
	store, err := newSQLiteStore(filepath.Join(tmp, "state.db"), nil)
	if err != nil {
		t.Fatalf("newSQLiteStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	s := &Server{
		cfg:   &Config{Server: ServerConfig{DataDir: dataDir}},
		store: store,
		keys:  newKeyStore(),
	}
	if err := s.ensureSigningKeys(domain); err != nil {
		t.Fatalf("ensureSigningKeys: %v", err)
	}

	// The legacy file should be gone, the new one should exist.
	if _, err := os.Stat(legacyPath); !os.IsNotExist(err) {
		t.Errorf("legacy signing.key still present (err=%v)", err)
	}
	if _, err := os.Stat(keyFilePath(dataDir, domain, domain+"-1")); err != nil {
		t.Errorf("migrated key file missing: %v", err)
	}

	// The DB row should exist with the preserved legacy kid.
	rows, err := store.ListSigningKeys(domain)
	if err != nil {
		t.Fatalf("ListSigningKeys: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows after migration: got %d, want 1", len(rows))
	}
	got := rows[0]
	if got.KID != domain+"-1" {
		t.Errorf("kid = %q, want %q", got.KID, domain+"-1")
	}
	if got.Algorithm != AlgRS256 {
		t.Errorf("algorithm = %q, want RS256", got.Algorithm)
	}
	if got.State != keyStateCurrent {
		t.Errorf("state = %q, want current", got.State)
	}
}

// TestServer_RotateAndSweep exercises one full rotation: starting from a
// fresh-install single current key, rotateKey produces a new current with
// the requested algorithm, the previous current becomes retiring, and the
// subsequent sweep at a far-future cutoff removes the retiring row + file.
func TestServer_RotateAndSweep(t *testing.T) {
	tmp := t.TempDir()
	domain := "rot.example"
	dataDir := filepath.Join(tmp, "data")
	if err := os.MkdirAll(filepath.Join(dataDir, domain), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	store, err := newSQLiteStore(filepath.Join(tmp, "state.db"), nil)
	if err != nil {
		t.Fatalf("newSQLiteStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	s := &Server{
		cfg:     &Config{Server: ServerConfig{DataDir: dataDir}},
		store:   store,
		keys:    newKeyStore(),
		domains: map[string]*domainEntry{domain: {name: domain}},
	}
	// Establish an initial current key (default algorithm). Mirror the
	// real startup path: ensureSigningKeys then primeKeyCache, so the
	// initial key is loaded into the cache before any rotation.
	if err := s.ensureSigningKeys(domain); err != nil {
		t.Fatalf("ensureSigningKeys: %v", err)
	}
	if err := s.primeKeyCache(domain); err != nil {
		t.Fatalf("primeKeyCache: %v", err)
	}
	initial, _ := s.store.ListSigningKeys(domain)
	if len(initial) != 1 || initial[0].State != keyStateCurrent {
		t.Fatalf("initial: %+v", initial)
	}
	initialKID := initial[0].KID

	// Rotate explicitly to RS256 -- confirms algorithm-migration path.
	newKID, err := s.rotateKey(domain, AlgRS256)
	if err != nil {
		t.Fatalf("rotateKey: %v", err)
	}
	if newKID == initialKID {
		t.Errorf("rotateKey returned same kid: %q", newKID)
	}

	after, _ := s.store.ListSigningKeys(domain)
	if len(after) != 2 {
		t.Fatalf("post-rotate row count: got %d, want 2", len(after))
	}
	var curAlg, retAlg, retKID string
	for _, r := range after {
		switch r.State {
		case keyStateCurrent:
			curAlg = r.Algorithm
		case keyStateRetiring:
			retAlg = r.Algorithm
			retKID = r.KID
		}
	}
	if curAlg != AlgRS256 {
		t.Errorf("current algorithm = %s, want RS256", curAlg)
	}
	if retAlg == "" {
		t.Error("no retiring key after rotation")
	}
	if retKID != initialKID {
		t.Errorf("retiring kid = %q, want initial %q", retKID, initialKID)
	}

	// Both key files exist on disk and both are cached.
	for _, kid := range []string{initialKID, newKID} {
		if _, err := os.Stat(keyFilePath(dataDir, domain, kid)); err != nil {
			t.Errorf("file for %s missing: %v", kid, err)
		}
		if _, ok := s.keys.Get(domain, kid); !ok {
			t.Errorf("cache miss for %s", kid)
		}
	}

	// Sweep with a far-future cutoff: the retiring row + file go.
	s.sweepSigningKeys(time.Now().Add(48 * time.Hour))
	rows, _ := s.store.ListSigningKeys(domain)
	if len(rows) != 1 || rows[0].KID != newKID {
		t.Errorf("post-sweep rows: got %+v, want only %s", rows, newKID)
	}
	if _, err := os.Stat(keyFilePath(dataDir, domain, initialKID)); !os.IsNotExist(err) {
		t.Errorf("retiring file survived sweep (err=%v)", err)
	}
	if _, ok := s.keys.Get(domain, initialKID); ok {
		t.Error("cache still has swept key")
	}
}

// TestServer_RevokeKey confirms revokeKey marks a key for immediate sweep.
func TestServer_RevokeKey(t *testing.T) {
	tmp := t.TempDir()
	domain := "rev.example"
	dataDir := filepath.Join(tmp, "data")
	if err := os.MkdirAll(filepath.Join(dataDir, domain), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	store, err := newSQLiteStore(filepath.Join(tmp, "state.db"), nil)
	if err != nil {
		t.Fatalf("newSQLiteStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	s := &Server{
		cfg:   &Config{Server: ServerConfig{DataDir: dataDir}},
		store: store,
		keys:  newKeyStore(),
	}
	if err := s.ensureSigningKeys(domain); err != nil {
		t.Fatalf("ensureSigningKeys: %v", err)
	}
	rows, _ := s.store.ListSigningKeys(domain)
	kid := rows[0].KID

	if err := s.revokeKey(domain, kid); err != nil {
		t.Fatalf("revokeKey: %v", err)
	}
	s.sweepSigningKeys(time.Now())
	rows, _ = s.store.ListSigningKeys(domain)
	if len(rows) != 0 {
		t.Errorf("post-revoke+sweep rows: got %d, want 0", len(rows))
	}
}

// legacyPKCS1PEM emits an RSA private key in the PKCS#1 "RSA PRIVATE KEY"
// PEM format the pre-rotation single-key layout wrote. Test helper only;
// production code in keys.go intentionally only emits PKCS#8.
func legacyPKCS1PEM(t *testing.T, k *rsa.PrivateKey) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(k),
	})
}
