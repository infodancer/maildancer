package authoidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// loadedKey is one signing key with parsed JWK material. The keyStore caches
// these so PEM files are not re-read on every signing request -- the DB
// (signing_keys table) is the authoritative state, the cache is just the
// material to satisfy that state.
type loadedKey struct {
	kid       string
	algorithm string
	privJWK   jwk.Key // private -- used to sign
	pubJWK    jwk.Key // public -- served via JWKS and used for /userinfo verification
}

// keyStore is a content-addressable cache of loaded JWK material keyed by
// (domain, kid). The Store interface (DB) is the source of truth for which
// kids exist and what state each is in; this cache only avoids re-parsing
// PEM files on every request.
type keyStore struct {
	mu   sync.RWMutex
	keys map[string]map[string]*loadedKey // domain → kid → loaded
}

func newKeyStore() *keyStore {
	return &keyStore{keys: make(map[string]map[string]*loadedKey)}
}

// Get returns the cached loaded key, or false if not cached.
func (ks *keyStore) Get(domain, kid string) (*loadedKey, bool) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	dm, ok := ks.keys[domain]
	if !ok {
		return nil, false
	}
	k, ok := dm[kid]
	return k, ok
}

// Put stores a loaded key in the cache.
func (ks *keyStore) Put(domain string, k *loadedKey) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if ks.keys[domain] == nil {
		ks.keys[domain] = make(map[string]*loadedKey)
	}
	ks.keys[domain][k.kid] = k
}

// Drop removes a cached key. Called after the corresponding DB row has been
// swept so the cache doesn't leak entries for keys that no longer exist.
func (ks *keyStore) Drop(domain, kid string) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if dm, ok := ks.keys[domain]; ok {
		delete(dm, kid)
	}
}

// keyDir returns the per-domain directory containing key files.
func keyDir(dataDir, domain string) string {
	return filepath.Join(dataDir, domain, "keys")
}

// keyFilePath returns the on-disk path for one key file.
func keyFilePath(dataDir, domain, kid string) string {
	return filepath.Join(keyDir(dataDir, domain), kid+".key")
}

// generateAndWriteKey creates a new keypair for algorithm, writes its PEM to
// {dataDir}/{domain}/keys/{kid}.key (0600, atomic rename + fsync), and
// returns the loaded JWK so the caller can cache it.
func generateAndWriteKey(dataDir, domain, kid, algorithm string) (*loadedKey, error) {
	if err := os.MkdirAll(keyDir(dataDir, domain), 0o700); err != nil {
		return nil, fmt.Errorf("create key dir: %w", err)
	}
	priv, err := generatePrivateKey(algorithm)
	if err != nil {
		return nil, err
	}
	pemBytes, err := encodePrivateKeyPEM(priv, algorithm)
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(keyFilePath(dataDir, domain, kid), pemBytes, 0o600); err != nil {
		return nil, err
	}
	return buildLoadedKey(kid, algorithm, priv)
}

// loadKeyFile reads and parses an existing key file. The returned key's
// declared algorithm is cross-checked against the algorithm stored in the
// DB; mismatch is a corruption signal and surfaces as an error.
func loadKeyFile(dataDir, domain, kid, algorithm string) (*loadedKey, error) {
	path := keyFilePath(dataDir, domain, kid)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file %s: %w", path, err)
	}
	priv, parsedAlg, err := decodePrivateKeyPEM(data)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	if parsedAlg != algorithm {
		return nil, fmt.Errorf("key %s: file algorithm %s does not match record algorithm %s",
			kid, parsedAlg, algorithm)
	}
	return buildLoadedKey(kid, algorithm, priv)
}

// generatePrivateKey returns a fresh private key for the named algorithm.
// Sources entropy from crypto/rand.
func generatePrivateKey(algorithm string) (crypto.PrivateKey, error) {
	switch algorithm {
	case AlgRS256:
		return rsa.GenerateKey(rand.Reader, 2048)
	case AlgES256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case AlgEdDSA:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	}
	return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
}

// encodePrivateKeyPEM serialises priv to a PKCS#8 PEM block. PKCS#8 is the
// modern algorithm-neutral container, so RSA/ECDSA/Ed25519 keys all use the
// same "PRIVATE KEY" PEM type. Legacy "RSA PRIVATE KEY" PKCS#1 blocks are
// accepted on read (decodePrivateKeyPEM) but never written.
func encodePrivateKeyPEM(priv crypto.PrivateKey, algorithm string) ([]byte, error) {
	if err := checkKeyMatchesAlg(priv, algorithm); err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal pkcs8: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// decodePrivateKeyPEM parses a private key from PEM. Three accepted forms:
//   - "PRIVATE KEY"     -- PKCS#8, the format we write for new keys
//   - "RSA PRIVATE KEY" -- PKCS#1, the legacy format the old single-key layout used
//   - "EC PRIVATE KEY"  -- SEC1, retained for completeness even though we never write it
//
// Returns the parsed key plus the JWA algorithm string it represents.
func decodePrivateKeyPEM(data []byte) (crypto.PrivateKey, string, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, "", fmt.Errorf("no PEM block found")
	}
	switch block.Type {
	case "PRIVATE KEY":
		priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, "", fmt.Errorf("parse pkcs8: %w", err)
		}
		alg, err := algForKey(priv)
		return priv, alg, err
	case "RSA PRIVATE KEY":
		priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, "", fmt.Errorf("parse pkcs1: %w", err)
		}
		return priv, AlgRS256, nil
	case "EC PRIVATE KEY":
		priv, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, "", fmt.Errorf("parse ec: %w", err)
		}
		alg, err := algForKey(priv)
		return priv, alg, err
	}
	return nil, "", fmt.Errorf("unsupported PEM type %q", block.Type)
}

// algForKey returns the JWA algorithm string for a parsed private key. P-256
// is the only ECDSA curve currently supported; other curves return an error
// so we never silently bind to something the JWS layer can't sign with.
func algForKey(priv crypto.PrivateKey) (string, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return AlgRS256, nil
	case *ecdsa.PrivateKey:
		if k.Curve == elliptic.P256() {
			return AlgES256, nil
		}
		return "", fmt.Errorf("unsupported ECDSA curve %s", k.Curve.Params().Name)
	case ed25519.PrivateKey:
		return AlgEdDSA, nil
	}
	return "", fmt.Errorf("unsupported key type %T", priv)
}

// checkKeyMatchesAlg verifies the runtime key type matches the declared JWA
// algorithm. Used during write so we never serialise a key that the DB row
// would mis-describe.
func checkKeyMatchesAlg(priv crypto.PrivateKey, algorithm string) error {
	actual, err := algForKey(priv)
	if err != nil {
		return err
	}
	if actual != algorithm {
		return fmt.Errorf("key type yields %s, declared algorithm is %s", actual, algorithm)
	}
	return nil
}

// buildLoadedKey constructs the jwx JWK objects (private + public) for one
// key, baking in kid, alg, and (for the public JWK) use=sig.
func buildLoadedKey(kid, algorithm string, priv crypto.PrivateKey) (*loadedKey, error) {
	privJWK, err := jwk.FromRaw(priv)
	if err != nil {
		return nil, fmt.Errorf("build private jwk: %w", err)
	}
	if err := privJWK.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, fmt.Errorf("set kid: %w", err)
	}
	if err := privJWK.Set(jwk.AlgorithmKey, algorithm); err != nil {
		return nil, fmt.Errorf("set alg: %w", err)
	}

	pubAny, err := publicKeyFor(priv)
	if err != nil {
		return nil, err
	}
	pubJWK, err := jwk.FromRaw(pubAny)
	if err != nil {
		return nil, fmt.Errorf("build public jwk: %w", err)
	}
	if err := pubJWK.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, fmt.Errorf("set kid: %w", err)
	}
	if err := pubJWK.Set(jwk.AlgorithmKey, algorithm); err != nil {
		return nil, fmt.Errorf("set alg: %w", err)
	}
	if err := pubJWK.Set(jwk.KeyUsageKey, "sig"); err != nil {
		return nil, fmt.Errorf("set use: %w", err)
	}
	return &loadedKey{
		kid:       kid,
		algorithm: algorithm,
		privJWK:   privJWK,
		pubJWK:    pubJWK,
	}, nil
}

// publicKeyFor extracts the public half of any supported private key.
func publicKeyFor(priv crypto.PrivateKey) (any, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return k.Public(), nil
	case *ecdsa.PrivateKey:
		return k.Public(), nil
	case ed25519.PrivateKey:
		return k.Public(), nil
	}
	return nil, fmt.Errorf("unsupported key type %T", priv)
}

// jwaAlgorithm maps the JWA string identifier to the jwx algorithm enum
// passed to jwt.WithKey.
func jwaAlgorithm(algorithm string) (jwa.SignatureAlgorithm, error) {
	switch algorithm {
	case AlgRS256:
		return jwa.RS256, nil
	case AlgES256:
		return jwa.ES256, nil
	case AlgEdDSA:
		return jwa.EdDSA, nil
	}
	return "", fmt.Errorf("unsupported algorithm: %s", algorithm)
}

// writeFileAtomic writes data to path via a sibling temp file + fsync +
// atomic rename. The temp file is created in the same directory so the
// rename is guaranteed to be atomic on the local filesystem.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once the rename succeeds
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename temp: %w", err)
	}
	return nil
}
