package authoidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

// domainKey holds the signing material for one domain.
type domainKey struct {
	privateKey *rsa.PrivateKey
	kid        string
	jwkSet     jwk.Set  // public keys only — served at jwks.json
	privJWK    jwk.Key  // private JWK — used to sign JWTs
}

// keyStore manages per-domain signing keypairs.
type keyStore struct {
	mu   sync.RWMutex
	keys map[string]*domainKey
}

func newKeyStore() *keyStore {
	return &keyStore{keys: make(map[string]*domainKey)}
}

// LoadOrGenerate loads an existing RS256 keypair for domain from dataDir, or
// generates and persists a fresh 2048-bit pair if none exists.
func (ks *keyStore) LoadOrGenerate(domain, dataDir string) error {
	dir := filepath.Join(dataDir, domain)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create key dir: %w", err)
	}

	privPath := filepath.Join(dir, "signing.key")

	var privKey *rsa.PrivateKey

	privData, err := os.ReadFile(privPath)
	if os.IsNotExist(err) {
		privKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return fmt.Errorf("generate key: %w", err)
		}
		privBytes := x509.MarshalPKCS1PrivateKey(privKey)
		privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})
		if err := os.WriteFile(privPath, privPEM, 0600); err != nil {
			return fmt.Errorf("write private key: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("read private key: %w", err)
	} else {
		block, _ := pem.Decode(privData)
		if block == nil {
			return fmt.Errorf("invalid PEM in %s", privPath)
		}
		privKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse private key: %w", err)
		}
	}

	kid := domain + "-1"

	// Build private JWK (used for signing).
	privJWK, err := jwk.FromRaw(privKey)
	if err != nil {
		return fmt.Errorf("build private jwk: %w", err)
	}
	if err := privJWK.Set(jwk.KeyIDKey, kid); err != nil {
		return fmt.Errorf("set kid: %w", err)
	}
	if err := privJWK.Set(jwk.AlgorithmKey, "RS256"); err != nil {
		return fmt.Errorf("set alg: %w", err)
	}

	// Build public JWK (served via JWKS endpoint).
	pubJWK, err := jwk.FromRaw(privKey.Public())
	if err != nil {
		return fmt.Errorf("build public jwk: %w", err)
	}
	if err := pubJWK.Set(jwk.KeyIDKey, kid); err != nil {
		return fmt.Errorf("set kid: %w", err)
	}
	if err := pubJWK.Set(jwk.AlgorithmKey, "RS256"); err != nil {
		return fmt.Errorf("set alg: %w", err)
	}
	if err := pubJWK.Set(jwk.KeyUsageKey, "sig"); err != nil {
		return fmt.Errorf("set use: %w", err)
	}

	set := jwk.NewSet()
	if err := set.AddKey(pubJWK); err != nil {
		return fmt.Errorf("add key to set: %w", err)
	}

	ks.mu.Lock()
	ks.keys[domain] = &domainKey{
		privateKey: privKey,
		kid:        kid,
		jwkSet:     set,
		privJWK:    privJWK,
	}
	ks.mu.Unlock()
	return nil
}

// Get returns the domainKey for the given domain.
func (ks *keyStore) Get(domain string) (*domainKey, bool) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	dk, ok := ks.keys[domain]
	return dk, ok
}
