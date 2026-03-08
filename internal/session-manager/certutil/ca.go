// Package certutil provides self-contained CA and certificate management
// for mTLS between protocol handlers and the session manager.
//
// All certificates use Ed25519 keys. The CA is a self-signed root certificate
// used only within the infodancer mail stack — it is not intended for
// public-facing TLS.
package certutil

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

// DefaultCAValidity is the default CA certificate lifetime.
const DefaultCAValidity = 10 * 365 * 24 * time.Hour // ~10 years

// DefaultCertValidity is the default client/server certificate lifetime.
const DefaultCertValidity = 365 * 24 * time.Hour // ~1 year

// GenerateCA creates a self-signed Ed25519 CA certificate and writes the
// certificate and private key to the specified paths.
func GenerateCA(certPath, keyPath string, validity time.Duration) error {
	if validity == 0 {
		validity = DefaultCAValidity
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "infodancer mail CA",
			Organization: []string{"infodancer"},
		},
		NotBefore:             now,
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	if err := writePEM(certPath, "CERTIFICATE", certDER, 0644); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	if err := writePEM(keyPath, "PRIVATE KEY", keyDER, 0600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}

	return nil
}

// randomSerial generates a random 128-bit certificate serial number.
func randomSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	return serial, nil
}

// writePEM writes a single PEM block to a file with the given permissions.
func writePEM(path, blockType string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: blockType, Bytes: data})
}
