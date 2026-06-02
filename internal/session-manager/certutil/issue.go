package certutil

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

// IssueCert generates an Ed25519 certificate signed by the CA.
// The name is used as the CommonName and as a DNS SAN.
// Set server=true for a server certificate, false for a client certificate.
func IssueCert(caCertPath, caKeyPath, certPath, keyPath, name string, server bool, validity time.Duration) error {
	if validity == 0 {
		validity = DefaultCertValidity
	}

	caCert, caKey, err := loadCA(caCertPath, caKeyPath)
	if err != nil {
		return err
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
			CommonName:   name,
			Organization: []string{"infodancer"},
		},
		NotBefore: now,
		NotAfter:  now.Add(validity),
		DNSNames:  []string{name},
	}

	if server {
		template.KeyUsage = x509.KeyUsageDigitalSignature
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	} else {
		template.KeyUsage = x509.KeyUsageDigitalSignature
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, pub, caKey)
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

// loadCA reads the CA certificate and private key from PEM files.
func loadCA(certPath, keyPath string) (*x509.Certificate, ed25519.PrivateKey, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read CA cert: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("CA cert file does not contain a PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA cert: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read CA key: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		return nil, nil, fmt.Errorf("CA key file does not contain a PEM private key")
	}
	rawKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA key: %w", err)
	}
	edKey, ok := rawKey.(ed25519.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("CA key is not Ed25519 (got %T)", rawKey)
	}

	return cert, edKey, nil
}
