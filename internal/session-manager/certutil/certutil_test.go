package certutil

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateCA(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	if err := GenerateCA(certPath, keyPath, 0); err != nil {
		t.Fatalf("GenerateCA() error: %v", err)
	}

	// Verify cert file exists and is valid.
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("cert file does not contain a PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	if !cert.IsCA {
		t.Error("certificate is not a CA")
	}
	if cert.Subject.CommonName != "infodancer mail CA" {
		t.Errorf("CN = %q, want %q", cert.Subject.CommonName, "infodancer mail CA")
	}
	if _, ok := cert.PublicKey.(ed25519.PublicKey); !ok {
		t.Errorf("public key type = %T, want ed25519.PublicKey", cert.PublicKey)
	}

	// Verify key file exists and has restrictive perms.
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if keyInfo.Mode().Perm() != 0600 {
		t.Errorf("key perms = %o, want 0600", keyInfo.Mode().Perm())
	}
}

func TestGenerateCA_RefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	if err := GenerateCA(certPath, keyPath, 0); err != nil {
		t.Fatalf("first GenerateCA() error: %v", err)
	}

	// Second call should fail because files already exist (O_EXCL).
	if err := GenerateCA(certPath, keyPath, 0); err == nil {
		t.Fatal("expected error on overwrite, got nil")
	}
}

func TestIssueCert_Client(t *testing.T) {
	dir := t.TempDir()
	caCert := filepath.Join(dir, "ca.crt")
	caKey := filepath.Join(dir, "ca.key")

	if err := GenerateCA(caCert, caKey, 0); err != nil {
		t.Fatalf("GenerateCA() error: %v", err)
	}

	clientCert := filepath.Join(dir, "smtpd.crt")
	clientKey := filepath.Join(dir, "smtpd.key")

	if err := IssueCert(caCert, caKey, clientCert, clientKey, "smtpd", false, 0); err != nil {
		t.Fatalf("IssueCert() error: %v", err)
	}

	// Parse and verify the issued cert.
	certPEM, _ := os.ReadFile(clientCert)
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	if cert.Subject.CommonName != "smtpd" {
		t.Errorf("CN = %q, want %q", cert.Subject.CommonName, "smtpd")
	}
	if cert.IsCA {
		t.Error("client cert should not be a CA")
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("ExtKeyUsage = %v, want [ClientAuth]", cert.ExtKeyUsage)
	}

	// Verify the cert is signed by the CA.
	caCertPEM, _ := os.ReadFile(caCert)
	caBlock, _ := pem.Decode(caCertPEM)
	ca, _ := x509.ParseCertificate(caBlock.Bytes)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Errorf("cert verification failed: %v", err)
	}
}

func TestIssueCert_Server(t *testing.T) {
	dir := t.TempDir()
	caCert := filepath.Join(dir, "ca.crt")
	caKey := filepath.Join(dir, "ca.key")

	if err := GenerateCA(caCert, caKey, 0); err != nil {
		t.Fatalf("GenerateCA() error: %v", err)
	}

	serverCert := filepath.Join(dir, "server.crt")
	serverKey := filepath.Join(dir, "server.key")

	if err := IssueCert(caCert, caKey, serverCert, serverKey, "session-manager", true, 0); err != nil {
		t.Fatalf("IssueCert() error: %v", err)
	}

	certPEM, _ := os.ReadFile(serverCert)
	block, _ := pem.Decode(certPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)

	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("ExtKeyUsage = %v, want [ServerAuth]", cert.ExtKeyUsage)
	}
}

func TestTLSConfigs(t *testing.T) {
	dir := t.TempDir()
	caCertPath := filepath.Join(dir, "ca.crt")
	caKeyPath := filepath.Join(dir, "ca.key")

	if err := GenerateCA(caCertPath, caKeyPath, 0); err != nil {
		t.Fatalf("GenerateCA() error: %v", err)
	}

	serverCert := filepath.Join(dir, "server.crt")
	serverKey := filepath.Join(dir, "server.key")
	if err := IssueCert(caCertPath, caKeyPath, serverCert, serverKey, "session-manager", true, 0); err != nil {
		t.Fatalf("issue server cert: %v", err)
	}

	clientCert := filepath.Join(dir, "client.crt")
	clientKey := filepath.Join(dir, "client.key")
	if err := IssueCert(caCertPath, caKeyPath, clientCert, clientKey, "smtpd", false, 0); err != nil {
		t.Fatalf("issue client cert: %v", err)
	}

	// Test server TLS config.
	serverTLS, err := ServerTLSConfig(caCertPath, serverCert, serverKey)
	if err != nil {
		t.Fatalf("ServerTLSConfig() error: %v", err)
	}
	if serverTLS.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Error("server should require client certs")
	}
	if serverTLS.MinVersion != tls.VersionTLS13 {
		t.Error("server should require TLS 1.3")
	}

	// Test client TLS config.
	clientTLS, err := ClientTLSConfig(caCertPath, clientCert, clientKey)
	if err != nil {
		t.Fatalf("ClientTLSConfig() error: %v", err)
	}
	if len(clientTLS.Certificates) != 1 {
		t.Error("client should have one certificate")
	}
	if clientTLS.MinVersion != tls.VersionTLS13 {
		t.Error("client should require TLS 1.3")
	}
}
