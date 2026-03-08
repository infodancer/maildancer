package certutil

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// ServerTLSConfig builds a TLS config for the session manager server.
// It requires client certificates signed by the CA.
func ServerTLSConfig(caCertPath, serverCertPath, serverKeyPath string) (*tls.Config, error) {
	caPool, err := loadCACertPool(caCertPath)
	if err != nil {
		return nil, err
	}

	cert, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load server cert: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// ClientTLSConfig builds a TLS config for protocol handlers connecting
// to the session manager. It presents a client certificate and verifies
// the server certificate against the CA.
func ClientTLSConfig(caCertPath, clientCertPath, clientKeyPath string) (*tls.Config, error) {
	caPool, err := loadCACertPool(caCertPath)
	if err != nil {
		return nil, err
	}

	cert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// loadCACertPool reads a PEM-encoded CA certificate and returns a cert pool.
func loadCACertPool(path string) (*x509.CertPool, error) {
	caPEM, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("CA cert file contains no valid certificates")
	}
	return pool, nil
}
