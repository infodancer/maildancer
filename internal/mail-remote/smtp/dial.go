package smtp

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	gosmtp "github.com/emersion/go-smtp"
)

const dialTimeout = 30 * time.Second

// DialMX dials an MX host with opportunistic STARTTLS and proper EHLO.
//
// Strategy (matches standard MTA behavior for direct MX delivery):
//  1. Connect, STARTTLS with verified cert, EHLO with hostname
//  2. On TLS failure: reconnect, STARTTLS with InsecureSkipVerify, EHLO
//  3. On STARTTLS not supported: reconnect, plaintext EHLO
//
// Smarthost delivery should use DialStartTLS (strict) instead.
var DialMX = func(addr, hostname string) (*gosmtp.Client, error) {
	host, _, _ := net.SplitHostPort(addr)

	// Attempt 1: strict TLS
	c, err := dialStartTLS(addr, hostname, &tls.Config{ServerName: host})
	if err == nil {
		return c, nil
	}

	// Attempt 2: insecure TLS
	c, err = dialStartTLS(addr, hostname, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, //nolint:gosec // opportunistic TLS for MX delivery
	})
	if err == nil {
		return c, nil
	}

	// Attempt 3: plaintext
	return dialPlaintext(addr, hostname)
}

// dialStartTLS connects and upgrades to TLS. After the TLS handshake,
// go-smtp resets didHello, so we call Hello(hostname) to send a proper
// post-TLS EHLO with our configured hostname.
func dialStartTLS(addr, hostname string, tlsConf *tls.Config) (*gosmtp.Client, error) {
	conn, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	c, err := gosmtp.NewClientStartTLS(conn, tlsConf)
	if err != nil {
		// NewClientStartTLS closes conn on error.
		return nil, err
	}

	// After TLS upgrade, didHello is reset. Send a proper EHLO with our
	// hostname (NewClientStartTLS used "localhost" for the pre-TLS EHLO).
	if err := c.Hello(hostname); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("post-tls ehlo %s: %w", addr, err)
	}
	return c, nil
}

func dialPlaintext(addr, hostname string) (*gosmtp.Client, error) {
	conn, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	c := gosmtp.NewClient(conn)
	if err := c.Hello(hostname); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("ehlo %s: %w", addr, err)
	}
	return c, nil
}
