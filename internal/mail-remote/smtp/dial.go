package smtp

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	gosmtp "github.com/emersion/go-smtp"
)

const dialTimeout = 30 * time.Second

// DialMX dials an MX host with opportunistic STARTTLS and proper EHLO.
//
// Strategy (matches standard MTA behavior for direct MX delivery):
//  1. Connect, EHLO with hostname, STARTTLS with verified cert, re-EHLO
//  2. On TLS failure: reconnect, EHLO, STARTTLS with InsecureSkipVerify, re-EHLO
//  3. On STARTTLS not supported: stay on the plaintext connection
//
// The hostname is used for all EHLO commands (both pre- and post-TLS).
// Smarthost delivery should use the strict dialFunc instead.
var DialMX = func(addr, hostname string) (*gosmtp.Client, error) {
	host, _, _ := net.SplitHostPort(addr)

	// Attempt 1: connect, EHLO, try strict STARTTLS.
	conn, err := dialTCP(addr)
	if err != nil {
		return nil, err
	}

	tlsConn, err := negotiateSTARTTLS(conn, hostname, &tls.Config{ServerName: host})
	if err == nil {
		// TLS succeeded -- create client on the encrypted connection.
		c := gosmtp.NewClient(tlsConn)
		if err := c.Hello(hostname); err != nil {
			_ = c.Close()
			return nil, fmt.Errorf("post-tls ehlo %s: %w", addr, err)
		}
		return c, nil
	}
	_ = conn.Close()

	// Attempt 2: reconnect, try insecure STARTTLS.
	conn, err = dialTCP(addr)
	if err != nil {
		return nil, err
	}

	tlsConn, err = negotiateSTARTTLS(conn, hostname, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, //nolint:gosec // opportunistic TLS for MX delivery
	})
	if err == nil {
		c := gosmtp.NewClient(tlsConn)
		if err := c.Hello(hostname); err != nil {
			_ = c.Close()
			return nil, fmt.Errorf("post-tls ehlo %s: %w", addr, err)
		}
		return c, nil
	}
	_ = conn.Close()

	// Attempt 3: plaintext only.
	conn, err = dialTCP(addr)
	if err != nil {
		return nil, err
	}
	c := gosmtp.NewClient(conn)
	if err := c.Hello(hostname); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("ehlo %s: %w", addr, err)
	}
	return c, nil
}

func dialTCP(addr string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	return conn, nil
}

// negotiateSTARTTLS performs the SMTP greeting, EHLO, and STARTTLS handshake
// at the raw protocol level, returning an upgraded TLS connection. This avoids
// go-smtp's NewClientStartTLS which hardcodes "localhost" for the pre-TLS EHLO.
//
// On any failure (no STARTTLS support, TLS handshake error), returns an error.
// The caller is responsible for closing conn on error.
func negotiateSTARTTLS(conn net.Conn, hostname string, tlsConf *tls.Config) (net.Conn, error) {
	r := bufio.NewReader(conn)

	// Read server greeting.
	if err := expectReply(r, 220); err != nil {
		return nil, fmt.Errorf("greeting: %w", err)
	}

	// Send EHLO.
	if _, err := fmt.Fprintf(conn, "EHLO %s\r\n", hostname); err != nil {
		return nil, fmt.Errorf("send ehlo: %w", err)
	}
	ehloReply, err := readReply(r, 250)
	if err != nil {
		return nil, fmt.Errorf("ehlo: %w", err)
	}

	// Check for STARTTLS in EHLO extensions.
	hasSTARTTLS := false
	for _, line := range ehloReply {
		if strings.EqualFold(strings.TrimSpace(line), "STARTTLS") {
			hasSTARTTLS = true
			break
		}
	}
	if !hasSTARTTLS {
		return nil, fmt.Errorf("server does not advertise STARTTLS")
	}

	// Send STARTTLS command.
	if _, err := fmt.Fprintf(conn, "STARTTLS\r\n"); err != nil {
		return nil, fmt.Errorf("send starttls: %w", err)
	}
	if err := expectReply(r, 220); err != nil {
		return nil, fmt.Errorf("starttls reply: %w", err)
	}

	// Upgrade to TLS.
	tlsConn := tls.Client(conn, tlsConf)
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("tls handshake: %w", err)
	}

	return tlsConn, nil
}

// expectReply reads a single SMTP reply and checks the status code.
func expectReply(r *bufio.Reader, wantCode int) error {
	_, err := readReply(r, wantCode)
	return err
}

// readReply reads a (possibly multi-line) SMTP reply. Returns the text
// lines (without the code prefix) and an error if the code doesn't match.
func readReply(r *bufio.Reader, wantCode int) ([]string, error) {
	var lines []string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("read reply: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if len(line) < 3 {
			return nil, fmt.Errorf("short reply: %q", line)
		}

		code, err := strconv.Atoi(line[:3])
		if err != nil {
			return nil, fmt.Errorf("invalid reply code: %q", line)
		}
		if code != wantCode {
			return nil, fmt.Errorf("unexpected reply %d (want %d): %s", code, wantCode, line)
		}

		// Extension text starts after "250-" or "250 ".
		if len(line) > 4 {
			lines = append(lines, line[4:])
		}

		// Last line of a multi-line reply uses space, not hyphen.
		if len(line) < 4 || line[3] != '-' {
			break
		}
	}
	return lines, nil
}
