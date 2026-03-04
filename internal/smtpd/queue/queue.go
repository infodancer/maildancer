// Package queue implements atomic on-disk queue injection for outbound mail.
// Bodies are stored under msg/{sender-tld}/{sender-domain}/{msgid} and
// envelopes under env/{rcpt-tld}/{rcpt-domain}/{localpart}@{msgid}.{n}.
// All writes are atomic (tmp → rename) so queue-manager never sees partial state.
package queue

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Config holds queue-injection parameters.
type Config struct {
	// Dir is the root of the on-disk mail queue.
	Dir string
	// MessageTTL is how long the message should be retried.
	MessageTTL time.Duration
	// Hostname is the smtpd hostname, used as the domain in VERP bounce addresses.
	Hostname string
}

// Write atomically injects a message into the queue.
//
// Protocol:
//  1. Generate a random msgid (RFC 5322 format: hex@hostname).
//  2. Prepend Message-ID header to the body.
//  3. Write body to msg/{sender-tld}/{sender-domain}/tmp_{msgidHex}, then rename.
//  4. For each recipient write an envelope to
//     env/{rcpt-tld}/{rcpt-domain}/tmp_{localpart}@{msgidHex}.{n}, then rename.
//
// Filesystem paths use only the hex left-hand part of the msgid so that
// queue-manager's extractMsgID (which does LastIndex("@") on envelope filenames)
// continues to work correctly. The full RFC 5322 msgid is stored in the MSGID
// envelope field and the Message-ID header.
//
// If smtpd crashes between steps the orphaned tmp_ files are swept by
// queue-manager (they never match the envelope filename pattern).
func Write(cfg Config, from string, recipients []string, body io.Reader) error {
	// Use the sender's domain in the msgid (RFC 5322 §3.6.4). The right-hand
	// side authenticates the message as originating from that domain, and in
	// the new messaging protocol the recipient resolves _mail._tcp.{sender-domain}
	// SRV to find the retrieval endpoint. cfg.Hostname is still used for VERP.
	fromDomain := extractDomain(from)
	msgid, msgidHex, err := newMsgID(fromDomain)
	if err != nil {
		return fmt.Errorf("queue: generate msgid: %w", err)
	}

	ttl := time.Now().Add(cfg.MessageTTL).UTC().Format(time.RFC3339)

	// --- body ---
	// Prepend Message-ID header. smtpd is the originating MTA for authenticated
	// submissions; the domain part ties the message to the sender's domain and
	// encodes the retrieval address for the new messaging protocol.
	messageIDHeader := fmt.Sprintf("Message-ID: <%s>\r\n", msgid)
	bodyWithHeader := io.MultiReader(strings.NewReader(messageIDHeader), body)

	senderTLD, senderDomain := splitDomainLabels(fromDomain)
	msgDir := filepath.Join(cfg.Dir, "msg", senderTLD, senderDomain)
	if err := os.MkdirAll(msgDir, 0700); err != nil {
		return fmt.Errorf("queue: mkdir %s: %w", msgDir, err)
	}

	bodyPath := filepath.Join(msgDir, msgidHex)
	if err := atomicWrite(msgDir, bodyPath, func(w io.Writer) error {
		_, err := io.Copy(w, bodyWithHeader)
		return err
	}); err != nil {
		return fmt.Errorf("queue: write body: %w", err)
	}

	// --- envelopes ---
	// Envelope filenames use msgidHex (no "@") so queue-manager can parse them
	// with a simple LastIndex("@"). The full RFC 5322 msgid goes in the MSGID field.
	for n, rcpt := range recipients {
		verpSender := verpAddress(from, rcpt, cfg.Hostname)
		rcptLocal, rcptDomain := splitAddress(rcpt)
		rcptTLD, rcptSLD := splitDomainLabels(rcptDomain)
		envDir := filepath.Join(cfg.Dir, "env", rcptTLD, rcptSLD)
		if err := os.MkdirAll(envDir, 0700); err != nil {
			return fmt.Errorf("queue: mkdir %s: %w", envDir, err)
		}

		envName := fmt.Sprintf("%s@%s.%d", rcptLocal, msgidHex, n)
		envPath := filepath.Join(envDir, envName)

		content := fmt.Sprintf("TTL %s\nSENDER %s\nRECIPIENT %s\nMSGID %s\n",
			ttl, verpSender, rcpt, msgid)

		if err := atomicWrite(envDir, envPath, func(w io.Writer) error {
			_, err := io.WriteString(w, content)
			return err
		}); err != nil {
			return fmt.Errorf("queue: write envelope for %s: %w", rcpt, err)
		}
	}

	return nil
}

// newMsgID generates a msgid in RFC 5322 format: {hex}@{hostname}.
// Returns the full form (for headers/envelopes) and the hex-only form
// (for filesystem paths, where the "@" would break filename parsing).
func newMsgID(hostname string) (msgid, msgidHex string, err error) {
	b := make([]byte, 16)
	if _, err = rand.Read(b); err != nil {
		return
	}
	msgidHex = hex.EncodeToString(b)
	msgid = msgidHex + "@" + hostname
	return
}

// atomicWrite writes to a tmp_ file in dir, then renames to finalPath.
func atomicWrite(dir, finalPath string, write func(io.Writer) error) error {
	tmp, err := os.CreateTemp(dir, "tmp_")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()

	if err := write(tmp); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, finalPath); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

// verpAddress computes the VERP bounce address for a single recipient.
// Format: bounces+{rcpt-localpart}={rcpt-domain}@{smtpd-hostname}
func verpAddress(from, rcpt, hostname string) string {
	rcptLocal, rcptDomain := splitAddress(rcpt)
	_ = from // VERP encodes recipient, not sender
	return fmt.Sprintf("bounces+%s=%s@%s", rcptLocal, rcptDomain, hostname)
}

// extractDomain returns the domain part of an email address.
// Strips optional angle brackets.
func extractDomain(addr string) string {
	addr = strings.TrimPrefix(addr, "<")
	addr = strings.TrimSuffix(addr, ">")
	idx := strings.LastIndex(addr, "@")
	if idx < 0 || idx == len(addr)-1 {
		return "unknown"
	}
	return strings.ToLower(addr[idx+1:])
}

// splitAddress returns (localpart, domain) from an email address.
// Strips angle brackets.
func splitAddress(addr string) (string, string) {
	addr = strings.TrimPrefix(addr, "<")
	addr = strings.TrimSuffix(addr, ">")
	idx := strings.LastIndex(addr, "@")
	if idx < 0 {
		return addr, "unknown"
	}
	return addr[:idx], strings.ToLower(addr[idx+1:])
}

// splitDomainLabels returns (tld, sld) from a domain name.
// For "mail.example.com" → ("com", "example").
// For a single-label domain → ("unknown", domain).
func splitDomainLabels(domain string) (tld, sld string) {
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return "unknown", domain
	}
	return labels[len(labels)-1], labels[len(labels)-2]
}
