// Package queue implements atomic on-disk queue injection for outbound mail.
// Bodies are stored under msg/{sender-tld}/{sender-domain}/{msgid} and
// envelopes under env/{rcpt-tld}/{rcpt-domain}/{localpart}@{msgid}.{n}.
// All writes are atomic (tmp → rename) so queue-manager never sees partial state.
package queue

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// queueEnvelope is the JSON envelope written to disk for each recipient.
type queueEnvelope struct {
	TTL       time.Time `json:"ttl"`
	Created   time.Time `json:"created"`
	Sender    string    `json:"sender"`
	Recipient string    `json:"recipient"`
	MsgID     string    `json:"msgid"`
	Origin    string    `json:"origin"`
}

// Config holds queue-injection parameters.
type Config struct {
	// Dir is the root of the on-disk mail queue.
	Dir string
	// MessageTTL is how long the message should be retried.
	MessageTTL time.Duration
	// Hostname is the server hostname, used as the domain in VERP bounce addresses.
	Hostname string
	// DKIMSign signs a message for the given sender domain, returning a reader
	// over the signed message (DKIM-Signature header prepended). If nil or if
	// it returns the input unchanged, DKIM signing is skipped.
	DKIMSign func(senderDomain string, msg io.Reader) (io.Reader, error)
}

// Write atomically injects a message into the queue and returns the assigned
// message ID (RFC 5322 format: hex@sender-domain).
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
func Write(cfg Config, from string, recipients []string, body io.Reader) (string, error) {
	fromDomain := extractDomain(from)
	msgid, msgidHex, err := newMsgID(fromDomain)
	if err != nil {
		return "", fmt.Errorf("queue: generate msgid: %w", err)
	}

	now := time.Now().UTC()
	ttl := now.Add(cfg.MessageTTL)

	// Prepend Message-ID header.
	messageIDHeader := fmt.Sprintf("Message-ID: <%s>\r\n", msgid)
	bodyReader := io.MultiReader(strings.NewReader(messageIDHeader), body)

	// DKIM sign the message if a signer is configured for this domain.
	if cfg.DKIMSign != nil {
		signed, err := cfg.DKIMSign(fromDomain, bodyReader)
		if err != nil {
			return "", fmt.Errorf("queue: DKIM sign: %w", err)
		}
		bodyReader = signed
	}

	senderTLD, senderDomain := splitDomainLabels(fromDomain)
	msgDir := filepath.Join(cfg.Dir, "msg", senderTLD, senderDomain)
	if err := os.MkdirAll(msgDir, 0700); err != nil {
		return "", fmt.Errorf("queue: mkdir %s: %w", msgDir, err)
	}

	bodyPath := filepath.Join(msgDir, msgidHex)
	if err := atomicWrite(msgDir, bodyPath, func(w io.Writer) error {
		_, err := io.Copy(w, bodyReader)
		return err
	}); err != nil {
		return "", fmt.Errorf("queue: write body: %w", err)
	}

	// Envelopes: one per recipient.
	for n, rcpt := range recipients {
		verpSender := verpAddress(from, rcpt, cfg.Hostname)
		rcptLocal, rcptDomain := splitAddress(rcpt)
		rcptTLD, rcptSLD := splitDomainLabels(rcptDomain)
		envDir := filepath.Join(cfg.Dir, "env", rcptTLD, rcptSLD)
		if err := os.MkdirAll(envDir, 0700); err != nil {
			return "", fmt.Errorf("queue: mkdir %s: %w", envDir, err)
		}

		envName := fmt.Sprintf("%s@%s.%d", rcptLocal, msgidHex, n)
		envPath := filepath.Join(envDir, envName)

		env := queueEnvelope{
			TTL:       ttl,
			Created:   now,
			Sender:    verpSender,
			Recipient: rcpt,
			MsgID:     msgid,
			Origin:    from,
		}

		if err := atomicWrite(envDir, envPath, func(w io.Writer) error {
			return json.NewEncoder(w).Encode(env)
		}); err != nil {
			return "", fmt.Errorf("queue: write envelope for %s: %w", rcpt, err)
		}
	}

	return msgid, nil
}

// newMsgID generates a msgid in RFC 5322 format: {hex}@{hostname}.
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
// Format: bounces+{rcpt-localpart}={rcpt-domain}@{hostname}
func verpAddress(from, rcpt, hostname string) string {
	rcptLocal, rcptDomain := splitAddress(rcpt)
	_ = from // VERP encodes recipient, not sender
	return fmt.Sprintf("bounces+%s=%s@%s", rcptLocal, rcptDomain, hostname)
}

// extractDomain returns the domain part of an email address.
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
func splitDomainLabels(domain string) (tld, sld string) {
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return "unknown", domain
	}
	return labels[len(labels)-1], labels[len(labels)-2]
}
