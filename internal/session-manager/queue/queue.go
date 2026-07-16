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

// Owner identifies the account that should own queue entries on disk.
type Owner struct {
	UID int
	GID int
}

// Config holds queue-injection parameters.
type Config struct {
	// Dir is the root of the on-disk mail queue.
	Dir string
	// Owner, when non-nil, assigns ownership of every directory and file
	// the queue creates. Set it when the writing process runs privileged
	// but the queue consumer (queue-manager) runs as a dedicated account;
	// nil leaves entries owned by the writing process. A failed chown
	// fails the write: entries the consumer cannot read would strand mail.
	Owner *Owner
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
// presetMsgIDHex, when non-empty, is the hex correlation id minted upstream at
// smtpd ingress; the queue reuses it instead of generating its own so the
// message keeps one id across the inbound->outbound boundary. Empty for
// queue-originated messages (e.g. DSNs), which mint their own.
func Write(cfg Config, from string, recipients []string, presetMsgIDHex string, body io.Reader) (string, error) {
	fromDomain := extractDomain(from)

	if !validAddressComponent(fromDomain) {
		return "", fmt.Errorf("queue: invalid sender domain %q", fromDomain)
	}

	var msgid, msgidHex string
	if presetMsgIDHex != "" {
		if !validMsgIDHex(presetMsgIDHex) {
			return "", fmt.Errorf("queue: invalid preset msgid %q", presetMsgIDHex)
		}
		msgidHex = presetMsgIDHex
		msgid = msgidHex + "@" + fromDomain
	} else {
		var err error
		msgid, msgidHex, err = newMsgID(fromDomain)
		if err != nil {
			return "", fmt.Errorf("queue: generate msgid: %w", err)
		}
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
	if err := mkdirAllOwned(cfg.Dir, msgDir, 0700, cfg.Owner); err != nil {
		return "", fmt.Errorf("queue: mkdir %s: %w", msgDir, err)
	}

	bodyPath := filepath.Join(msgDir, msgidHex)
	if err := atomicWrite(msgDir, bodyPath, cfg.Owner, func(w io.Writer) error {
		_, err := io.Copy(w, bodyReader)
		return err
	}); err != nil {
		return "", fmt.Errorf("queue: write body: %w", err)
	}

	// Envelopes: one per recipient.
	for n, rcpt := range recipients {
		rcptLocal, rcptDomain := splitAddress(rcpt)
		if !validAddressComponent(rcptLocal) || !validAddressComponent(rcptDomain) {
			return "", fmt.Errorf("queue: invalid recipient %q", rcpt)
		}

		verpSender := verpAddress(from, rcpt, cfg.Hostname)
		rcptTLD, rcptSLD := splitDomainLabels(rcptDomain)
		envDir := filepath.Join(cfg.Dir, "env", rcptTLD, rcptSLD)
		if err := mkdirAllOwned(cfg.Dir, envDir, 0700, cfg.Owner); err != nil {
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

		if err := atomicWrite(envDir, envPath, cfg.Owner, func(w io.Writer) error {
			return json.NewEncoder(w).Encode(env)
		}); err != nil {
			return "", fmt.Errorf("queue: write envelope for %s: %w", rcpt, err)
		}
	}

	return msgid, nil
}

// validAddressComponent rejects address parts that would escape the queue
// directory when used as a path component. Matches the predicate enforced by
// the delivery agent in internal/mail-session/deliver.
func validAddressComponent(s string) bool {
	return s != "" &&
		!strings.ContainsAny(s, "/\\") &&
		!strings.Contains(s, "..")
}

// validMsgIDHex reports whether s is a 16-byte (32-char) hex string, the form
// minted at smtpd ingress. The id is used in queue filenames, so this both
// rejects malformed input and keeps paths filesystem-safe.
func validMsgIDHex(s string) bool {
	if len(s) != 32 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
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
// mkdirAllOwned is os.MkdirAll plus ownership: it ensures path exists, then
// chowns every level between root (exclusive) and path (inclusive) to owner.
// Levels that already existed are chowned too -- chown is idempotent and the
// queue tree has a single legitimate owner -- so a level created earlier by a
// differently-privileged writer is repaired rather than left blocking the
// consumer. A nil owner makes this plain os.MkdirAll.
func mkdirAllOwned(root, path string, mode os.FileMode, owner *Owner) error {
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	if owner == nil {
		return nil
	}
	rel, err := filepath.Rel(root, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		return fmt.Errorf("queue path %s not under root %s", path, root)
	}
	p := root
	for part := range strings.SplitSeq(rel, string(filepath.Separator)) {
		p = filepath.Join(p, part)
		if err := os.Chown(p, owner.UID, owner.GID); err != nil {
			return fmt.Errorf("chown %s: %w", p, err)
		}
	}
	return nil
}

func atomicWrite(dir, finalPath string, owner *Owner, write func(io.Writer) error) error {
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
	// Assign ownership before the rename makes the file visible to the
	// queue consumer; Fchown on the open handle avoids a path race.
	if owner != nil {
		if err := tmp.Chown(owner.UID, owner.GID); err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
			return fmt.Errorf("chown %s: %w", tmpName, err)
		}
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
