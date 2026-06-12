package deliver

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/nacl/box"

	"github.com/infodancer/maildancer/msgstore"
)

// setupEncryptedFixture builds the standard domain fixture and provisions an
// NaCl box keypair for alice: the public key goes into the domain key backend
// (keys/alice.pub, raw 32 bytes), the private key is returned for decryption
// assertions.
func setupEncryptedFixture(t *testing.T) (*Deliverer, *[32]byte) {
	t.Helper()
	dlvr := setupDomainFixture(t, "")

	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	keyPath := filepath.Join(dlvr.cfg.DomainsPath, "example.com", "keys", "alice.pub")
	if err := os.WriteFile(keyPath, pub[:], 0644); err != nil {
		t.Fatalf("write public key: %v", err)
	}
	return dlvr, priv
}

// deliverAliceEncrypted runs a delivery to alice with the encryption key hint set.
func deliverAliceEncrypted(t *testing.T, dlvr *Deliverer) (DeliverResponse, error) {
	t.Helper()
	return dlvr.Deliver(context.Background(),
		DeliverRequest{
			Sender:            "sender@example.com",
			Recipient:         "alice@example.com",
			EncryptionKeyHint: "alice",
		},
		[]byte(minimalMsg))
}

// readSoleMessage returns the content of the single message in a maildir.
func readSoleMessage(t *testing.T, maildirPath string) []byte {
	t.Helper()
	for _, sub := range []string{"new", "cur"} {
		dir := filepath.Join(maildirPath, sub)
		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatalf("read %s: %v", dir, err)
		}
		if len(entries) == 1 {
			data, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
			if err != nil {
				t.Fatalf("read message: %v", err)
			}
			return data
		}
		if len(entries) > 1 {
			t.Fatalf("want exactly 1 message in %s, got %d", dir, len(entries))
		}
	}
	t.Fatalf("no message found in %s", maildirPath)
	return nil
}

// assertEncryptedBlob verifies the on-disk blob is not plaintext and decrypts
// back to the original message with the recipient's private key.
func assertEncryptedBlob(t *testing.T, blob []byte, priv *[32]byte) {
	t.Helper()
	if bytes.Equal(blob, []byte(minimalMsg)) {
		t.Fatal("on-disk blob is plaintext; encryption was requested")
	}
	if bytes.Contains(blob, []byte("Hello.")) {
		t.Fatal("on-disk blob contains plaintext body content")
	}
	plain, err := msgstore.DecryptMessage(blob, priv[:])
	if err != nil {
		t.Fatalf("decrypt blob: %v", err)
	}
	if !bytes.Equal(plain, []byte(minimalMsg)) {
		t.Errorf("decrypted content mismatch: got %q", plain)
	}
}

func TestEncrypt_KeepPath(t *testing.T) {
	dlvr, priv := setupEncryptedFixture(t)

	resp, err := deliverAliceEncrypted(t, dlvr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Result != ResultDelivered {
		t.Fatalf("want ResultDelivered, got %v (reason: %q)", resp.Result, resp.Reason)
	}
	assertEncryptedBlob(t, readSoleMessage(t, inboxPath(dlvr)), priv)
}

// TestEncrypt_SieveFileInto is the guard test from issue #53: a sieve
// fileinto delivery with encryption requested must write ciphertext, not
// plaintext, to the folder. The header condition matches against the
// plaintext Subject, proving sieve still evaluates before encryption.
func TestEncrypt_SieveFileInto(t *testing.T) {
	dlvr, priv := setupEncryptedFixture(t)
	writeSieve(t, dlvr, `require "fileinto";
if header :contains "Subject" "test" {
    fileinto "Archive";
}
`)

	resp, err := deliverAliceEncrypted(t, dlvr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Result != ResultDelivered {
		t.Fatalf("want ResultDelivered, got %v (reason: %q)", resp.Result, resp.Reason)
	}
	if n := countMessages(t, inboxPath(dlvr)); n != 0 {
		t.Errorf("want 0 messages in inbox, got %d", n)
	}
	assertEncryptedBlob(t, readSoleMessage(t, folderPath(dlvr, "Archive")), priv)
}

// TestEncrypt_SieveFileIntoWithFlags covers the AppendToFolder write path
// (used when imap4flags are set), which must also receive ciphertext.
func TestEncrypt_SieveFileIntoWithFlags(t *testing.T) {
	dlvr, priv := setupEncryptedFixture(t)
	writeSieve(t, dlvr, `require ["fileinto", "imap4flags"];
fileinto :flags ["\\Seen"] "Archive";
`)

	resp, err := deliverAliceEncrypted(t, dlvr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Result != ResultDelivered {
		t.Fatalf("want ResultDelivered, got %v (reason: %q)", resp.Result, resp.Reason)
	}
	assertEncryptedBlob(t, readSoleMessage(t, folderPath(dlvr, "Archive")), priv)
}

// TestEncrypt_SieveRedirectCopy: the local copy from redirect :copy must be
// encrypted; the redirect itself propagates normally (smtpd re-sends from
// its own plaintext copy).
func TestEncrypt_SieveRedirectCopy(t *testing.T) {
	dlvr, priv := setupEncryptedFixture(t)
	writeSieve(t, dlvr, `require "copy";
redirect :copy "bob@elsewhere.example.com";
`)

	resp, err := deliverAliceEncrypted(t, dlvr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Result != ResultRedirected {
		t.Fatalf("want ResultRedirected, got %v (reason: %q)", resp.Result, resp.Reason)
	}
	assertEncryptedBlob(t, readSoleMessage(t, inboxPath(dlvr)), priv)
}

// TestEncrypt_MissingKeyFailsClosed: encryption explicitly requested but no
// key on file must temp-fail, never silently deliver plaintext.
func TestEncrypt_MissingKeyFailsClosed(t *testing.T) {
	dlvr := setupDomainFixture(t, "") // no key provisioned

	resp, err := dlvr.Deliver(context.Background(),
		DeliverRequest{
			Sender:            "sender@example.com",
			Recipient:         "alice@example.com",
			EncryptionKeyHint: "alice",
		},
		[]byte(minimalMsg))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Result != ResultRejected {
		t.Fatalf("want ResultRejected (fail closed), got %v", resp.Result)
	}
	if !resp.Temporary {
		t.Error("want Temporary=true (configuration error, sender should retry)")
	}
	if n := countMessages(t, inboxPath(dlvr)); n != 0 {
		t.Errorf("want 0 messages in inbox (no plaintext fallback), got %d", n)
	}
}

// TestEncrypt_NoHintStaysPlaintext: without the hint, delivery is plaintext
// even when the user has a key -- encryption happens only on request.
func TestEncrypt_NoHintStaysPlaintext(t *testing.T) {
	dlvr, _ := setupEncryptedFixture(t)

	resp := deliverAlice(t, dlvr, false)
	if resp.Result != ResultDelivered {
		t.Fatalf("want ResultDelivered, got %v (reason: %q)", resp.Result, resp.Reason)
	}
	if got := readSoleMessage(t, inboxPath(dlvr)); !bytes.Equal(got, []byte(minimalMsg)) {
		t.Errorf("want plaintext delivery without hint, got %d bytes differing from original", len(got))
	}
}
