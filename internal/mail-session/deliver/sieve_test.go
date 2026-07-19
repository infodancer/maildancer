package deliver

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeSieve writes a .sieve script for alice in the fixture created by
// setupDomainFixture. The script lives in the user's mailbox root, adjacent
// to the Maildir directory.
func writeSieve(t *testing.T, dlvr *Deliverer, script string) {
	t.Helper()
	dir := filepath.Join(dlvr.cfg.DataPath(), "example.com", "users", "alice")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("create user dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".sieve"), []byte(script), 0644); err != nil {
		t.Fatalf("write .sieve: %v", err)
	}
}

// countMessages counts messages in a maildir (new/ plus cur/).
// A missing directory counts as zero.
func countMessages(t *testing.T, maildirPath string) int {
	t.Helper()
	total := 0
	for _, sub := range []string{"new", "cur"} {
		entries, err := os.ReadDir(filepath.Join(maildirPath, sub))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatalf("read %s: %v", filepath.Join(maildirPath, sub), err)
		}
		total += len(entries)
	}
	return total
}

// inboxPath returns alice's inbox maildir path in the fixture.
func inboxPath(dlvr *Deliverer) string {
	return filepath.Join(dlvr.cfg.DataPath(), "example.com", "users", "alice", "Maildir")
}

// folderPath returns the Maildir++ path for a folder in alice's mailbox.
func folderPath(dlvr *Deliverer, folder string) string {
	return filepath.Join(inboxPath(dlvr), "."+folder)
}

// deliverAlice runs a standard delivery to alice@example.com and returns the response.
func deliverAlice(t *testing.T, dlvr *Deliverer, forwarded bool) DeliverResponse {
	t.Helper()
	resp, err := dlvr.Deliver(context.Background(),
		DeliverRequest{
			Sender:    "sender@example.com",
			Recipient: "alice@example.com",
			Forwarded: forwarded,
		},
		[]byte(minimalMsg))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return resp
}

func TestSieve_FileInto(t *testing.T) {
	dlvr := setupDomainFixture(t, "")
	writeSieve(t, dlvr, `require "fileinto";
fileinto "Archive";
`)

	resp := deliverAlice(t, dlvr, false)
	if resp.Result != ResultDelivered {
		t.Fatalf("want ResultDelivered, got %v (reason: %q)", resp.Result, resp.Reason)
	}
	if n := countMessages(t, folderPath(dlvr, "Archive")); n != 1 {
		t.Errorf("want 1 message in Archive, got %d", n)
	}
	if n := countMessages(t, inboxPath(dlvr)); n != 0 {
		t.Errorf("want 0 messages in inbox (fileinto cancels implicit keep), got %d", n)
	}
}

func TestSieve_HeaderConditionalFileInto(t *testing.T) {
	t.Run("matching header routes to folder", func(t *testing.T) {
		dlvr := setupDomainFixture(t, "")
		writeSieve(t, dlvr, `require "fileinto";
if header :contains "Subject" "test" {
    fileinto "Filtered";
}
`)
		resp := deliverAlice(t, dlvr, false)
		if resp.Result != ResultDelivered {
			t.Fatalf("want ResultDelivered, got %v (reason: %q)", resp.Result, resp.Reason)
		}
		if n := countMessages(t, folderPath(dlvr, "Filtered")); n != 1 {
			t.Errorf("want 1 message in Filtered, got %d", n)
		}
		if n := countMessages(t, inboxPath(dlvr)); n != 0 {
			t.Errorf("want 0 messages in inbox, got %d", n)
		}
	})

	t.Run("non-matching header falls through to inbox", func(t *testing.T) {
		dlvr := setupDomainFixture(t, "")
		writeSieve(t, dlvr, `require "fileinto";
if header :contains "Subject" "no-such-subject" {
    fileinto "Filtered";
}
`)
		resp := deliverAlice(t, dlvr, false)
		if resp.Result != ResultDelivered {
			t.Fatalf("want ResultDelivered, got %v (reason: %q)", resp.Result, resp.Reason)
		}
		if n := countMessages(t, inboxPath(dlvr)); n != 1 {
			t.Errorf("want 1 message in inbox (implicit keep), got %d", n)
		}
		if n := countMessages(t, folderPath(dlvr, "Filtered")); n != 0 {
			t.Errorf("want 0 messages in Filtered, got %d", n)
		}
	})
}

func TestSieve_FileInto_ReportsFolder(t *testing.T) {
	dlvr := setupDomainFixture(t, "")
	writeSieve(t, dlvr, `require "fileinto";
fileinto "Archive";
`)

	resp := deliverAlice(t, dlvr, false)
	if resp.Result != ResultDelivered {
		t.Fatalf("want ResultDelivered, got %v (reason: %q)", resp.Result, resp.Reason)
	}
	if resp.Folder != "Archive" {
		t.Errorf("want Folder %q, got %q", "Archive", resp.Folder)
	}
}

func TestSieve_ImplicitKeep_ReportsInboxFolder(t *testing.T) {
	dlvr := setupDomainFixture(t, "")
	// No .sieve script -- falls through to normal delivery (deliverLocal).
	resp := deliverAlice(t, dlvr, false)
	if resp.Result != ResultDelivered {
		t.Fatalf("want ResultDelivered, got %v (reason: %q)", resp.Result, resp.Reason)
	}
	if resp.Folder != "INBOX" {
		t.Errorf("want Folder %q, got %q", "INBOX", resp.Folder)
	}
}

func TestSieve_FileIntoINBOX(t *testing.T) {
	// fileinto "INBOX" must deliver to the inbox, not create a ".INBOX" folder.
	dlvr := setupDomainFixture(t, "")
	writeSieve(t, dlvr, `require "fileinto";
fileinto "INBOX";
`)

	resp := deliverAlice(t, dlvr, false)
	if resp.Result != ResultDelivered {
		t.Fatalf("want ResultDelivered, got %v (reason: %q)", resp.Result, resp.Reason)
	}
	if n := countMessages(t, inboxPath(dlvr)); n != 1 {
		t.Errorf("want 1 message in inbox, got %d", n)
	}
	if _, err := os.Stat(folderPath(dlvr, "INBOX")); !os.IsNotExist(err) {
		t.Errorf("a .INBOX folder must not be created (stat err: %v)", err)
	}
}

func TestSieve_Discard(t *testing.T) {
	dlvr := setupDomainFixture(t, "")
	writeSieve(t, dlvr, `discard;
`)

	resp := deliverAlice(t, dlvr, false)
	if resp.Result != ResultDelivered {
		t.Fatalf("want ResultDelivered (silent discard), got %v (reason: %q)", resp.Result, resp.Reason)
	}
	if n := countMessages(t, inboxPath(dlvr)); n != 0 {
		t.Errorf("want 0 messages in inbox after discard, got %d", n)
	}
}

func TestSieve_Redirect(t *testing.T) {
	dlvr := setupDomainFixture(t, "")
	writeSieve(t, dlvr, `redirect "bob@elsewhere.example.com";
`)

	resp := deliverAlice(t, dlvr, false)
	if resp.Result != ResultRedirected {
		t.Fatalf("want ResultRedirected, got %v (reason: %q)", resp.Result, resp.Reason)
	}
	if len(resp.RedirectAddresses) != 1 || resp.RedirectAddresses[0] != "bob@elsewhere.example.com" {
		t.Errorf("want redirect to bob@elsewhere.example.com, got %v", resp.RedirectAddresses)
	}
	if n := countMessages(t, inboxPath(dlvr)); n != 0 {
		t.Errorf("want 0 messages in inbox (redirect cancels implicit keep), got %d", n)
	}
}

func TestSieve_RedirectCopy(t *testing.T) {
	dlvr := setupDomainFixture(t, "")
	writeSieve(t, dlvr, `require "copy";
redirect :copy "bob@elsewhere.example.com";
`)

	resp := deliverAlice(t, dlvr, false)
	if resp.Result != ResultRedirected {
		t.Fatalf("want ResultRedirected, got %v (reason: %q)", resp.Result, resp.Reason)
	}
	if len(resp.RedirectAddresses) != 1 || resp.RedirectAddresses[0] != "bob@elsewhere.example.com" {
		t.Errorf("want redirect to bob@elsewhere.example.com, got %v", resp.RedirectAddresses)
	}
	if n := countMessages(t, inboxPath(dlvr)); n != 1 {
		t.Errorf("want 1 message in inbox (:copy preserves implicit keep), got %d", n)
	}
}

func TestSieve_RedirectSuppressedWhenForwarded(t *testing.T) {
	// 1-hop rule: a message that was already forwarded must not be redirected
	// again by sieve. The redirect is skipped and implicit keep applies.
	dlvr := setupDomainFixture(t, "")
	writeSieve(t, dlvr, `redirect "bob@elsewhere.example.com";
`)

	resp := deliverAlice(t, dlvr, true)
	if resp.Result != ResultDelivered {
		t.Fatalf("want ResultDelivered (redirect suppressed), got %v (reason: %q)", resp.Result, resp.Reason)
	}
	if len(resp.RedirectAddresses) != 0 {
		t.Errorf("want no redirect addresses, got %v", resp.RedirectAddresses)
	}
	if n := countMessages(t, inboxPath(dlvr)); n != 1 {
		t.Errorf("want 1 message in inbox (fallback to keep), got %d", n)
	}
}

func TestSieve_RedirectToSelfSuppressed(t *testing.T) {
	// A redirect to the recipient's own address is a no-op kept locally,
	// not a redirect loop handed back to smtpd.
	dlvr := setupDomainFixture(t, "")
	writeSieve(t, dlvr, `redirect "alice@example.com";
`)

	resp := deliverAlice(t, dlvr, false)
	if resp.Result != ResultDelivered {
		t.Fatalf("want ResultDelivered (self-redirect suppressed), got %v (reason: %q)", resp.Result, resp.Reason)
	}
	if n := countMessages(t, inboxPath(dlvr)); n != 1 {
		t.Errorf("want 1 message in inbox, got %d", n)
	}
}

func TestSieve_Reject(t *testing.T) {
	dlvr := setupDomainFixture(t, "")
	writeSieve(t, dlvr, `require "reject";
reject "content not wanted here";
`)

	resp := deliverAlice(t, dlvr, false)
	if resp.Result != ResultRejected {
		t.Fatalf("want ResultRejected, got %v (reason: %q)", resp.Result, resp.Reason)
	}
	if resp.Temporary {
		t.Error("sieve reject must be permanent, got Temporary=true")
	}
	if !strings.Contains(resp.Reason, "content not wanted here") {
		t.Errorf("want reject reason in response, got %q", resp.Reason)
	}
	if n := countMessages(t, inboxPath(dlvr)); n != 0 {
		t.Errorf("want 0 messages in inbox after reject, got %d", n)
	}
}

func TestSieve_Stop(t *testing.T) {
	// stop ends the script; the discard after it must not run, so
	// implicit keep delivers to the inbox.
	dlvr := setupDomainFixture(t, "")
	writeSieve(t, dlvr, `if header :contains "Subject" "test" {
    stop;
}
discard;
`)

	resp := deliverAlice(t, dlvr, false)
	if resp.Result != ResultDelivered {
		t.Fatalf("want ResultDelivered, got %v (reason: %q)", resp.Result, resp.Reason)
	}
	if n := countMessages(t, inboxPath(dlvr)); n != 1 {
		t.Errorf("want 1 message in inbox (stop preserves implicit keep), got %d", n)
	}
}

func TestSieve_KeepPlusFileInto(t *testing.T) {
	dlvr := setupDomainFixture(t, "")
	writeSieve(t, dlvr, `require "fileinto";
fileinto "Archive";
keep;
`)

	resp := deliverAlice(t, dlvr, false)
	if resp.Result != ResultDelivered {
		t.Fatalf("want ResultDelivered, got %v (reason: %q)", resp.Result, resp.Reason)
	}
	if n := countMessages(t, folderPath(dlvr, "Archive")); n != 1 {
		t.Errorf("want 1 message in Archive, got %d", n)
	}
	if n := countMessages(t, inboxPath(dlvr)); n != 1 {
		t.Errorf("want 1 message in inbox (explicit keep), got %d", n)
	}
}

func TestSieve_EnvelopeTest(t *testing.T) {
	dlvr := setupDomainFixture(t, "")
	writeSieve(t, dlvr, `require ["envelope", "fileinto"];
if envelope :is "from" "sender@example.com" {
    fileinto "FromSender";
}
`)

	resp := deliverAlice(t, dlvr, false)
	if resp.Result != ResultDelivered {
		t.Fatalf("want ResultDelivered, got %v (reason: %q)", resp.Result, resp.Reason)
	}
	if n := countMessages(t, folderPath(dlvr, "FromSender")); n != 1 {
		t.Errorf("want 1 message in FromSender (envelope from matched), got %d", n)
	}
}

func TestSieve_BodyTest(t *testing.T) {
	dlvr := setupDomainFixture(t, "")
	writeSieve(t, dlvr, `require ["body", "fileinto"];
if body :contains "Hello" {
    fileinto "Bodies";
}
`)

	resp := deliverAlice(t, dlvr, false)
	if resp.Result != ResultDelivered {
		t.Fatalf("want ResultDelivered, got %v (reason: %q)", resp.Result, resp.Reason)
	}
	if n := countMessages(t, folderPath(dlvr, "Bodies")); n != 1 {
		t.Errorf("want 1 message in Bodies (body matched), got %d", n)
	}
}

func TestSieve_ParseErrorFailSafe(t *testing.T) {
	// A script that fails to parse must not break delivery: log and fall
	// through to normal inbox delivery (RFC 5228 implicit keep on error).
	dlvr := setupDomainFixture(t, "")
	writeSieve(t, dlvr, `this is not a valid sieve script {{{`)

	resp := deliverAlice(t, dlvr, false)
	if resp.Result != ResultDelivered {
		t.Fatalf("want ResultDelivered (fail-safe), got %v (reason: %q)", resp.Result, resp.Reason)
	}
	if n := countMessages(t, inboxPath(dlvr)); n != 1 {
		t.Errorf("want 1 message in inbox, got %d", n)
	}
}

func TestSieve_OversizeScriptFailSafe(t *testing.T) {
	// A script over the size cap is ignored: normal delivery proceeds.
	// The trailing discard would empty the inbox if the script were executed.
	dlvr := setupDomainFixture(t, "")
	writeSieve(t, dlvr, strings.Repeat("# padding padding padding\n", 11000)+"discard;\n")

	resp := deliverAlice(t, dlvr, false)
	if resp.Result != ResultDelivered {
		t.Fatalf("want ResultDelivered (fail-safe), got %v (reason: %q)", resp.Result, resp.Reason)
	}
	if n := countMessages(t, inboxPath(dlvr)); n != 1 {
		t.Errorf("want 1 message in inbox, got %d", n)
	}
}

func TestSieve_NoScriptNormalDelivery(t *testing.T) {
	dlvr := setupDomainFixture(t, "")

	resp := deliverAlice(t, dlvr, false)
	if resp.Result != ResultDelivered {
		t.Fatalf("want ResultDelivered, got %v (reason: %q)", resp.Result, resp.Reason)
	}
	if n := countMessages(t, inboxPath(dlvr)); n != 1 {
		t.Errorf("want 1 message in inbox, got %d", n)
	}
}
