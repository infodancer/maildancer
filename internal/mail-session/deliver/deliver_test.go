package deliver

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/infodancer/maildancer/auth/passwd"
	_ "github.com/infodancer/maildancer/msgstore/maildir"
)

// minimalMsg is a tiny but valid RFC 5322 message body used across tests.
const minimalMsg = "From: sender@example.com\r\nTo: alice@example.com\r\nSubject: test\r\n\r\nHello.\r\n"

// setupDomainFixture builds a temp domain tree under t.TempDir() and returns
// a configured *Deliverer. The caller is responsible for calling dlvr.Close().
//
// Domain layout created:
//
//	<base>/example.com/
//	  config.toml            (auth + msgstore + optional [forwards])
//	  passwd                 (alice:testpassHash:alice)
//	  keys/
//	  users/alice/Maildir/{cur,new,tmp}
//
// The forwards parameter, if non-empty, is appended verbatim after the base
// config as a [forwards] TOML section (e.g. `[forwards]\nalice = "..."`)
// so callers can inject forwarding rules without modifying production code.
func setupDomainFixture(t *testing.T, forwards string) *Deliverer {
	t.Helper()
	dlvr, _ := setupDomainFixtureBase(t, forwards)
	return dlvr
}

// setupDomainFixtureBase is setupDomainFixture for tests that also need the
// domains root, e.g. to pre-create a Maildir++ folder on disk.
func setupDomainFixtureBase(t *testing.T, forwards string) (*Deliverer, string) {
	t.Helper()

	base := t.TempDir()
	domainDir := filepath.Join(base, "example.com")

	// Domain directory
	if err := os.MkdirAll(domainDir, 0755); err != nil {
		t.Fatalf("create domain dir: %v", err)
	}

	// Keys directory
	if err := os.MkdirAll(filepath.Join(domainDir, "keys"), 0755); err != nil {
		t.Fatalf("create keys dir: %v", err)
	}

	// Maildir for alice
	for _, sub := range []string{"cur", "new", "tmp"} {
		p := filepath.Join(domainDir, "users", "alice", "Maildir", sub)
		if err := os.MkdirAll(p, 0755); err != nil {
			t.Fatalf("create maildir subdir %s: %v", sub, err)
		}
	}

	// passwd -- pre-computed argon2id hash for "testpass" (from smtpd testutil)
	const testpassHash = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0c2FsdA$qqSCqQPLbO7RKU/qFwvGng"
	passwd := "alice:" + testpassHash + ":alice\n"
	if err := os.WriteFile(filepath.Join(domainDir, "passwd"), []byte(passwd), 0644); err != nil {
		t.Fatalf("write passwd: %v", err)
	}

	// config.toml
	cfg := `[auth]
type = "passwd"
credential_backend = "passwd"
key_backend = "keys"

[msgstore]
type = "maildir"
base_path = "users"

[msgstore.options]
maildir_subdir = "Maildir"
`
	if forwards != "" {
		cfg += "\n" + forwards + "\n"
	}
	if err := os.WriteFile(filepath.Join(domainDir, "config.toml"), []byte(cfg), 0644); err != nil {
		t.Fatalf("write config.toml: %v", err)
	}

	// StoreBasePath is the recipient user-store root, as session-manager passes
	// via --basepath. At-rest encryption reads keyrings from here.
	dlvr, err := New(Config{
		DomainsPath:   base,
		StoreBasePath: filepath.Join(base, "example.com", "users"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = dlvr.Close() })
	return dlvr, base
}

// TestDeliver_Subaddress_ReportsFolder covers #168: mail to alice+lists@ is
// filed in the "lists" folder, and DeliverResponse must say so. Reporting
// INBOX here sends the IMAP IDLE notification -- and the client -- to a
// mailbox the message is not in.
func TestDeliver_Subaddress_ReportsFolder(t *testing.T) {
	dlvr, base := setupDomainFixtureBase(t, "")

	// Delivery only routes to a +extension folder that already exists, so
	// create the Maildir++ folder first.
	for _, sub := range []string{"cur", "new", "tmp"} {
		p := filepath.Join(base, "example.com", "users", "alice", "Maildir", ".lists", sub)
		if err := os.MkdirAll(p, 0755); err != nil {
			t.Fatalf("create folder maildir %s: %v", p, err)
		}
	}

	resp, err := dlvr.Deliver(context.Background(),
		DeliverRequest{
			Sender:    "sender@example.com",
			Recipient: "alice+lists@example.com",
		},
		[]byte(minimalMsg))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Result != ResultDelivered {
		t.Fatalf("want ResultDelivered, got %v (reason: %q)", resp.Result, resp.Reason)
	}
	if resp.Folder != "lists" {
		t.Errorf("want Folder %q, got %q", "lists", resp.Folder)
	}
}

// TestDeliver_SubaddressUnknownFolder_ReportsInbox is the other half of #168:
// an extension with no matching folder falls back to the inbox, and the
// reported folder must follow the message rather than the address.
func TestDeliver_SubaddressUnknownFolder_ReportsInbox(t *testing.T) {
	dlvr := setupDomainFixture(t, "")

	resp, err := dlvr.Deliver(context.Background(),
		DeliverRequest{
			Sender:    "sender@example.com",
			Recipient: "alice+nosuchfolder@example.com",
		},
		[]byte(minimalMsg))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Result != ResultDelivered {
		t.Fatalf("want ResultDelivered, got %v (reason: %q)", resp.Result, resp.Reason)
	}
	if resp.Folder != "INBOX" {
		t.Errorf("want Folder %q, got %q", "INBOX", resp.Folder)
	}
}

// TestDeliver_HappyPath is a smoke test: a well-formed delivery to a known
// local address must return ResultDelivered with no error.
func TestDeliver_HappyPath(t *testing.T) {
	dlvr := setupDomainFixture(t, "")
	resp, err := dlvr.Deliver(context.Background(),
		DeliverRequest{
			Sender:    "sender@example.com",
			Recipient: "alice@example.com",
		},
		[]byte(minimalMsg))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Result != ResultDelivered {
		t.Errorf("want ResultDelivered, got %v (reason: %q)", resp.Result, resp.Reason)
	}
}

// TestDeliver_LogsMsgID verifies the ingress correlation id threads into the
// delivery pipeline's log output, so a message is traceable by id (no content).
func TestDeliver_LogsMsgID(t *testing.T) {
	dlvr := setupDomainFixture(t, "")

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	const id = "0123456789abcdef0123456789abcdef"
	resp, err := dlvr.Deliver(context.Background(),
		DeliverRequest{Sender: "sender@example.com", Recipient: "alice@example.com", MsgID: id},
		[]byte(minimalMsg))
	if err != nil || resp.Result != ResultDelivered {
		t.Fatalf("deliver: err=%v result=%v", err, resp.Result)
	}
	if !strings.Contains(buf.String(), `"msgid":"`+id+`"`) {
		t.Errorf("expected msgid %q in delivery logs, got:\n%s", id, buf.String())
	}
}

// TestDeliverResultString pins the log tokens used in the result line.
func TestDeliverResultString(t *testing.T) {
	for r, want := range map[DeliverResult]string{
		ResultDelivered:   "delivered",
		ResultRejected:    "rejected",
		ResultRedirected:  "redirected",
		DeliverResult(99): "unknown",
	} {
		if got := r.String(); got != want {
			t.Errorf("DeliverResult(%d).String() = %q, want %q", int(r), got, want)
		}
	}
}

// TestDeliver is the table-driven suite covering pipeline rejection branches
// and the happy path together.
func TestDeliver(t *testing.T) {
	dlvr := setupDomainFixture(t, "")

	tests := []struct {
		name       string
		recipient  string
		forwarded  bool
		wantResult DeliverResult
		wantTemp   bool
		wantReason bool // true if Reason must be non-empty
	}{
		{
			name:       "empty recipient",
			recipient:  "",
			wantResult: ResultRejected,
			wantTemp:   false,
			wantReason: true,
		},
		{
			name:       "path traversal in localpart",
			recipient:  "../../etc/x@example.com",
			wantResult: ResultRejected,
			wantTemp:   false,
			wantReason: true,
		},
		{
			name:       "slash in localpart",
			recipient:  "a/b@example.com",
			wantResult: ResultRejected,
			wantTemp:   false,
			wantReason: true,
		},
		{
			name:       "backslash in domain",
			recipient:  `alice@exa\mple.com`,
			wantResult: ResultRejected,
			wantTemp:   false,
			wantReason: true,
		},
		{
			name:       "dotdot in domain",
			recipient:  "alice@ex..ample",
			wantResult: ResultRejected,
			wantTemp:   false,
			wantReason: true,
		},
		{
			name:       "unknown domain",
			recipient:  "bob@nope.invalid",
			wantResult: ResultRejected,
			wantTemp:   true,
			wantReason: true,
		},
		{
			name:       "happy path",
			recipient:  "alice@example.com",
			wantResult: ResultDelivered,
			wantTemp:   false,
			wantReason: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := dlvr.Deliver(context.Background(),
				DeliverRequest{
					Sender:    "sender@example.com",
					Recipient: tc.recipient,
					Forwarded: tc.forwarded,
				},
				[]byte(minimalMsg))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.Result != tc.wantResult {
				t.Errorf("Result: want %v, got %v (reason: %q)", tc.wantResult, resp.Result, resp.Reason)
			}
			if resp.Temporary != tc.wantTemp {
				t.Errorf("Temporary: want %v, got %v", tc.wantTemp, resp.Temporary)
			}
			if tc.wantReason && resp.Reason == "" {
				t.Errorf("want non-empty Reason, got empty")
			}
		})
	}
}

// TestDeliver_Forwarding exercises the forwarding stage of the pipeline.
// Forwarding rules are injected by writing a [forwards] section in config.toml;
// no production code is modified.
// TestDeliver_DoesNotResolveForwarding pins the post-#95 contract: forwarding is
// resolved upstream in session-manager (as root, before the privilege drop), so
// this pipeline -- which runs as the recipient uid -- never resolves forwards.
// Even with a matching [forwards] rule present, a message reaching Deliver is
// always written to the local mailbox; it is never redirected here.
func TestDeliver_DoesNotResolveForwarding(t *testing.T) {
	for _, forwarded := range []bool{false, true} {
		t.Run(fmt.Sprintf("forwarded=%v", forwarded), func(t *testing.T) {
			dlvr := setupDomainFixture(t, `[forwards]
alice = "alice@other.example.com"`)

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
			if resp.Result != ResultDelivered {
				t.Errorf("want ResultDelivered (deliver.go ignores forwarding), got %v (reason: %q)", resp.Result, resp.Reason)
			}
			if len(resp.RedirectAddresses) != 0 {
				t.Errorf("want no redirect addresses, got %v", resp.RedirectAddresses)
			}
		})
	}
}

// Sieve execution behavior is covered in sieve_test.go.
