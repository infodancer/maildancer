package deliver

import (
	"context"
	"testing"
)

// The rule this whole mechanism exists to make writable: a user filing spam to
// Junk on a threshold, reading a verdict the sender cannot influence.
const junkOnValueScript = `require ["fileinto", "environment", "relational", "comparator-i;ascii-numeric"];
if environment :value "ge" :comparator "i;ascii-numeric" "vnd.maildancer.spam-value" "5" {
    fileinto "Junk";
}
`

// deliverAliceWithVerdict runs a delivery carrying the given out-of-band spam
// verdict. A nil verdict means no scan ran.
func deliverAliceWithVerdict(t *testing.T, dlvr *Deliverer, spam *SpamVerdict) DeliverResponse {
	t.Helper()
	resp, err := dlvr.Deliver(context.Background(),
		DeliverRequest{
			Sender:    "sender@example.com",
			Recipient: "alice@example.com",
			Spam:      spam,
		},
		[]byte(minimalMsg))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return resp
}

// TestSieveEnvironment_FilesSpamOnThreshold is the end-to-end case for #244:
// the verdict travels out of band, the script reads it through the environment
// extension, and the message is filed. Nothing in the message itself is
// consulted, so a sender cannot influence the outcome.
func TestSieveEnvironment_FilesSpamOnThreshold(t *testing.T) {
	dlvr := setupDomainFixture(t, "")
	writeSieve(t, dlvr, junkOnValueScript)

	resp := deliverAliceWithVerdict(t, dlvr, &SpamVerdict{
		IsSpam:  true,
		Score:   12.8,
		Headers: map[string]string{"X-Spam-Value": "9"},
	})
	if resp.Result != ResultDelivered {
		t.Fatalf("want ResultDelivered, got %v (reason: %q)", resp.Result, resp.Reason)
	}

	if n := countMessages(t, folderPath(dlvr, "Junk")); n != 1 {
		t.Errorf("want 1 message in Junk, got %d", n)
	}
	if n := countMessages(t, inboxPath(dlvr)); n != 0 {
		t.Errorf("want 0 in inbox (fileinto cancels implicit keep), got %d", n)
	}
}

// TestSieveEnvironment_KeepsCleanMail: a scanned-clean verdict is below the
// threshold, so the rule does not fire and implicit keep applies.
func TestSieveEnvironment_KeepsCleanMail(t *testing.T) {
	dlvr := setupDomainFixture(t, "")
	writeSieve(t, dlvr, junkOnValueScript)

	deliverAliceWithVerdict(t, dlvr, &SpamVerdict{
		IsSpam:  false,
		Score:   -2.5,
		Headers: map[string]string{"X-Spam-Value": "1"},
	})

	if n := countMessages(t, inboxPath(dlvr)); n != 1 {
		t.Errorf("want 1 message in inbox, got %d", n)
	}
	if n := countMessages(t, folderPath(dlvr, "Junk")); n != 0 {
		t.Errorf("want 0 in Junk, got %d", n)
	}
}

// TestSieveEnvironment_NoScanDoesNotFile: with no scan, a spam threshold rule
// must not fire.
func TestSieveEnvironment_NoScanDoesNotFile(t *testing.T) {
	dlvr := setupDomainFixture(t, "")
	writeSieve(t, dlvr, junkOnValueScript)

	deliverAliceWithVerdict(t, dlvr, nil)

	if n := countMessages(t, folderPath(dlvr, "Junk")); n != 0 {
		t.Errorf("filed unscanned mail to Junk (%d messages)", n)
	}
	if n := countMessages(t, inboxPath(dlvr)); n != 1 {
		t.Errorf("want 1 message in inbox, got %d", n)
	}
}

// TestSieveEnvironment_NoScanIsNotClean tests from the clean side, and is the
// one that actually pins "no verdict" apart from "judged clean".
//
// A rule keying on a *low* value catches the failure a spam-side rule cannot: if
// an unsupported item ever collapsed into "" or "0", a "ge 5" test would still
// not fire (0 is not >= 5) and the bug would pass unnoticed -- but "le 1" would
// fire, and unscanned mail would be sorted as though a scanner had cleared it.
// That is the direction where a silent default does damage: it launders
// unexamined mail as vouched-for.
func TestSieveEnvironment_NoScanIsNotClean(t *testing.T) {
	dlvr := setupDomainFixture(t, "")
	writeSieve(t, dlvr, `require ["fileinto", "environment", "relational", "comparator-i;ascii-numeric"];
if environment :value "le" :comparator "i;ascii-numeric" "vnd.maildancer.spam-value" "1" {
    fileinto "Vouched";
}
`)

	deliverAliceWithVerdict(t, dlvr, nil)

	if n := countMessages(t, folderPath(dlvr, "Vouched")); n != 0 {
		t.Errorf("unscanned mail was treated as scanned-clean (%d filed); "+
			"an unsupported item must not compare as a value", n)
	}

	// The same rule must fire on a real clean verdict, or the test above would
	// pass for the wrong reason -- an item that never resolves proves nothing.
	dlvr2 := setupDomainFixture(t, "")
	writeSieve(t, dlvr2, `require ["fileinto", "environment", "relational", "comparator-i;ascii-numeric"];
if environment :value "le" :comparator "i;ascii-numeric" "vnd.maildancer.spam-value" "1" {
    fileinto "Vouched";
}
`)
	deliverAliceWithVerdict(t, dlvr2, &SpamVerdict{
		IsSpam:  false,
		Headers: map[string]string{"X-Spam-Value": "1"},
	})
	if n := countMessages(t, folderPath(dlvr2, "Vouched")); n != 1 {
		t.Errorf("scanned-clean verdict did not match a le-1 rule (got %d); "+
			"the negative case above may be passing vacuously", n)
	}
}

// TestSieveEnvironment_IgnoresForgedHeader is the security case, and the reason
// the verdict is carried out of band at all. The message asserts it is clean;
// the out-of-band verdict says otherwise. The script reads the environment, so
// the sender's claim has no effect.
func TestSieveEnvironment_IgnoresForgedHeader(t *testing.T) {
	dlvr := setupDomainFixture(t, "")
	writeSieve(t, dlvr, junkOnValueScript)

	forged := "From: attacker@evil.example\r\n" +
		"X-Spam-Value: 0\r\n" +
		"X-Spam-Flag: NO\r\n" +
		"Subject: test\r\n\r\nbody\r\n"

	resp, err := dlvr.Deliver(context.Background(),
		DeliverRequest{
			Sender:    "sender@example.com",
			Recipient: "alice@example.com",
			Spam:      &SpamVerdict{IsSpam: true, Score: 12.8, Headers: map[string]string{"X-Spam-Value": "9"}},
		},
		[]byte(forged))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Result != ResultDelivered {
		t.Fatalf("want ResultDelivered, got %v (reason: %q)", resp.Result, resp.Reason)
	}

	if n := countMessages(t, folderPath(dlvr, "Junk")); n != 1 {
		t.Errorf("forged in-band header beat the out-of-band verdict: want 1 in Junk, got %d", n)
	}
}

// TestSieveEnvironment_FlagItem: the boolean form, for users who want the
// scanner's own call rather than a threshold of their own.
func TestSieveEnvironment_FlagItem(t *testing.T) {
	dlvr := setupDomainFixture(t, "")
	writeSieve(t, dlvr, `require ["fileinto", "environment"];
if environment :is "vnd.maildancer.spam-flag" "YES" {
    fileinto "Junk";
}
`)

	deliverAliceWithVerdict(t, dlvr, &SpamVerdict{IsSpam: true, Score: 12.8})

	if n := countMessages(t, folderPath(dlvr, "Junk")); n != 1 {
		t.Errorf("want 1 message in Junk, got %d", n)
	}
}

// TestSieveEnvironment_RequireParses: before this change `require "environment"`
// parsed but every test against it failed, because go-sieve had no provider to
// consult. Guards against the provider being dropped from runSieve and the
// scripts silently going quiet again rather than erroring.
func TestSieveEnvironment_RequireParses(t *testing.T) {
	dlvr := setupDomainFixture(t, "")
	writeSieve(t, dlvr, `require ["fileinto", "environment"];
if environment :is "name" "maildancer" {
    fileinto "Matched";
}
`)

	deliverAliceWithVerdict(t, dlvr, nil)

	if n := countMessages(t, folderPath(dlvr, "Matched")); n != 1 {
		t.Errorf("environment test did not match; provider likely not wired into runSieve (got %d)", n)
	}
}
