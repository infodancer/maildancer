package deliver

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// writeSystemSieve installs the site-wide fallback script.
func writeSystemSieve(t *testing.T, dlvr *Deliverer, script string) {
	t.Helper()
	path := filepath.Join(dlvr.cfg.DataPath(), systemSieveName)
	if err := os.WriteFile(path, []byte(script), 0644); err != nil {
		t.Fatalf("write system sieve: %v", err)
	}
}

// junkOnFlagScript is the shape the shipped default takes: file what the
// scanner itself called spam, with no threshold of our own invented on top.
const junkOnFlagScript = `require ["fileinto", "environment"];
if environment :is "vnd.maildancer.spam-flag" "YES" {
    fileinto "Junk";
}
`

func spamVerdict() *SpamVerdict {
	return &SpamVerdict{IsSpam: true, Score: 12.8, Headers: map[string]string{"X-Spam-Value": "9"}}
}

// TestSystemSieve_AppliesWhenUserHasNone is the point of the fallback: filing
// works with no per-user configuration, which matters because there is still no
// editor for users to author a script with.
func TestSystemSieve_AppliesWhenUserHasNone(t *testing.T) {
	dlvr := setupDomainFixture(t, "")
	writeSystemSieve(t, dlvr, junkOnFlagScript)

	resp := deliverAliceWithVerdict(t, dlvr, spamVerdict())
	if resp.Result != ResultDelivered {
		t.Fatalf("want ResultDelivered, got %v (reason: %q)", resp.Result, resp.Reason)
	}
	if n := countMessages(t, folderPath(dlvr, "Junk")); n != 1 {
		t.Errorf("want 1 message in Junk, got %d", n)
	}
	if n := countMessages(t, inboxPath(dlvr)); n != 0 {
		t.Errorf("want 0 in inbox, got %d", n)
	}
}

// TestSystemSieve_UserScriptWins is the policy decision made explicit: a user
// script REPLACES the default rather than layering under it.
//
// The two are not chained. RFC 5228 implicit keep and fileinto do not compose
// across independent scripts without inventing semantics the RFC does not
// define -- and more to the point, a user who writes a script that ignores spam
// has made a choice. Re-applying the site default on top would quietly overrule
// it, which is the opposite of letting users control their own mail.
func TestSystemSieve_UserScriptWins(t *testing.T) {
	dlvr := setupDomainFixture(t, "")
	writeSystemSieve(t, dlvr, junkOnFlagScript)
	// Alice deliberately wants flagged mail left in her inbox.
	writeSieve(t, dlvr, `require "fileinto";
if header :contains "Subject" "nonesuch" {
    fileinto "Never";
}
`)

	deliverAliceWithVerdict(t, dlvr, spamVerdict())

	if n := countMessages(t, folderPath(dlvr, "Junk")); n != 0 {
		t.Errorf("system default overrode the user's own script (%d filed to Junk)", n)
	}
	if n := countMessages(t, inboxPath(dlvr)); n != 1 {
		t.Errorf("want 1 message in inbox, got %d", n)
	}
}

// TestSystemSieve_BrokenUserScriptDoesNotFallBack pins the "exists but is
// unusable" case, which is distinct from "does not exist".
//
// A user whose own script is unusable -- here, over the size cap -- gets no
// filtering. They do not silently get the site default in its place. Falling
// back would mean a user who deliberately wrote a script that leaves flagged
// mail in the inbox, and then let it grow too large, has their policy quietly
// handed back to the server without anything saying so.
//
// Worth a test rather than just a comment: the fallback is one `if` away from
// swallowing this case, and nothing else in the suite would notice.
func TestSystemSieve_BrokenUserScriptDoesNotFallBack(t *testing.T) {
	dlvr := setupDomainFixture(t, "")
	writeSystemSieve(t, dlvr, junkOnFlagScript)

	big := make([]byte, maxSieveScriptSize+1)
	for i := range big {
		big[i] = '\n'
	}
	writeSieve(t, dlvr, string(big))

	resp := deliverAliceWithVerdict(t, dlvr, spamVerdict())
	if resp.Result != ResultDelivered {
		t.Fatalf("want ResultDelivered, got %v (reason: %q)", resp.Result, resp.Reason)
	}

	if n := countMessages(t, folderPath(dlvr, "Junk")); n != 0 {
		t.Errorf("unusable user script fell back to the system default (%d filed to Junk)", n)
	}
	if n := countMessages(t, inboxPath(dlvr)); n != 1 {
		t.Errorf("want 1 message in inbox, got %d", n)
	}
}

// TestSystemSieve_AbsentIsNotAnError: no system script and no user script is the
// ordinary unconfigured case, not a failure.
func TestSystemSieve_AbsentIsNotAnError(t *testing.T) {
	dlvr := setupDomainFixture(t, "")

	resp := deliverAliceWithVerdict(t, dlvr, spamVerdict())
	if resp.Result != ResultDelivered {
		t.Fatalf("want ResultDelivered, got %v (reason: %q)", resp.Result, resp.Reason)
	}
	if n := countMessages(t, inboxPath(dlvr)); n != 1 {
		t.Errorf("want 1 message in inbox, got %d", n)
	}
}

// TestSystemSieve_UnparseableFallsThrough: a broken site script must not break
// delivery for every user on the server. RFC 5228 section 2.10.6 -- implicit
// keep on error. This is the failure mode with the widest blast radius here, so
// it is pinned.
func TestSystemSieve_UnparseableFallsThrough(t *testing.T) {
	dlvr := setupDomainFixture(t, "")
	writeSystemSieve(t, dlvr, "this is not sieve {{{\n")

	resp := deliverAliceWithVerdict(t, dlvr, spamVerdict())
	if resp.Result != ResultDelivered {
		t.Fatalf("broken system script failed the delivery: %v (reason: %q)", resp.Result, resp.Reason)
	}
	if n := countMessages(t, inboxPath(dlvr)); n != 1 {
		t.Errorf("want 1 message in inbox, got %d", n)
	}
}

// TestSystemSieve_OversizedIsIgnored: same cap as a user script, same fail-safe.
func TestSystemSieve_OversizedIsIgnored(t *testing.T) {
	dlvr := setupDomainFixture(t, "")
	big := make([]byte, maxSieveScriptSize+1)
	for i := range big {
		big[i] = '\n'
	}
	writeSystemSieve(t, dlvr, junkOnFlagScript+string(big))

	deliverAliceWithVerdict(t, dlvr, spamVerdict())

	if n := countMessages(t, inboxPath(dlvr)); n != 1 {
		t.Errorf("want 1 message in inbox (oversized script ignored), got %d", n)
	}
	if n := countMessages(t, folderPath(dlvr, "Junk")); n != 0 {
		t.Errorf("oversized script was executed anyway (%d filed)", n)
	}
}

// TestSystemSieve_CleanMailUntouched: the default must not file mail the
// scanner cleared. A false positive here costs the user real mail.
func TestSystemSieve_CleanMailUntouched(t *testing.T) {
	dlvr := setupDomainFixture(t, "")
	writeSystemSieve(t, dlvr, junkOnFlagScript)

	deliverAliceWithVerdict(t, dlvr, &SpamVerdict{
		IsSpam:  false,
		Score:   -2.5,
		Headers: map[string]string{"X-Spam-Value": "1"},
	})

	if n := countMessages(t, folderPath(dlvr, "Junk")); n != 0 {
		t.Errorf("filed scanned-clean mail to Junk (%d)", n)
	}
	if n := countMessages(t, inboxPath(dlvr)); n != 1 {
		t.Errorf("want 1 message in inbox, got %d", n)
	}
}

// TestSystemSieve_UnscannedMailUntouched: with no scan the environment item is
// unsupported, so the rule cannot fire. Delivering unscanned mail to Junk
// because a missing verdict read as spam would be a bad failure.
func TestSystemSieve_UnscannedMailUntouched(t *testing.T) {
	dlvr := setupDomainFixture(t, "")
	writeSystemSieve(t, dlvr, junkOnFlagScript)

	deliverAliceWithVerdict(t, dlvr, nil)

	if n := countMessages(t, folderPath(dlvr, "Junk")); n != 0 {
		t.Errorf("filed unscanned mail to Junk (%d)", n)
	}
	if n := countMessages(t, inboxPath(dlvr)); n != 1 {
		t.Errorf("want 1 message in inbox, got %d", n)
	}
}

// TestSystemSieve_ShippedDefaultWorks runs the actual file we ship, rather than
// a paraphrase of it, so a typo in the shipped script fails the build instead of
// silently filing nothing in production.
func TestSystemSieve_ShippedDefaultWorks(t *testing.T) {
	shipped, err := os.ReadFile(filepath.Join("..", "..", "..",
		"docker", "all-in-one", "rootfs", "usr", "share", "maildancer", "system.sieve"))
	if err != nil {
		t.Fatalf("read shipped default script: %v", err)
	}

	t.Run("files spam", func(t *testing.T) {
		dlvr := setupDomainFixture(t, "")
		writeSystemSieve(t, dlvr, string(shipped))
		deliverAliceWithVerdict(t, dlvr, spamVerdict())
		if n := countMessages(t, folderPath(dlvr, "Junk")); n != 1 {
			t.Errorf("shipped default did not file spam to Junk (got %d)", n)
		}
	})

	t.Run("keeps clean", func(t *testing.T) {
		dlvr := setupDomainFixture(t, "")
		writeSystemSieve(t, dlvr, string(shipped))
		deliverAliceWithVerdict(t, dlvr, &SpamVerdict{IsSpam: false, Headers: map[string]string{"X-Spam-Value": "1"}})
		if n := countMessages(t, inboxPath(dlvr)); n != 1 {
			t.Errorf("shipped default did not keep clean mail in the inbox (got %d)", n)
		}
	})

	t.Run("keeps unscanned", func(t *testing.T) {
		dlvr := setupDomainFixture(t, "")
		writeSystemSieve(t, dlvr, string(shipped))
		deliverAliceWithVerdict(t, dlvr, nil)
		if n := countMessages(t, inboxPath(dlvr)); n != 1 {
			t.Errorf("shipped default did not keep unscanned mail in the inbox (got %d)", n)
		}
	})
}

// TestSystemSieve_NoLearnOnServerSideFiling guards the design invariant that
// server-side filing must not train Bayes.
//
// Training is driven by IMAP MOVE across the Junk boundary (imapd
// storeops.go triggerLearn), and delivery-time filing performs no IMAP
// operation at all -- so it is correct by construction. This test pins the
// construction: the delivery path must reach the store directly and never route
// a fileinto through anything IMAP-shaped. If that ever changed, every
// auto-filed message would train itself as spam and the classifier would
// reinforce its own guesses instead of learning from the user's corrections.
func TestSystemSieve_NoLearnOnServerSideFiling(t *testing.T) {
	dlvr := setupDomainFixture(t, "")
	writeSystemSieve(t, dlvr, junkOnFlagScript)

	resp, err := dlvr.Deliver(context.Background(),
		DeliverRequest{
			Sender:    "sender@example.com",
			Recipient: "alice@example.com",
			Spam:      spamVerdict(),
		},
		[]byte(minimalMsg))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Result != ResultDelivered {
		t.Fatalf("want ResultDelivered, got %v", resp.Result)
	}

	// The delivery pipeline has no learner and no IMAP session; the only
	// observable is that filing happened without one existing.
	if n := countMessages(t, folderPath(dlvr, "Junk")); n != 1 {
		t.Errorf("want 1 message in Junk, got %d", n)
	}
}
